package wgturnclient

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	workersPerGroup         = 12
	multiRoomGroupSize      = 1
	defaultCycleSecs        = 36000
	quotaRetryInitial       = 5 * time.Second
	quotaRetryMaximum       = 1 * time.Minute
	rotationSafetySeconds   = 120
	rotationOffsetStep      = 10 * time.Second
	rotationOffsetCap       = 60 * time.Second
	rotationMinimumInterval = 60 * time.Second
	workerStopTimeout       = 10 * time.Second
	workerRecoveryTimeout   = 15 * time.Second
	workerRecoveryPoll      = 250 * time.Millisecond
	workerRecoveryFallback  = 2500 * time.Millisecond
	credentialRetryDelay    = 30 * time.Second
)

func rotationOffset(groupID int) time.Duration {
	if groupID <= 0 {
		return 0
	}
	offset := time.Duration(groupID) * rotationOffsetStep
	if offset > rotationOffsetCap {
		return rotationOffsetCap
	}
	return offset
}

func rotationSleepDuration(lifetime, groupID int) time.Duration {
	if lifetime <= 0 {
		lifetime = defaultCycleSecs
	}
	safety := rotationSafetySeconds
	if lifetime <= 240 {
		safety = 30
	}
	if lifetime <= 60 {
		safety = 5
	}
	delay := time.Duration(lifetime-safety)*time.Second - rotationOffset(groupID)
	if delay < rotationMinimumInterval {
		return rotationMinimumInterval
	}
	return delay
}

func doneChannelsClosed(channels []chan struct{}) bool {
	for _, ch := range channels {
		select {
		case <-ch:
		default:
			return false
		}
	}
	return true
}

func waitDoneChannels(ctx context.Context, channels []chan struct{}, timeout time.Duration) bool {
	if doneChannelsClosed(channels) {
		return true
	}
	timer := time.NewTimer(timeout)
	ticker := time.NewTicker(workerRecoveryPoll)
	defer timer.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if doneChannelsClosed(channels) {
				return true
			}
		case <-timer.C:
			return doneChannelsClosed(channels)
		case <-ctx.Done():
			return false
		}
	}
}

func waitWorkerRecovery(ctx context.Context, d *Dispatcher, workerIDs map[int]struct{}, requiredID, target int) bool {
	ready := func() bool {
		count, requiredActive := d.workerGroupState(workerIDs, requiredID)
		return requiredActive && count >= target
	}
	if ready() {
		return true
	}
	timer := time.NewTimer(workerRecoveryTimeout)
	ticker := time.NewTicker(workerRecoveryPoll)
	defer timer.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if ready() {
				return true
			}
		case <-timer.C:
			fallback := time.NewTimer(workerRecoveryFallback)
			defer fallback.Stop()
			select {
			case <-fallback.C:
				return ready()
			case <-ctx.Done():
				return false
			}
		case <-ctx.Done():
			return false
		}
	}
}

func nextQuotaRetryDelay(current time.Duration) time.Duration {
	if current < quotaRetryInitial {
		return quotaRetryInitial
	}
	next := current * 2
	if next > quotaRetryMaximum {
		return quotaRetryMaximum
	}
	return next
}

type configBroker struct {
	ch             chan<- string
	sent           atomic.Bool
	inFlight       atomic.Bool
	recoveryNeeded atomic.Bool
}

func (b *configBroker) claim() bool {
	if b == nil {
		return false
	}
	if !b.sent.Load() {
		return b.inFlight.CompareAndSwap(false, true)
	}
	if !b.recoveryNeeded.Load() || !b.inFlight.CompareAndSwap(false, true) {
		return false
	}
	if !b.recoveryNeeded.CompareAndSwap(true, false) {
		b.inFlight.Store(false)
		return false
	}
	return true
}

func (b *configBroker) complete(delivered bool) {
	if b == nil {
		return
	}
	if delivered {
		b.sent.Store(true)
		b.recoveryNeeded.Store(false)
	}
	b.inFlight.Store(false)
}

func (b *configBroker) requestRecovery() {
	if b != nil && b.sent.Load() {
		b.recoveryNeeded.Store(true)
	}
}

func (b *configBroker) channel() chan<- string {
	if b == nil {
		return nil
	}
	return b.ch
}

// workerGroup:
// бесшовная ротация: получить новые креды → запустить новый батч → убить старый.
func (r *Runner) workerGroup(
	ctx context.Context,
	groupID int,
	hashIndex int,
	roomID int,
	tp *TurnParams,
	peer *net.UDPAddr,
	d *Dispatcher,
	localPort string,
	useUDP bool,
	broker *configBroker,
	workerIDs []int,
	cycleDuration time.Duration,
	pauseFlag *int32,
	deviceID, password string,
	stats *Stats,
	waitReady <-chan struct{},
	signalReady chan<- struct{},
	dialer DialContextFunc,
	bondV2 bool,
	bondID bondRunnerIdentity,
) {
	// Каскадный запуск: ждем свою очередь
	if waitReady != nil {
		log.Printf("[ГРУППА #%d] Ожидание сигнала от предыдущей группы...", groupID)
		select {
		case <-waitReady:
		case <-ctx.Done():
			return
		}
	}

	cycleNumber := 0
	quotaRetryDelay := quotaRetryInitial
	workerIDSet := make(map[int]struct{}, len(workerIDs))
	for _, wid := range workerIDs {
		workerIDSet[wid] = struct{}{}
	}

	// Предыдущий батч
	var prevCancel context.CancelFunc
	var prevDoneChs []chan struct{}
	var commonSignalOnce sync.Once
	var forcedPrevious *Credentials
	recoveryReplacement := false

	killBatch := func() bool {
		if prevCancel != nil {
			prevCancel()
			if !waitDoneChannels(ctx, prevDoneChs, workerStopTimeout) {
				log.Printf("[ГРУППА #%d] Таймаут остановки batch; замена не запускается", groupID)
				return false
			}
			prevCancel = nil
			prevDoneChs = nil
		}
		return true
	}
	defer func() { _ = killBatch() }()

	for {
		if ctx.Err() != nil {
			return
		}

		// Doze-mode пауза: убиваем воркеров и ждём RESUME
		if atomic.LoadInt32(pauseFlag) != 0 {
			if !killBatch() {
				return
			}
			log.Printf("[ГРУППА #%d] Пауза (Doze)", groupID)
			for {
				if ctx.Err() != nil {
					return
				}
				if atomic.LoadInt32(pauseFlag) == 0 {
					log.Printf("[ГРУППА #%d] Возобновление — новые креды", groupID)
					break
				}
				time.Sleep(1 * time.Second)
			}
		}

		// Получаем креды ДО убийства старого батча (бесшовная ротация)
		hash := tp.Hashes[hashIndex%len(tp.Hashes)]
		log.Printf("[ГРУППА #%d] Цикл %d: ожидание очереди получения кредов", groupID, cycleNumber)

		var creds *Credentials
		var err error
		if forcedPrevious != nil {
			creds, err = r.refreshCredentialsForGeneration(ctx, tp, hash, forcedPrevious, stats)
			if err == nil {
				forcedPrevious = nil
			}
		} else {
			creds, err = func() (*Credentials, error) {
				authLock := r.credentialLock(hash)
				authLock.Lock()
				defer authLock.Unlock()
				log.Printf("[ГРУППА #%d] Цикл %d: запрос кредов", groupID, cycleNumber)
				return r.getCredsWithFallback(ctx, tp, hash, stats)
			}()
		}

		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if bondV2 && roomID >= 0 && roomID < len(stats.BondRoomCredentialErrors) {
				atomic.AddInt64(&stats.BondRoomCredentialErrors[roomID], 1)
			}
			log.Printf("[ГРУППА #%d] Ошибка кредов: %v", groupID, err)
			select {
			case <-time.After(credentialRetryDelay):
			case <-ctx.Done():
				return
			}
			continue
		}

		// Group offsets spread refresh load; the period is never below 60s.
		cycleDurationLocal := rotationSleepDuration(creds.Lifetime, groupID)

		workerCount := len(workerIDs)
		if workerCount <= 0 {
			workerCount = workersPerGroup
		}
		log.Printf("[ГРУППА #%d] Запуск %d потоков (до смены кредов: %v)", groupID, workerCount, cycleDurationLocal)

		log.Printf("[ГРУППА #%d] Креды OK, TURN urls=%d, %d воркеров", groupID, len(creds.TurnURLs), len(workerIDs))

		// ТЕПЕРЬ убиваем старый батч (креды уже готовы — минимальный простой)
		rollingReplacement := prevCancel != nil || recoveryReplacement
		if !killBatch() {
			return
		}

		// Создаём новый batch
		batchCtx, batchCancel := context.WithCancel(ctx)

		refreshCh := make(chan struct{}, 1)
		quotaBackoffCh := make(chan *Credentials, 1)
		doneChs := make([]chan struct{}, len(workerIDs))
		var quotaErrorWorkers sync.Map
		var notFoundErrorWorkers sync.Map
		var quotaBackoffOnce sync.Once

		// Сигнализируем следующей группе, что мы успешно запустились (креды получены + 2 сек форы)
		go func() {
			commonSignalOnce.Do(func() {
				if signalReady != nil {
					time.Sleep(2000 * time.Millisecond) // Запас времени для рукопожатий (3*500ms + 500ms)
					close(signalReady)
					log.Printf("[ГРУППА #%d] Успешный старт! Передача эстафеты следующей группе...", groupID)
				}
			})
		}()

		for i, wid := range workerIDs {
			doneCh := make(chan struct{})
			doneChs[i] = doneCh

			// Stagger: 500мс между воркерами
			workerDelay := time.Duration(i) * 500 * time.Millisecond

			go func(wid int, delay time.Duration, doneCh chan struct{}) {
				defer close(doneCh)
				workerQuotaDelay := quotaRetryInitial

				if delay > 0 {
					select {
					case <-time.After(delay):
					case <-batchCtx.Done():
						return
					}
				}

				// Retry loop: воркер переподключается при ошибке
				attempt := 0
				for {
					if batchCtx.Err() != nil {
						return
					}

					getConf := broker.claim()
					var cc chan<- string
					if getConf {
						cc = broker.channel()
					}

					attemptCreds := r.credentialsForAttempt(hash, creds)
					configDelivered, sessErr := RunSession(batchCtx, tp, peer, d, localPort, useUDP,
						getConf, cc, wid, attemptCreds, deviceID, password, stats, dialer, r.cfg.OnEvent,
						memoryProfileForWorkers(r.cfg.Workers), bondV2, bondID, roomID)

					if getConf {
						broker.complete(configDelivered)
					}

					if sessErr != nil {
						if batchCtx.Err() != nil {
							return
						}
						errStr := sessErr.Error()
						if bondV2 && roomID >= 0 && roomID < len(stats.BondRoomSessionErrors) {
							atomic.AddInt64(&stats.BondRoomSessionErrors[roomID], 1)
						}

						// Дописываем понятные пояснения для типичных ошибок со стороны балансировщиков ВК
						errStrLower := strings.ToLower(errStr)
						if bondV2 && strings.Contains(errStrLower, "bind wait retries exhausted") {
							// The server can restart while this runner and its TURN sessions
							// remain alive. Re-elect exactly one password-bearing owner so the
							// same run can recreate its server-side Bond without a process restart.
							broker.requestRecovery()
							log.Printf("[ГРУППА #%d] Bond owner потерян на сервере; автоматическое переизбрание", groupID)
						}
						if strings.Contains(errStrLower, "attribute not found") ||
							strings.Contains(errStrLower, "rate limit") ||
							strings.Contains(errStrLower, "flood control") ||
							strings.Contains(errStrLower, "ip mismatch") ||
							strings.Contains(errStrLower, "error 29") {
							errStr += " (ошибка со стороны ВК)"
						}

						// Фатальные ошибки — смерть аккаунта
						if strings.Contains(errStr, "хеш мёртв") ||
							strings.Contains(errStr, "FATAL_AUTH") {
							log.Printf("[ВОРКЕР #%d] Фатальная ошибка: %s", wid, errStr)
							if broker != nil && broker.sent.Load() {
								retryDelay := workerQuotaDelay + time.Duration(rand.Intn(3000))*time.Millisecond
								workerQuotaDelay = nextQuotaRetryDelay(workerQuotaDelay)
								log.Printf("[ВОРКЕР #%d] TURN quota: повтор через %v без остановки рабочего batch", wid, retryDelay)
								select {
								case <-time.After(retryDelay):
									continue
								case <-batchCtx.Done():
									return
								}
							}
							return
						}

						// Исчерпана ли квота TURN? Do not sleep-and-retry the same
						// credential batch: that hammers VK allocations and keeps gate in
						// a restart loop. iOS behavior is important here: partial quota
						// after GETCONF/attach is degraded capacity, not a fatal tunnel
						// condition. Only pre-GETCONF quota should trigger process-level
						// backoff because there is no usable tunnel yet.
						if strings.Contains(errStrLower, "turn квота") || strings.Contains(errStrLower, "quota") {
							if bondV2 && roomID >= 0 && roomID < len(stats.BondRoomQuotaErrors) {
								atomic.AddInt64(&stats.BondRoomQuotaErrors[roomID], 1)
							}
							quotaErrorWorkers.Store(wid, true)
							qCount := 0
							quotaErrorWorkers.Range(func(k, v any) bool { qCount++; return true })
							threshold := len(workerIDs)
							if threshold <= 0 || threshold > 5 {
								threshold = 5
							}
							log.Printf("[ВОРКЕР #%d] Ошибка квоты TURN: %s", wid, errStr)
							if qCount >= threshold {
								quotaBackoffOnce.Do(func() {
									phase := "до GETCONF"
									if broker != nil && broker.sent.Load() {
										phase = "после GETCONF/attach"
									}
									log.Printf("[ГРУППА #%d] TURN quota у %d/%d воркеров %s; обновление поколения без hammer", groupID, qCount, len(workerIDs), phase)
									if r.cfg.OnQuota != nil {
										r.cfg.OnQuota(errStr)
									}
									quotaBackoffCh <- cloneCredentials(attemptCreds)
								})
								return
							}

							// A partial quota error is local to one allocation. Preserve the
							// rest of the batch and retry only this worker.
							retryDelay := workerQuotaDelay + time.Duration(rand.Intn(3000))*time.Millisecond
							workerQuotaDelay = nextQuotaRetryDelay(workerQuotaDelay)
							log.Printf("[ВОРКЕР #%d] TURN quota: локальный повтор через %v без ротации рабочего batch", wid, retryDelay)
							select {
							case <-time.After(retryDelay):
								continue
							case <-batchCtx.Done():
								return
							}
						}

						attempt++
						log.Printf("[ВОРКЕР #%d] Ошибка (попытка %d): %s", wid, attempt, errStr)

						// Умерли ли креды? (Строго STUN/TURN ошибки: интернет работает, но сервер отвергает ключи)
						isStunDeath := strings.Contains(errStrLower, "attribute not found") ||
							strings.Contains(errStrLower, "error 29") ||
							strings.Contains(errStrLower, "unauthorized") ||
							strings.Contains(errStrLower, "allocation mismatch") ||
							strings.Contains(errStrLower, "error 508") ||
							strings.Contains(errStrLower, "cannot create socket")

						isStreamClosed := strings.Contains(errStrLower, "stream closed")

						if isStreamClosed {
							select {
							case refreshCh <- struct{}{}:
								log.Printf("[ГРУППА #%d] Мгновенная ротация: сервер ВК закрыл поток (Stream Closed)", groupID)
							default:
							}
						} else if isStunDeath {
							notFoundErrorWorkers.Store(wid, true)
							nfCount := 0
							notFoundErrorWorkers.Range(func(k, v any) bool { nfCount++; return true })

							// Если 8 уникальных воркеров получили явный отказ от сервера — ключи 100% протухли
							if nfCount >= 8 {
								select {
								case refreshCh <- struct{}{}:
									log.Printf("[ГРУППА #%d] Досрочная ротация: сервер ВК убил сессию (у %d воркеров)", groupID, nfCount)
								default:
								}
							}
						}
					} else {
						quotaErrorWorkers.Delete(wid)
						workerQuotaDelay = quotaRetryInitial
					}

					if batchCtx.Err() != nil {
						return
					}

					// Пауза перед ретраем с джиттером 5-15 сек
					retryDelay := time.Duration(5+rand.Intn(11)) * time.Second
					select {
					case <-time.After(retryDelay):
					case <-batchCtx.Done():
						return
					}
				}
			}(wid, workerDelay, doneCh)
		}

		// Сохраняем батч для бесшовной ротации
		prevCancel = batchCancel
		prevDoneChs = doneChs
		if rollingReplacement {
			for _, wid := range workerIDs {
				if !waitWorkerRecovery(ctx, d, workerIDSet, wid, len(workerIDs)) {
					count, _ := d.workerGroupState(workerIDSet, wid)
					log.Printf("[ГРУППА #%d] Воркер #%d не восстановился за %v + %v (активно %d/%d), продолжаем", groupID, wid, workerRecoveryTimeout, workerRecoveryFallback, count, len(workerIDs))
					break
				}
			}
		}
		recoveryReplacement = false

		// Ждём TTL либо сигнала досрочной ротации
		select {
		case <-time.After(cycleDurationLocal):
			log.Printf("[ГРУППА #%d] TTL %v истёк, ротация", groupID, cycleDurationLocal)
			forcedPrevious = cloneCredentials(creds)
		case <-refreshCh:
			log.Printf("[ГРУППА #%d] Вызвана досрочная ротация (креды не отвечали)", groupID)
			forcedPrevious = cloneCredentials(creds)
		case quotaCreds := <-quotaBackoffCh:
			log.Printf("[ГРУППА #%d] TURN 486: останавливаем старое поколение и запрашиваем новое", groupID)
			if !killBatch() {
				return
			}
			for {
				_, refreshErr := r.refreshCredentialsForGeneration(ctx, tp, hash, quotaCreds, stats)
				if refreshErr == nil {
					quotaRetryDelay = quotaRetryInitial
					recoveryReplacement = true
					break
				}
				if bondV2 && roomID >= 0 && roomID < len(stats.BondRoomCredentialErrors) {
					atomic.AddInt64(&stats.BondRoomCredentialErrors[roomID], 1)
				}
				log.Printf("[ГРУППА #%d] Новое поколение кредов пока недоступно; повтор через %v", groupID, quotaRetryDelay)
				timer := time.NewTimer(quotaRetryDelay)
				select {
				case <-timer.C:
					quotaRetryDelay = nextQuotaRetryDelay(quotaRetryDelay)
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
		case <-ctx.Done():
			return
		}

		cycleNumber++
	}
}

// ParseHashes — парсит строку хешей
func ParseHashes(raw string) []string {
	var result []string
	for _, h := range strings.Split(raw, ",") {
		h = strings.TrimSpace(h)
		if idx := strings.IndexAny(h, "/?#"); idx != -1 {
			h = h[:idx]
		}
		if h != "" {
			result = append(result, h)
		}
	}
	return result
}

// TurnParams — конфигурация TURN
type TurnParams struct {
	Host          string
	Port          string
	Hashes        []string
	SecondaryHash string
	Sni           string
}

// Unused import suppressor
var _ = fmt.Sprintf
