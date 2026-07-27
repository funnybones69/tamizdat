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
	workersPerGroup    = 12
	multiRoomGroupSize = 1
	defaultCycleSecs   = 36000
	quotaStartupGrace  = 15 * time.Second
	quotaRetryInitial  = 5 * time.Second
	quotaRetryMaximum  = 1 * time.Minute
)

func credentialCycleSeconds(lifetime, stagger int) int {
	if lifetime <= 0 {
		return defaultCycleSecs
	}
	safety := 120
	if lifetime <= 240 {
		safety = 30
	}
	if lifetime <= 60 {
		safety = 5
	}
	seconds := lifetime - safety + stagger
	maxSeconds := lifetime - 5
	if seconds > maxSeconds {
		seconds = maxSeconds
	}
	if seconds < 5 {
		seconds = 5
	}
	return seconds
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

	// Предыдущий батч
	var prevCancel context.CancelFunc
	var prevDoneChs []chan struct{}
	var commonSignalOnce sync.Once

	killBatch := func() {
		if prevCancel != nil {
			prevCancel()
			for _, ch := range prevDoneChs {
				select {
				case <-ch:
				case <-time.After(3 * time.Second):
				}
			}
			prevCancel = nil
			prevDoneChs = nil
		}
	}
	defer killBatch()

	for {
		if ctx.Err() != nil {
			return
		}

		// Doze-mode пауза: убиваем воркеров и ждём RESUME
		if atomic.LoadInt32(pauseFlag) != 0 {
			killBatch()
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

		creds, err := func() (*Credentials, error) {
			authLock := r.credentialLock(hash)
			authLock.Lock()
			defer authLock.Unlock()
			log.Printf("[ГРУППА #%d] Цикл %d: запрос кредов", groupID, cycleNumber)
			return r.getCredsWithFallback(ctx, tp, hash, stats)
		}()

		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if bondV2 && roomID >= 0 && roomID < len(stats.BondRoomCredentialErrors) {
				atomic.AddInt64(&stats.BondRoomCredentialErrors[roomID], 1)
			}
			log.Printf("[ГРУППА #%d] Ошибка кредов: %v", groupID, err)
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}

		// Вычисляем точное время жизни на основе ответа VK (минус 2 минуты для надёжности)
		stagger := 0
		if bondV2 && len(workerIDs) == 1 {
			// Multi-room uses one lifecycle group per allocation.  Groups start two
			// seconds apart and retain the same spacing on every credential cycle,
			// so a rotation retires at most one worker per room instead of all 80.
			stagger = ((workerIDs[0] - 1) % 20) * 2
		}
		sleepDuration := credentialCycleSeconds(creds.Lifetime, stagger)
		cycleDurationLocal := time.Duration(sleepDuration) * time.Second

		workerCount := len(workerIDs)
		if workerCount <= 0 {
			workerCount = workersPerGroup
		}
		log.Printf("[ГРУППА #%d] Запуск %d потоков (до смены кредов: %d сек)", groupID, workerCount, sleepDuration)

		log.Printf("[ГРУППА #%d] Креды OK, TURN urls=%d, %d воркеров", groupID, len(creds.TurnURLs), len(workerIDs))

		// ТЕПЕРЬ убиваем старый батч (креды уже готовы — минимальный простой)
		killBatch()

		// Создаём новый batch
		batchCtx, batchCancel := context.WithCancel(ctx)

		refreshCh := make(chan struct{}, 1)
		quotaBackoffCh := make(chan string, 1)
		doneChs := make([]chan struct{}, len(workerIDs))
		var quotaErrorWorkers sync.Map
		var notFoundErrorWorkers sync.Map

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

					configDelivered, sessErr := RunSession(batchCtx, tp, peer, d, localPort, useUDP,
						getConf, cc, wid, creds, deviceID, password, stats, dialer, r.cfg.OnEvent,
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
							attached := broker != nil && broker.sent.Load()
							if !attached && qCount >= threshold {
								log.Printf("[ГРУППА #%d] TURN quota у %d/%d воркеров до GETCONF; backoff без hammer", groupID, qCount, len(workerIDs))
								select {
								case quotaBackoffCh <- errStr:
								default:
								}
								return
							}

							// A quota error is local to this allocation.  Once any worker has
							// delivered GETCONF, preserve the live Bond and retry only the
							// missing worker.  This lets a 4x20 pool converge back to 80/80
							// instead of permanently losing every worker that hit a stale VK
							// allocation during a process or server restart.
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

		// Ждём TTL либо сигнала досрочной ротации
		select {
		case <-time.After(cycleDurationLocal):
			log.Printf("[ГРУППА #%d] TTL %v истёк, ротация", groupID, cycleDurationLocal)
		case <-refreshCh:
			log.Printf("[ГРУППА #%d] Вызвана досрочная ротация (креды не отвечали)", groupID)
		case quotaReason := <-quotaBackoffCh:
			// Quota failures arrive faster than successful TURN handshakes.  The
			// old implementation killed the whole batch after the first five
			// failures, which also destroyed workers that still had a chance to
			// attach.  Give the batch enough time to deliver GETCONF and preserve
			// every usable worker when it does.
			log.Printf("[ГРУППА #%d] TURN quota до GETCONF: ждём успешный канал до %v", groupID, quotaStartupGrace)
			graceTimer := time.NewTimer(quotaStartupGrace)
			poll := time.NewTicker(250 * time.Millisecond)
			attached := broker != nil && broker.sent.Load()
		waitForAttach:
			for !attached {
				select {
				case <-poll.C:
					attached = broker != nil && broker.sent.Load()
				case <-graceTimer.C:
					break waitForAttach
				case <-ctx.Done():
					poll.Stop()
					if !graceTimer.Stop() {
						select {
						case <-graceTimer.C:
						default:
						}
					}
					return
				}
			}
			poll.Stop()
			if !graceTimer.Stop() {
				select {
				case <-graceTimer.C:
				default:
				}
			}
			// A successful GETCONF may race with the grace timer firing.
			attached = broker != nil && broker.sent.Load()

			if attached {
				quotaRetryDelay = quotaRetryInitial
				if r.cfg.OnQuota != nil {
					r.cfg.OnQuota(quotaReason)
				}
				log.Printf("[ГРУППА #%d] TURN quota частичная: сохраняем рабочий batch без разрыва туннеля", groupID)
				select {
				case <-time.After(cycleDurationLocal):
					log.Printf("[ГРУППА #%d] TTL %v истёк после частичной квоты, ротация", groupID, cycleDurationLocal)
				case <-refreshCh:
					log.Printf("[ГРУППА #%d] Досрочная ротация после частичной квоты", groupID)
				case <-ctx.Done():
					return
				}
			} else {
				if r.cfg.OnQuota != nil {
					r.cfg.OnQuota(quotaReason)
				}
				log.Printf("[ГРУППА #%d] TURN quota полная: повтор через %v без фиксированной 10-минутной паузы", groupID, quotaRetryDelay)
				killBatch()
				// Do not retry a room-scoped cached credential batch forever. The
				// next cycle must obtain fresh TURN material so a stale allocation
				// quota cannot strand this room at zero workers.
				r.invalidateRoomCreds(hash)
				select {
				case <-time.After(quotaRetryDelay):
					quotaRetryDelay = nextQuotaRetryDelay(quotaRetryDelay)
				case <-ctx.Done():
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
