package wgturnclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/funnybones69/tamizdat/internal/vkcreds"
	"github.com/google/uuid"
)

var (
	sharedTransportOnce sync.Once
	sharedTransport     *http.Transport
)

const forcedCredentialRefreshInterval = 60 * time.Second

func (r *Runner) reserveForcedCredentialRefresh(hash string, now time.Time) bool {
	key := normalizeVKCallHash(hash)
	r.forcedCredsMu.Lock()
	defer r.forcedCredsMu.Unlock()
	if r.forcedCredsAt == nil {
		r.forcedCredsAt = make(map[string]time.Time)
	}
	if last := r.forcedCredsAt[key]; !last.IsZero() && now.Sub(last) < forcedCredentialRefreshInterval {
		return false
	}
	r.forcedCredsAt[key] = now
	return true
}

// refreshCredentialsForGeneration reuses a fresh sibling generation when one
// exists. Otherwise it invalidates exactly the rejected generation and permits
// at most one forced provider fetch per room per minute.
func (r *Runner) refreshCredentialsForGeneration(ctx context.Context, tp *TurnParams, hash string, previous *Credentials, stats *Stats) (*Credentials, error) {
	authLock := r.credentialLock(hash)
	authLock.Lock()
	defer authLock.Unlock()

	var cached *Credentials
	if r.cfg.WorkersPerRoom > 0 {
		cached = r.currentRoomCreds(hash)
	} else {
		cached = r.currentPreloadedCreds()
	}
	if cached != nil && !sameCredentialGeneration(cached, previous) {
		return cached, nil
	}
	r.invalidateCredentials(hash, previous)
	if !r.reserveForcedCredentialRefresh(hash, time.Now()) {
		return nil, fmt.Errorf("принудительное обновление кредов временно ограничено")
	}
	return r.getCredsWithFallback(ctx, tp, hash, stats)
}

func (r *Runner) popCachedToken() string {
	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()
	if r.cachedTokenUsages > 0 {
		r.cachedTokenUsages--
		return r.cachedSuccessToken
	}
	return ""
}

func (r *Runner) pushCachedToken(token string, usages int32) {
	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()
	r.cachedSuccessToken = token
	r.cachedTokenUsages = usages
}

func (r *Runner) invalidateCachedToken() {
	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()
	r.cachedSuccessToken = ""
	r.cachedTokenUsages = 0
}

func (r *Runner) getUserAgent() string {
	return r.userAgent.Load().(string)
}

func getSharedTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		dialer := &net.Dialer{
			Timeout: 10 * time.Second,
		}
		sharedTransport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	})
	return sharedTransport
}

type Credentials struct {
	User string
	Pass string
	// Source is non-secret observability metadata. It is never sent to TURN.
	Source string
	// TurnURLs is the legacy "host:port" list. TurnServers, when present,
	// is authoritative because it preserves VK's per-URL scheme/transport
	// metadata (turn|turns, udp|tcp) like the iOS VK TURN path.
	TurnURLs    []string
	TurnServers []TurnServer
	Lifetime    int
}

// TurnServer carries one TURN URL split into components so sessions can
// honour VK's advertised transport instead of applying a global UDP/TCP knob
// to every endpoint.
type TurnServer struct {
	Host      string
	Port      int
	Scheme    string // "turn" | "turns"
	Transport string // "udp" | "tcp"
}

func (r *Runner) getCredsWithFallback(ctx context.Context, tp *TurnParams, hash string, stats *Stats) (*Credentials, error) {
	if r.cfg.WorkersPerRoom > 0 {
		if creds := r.currentRoomCreds(hash); creds != nil {
			return creds, nil
		}
	} else if pc := r.currentPreloadedCreds(); pc != nil {
		return pc, nil
	}
	creds, err := r.getCredsForHash(ctx, hash, 5, stats)
	if err == nil {
		r.publishFreshCredentials(hash, creds)
		return creds, nil
	}
	if tp.SecondaryHash != "" && hash != tp.SecondaryHash {
		log.Println("Основной хеш не сработал, пробую запасной")
		creds, err = r.getCredsForHash(ctx, tp.SecondaryHash, 3, stats)
		if err == nil {
			r.publishFreshCredentials(hash, creds)
		}
		return creds, err
	}
	return nil, err
}

func (r *Runner) publishFreshCredentials(hash string, creds *Credentials) {
	if creds == nil {
		return
	}
	if r.cfg.WorkersPerRoom > 0 {
		r.updateRoomCreds(hash, creds)
		if r.cfg.OnRoomCredentials != nil {
			r.cfg.OnRoomCredentials(hash, cloneCredentials(creds))
		}
		return
	}
	// Reuse one acquisition across all worker groups. With 20 workers the
	// runner creates groups of 12+8; without this cache both groups hit VK.
	r.UpdatePreloadedCreds(creds)
	if r.cfg.OnCredentials != nil {
		r.cfg.OnCredentials(r.currentPreloadedCreds())
	}
}

func (r *Runner) getCredsForHash(ctx context.Context, hash string, legacyRetries int, stats *Stats) (*Credentials, error) {
	mode := r.getCredentialMode()
	if r.cfg.AcquireRoomCredentials != nil && mode != "rjs-only" {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r.vkSemaphore <- struct{}{}:
		}
		creds, helperErr := r.cfg.AcquireRoomCredentials(ctx, hash)
		<-r.vkSemaphore
		if helperErr == nil && completeCredentials(creds) {
			return cloneCredentials(creds), nil
		}
		if helperErr == nil {
			helperErr = fmt.Errorf("helper returned incomplete credentials")
		}
		// The helper is deliberately only the first anonymous provider. A
		// transient helper failure must not take the router offline: continue to
		// the in-process accountless VKCalls flow, then autonomous RJS fallback.
		log.Printf("[VKCALLS] local credential helper unavailable; trying built-in anonymous flow: %s", sanitizeErrForEvent(helperErr))
	}
	var vkCallsErr error
	if mode != "rjs-only" {
		creds, err := r.getVKCallsCreds(ctx, hash)
		if err == nil {
			return creds, nil
		}
		vkCallsErr = err
		if mode == "anonymous-only" {
			return nil, fmt.Errorf("anonymous VKCalls credential flow failed")
		}
		log.Printf("[VKCALLS] anonymous flow unavailable, falling back to autonomous RJS: %v", vkCallsErr)
	} else {
		log.Printf("[VKCALLS] credential mode rjs-only: using autonomous accountless RJS flow")
	}

	creds, legacyErr := r.getUniqueVKCreds(ctx, hash, legacyRetries, stats)
	if legacyErr == nil {
		return creds, nil
	}
	if strings.Contains(strings.ToLower(legacyErr.Error()), "хеш мёртв") {
		return nil, fmt.Errorf("хеш мёртв: credential providers rejected room")
	}
	// Legacy captcha errors can contain redirect URLs/session tokens. Do not
	// propagate their raw text into router logs or LuCI status.
	return nil, fmt.Errorf("anonymous VKCalls and automatic captcha fallback failed")
}

func completeCredentials(creds *Credentials) bool {
	return creds != nil && strings.TrimSpace(creds.User) != "" && strings.TrimSpace(creds.Pass) != "" &&
		(len(creds.TurnURLs) > 0 || len(creds.TurnServers) > 0)
}

type vkCaptchaError struct {
	ErrorCode      int
	ErrorMsg       string
	CaptchaSid     string
	RedirectUri    string
	SessionToken   string
	CaptchaTs      string
	CaptchaAttempt string
}

func parseVkCaptchaError(errData map[string]interface{}) *vkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	redirectUri, _ := errData["redirect_uri"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	captchaSid, _ := errData["captcha_sid"].(string)
	if captchaSid == "" {
		if sidNum, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}

	var sessionToken string
	if redirectUri != "" {
		if parsed, err := neturl.Parse(redirectUri); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = strconv.FormatFloat(tsFloat, 'f', -1, 64)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &vkCaptchaError{
		ErrorCode:      int(codeFloat),
		ErrorMsg:       errorMsg,
		CaptchaSid:     captchaSid,
		RedirectUri:    redirectUri,
		SessionToken:   sessionToken,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}

func (r *Runner) solveVkCaptcha(ctx context.Context, captchaErr *vkCaptchaError, profile BotProfile) (string, error) {
	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("нет session_token в redirect_uri")
	}

	mode := r.getCaptchaMode()
	if mode == "wv" {
		log.Printf("[КАПЧА] Режим: WebView")
		return r.solveVkCaptchaViaWV(ctx, captchaErr)
	}
	if mode == "manual" {
		log.Printf("[КАПЧА] Режим: реальный браузер через локальную панель")
		return r.solveVkCaptchaViaFile(ctx, captchaErr)
	}

	log.Printf("[КАПЧА] Режим: Автоматический")
	token, err := r.solveVkCaptchaViaRJS(ctx, captchaErr, profile)
	if err == nil || r.cfg.CaptchaDir == "" {
		return token, err
	}
	log.Printf("[КАПЧА] Headless RJS отклонён VK; ожидается решение в реальном браузере через локальную панель")
	return r.solveVkCaptchaViaFile(ctx, captchaErr)
}

func (r *Runner) solveVkCaptchaViaFile(ctx context.Context, captchaErr *vkCaptchaError) (string, error) {
	if r.cfg.CaptchaDir == "" {
		return "", fmt.Errorf("manual captcha directory is not configured")
	}
	waitCtx, cancel := context.WithTimeout(ctx, r.cfg.CaptchaWait)
	defer cancel()
	solver := &vkcreds.FileCaptchaSolver{Dir: r.cfg.CaptchaDir}
	return solver.SolveCaptcha(waitCtx, captchaErr.RedirectUri, captchaErr.SessionToken)
}

func (r *Runner) getCaptchaMode() string {
	mode, _ := r.captchaMode.Load().(string)
	if mode == "" {
		return "rjs"
	}
	return mode
}

func (r *Runner) solveVkCaptchaViaWV(ctx context.Context, captchaErr *vkCaptchaError) (string, error) {
	select {
	case r.captchaWVSem <- struct{}{}:
	case <-ctx.Done():
		return "", fmt.Errorf("отмена во время ожидания очереди капчи: %w", ctx.Err())
	}
	defer func() {
		// Даем Kotlin гарантированную секунду на очистку Mutex и WebView
		time.Sleep(1 * time.Second)
		<-r.captchaWVSem
	}()

	log.Printf("[КАПЧА] WV: Запрос отправлен")

	r.drainCaptchaResult()

	fmt.Printf("CAPTCHA_SOLVE|%s|%s\n", captchaErr.RedirectUri, captchaErr.SessionToken)
	os.Stdout.Sync()

	select {
	case result := <-r.captchaResultCh:
		if strings.HasPrefix(result, "error:") {
			errMsg := strings.TrimPrefix(result, "error:")
			if !strings.Contains(errMsg, "tunnel stopped") {
				log.Printf("[КАПЧА] WV: Ошибка — %s", errMsg)
			}
			return "", fmt.Errorf("WV captcha error: %s", errMsg)
		}
		log.Printf("[КАПЧА] WV: Токен получен ✓")
		return result, nil
	case <-ctx.Done():
		return "", fmt.Errorf("отмена контекста во время ожидания капчи: %w", ctx.Err())
	case <-time.After(300 * time.Second):
		return "", fmt.Errorf("таймаут решения капчи через WV (5мин)")
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (r *Runner) solveVkCaptchaViaRJS(ctx context.Context, captchaErr *vkCaptchaError, profile BotProfile) (string, error) {
	captchaProfile := profile
	captchaProfile.UserAgent = normalizeCaptchaUserAgent(profile.UserAgent)

	// Create a tls-client instance to match the slider POC requirements
	tlsClient, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(selectCaptchaTLSProfile(captchaProfile.UserAgent)),
	)
	if err != nil {
		return "", fmt.Errorf("не удалось создать tls-client: %w", err)
	}

	bootstrap, err := fetchPowInput(ctx, captchaErr.RedirectUri, tlsClient, captchaProfile)
	if err != nil {
		return "", fmt.Errorf("не удалось загрузить captcha settings: %w", err)
	}
	if bootstrap.DebugInfo != "" {
		captchaProfile.DebugInfo = bootstrap.DebugInfo
		log.Printf("[КАПЧА RJS] Используется актуальный debug_info из JS bundle")
	} else {
		log.Printf("[КАПЧА RJS] Не удалось извлечь актуальный debug_info; fallback может быть отклонён")
	}

	captchaRng := rand.New(rand.NewSource(time.Now().UnixNano()))
	log.Printf("[КАПЧА RJS] Старт автоматического решения...")

	timing := GenerateCaptchaTiming(captchaRng)

	log.Printf("[КАПЧА RJS] Имитация ожидания человека (пауза %d мс)...", timing.ReadCaptchaMs)
	time.Sleep(time.Duration(timing.ReadCaptchaMs) * time.Millisecond)

	log.Printf("[КАПЧА RJS] Выполнение PoW-задачи (сложность %d)...", bootstrap.Difficulty)
	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	time.Sleep(time.Duration(timing.FetchPowMs) * time.Millisecond)

	if bootstrap.Settings != nil {
		log.Printf(
			"[КАПЧА RJS] Тип капчи: %s | доступно: %s",
			emptyAsUnknown(bootstrap.Settings.ShowCaptchaType),
			emptyAsUnknown(describeCaptchaTypes(bootstrap.Settings.SettingsByType)),
		)
	}

	var successToken string
	if captchaSettingsPreferSlider(bootstrap.Settings) {
		log.Printf("[КАПЧА RJS] Выбран solver: slider")
		successToken, err = callCaptchaNotRobotWithSliderPOC(ctx, captchaErr.SessionToken, hash, 5, tlsClient, captchaProfile, bootstrap.Settings)
	} else {
		log.Printf("[КАПЧА RJS] Выбран solver: checkbox")
		successToken, err = callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, profile, captchaRng)
		if err != nil {
			log.Printf("[КАПЧА RJS] Checkbox solver не завершил сессию: %v", err)
			log.Printf("[КАПЧА RJS] Повтор через универсальный slider-POC (поддержка сценария checkbox -> slider)...")
			successToken, err = callCaptchaNotRobotWithSliderPOC(ctx, captchaErr.SessionToken, hash, 5, tlsClient, captchaProfile, bootstrap.Settings)
		}
	}

	if err == nil && successToken != "" {
		log.Printf("[КАПЧА RJS] Капча решена автоматически ✓")
		return successToken, nil
	}

	return "", err
}

func selectCaptchaTLSProfile(userAgent string) profiles.ClientProfile {
	lowerUA := strings.ToLower(userAgent)
	return whenCaptchaTLSProfile(lowerUA)
}

func whenCaptchaTLSProfile(lowerUA string) profiles.ClientProfile {
	return func() profiles.ClientProfile {
		if strings.Contains(lowerUA, "android") || strings.Contains(lowerUA, "mobile") {
			return profiles.Okhttp4Android13
		}
		return profiles.Chrome_120
	}()
}

func captchaSettingsPreferSlider(settings *captchaSettingsResponse) bool {
	if settings == nil {
		return false
	}
	if settings.ShowCaptchaType == sliderCaptchaType {
		return true
	}
	_, hasSlider := settings.SettingsByType[sliderCaptchaType]
	return hasSlider
}

func emptyAsUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func fetchPowInput(ctx context.Context, redirectUri string, client tlsclient.HttpClient, profile BotProfile) (*captchaBootstrap, error) {
	req, err := fhttp.NewRequestWithContext(ctx, "GET", redirectUri, nil)
	if err != nil {
		return nil, err
	}

	if parsedURL, err := neturl.Parse(redirectUri); err == nil {
		req.Host = parsedURL.Hostname()
	}

	applyCaptchaDocumentHeaders(req.Header, profile.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	html := string(body)
	bootstrap, err := parseCaptchaBootstrapHTML(html)
	if err != nil {
		return nil, err
	}
	bootstrap.DebugInfo = fetchCaptchaDebugInfo(ctx, html, client, profile)
	return bootstrap, nil
}

func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}
	return ""
}

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash string, profile BotProfile, captchaRng *rand.Rand) (string, error) {
	captchaUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	captchaBrowserFP := fmt.Sprintf("%016x%016x", rand.Uint64(), rand.Uint64())
	captchaDeviceJSON := `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1032,"innerWidth":1920,"innerHeight":945,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":16,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`

	captchaCursor := GenerateCaptchaCursor(captchaRng)

	captchaDownlink := GenerateCaptchaDownlink(captchaRng)

	captchaRTT := GenerateCaptchaConnectionRtt(captchaRng)

	captchaAccel := "[]"
	captchaGyro := "[]"
	captchaMotion := "[]"
	captchaTaps := "[]"

	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", captchaUA)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("sec-ch-ua-platform", `"Windows"`)
		req.Header.Set("sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`)
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("DNT", "1")
		req.Header.Set("Priority", "u=1, i")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		client := &http.Client{
			Timeout:   20 * time.Second,
			Transport: getSharedTransport(),
		}
		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	baseParams := fmt.Sprintf("session_token=%s&domain=vk.com&adFp=&access_token=", neturl.QueryEscape(sessionToken))

	timing := GenerateCaptchaTiming(captchaRng)

	log.Printf("[КАПЧА]   Шаг 1/4: settings...")
	_, err := vkReq("captchaNotRobot.settings", baseParams)
	if err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}

	log.Printf("[КАПЧА]   ...пауза: изучение виджета...")
	time.Sleep(time.Duration(timing.SettingsToComponentMs) * time.Millisecond)

	log.Printf("[КАПЧА]   Шаг 2/4: componentDone...")
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", captchaBrowserFP, neturl.QueryEscape(captchaDeviceJSON))
	_, err = vkReq("captchaNotRobot.componentDone", componentDoneData)
	if err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}

	log.Printf("[КАПЧА]   ...пауза: движение мыши к чекбоксу + клик...")
	time.Sleep(time.Duration(timing.ComponentToCheckMs) * time.Millisecond)

	if timing.ExtraPauseMs > 0 {
		log.Printf("[КАПЧА]   ...дополнительная пауза: человек 'завис'...")
		time.Sleep(time.Duration(timing.ExtraPauseMs) * time.Millisecond)
	}

	log.Printf("[КАПЧА]   Шаг 3/4: check...")
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	debugInfo := profile.DebugInfo

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape(captchaAccel),
		neturl.QueryEscape(captchaGyro),
		neturl.QueryEscape(captchaMotion),
		neturl.QueryEscape(captchaCursor),
		neturl.QueryEscape(captchaTaps),
		neturl.QueryEscape(captchaRTT),
		neturl.QueryEscape(captchaDownlink),
		captchaBrowserFP,
		hash,
		answer,
		debugInfo,
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}
	status, _ := respObj["status"].(string)
	if status != "OK" {
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found")
	}

	time.Sleep(time.Duration(timing.CheckToEndMs) * time.Millisecond)

	return successToken, nil
}

func (r *Runner) getUniqueVKCreds(ctx context.Context, hash string, maxRetries int, stats *Stats) (*Credentials, error) {
	var lastErr error

	realUA := r.getUserAgent()
	actionSeed := uint64(time.Now().UnixNano()) ^ uint64(len(hash))
	profile := GenerateBotProfile(realUA, hash, actionSeed)

	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r.vkSemaphore <- struct{}{}:
		}

		creds, err := r.getVKCredsOnce(ctx, hash, profile)
		<-r.vkSemaphore

		if err == nil {
			return creds, nil
		}

		atomic.AddInt64(&stats.CredsErrors, 1)
		lastErr = err
		errStr := err.Error()

		if strings.Contains(errStr, "9000") || strings.Contains(errStr, "call not found") {
			return nil, fmt.Errorf("хеш мёртв: %w", err)
		}

		var backoff time.Duration
		if strings.Contains(errStr, "flood") || strings.Contains(errStr, "Flood") {
			secs := 5 * (attempt + 1)
			if secs > 60 {
				secs = 60
			}
			backoff = time.Duration(secs) * time.Second
		} else {
			base := 1 << uint(min(attempt, 5))
			if base > 30 {
				base = 30
			}
			backoff = time.Duration(base)*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}

	return nil, fmt.Errorf("исчерпаны %d попыток: %w", maxRetries, lastErr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (runner *Runner) getVKCredsOnce(ctx context.Context, hash string, profile BotProfile) (*Credentials, error) {
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: getSharedTransport(),
	}

	okAppKey := "CGMMEJLGDIHBABABA"
	appID := runner.vkAppID.Load().(string)
	appSecret := runner.vkAppSecret.Load().(string)

	doReq := func(data, url string) (map[string]interface{}, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(data))
		if err != nil {
			return nil, fmt.Errorf("создание запроса: %w", err)
		}
		req.Header.Set("User-Agent", profile.UserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("sec-ch-ua-platform", `"Android"`)
		req.Header.Set("sec-ch-ua", `"Not(A:Brand";v="99", "Android WebView";v="133", "Chromium";v="133"`)
		req.Header.Set("sec-ch-ua-mobile", "?1")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
		if strings.Contains(url, "api.vk.ru") {
			req.Header.Set("Origin", "https://vk.com")
			req.Header.Set("Referer", "https://vk.com/")
		} else {
			req.Header.Set("Origin", "https://login.vk.ru")
			req.Header.Set("Referer", "https://login.vk.ru/")
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("чтение ответа: %w", err)
		}

		var m map[string]interface{}
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, fmt.Errorf("парсинг JSON: %w | Body: %s", err, string(body))
		}
		return m, nil
	}

	checkAPIError := func(m map[string]interface{}, step string) error {
		if errObj, ok := m["error"]; ok {
			return fmt.Errorf("%s API error: %v", step, errObj)
		}
		return nil
	}

	get := func(m map[string]interface{}, keys ...string) (string, error) {
		var cur interface{} = m
		for _, k := range keys {
			mm, ok := cur.(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("path %q not found", k)
			}
			cur = mm[k]
		}
		s, ok := cur.(string)
		if !ok {
			return "", fmt.Errorf("value at path is not string")
		}
		return s, nil
	}

	r, err := doReq(fmt.Sprintf(
		"client_secret=%s&client_id=%s&scopes=audio_anonymous%%2Cvideo_anonymous%%2Cphotos_anonymous%%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=%s",
		appSecret, appID, appID,
	), "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("шаг 1: %w", err)
	}
	if err := checkAPIError(r, "шаг 1"); err != nil {
		return nil, err
	}
	t1, err := get(r, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("шаг 1 парсинг: %w", err)
	}

	r, err = doReq(fmt.Sprintf(
		"client_id=%s&token_type=messages&payload=%s&client_secret=%s&version=1&app_id=%s",
		appID, t1, appSecret, appID,
	), "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("шаг 2: %w", err)
	}
	if err := checkAPIError(r, "шаг 2"); err != nil {
		return nil, err
	}
	t3, err := get(r, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("шаг 2 парсинг: %w", err)
	}

	var t4 string

	postData := fmt.Sprintf(
		"vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s",
		hash, neturl.QueryEscape(profile.Name), t3,
	)
	r, err = doReq(postData, "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264")
	if err != nil {
		return nil, fmt.Errorf("шаг 3: %w", err)
	}

	if errObj, hasErr := r["error"].(map[string]interface{}); hasErr {
		errCode, _ := errObj["error_code"].(float64)
		if errCode == 14 {
			captchaErr := parseVkCaptchaError(errObj)
			log.Printf("[КАПЧА] Обнаружена: sid=%s, ts=%s, attempt=%s", captchaErr.CaptchaSid, captchaErr.CaptchaTs, captchaErr.CaptchaAttempt)
			if captchaErr.SessionToken == "" {
				return nil, fmt.Errorf("капча без session_token (старый тип)")
			}

			var successToken string
			var usedCache bool
			tokenFromCache := runner.popCachedToken()
			if tokenFromCache != "" {
				log.Printf("[КАПЧА] Пробую использовать кэшированный success_token...")
				successToken = tokenFromCache
				usedCache = true
			} else {
				solveToken, solveErr := runner.solveVkCaptcha(ctx, captchaErr, profile)
				if solveErr != nil {
					if !strings.Contains(solveErr.Error(), "tunnel stopped") {
						log.Printf("[КАПЧА] ОШИБКА решения: %v", solveErr)
					}
					return nil, fmt.Errorf("ошибка решения капчи: %w", solveErr)
				}
				successToken = solveToken
				log.Printf("[КАПЧА] Сохраняю success_token в кэш для 4 следующих группы")
				runner.pushCachedToken(successToken, 4)
			}

			captchaAttemptStr := captchaErr.CaptchaAttempt
			if captchaAttemptStr == "0" || captchaAttemptStr == "" {
				captchaAttemptStr = "1"
			}

			postData = fmt.Sprintf(
				"vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s",
				hash, neturl.QueryEscape(profile.Name), t3, captchaErr.CaptchaSid,
				neturl.QueryEscape(successToken), captchaErr.CaptchaTs, captchaAttemptStr,
			)
			r, err = doReq(postData, "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264")
			if err != nil {
				return nil, fmt.Errorf("шаг 3 (после капчи): %w", err)
			}

			if errObj2, hasErr2 := r["error"].(map[string]interface{}); hasErr2 {
				errCode2, _ := errObj2["error_code"].(float64)
				if errCode2 == 14 {
					if usedCache {
						log.Printf("[КАПЧА] Кэшированный токен отклонён API, пробуем новую капчу...")
						runner.invalidateCachedToken()
						return nil, fmt.Errorf("кэшированный токен отклонён")
					}
					time.Sleep(30 * time.Second)
					log.Printf("[КАПЧА] ОТКАЗ: VK всё ещё требует капчу после решения")
					return nil, fmt.Errorf("капча не пройдена после решения (пауза 30с)")
				}
				log.Printf("[КАПЧА] ОШИБКА после решения: %v", errObj2)
				return nil, fmt.Errorf("VK API error после капчи: %v", errObj2)
			}
			log.Printf("[КАПЧА] УСПЕХ: токен получен после решения капчи")
		} else {
			return nil, fmt.Errorf("VK API error: %v", errObj)
		}
	}

	t4, err = get(r, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("шаг 3 парсинг: %w", err)
	}

	r, err = doReq(fmt.Sprintf(
		"session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22%s%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=%s",
		uuid.New().String(), okAppKey,
	), "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("шаг 4: %w", err)
	}
	if err := checkAPIError(r, "шаг 4"); err != nil {
		return nil, err
	}
	t5, err := get(r, "session_key")
	if err != nil {
		return nil, fmt.Errorf("шаг 4 парсинг: %w", err)
	}

	r, err = doReq(fmt.Sprintf(
		"joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=%s&session_key=%s",
		hash, t4, okAppKey, t5,
	), "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("шаг 5: %w", err)
	}
	if err := checkAPIError(r, "шаг 5"); err != nil {
		return nil, err
	}

	ts, ok := r["turn_server"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("turn_server не найден в ответе")
	}

	user, _ := ts["username"].(string)
	pass, _ := ts["credential"].(string)
	if user == "" || pass == "" {
		return nil, fmt.Errorf("пустые credentials в ответе")
	}

	lifetime, okLife := ts["lifetime"].(float64)
	if !okLife || lifetime <= 0 {
		ttl, okTtl := ts["ttl"].(float64)
		if okTtl && ttl > 0 {
			lifetime = ttl
		}
	}

	if lifetime > 0 {
		log.Printf("[ВК] Креды получены ✓")
	} else {
		log.Printf("[ВК] Креды получены ✓")
	}

	urls, _ := ts["urls"].([]interface{})
	var turnAddrs []string
	for _, u := range urls {
		s, ok := u.(string)
		if !ok {
			continue
		}
		clean := strings.Split(s, "?")[0]
		addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		if addr != "" {
			turnAddrs = append(turnAddrs, addr)
		}
	}
	if len(turnAddrs) == 0 {
		return nil, fmt.Errorf("нет TURN urls в ответе")
	}

	return &Credentials{User: user, Pass: pass, Source: "autonomous-rjs", TurnURLs: turnAddrs, Lifetime: int(lifetime)}, nil
}
