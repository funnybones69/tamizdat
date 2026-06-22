package vkcreds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Config holds all settings for VK TURN credential acquisition.
// Pass it by pointer to GetCredentials; it must not be mutated
// concurrently with calls.
type Config struct {
	// AppID is the VK application ID (e.g. "6287487").
	AppID string

	// AppSecret is the VK application secret.
	AppSecret string

	// UserAgent is the HTTP User-Agent used for VK API calls.
	UserAgent string

	// DeviceID is a stable device identifier used to derive
	// deterministic fingerprint data (BotProfile).
	DeviceID string

	// CaptchaSolver, if non-nil, is used to solve VK Smart Captcha
	// challenges. When nil the package creates a default reverse-JS
	// solver (rjsCaptchaSolver).
	CaptchaSolver CaptchaSolver

	// SecondaryHash is an optional fallback call hash to try if the
	// primary one fails (e.g. a backup call link).
	SecondaryHash string

	// CaptchaBrowserFP, when non-empty, overrides the synthetic browser_fp
	// with a real one captured from a browser's captchaNotRobot flow.
	// Replaying a real fingerprint is what makes the auto-solver pass VK's
	// bot check (synthetic fp -> ~always BOT).
	CaptchaBrowserFP string

	// CaptchaDeviceJSON, when non-empty, overrides the synthetic device JSON
	// (navigator/screen-derived) sent in componentDone with a real captured
	// one. Should be consistent with UserAgent.
	CaptchaDeviceJSON string

	// MaxRetries controls how many times getUniqueVKCreds will retry
	// on transient errors. Zero means use the default (5).
	MaxRetries int

	// Concurrency limits parallel VK API calls. Zero means use the
	// default (2).
	Concurrency int

	// HTTPClient, if non-nil, is used for all HTTP requests. When nil
	// a default client is created with sensible timeouts.
	HTTPClient *http.Client
}

// Credentials holds the TURN relay credentials returned by VK.
type Credentials struct {
	User     string
	Pass     string
	TurnURLs []string
	Lifetime int
}

// GetCredentials acquires TURN credentials for the given call hash.
// It implements the full 5-step VK API flow, including captcha solving
// and retry logic with exponential back-off.
//
// If cfg.SecondaryHash is set and the primary hash fails, the secondary
// hash is tried as a fallback.
func GetCredentials(ctx context.Context, cfg *Config, hash string) (*Credentials, error) {
	s := newSession(cfg)

	creds, err := s.getUniqueVKCreds(ctx, hash, s.maxRetries)
	if err == nil {
		return creds, nil
	}

	if cfg.SecondaryHash != "" && hash != cfg.SecondaryHash {
		log.Println("primary hash failed, trying secondary")
		return s.getUniqueVKCreds(ctx, cfg.SecondaryHash, min(s.maxRetries, 3))
	}

	return nil, err
}

// --- internal session: holds per-call state ---

type session struct {
	cfg        *Config
	httpClient *http.Client
	semaphore  chan struct{}
	maxRetries int
}

func newSession(cfg *Config) *session {
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 2
	}
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 5
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = NewChromeHTTPClient()
	}

	return &session{
		cfg:        cfg,
		httpClient: httpClient,
		semaphore:  make(chan struct{}, concurrency),
		maxRetries: maxRetries,
	}
}

// --- VK captcha error ---

type vkCaptchaError struct {
	ErrorCode      int
	ErrorMsg       string
	CaptchaSid     string
	RedirectURI    string
	SessionToken   string
	CaptchaTs      string
	CaptchaAttempt string
}

func parseVkCaptchaError(errData map[string]interface{}) *vkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	redirectURI, _ := errData["redirect_uri"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	captchaSid, _ := errData["captcha_sid"].(string)
	if captchaSid == "" {
		if sidNum, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}

	var sessionToken string
	if redirectURI != "" {
		if parsed, err := neturl.Parse(redirectURI); err == nil {
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
		RedirectURI:    redirectURI,
		SessionToken:   sessionToken,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}

// --- Retry loop ---

func (s *session) getUniqueVKCreds(ctx context.Context, hash string, maxRetries int) (*Credentials, error) {
	var lastErr error

	ua := s.cfg.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0"
	}
	actionSeed := uint64(time.Now().UnixNano()) ^ uint64(len(hash))
	profile := GenerateBotProfile(ua, hash, actionSeed)
	// Replay a real captured fingerprint when provided — the single biggest
	// lever for passing VK's captchaNotRobot.check bot scoring.
	if s.cfg.CaptchaBrowserFP != "" {
		profile.BrowserFP = s.cfg.CaptchaBrowserFP
	}
	if s.cfg.CaptchaDeviceJSON != "" {
		profile.DeviceJSON = s.cfg.CaptchaDeviceJSON
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case s.semaphore <- struct{}{}:
		}

		creds, err := s.getVKCredsOnce(ctx, hash, profile)
		<-s.semaphore

		if err == nil {
			return creds, nil
		}

		lastErr = err
		errStr := err.Error()

		// Dead hash -- no point retrying.
		if strings.Contains(errStr, "9000") || strings.Contains(errStr, "call not found") {
			return nil, fmt.Errorf("hash is dead: %w", err)
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

	return nil, fmt.Errorf("exhausted %d attempts: %w", maxRetries, lastErr)
}

// --- 5-step VK API flow ---

func (s *session) getVKCredsOnce(ctx context.Context, hash string, profile BotProfile) (*Credentials, error) {
	okAppKey := "CGMMEJLGDIHBABABA"
	appID := s.cfg.AppID
	appSecret := s.cfg.AppSecret

	doReq := func(data, url string) (map[string]interface{}, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(data))
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
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

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}

		var m map[string]interface{}
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, fmt.Errorf("parse JSON: %w | Body: %s", err, truncateStr(string(body), 200))
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
		sv, ok := cur.(string)
		if !ok {
			return "", fmt.Errorf("value at path is not string")
		}
		return sv, nil
	}

	// Step 1: get_anonym_token (profile scope)
	r, err := doReq(fmt.Sprintf(
		"client_secret=%s&client_id=%s&scopes=audio_anonymous%%2Cvideo_anonymous%%2Cphotos_anonymous%%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=%s",
		appSecret, appID, appID,
	), "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("step 1: %w", err)
	}
	if err := checkAPIError(r, "step 1"); err != nil {
		return nil, err
	}
	t1, err := get(r, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("step 1 parse: %w", err)
	}

	// Step 2: get_anonym_token (messages scope)
	r, err = doReq(fmt.Sprintf(
		"client_id=%s&token_type=messages&payload=%s&client_secret=%s&version=1&app_id=%s",
		appID, t1, appSecret, appID,
	), "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("step 2: %w", err)
	}
	if err := checkAPIError(r, "step 2"); err != nil {
		return nil, err
	}
	t3, err := get(r, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("step 2 parse: %w", err)
	}

	// Step 3: calls.getAnonymousToken (join VK call)
	var t4 string

	postData := fmt.Sprintf(
		"vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s",
		hash, neturl.QueryEscape(profile.Name), t3,
	)
	r, err = doReq(postData, "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264")
	if err != nil {
		return nil, fmt.Errorf("step 3: %w", err)
	}

	if errObj, hasErr := r["error"].(map[string]interface{}); hasErr {
		errCode, _ := errObj["error_code"].(float64)
		if errCode == 14 {
			captchaErr := parseVkCaptchaError(errObj)
			log.Printf("[CAPTCHA] detected: sid=%s, ts=%s, attempt=%s", captchaErr.CaptchaSid, captchaErr.CaptchaTs, captchaErr.CaptchaAttempt)
			if captchaErr.SessionToken == "" {
				return nil, fmt.Errorf("step 3: captcha without session_token (old type)")
			}

			solver := s.cfg.CaptchaSolver
			if solver == nil {
				solver = NewRJSCaptchaSolver(s.httpClient, profile)
			}

			successToken, solveErr := solver.SolveCaptcha(ctx, captchaErr.RedirectURI, captchaErr.SessionToken)
			if solveErr != nil {
				log.Printf("[CAPTCHA] solve error: %v", solveErr)
				return nil, fmt.Errorf("step 3: captcha solve failed: %w", solveErr)
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
				return nil, fmt.Errorf("step 3 (after captcha): %w", err)
			}

			if errObj2, hasErr2 := r["error"].(map[string]interface{}); hasErr2 {
				errCode2, _ := errObj2["error_code"].(float64)
				if errCode2 == 14 {
					sleepCtx(ctx, 30*time.Second)
					log.Printf("[CAPTCHA] REJECT: VK still requires captcha after solve")
					return nil, fmt.Errorf("step 3: captcha not accepted after solve (30s pause)")
				}
				log.Printf("[CAPTCHA] error after solve: %v", errObj2)
				return nil, fmt.Errorf("step 3: VK API error after captcha: %v", errObj2)
			}
			log.Printf("[CAPTCHA] success: token obtained after captcha solve")
		} else {
			return nil, fmt.Errorf("step 3: VK API error: %v", errObj)
		}
	}

	t4, err = get(r, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("step 3 parse: %w", err)
	}

	// Step 4: OK FB auth.anonymLogin
	r, err = doReq(fmt.Sprintf(
		"session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22%s%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=%s",
		uuid.New().String(), okAppKey,
	), "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("step 4: %w", err)
	}
	if err := checkAPIError(r, "step 4"); err != nil {
		return nil, err
	}
	t5, err := get(r, "session_key")
	if err != nil {
		return nil, fmt.Errorf("step 4 parse: %w", err)
	}

	// Step 5: vchat.joinConversationByLink -> TURN credentials
	r, err = doReq(fmt.Sprintf(
		"joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=%s&session_key=%s",
		hash, t4, okAppKey, t5,
	), "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("step 5: %w", err)
	}
	if err := checkAPIError(r, "step 5"); err != nil {
		return nil, err
	}

	ts, ok := r["turn_server"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("step 5: turn_server not found in response")
	}

	user, _ := ts["username"].(string)
	pass, _ := ts["credential"].(string)
	if user == "" || pass == "" {
		return nil, fmt.Errorf("step 5: empty credentials in response")
	}

	lifetime, okLife := ts["lifetime"].(float64)
	if !okLife || lifetime <= 0 {
		ttl, okTtl := ts["ttl"].(float64)
		if okTtl && ttl > 0 {
			lifetime = ttl
		}
	}

	log.Printf("[VK] credentials obtained")

	urls, _ := ts["urls"].([]interface{})
	var turnAddrs []string
	for _, u := range urls {
		sv, ok := u.(string)
		if !ok {
			continue
		}
		clean := strings.Split(sv, "?")[0]
		addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		if addr != "" {
			turnAddrs = append(turnAddrs, addr)
		}
	}
	if len(turnAddrs) == 0 {
		return nil, fmt.Errorf("step 5: no TURN urls in response")
	}

	return &Credentials{User: user, Pass: pass, TurnURLs: turnAddrs, Lifetime: int(lifetime)}, nil
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// min returns the smaller of a and b.
// (Go 1.25 has a builtin min but we keep this explicit for clarity.)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
