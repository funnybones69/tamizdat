package wgturnclient

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptchaBundlePatternsExtractLiveDebugInfo(t *testing.T) {
	const live = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	html := `<script src="https://id.vk.ru/js/not_robot_captcha.123.js"></script>`
	m := reCaptchaJSURL.FindStringSubmatch(html)
	if len(m) != 2 || !strings.Contains(m[1], "not_robot_captcha") {
		t.Fatalf("bundle URL not extracted: %#v", m)
	}
	js := []byte(`x={debug_info:q||"` + live + `"}`)
	dm := reDebugInfoFallback.FindSubmatch(js)
	if len(dm) != 2 || string(dm[1]) != live {
		t.Fatalf("debug_info not extracted: %#v", dm)
	}
}

func TestCaptchaDeviceShapeHasOnlyWidgetKeys(t *testing.T) {
	raw := buildCaptchaDeviceJSON(BotProfile{UserAgent: "Mozilla/5.0 (Linux; Android 13) Chrome/120.0.0.0 Mobile"})
	var device map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &device); err != nil {
		t.Fatal(err)
	}
	if len(device) != 14 {
		t.Fatalf("device fields=%d, want 14: %s", len(device), raw)
	}
	for _, forbidden := range []string{"timezoneOffset", "platform", "productSub", "vendor", "userAgent"} {
		if _, ok := device[forbidden]; ok {
			t.Fatalf("forbidden bot-signal field %q present", forbidden)
		}
	}
}

func TestParseVKCaptchaErrorExtractsChallengeWithoutDroppingNumericFields(t *testing.T) {
	got := parseVkCaptchaError(map[string]interface{}{
		"error_code":      float64(14),
		"error_msg":       "Captcha needed",
		"captcha_sid":     float64(12345),
		"captcha_ts":      float64(1700000000),
		"captcha_attempt": float64(2),
		"redirect_uri":    "https://captcha.vk.com/?session_token=secret-token",
	})
	if got.ErrorCode != 14 || got.CaptchaSid != "12345" || got.CaptchaAttempt != "2" || got.SessionToken != "secret-token" {
		t.Fatalf("unexpected parsed challenge: %#v", got)
	}
}

func TestCaptchaSettingsPreferSlider(t *testing.T) {
	if captchaSettingsPreferSlider(nil) {
		t.Fatal("nil settings preferred slider")
	}
	if !captchaSettingsPreferSlider(&captchaSettingsResponse{ShowCaptchaType: sliderCaptchaType}) {
		t.Fatal("explicit slider type not selected")
	}
	if !captchaSettingsPreferSlider(&captchaSettingsResponse{SettingsByType: map[string]string{sliderCaptchaType: "{}"}}) {
		t.Fatal("available slider settings not selected")
	}
}

func TestSolvePoWReturnsMatchingPrefix(t *testing.T) {
	input := "unit-test-pow"
	powHash := solvePoW(input, 2)
	if powHash == "" {
		t.Fatal("empty PoW hash")
	}
	if !strings.HasPrefix(powHash, "00") {
		t.Fatalf("PoW hash did not satisfy difficulty: %s", powHash)
	}
}

func TestManualCaptchaFileBridge(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		PeerAddr:    "127.0.0.1:443",
		VKHashes:    []string{"test"},
		CaptchaMode: "manual",
		CaptchaDir:  dir,
		CaptchaWait: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	type challenge struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	done := make(chan struct {
		token string
		err   error
	}, 1)
	go func() {
		token, err := r.solveVkCaptcha(context.Background(), &vkCaptchaError{
			RedirectUri:  "https://id.vk.ru/not_robot_captcha?session_token=test-token",
			SessionToken: "test-token",
		}, BotProfile{})
		done <- struct {
			token string
			err   error
		}{token, err}
	}()

	var ch challenge
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		raw, readErr := os.ReadFile(filepath.Join(dir, "challenge.json"))
		if readErr == nil && json.Unmarshal(raw, &ch) == nil && ch.ID != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ch.ID == "" || ch.Status != "pending" {
		t.Fatalf("pending challenge not written: %#v", ch)
	}
	result, _ := json.Marshal(map[string]interface{}{
		"id":            ch.ID,
		"success_token": "success-token-from-real-browser",
		"submitted_at":  time.Now().UTC(),
	})
	if err := os.WriteFile(filepath.Join(dir, "result-"+ch.ID+".json"), result, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.token != "success-token-from-real-browser" {
			t.Fatalf("manual bridge result token=%q err=%v", got.token, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("manual bridge did not consume result")
	}
}

func TestAutonomousRJSFallbackLive(t *testing.T) {
	hash := strings.TrimSpace(os.Getenv("VKCALLS_RJS_LIVE_HASH"))
	if hash == "" {
		t.Skip("set VKCALLS_RJS_LIVE_HASH for a forced autonomous-RJS live probe")
	}
	r, err := New(Config{
		PeerAddr:       "127.0.0.1:443",
		VKHashes:       []string{hash},
		CredentialMode: "rjs-only",
		CaptchaMode:    "rjs",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	creds, err := r.getCredsForHash(ctx, hash, 2, NewStats())
	if err != nil {
		t.Fatalf("forced autonomous-RJS flow: %v", err)
	}
	if creds.User == "" || creds.Pass == "" || len(creds.TurnURLs) == 0 {
		t.Fatalf("incomplete credentials: user_set=%t pass_set=%t urls=%d", creds.User != "", creds.Pass != "", len(creds.TurnURLs))
	}
	if creds.Source != "autonomous-rjs" {
		t.Fatalf("source=%q, want autonomous-rjs", creds.Source)
	}
	t.Logf("forced autonomous-RJS flow OK: urls=%d lifetime=%ds", len(creds.TurnURLs), creds.Lifetime)
}
