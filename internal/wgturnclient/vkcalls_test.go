package wgturnclient

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"
)

type vkCallsFakeDoer struct {
	t           *testing.T
	responses   []string
	paths       []string
	queries     []map[string]string
	requestSeen int
}

func (f *vkCallsFakeDoer) Do(req *fhttp.Request) (*fhttp.Response, error) {
	f.t.Helper()
	if f.requestSeen >= len(f.responses) {
		f.t.Fatalf("unexpected request %d: %s", f.requestSeen, req.URL)
	}
	f.paths = append(f.paths, req.URL.Path)
	q := make(map[string]string)
	for key := range req.URL.Query() {
		q[key] = req.URL.Query().Get(key)
	}
	f.queries = append(f.queries, q)
	body := f.responses[f.requestSeen]
	f.requestSeen++
	return &fhttp.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(fhttp.Header),
		Request:    req,
	}, nil
}

func TestVKCallsAnonymousFlow(t *testing.T) {
	fake := &vkCallsFakeDoer{t: t, responses: []string{
		`{"response":{"token":"anon-primary"}}`,
		`{"response":{"user_id":-12345,"secret":"preview-secret"}}`,
		`{"response":{"token":"call-token"}}`,
		`{"session_key":"ok-session"}`,
		`{"turn_server":{"username":"turn-user","credential":"turn-pass","lifetime":720,"urls":["turn:192.0.2.10:19302?transport=udp","turn:192.0.2.11:19302"]}}`,
	}}

	creds, err := getVKCallsCredsWithClient(context.Background(), fake, vkCallsEndpoints{
		api: "https://vk.test",
		ok:  "https://ok.test",
	}, "https://vk.com/call/join/test-hash?ignored=1")
	if err != nil {
		t.Fatalf("getVKCallsCredsWithClient: %v", err)
	}
	if creds.User != "turn-user" || creds.Pass != "turn-pass" {
		t.Fatalf("unexpected credentials: user=%q pass_set=%t", creds.User, creds.Pass != "")
	}
	if creds.Source != "anonymous-vkcalls" {
		t.Fatalf("credential source=%q", creds.Source)
	}
	if creds.Lifetime != 720 {
		t.Fatalf("lifetime=%d, want 720", creds.Lifetime)
	}
	if len(creds.TurnURLs) != 2 || creds.TurnURLs[0] != "192.0.2.10:19302" || creds.TurnURLs[1] != "192.0.2.11:19302" {
		t.Fatalf("TURN URLs=%v", creds.TurnURLs)
	}
	if len(creds.TurnServers) != 2 || creds.TurnServers[0].Transport != "udp" || creds.TurnServers[0].Scheme != "turn" {
		t.Fatalf("TURN server metadata=%+v", creds.TurnServers)
	}
	if fake.requestSeen != 5 {
		t.Fatalf("requests=%d, want 5", fake.requestSeen)
	}
	wantPaths := []string{
		"/method/auth.getAnonymToken",
		"/method/messages.getCallPreview",
		"/method/messages.getAnonymCallToken",
		"/fb.do",
		"/fb.do",
	}
	for i, want := range wantPaths {
		if fake.paths[i] != want {
			t.Fatalf("request %d path=%q, want %q", i, fake.paths[i], want)
		}
	}
	if got := fake.queries[0]["link"]; got != "https://vk.com/call/join/test-hash" {
		t.Fatalf("step1 link=%q", got)
	}
	if got := fake.queries[2]["user_id"]; got != "-12345" {
		t.Fatalf("step3 user_id=%q", got)
	}
	if got := fake.queries[4]["joinLink"]; got != "test-hash" {
		t.Fatalf("step5 joinLink=%q", got)
	}
}

func TestVKCallsRejectsCaptchaWithoutLeakingPayload(t *testing.T) {
	fake := &vkCallsFakeDoer{t: t, responses: []string{
		`{"response":{"token":"anon-primary"}}`,
		`{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://captcha.test/?session_token=secret"}}`,
	}}

	_, err := getVKCallsCredsWithClient(context.Background(), fake, vkCallsEndpoints{
		api: "https://vk.test",
		ok:  "https://ok.test",
	}, "test-hash")
	if err == nil {
		t.Fatal("expected captcha error")
	}
	got := err.Error()
	if !strings.Contains(got, "error_code=14") {
		t.Fatalf("error=%q, want error_code=14", got)
	}
	if strings.Contains(got, "session_token") || strings.Contains(got, "secret") {
		t.Fatalf("error leaked captcha payload: %q", got)
	}
}

func TestVKCallsLifetimeFallback(t *testing.T) {
	resp := map[string]interface{}{"turn_server": map[string]interface{}{}}
	if got := vkCallsLifetime(resp); got != 600 {
		t.Fatalf("fallback lifetime=%d, want 600", got)
	}
}

func TestVKCallsLive(t *testing.T) {
	hash := strings.TrimSpace(os.Getenv("VKCALLS_LIVE_HASH"))
	if hash == "" {
		t.Skip("set VKCALLS_LIVE_HASH for a live anonymous VKCalls probe")
	}
	r := &Runner{}
	creds, err := r.getVKCallsCreds(context.Background(), hash)
	if err != nil {
		t.Fatalf("live VKCalls flow: %v", err)
	}
	if creds.User == "" || creds.Pass == "" || len(creds.TurnURLs) == 0 {
		t.Fatalf("incomplete live credentials: user_set=%t pass_set=%t urls=%d", creds.User != "", creds.Pass != "", len(creds.TurnURLs))
	}
	t.Logf("live VKCalls OK: urls=%d lifetime=%ds", len(creds.TurnURLs), creds.Lifetime)
}

func TestNormalizeVKCallHash(t *testing.T) {
	for input, want := range map[string]string{
		"abc":                          "abc",
		"https://vk.com/call/join/abc": "abc",
		"https://vk.ru/call/join/abc?from=browser": "abc",
		"call/join/abc#fragment":                   "abc",
	} {
		if got := normalizeVKCallHash(input); got != want {
			t.Errorf("normalizeVKCallHash(%q)=%q, want %q", input, got, want)
		}
	}
}
