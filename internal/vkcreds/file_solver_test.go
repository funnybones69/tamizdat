package vkcreds

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func waitChallenge(t *testing.T, dir string) *captchaChallengeFile {
	t.Helper()
	path := filepath.Join(dir, challengeFileName)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		buf, err := os.ReadFile(path)
		if err == nil {
			var ch captchaChallengeFile
			if json.Unmarshal(buf, &ch) == nil && ch.ID != "" {
				return &ch
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("challenge.json never appeared")
	return nil
}

func writeResultRaw(t *testing.T, dir, id string, rf captchaResultFile) {
	t.Helper()
	buf, err := json.Marshal(rf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "result-"+id+".json"), buf, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileCaptchaSolverReturnsToken(t *testing.T) {
	dir := t.TempDir()
	s := &FileCaptchaSolver{Dir: dir, PollEvery: 5 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type res struct {
		tok string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		tok, err := s.SolveCaptcha(ctx, "https://id.vk.ru/not_robot_captcha?session_token=ST&variant=popup", "ST")
		ch <- res{tok, err}
	}()

	chal := waitChallenge(t, dir)
	writeResultRaw(t, dir, chal.ID, captchaResultFile{ID: chal.ID, SuccessToken: "SUCCESS-TOK", SubmittedAt: time.Now()})

	r := <-ch
	if r.err != nil {
		t.Fatalf("SolveCaptcha: %v", r.err)
	}
	if r.tok != "SUCCESS-TOK" {
		t.Fatalf("token = %q, want SUCCESS-TOK", r.tok)
	}
	// Token is single-use: the result file must be consumed.
	if _, err := os.Stat(filepath.Join(dir, "result-"+chal.ID+".json")); !os.IsNotExist(err) {
		t.Fatalf("result file not consumed: err=%v", err)
	}
	// Challenge marked solved.
	final := readChallengeForTest(t, dir)
	if final.Status != "solved" {
		t.Fatalf("challenge status = %q, want solved", final.Status)
	}
}

func TestFileCaptchaSolverContextTimeout(t *testing.T) {
	dir := t.TempDir()
	s := &FileCaptchaSolver{Dir: dir, PollEvery: 5 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	tok, err := s.SolveCaptcha(ctx, "uri", "ST")
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
	if tok != "" {
		t.Fatalf("token = %q, want empty", tok)
	}
	final := readChallengeForTest(t, dir)
	if final.Status != "expired" {
		t.Fatalf("challenge status = %q, want expired", final.Status)
	}
}

func TestFileCaptchaSolverIgnoresMismatchedResult(t *testing.T) {
	dir := t.TempDir()
	s := &FileCaptchaSolver{Dir: dir, PollEvery: 5 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := make(chan string, 1)
	go func() {
		tok, _ := s.SolveCaptcha(ctx, "uri", "ST")
		ch <- tok
	}()

	chal := waitChallenge(t, dir)
	// Correct file path, but wrong inner id and an empty token: both must be ignored.
	writeResultRaw(t, dir, chal.ID, captchaResultFile{ID: "0000000000000000", SuccessToken: "NOPE"})
	time.Sleep(40 * time.Millisecond)
	writeResultRaw(t, dir, chal.ID, captchaResultFile{ID: chal.ID, SuccessToken: ""})
	time.Sleep(40 * time.Millisecond)
	select {
	case tok := <-ch:
		t.Fatalf("solver returned early with token %q", tok)
	default:
	}
	// Now a valid result.
	writeResultRaw(t, dir, chal.ID, captchaResultFile{ID: chal.ID, SuccessToken: "YES"})
	if tok := <-ch; tok != "YES" {
		t.Fatalf("token = %q, want YES", tok)
	}
}

func TestFileCaptchaSolverChallengeContract(t *testing.T) {
	dir := t.TempDir()
	s := &FileCaptchaSolver{Dir: dir, PollEvery: 5 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.SolveCaptcha(ctx, "https://id.vk.ru/not_robot_captcha?session_token=ST&variant=popup", "ST")
	}()

	chal := waitChallenge(t, dir)
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("SolveCaptcha did not exit after context cancellation")
		}
	}()
	if len(chal.ID) != 16 {
		t.Errorf("id = %q, want 16 hex chars", chal.ID)
	}
	if chal.Status != "pending" {
		t.Errorf("status = %q, want pending", chal.Status)
	}
	if !chal.SessionTokenSet {
		t.Error("session_token_set = false, want true")
	}
	if chal.RedirectURI == "" {
		t.Error("redirect_uri empty")
	}
	if !chal.ExpiresAt.After(chal.CreatedAt) {
		t.Errorf("expires_at %v not after created_at %v", chal.ExpiresAt, chal.CreatedAt)
	}
	if chal.Message == "" {
		t.Error("message empty")
	}
}

func readChallengeForTest(t *testing.T, dir string) *captchaChallengeFile {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join(dir, challengeFileName))
	if err != nil {
		t.Fatal(err)
	}
	var ch captchaChallengeFile
	if err := json.Unmarshal(buf, &ch); err != nil {
		t.Fatal(err)
	}
	return &ch
}
