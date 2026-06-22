package vkcreds

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileCaptchaSolver implements CaptchaSolver out-of-band via the filesystem: it
// writes a challenge descriptor and waits for a result file carrying the
// success_token. The token is produced by a human solving the captcha in a
// *real* browser (e.g. a router panel page opened on the LAN) — the only client
// VK reliably accepts, since its headless-solver detection now returns BOT
// before even serving the visual puzzle.
//
// This is the break-glass acquisition path for a network whitelist that leaves
// only VK and the LAN reachable: no Telegram, no external helper, and no other
// server is involved. It plugs into the existing vkcreds.Config.CaptchaSolver
// seam, so GetCredentials needs no special-casing — when a captcha is required
// it simply delegates here instead of to the (now ineffective) automated
// reverse-JS solver.
//
// File contract (compatible with the deployed keenetic panel):
//
//	<Dir>/challenge.json        written here:  {id,status,redirect_uri,...}
//	<Dir>/result-<id>.json      written by panel: {id,success_token,submitted_at}
//
// challenge.json carries the redirect_uri, which embeds a session_token, so the
// directory must be 0600/0700 and never logged.
type FileCaptchaSolver struct {
	// Dir is the directory holding challenge.json and result-<id>.json.
	Dir string
	// PollEvery is how often the result file is checked. Zero uses the default.
	PollEvery time.Duration
	// now is an injectable clock for tests; nil means time.Now.
	now func() time.Time
}

const (
	challengeFileName  = "challenge.json"
	defaultCaptchaPoll = 2 * time.Second
	// fallbackSolveWindow bounds the human solve when the caller supplied no
	// context deadline. The vkturn path always passes a deadline
	// (credentialAcquireTimeout), so this is only a safety net.
	fallbackSolveWindow = 15 * time.Minute
)

// captchaChallengeFile is the on-disk challenge descriptor handed to the panel.
type captchaChallengeFile struct {
	ID              string    `json:"id"`
	Status          string    `json:"status"` // pending | solved | expired
	RedirectURI     string    `json:"redirect_uri"`
	SessionTokenSet bool      `json:"session_token_set"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Message         string    `json:"message,omitempty"`
}

// captchaResultFile is what the panel writes once the human solves the captcha.
type captchaResultFile struct {
	ID           string    `json:"id"`
	SuccessToken string    `json:"success_token"`
	SubmittedAt  time.Time `json:"submitted_at"`
}

func (s *FileCaptchaSolver) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// SolveCaptcha writes a pending challenge and blocks until a matching result
// file appears or ctx is done. On success it returns the success_token and
// consumes (removes) the result file; tokens are single-use.
func (s *FileCaptchaSolver) SolveCaptcha(ctx context.Context, redirectURI string, sessionToken string) (string, error) {
	if s.Dir == "" {
		return "", fmt.Errorf("vkcreds: FileCaptchaSolver.Dir is empty")
	}
	id, err := newChallengeID()
	if err != nil {
		return "", fmt.Errorf("vkcreds: generate challenge id: %w", err)
	}

	now := s.clock()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = now.Add(fallbackSolveWindow)
	}

	ch := &captchaChallengeFile{
		ID:              id,
		Status:          "pending",
		RedirectURI:     redirectURI,
		SessionTokenSet: sessionToken != "",
		CreatedAt:       now,
		ExpiresAt:       deadline,
		UpdatedAt:       now,
		Message:         "Open the router panel on the LAN and solve the VK captcha in a browser.",
	}
	if err := s.writeChallenge(ch); err != nil {
		return "", err
	}

	resultPath := filepath.Join(s.Dir, "result-"+id+".json")
	poll := s.PollEvery
	if poll <= 0 {
		poll = defaultCaptchaPoll
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.markStatus(ch, "expired")
			return "", ctx.Err()
		case <-ticker.C:
			rf, err := readResult(resultPath)
			if err != nil || rf.ID != id || rf.SuccessToken == "" {
				continue
			}
			s.markStatus(ch, "solved")
			_ = os.Remove(resultPath) // single-use token
			return rf.SuccessToken, nil
		}
	}
}

func (s *FileCaptchaSolver) challengePath() string {
	return filepath.Join(s.Dir, challengeFileName)
}

func (s *FileCaptchaSolver) writeChallenge(ch *captchaChallengeFile) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("vkcreds: mkdir captcha dir: %w", err)
	}
	buf, err := json.MarshalIndent(ch, "", "  ")
	if err != nil {
		return fmt.Errorf("vkcreds: marshal challenge: %w", err)
	}
	return writeFileAtomic(s.challengePath(), buf, 0o600)
}

// markStatus best-effort updates the challenge status so the panel can stop
// showing a solved/expired challenge. Failures are ignored: the result has
// already been captured (or the deadline passed) and must not be lost.
func (s *FileCaptchaSolver) markStatus(ch *captchaChallengeFile, status string) {
	ch.Status = status
	ch.UpdatedAt = s.clock()
	if buf, err := json.MarshalIndent(ch, "", "  "); err == nil {
		_ = writeFileAtomic(s.challengePath(), buf, 0o600)
	}
}

func readResult(path string) (*captchaResultFile, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf captchaResultFile
	if err := json.Unmarshal(buf, &rf); err != nil {
		return nil, err
	}
	return &rf, nil
}

func newChallengeID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// writeFileAtomic writes data to path via a temp file + rename so a reader
// (the panel) never observes a partially written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".captcha-*.tmp")
	if err != nil {
		return fmt.Errorf("vkcreds: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
