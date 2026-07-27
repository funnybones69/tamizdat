package wgturnclient

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// RequestConfig запрашивает WireGuard конфиг через DTLS-соединение.
func RequestConfig(conn net.Conn, localPort, deviceID, password string) (string, error) {
	payload := fmt.Sprintf("GETCONF:%s|%s|%s", localPort, deviceID, password)
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", fmt.Errorf("отправка GETCONF: %w", err)
	}

	b := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", fmt.Errorf("установка дедлайна: %w", err)
	}
	n, err := conn.Read(b)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return "", fmt.Errorf("чтение ответа конфига: %w", err)
	}

	resp := string(b[:n])
	if resp == "NOCONF" {
		return "", nil
	}

	if strings.HasPrefix(resp, "DENIED:") {
		reason := strings.TrimPrefix(resp, "DENIED:")
		switch reason {
		case "wrong_password":
			return "", fmt.Errorf("FATAL_AUTH: неверный пароль подключения")
		case "expired":
			return "", fmt.Errorf("FATAL_AUTH: срок действия пароля истёк")
		case "device_mismatch":
			return "", fmt.Errorf("FATAL_AUTH: пароль привязан к другому устройству")
		default:
			return "", fmt.Errorf("FATAL_AUTH: доступ запрещён (%s)", reason)
		}
	}

	return resp, nil
}

// RequestBondV2Bind negotiates binary TZB2/BIND before worker registration.
// The legacy GETCONF path above is intentionally separate so single-room raw
// wire behavior is unchanged.
func RequestBondV2Bind(conn net.Conn, bind bondBindPayload, wantConfig bool) (string, error) {
	if bind.RunID == "" || bind.Token == "" {
		return "", bondNegotiationError{Reason: "missing runner identity"}
	}
	bind.WantConfig = wantConfig
	if !wantConfig {
		bind.Password = ""
	}
	deadline := time.Now().Add(20 * time.Second)
	backoff := bondBindInitialBackoff
	for attempt := 0; attempt < bondBindMaxAttempts; attempt++ {
		frame, err := encodeBondBind(bind)
		if err != nil {
			return "", bondNegotiationError{Reason: err.Error()}
		}
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return "", fmt.Errorf("bond bind write deadline: %w", err)
		}
		if _, err := conn.Write(frame); err != nil {
			_ = conn.SetWriteDeadline(time.Time{})
			return "", fmt.Errorf("bond bind write: %w", err)
		}
		_ = conn.SetWriteDeadline(time.Time{})

		buf := make([]byte, bondMaxBindJSON+bondHeaderLen)
		if err := conn.SetReadDeadline(deadline); err != nil {
			return "", fmt.Errorf("bond bind read deadline: %w", err)
		}
		n, err := conn.Read(buf)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			return "", bondNegotiationError{Reason: "no TZB2 response: " + err.Error()}
		}
		resp, err := decodeBondFrame(buf[:n])
		if err != nil {
			return "", bondNegotiationError{Reason: "invalid TZB2 response: " + err.Error()}
		}
		if resp.Flags != bondFlagLatency || resp.Seq != 0 {
			return "", bondNegotiationError{Reason: "server lacks latency-lane capability"}
		}
		switch resp.Type {
		case bondFrameBindWait:
			if time.Now().Add(backoff).After(deadline) {
				return "", bondNegotiationError{Reason: "bind wait timeout"}
			}
			time.Sleep(backoff)
			if backoff < time.Second {
				backoff *= 2
			}
			continue
		case bondFrameBindOK:
			return "", nil
		case bondFrameBindConfig:
			if !wantConfig {
				return "", bondNegotiationError{Reason: "unexpected config on token-only join"}
			}
			return string(resp.Payload), nil
		case bondFrameError:
			return "", bondNegotiationError{Reason: sanitizeErrForEvent(stringError(resp.Payload))}
		default:
			return "", bondNegotiationError{Reason: fmt.Sprintf("unexpected response type %d", resp.Type)}
		}
	}
	return "", bondNegotiationError{Reason: "bind wait retries exhausted"}
}
