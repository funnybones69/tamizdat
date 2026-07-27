package wgturnclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	neturl "net/url"
	"strconv"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
)

const (
	vkCallsClientID   = "8093730"
	vkCallsAPIVersion = "5.276"
	vkCallsUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	vkCallsOKAppKey   = "CGMMEJLGDIHBABABA"
)

type vkCallsEndpoints struct {
	api string
	ok  string
}

func defaultVKCallsEndpoints() vkCallsEndpoints {
	return vkCallsEndpoints{
		api: "https://api.vk.me",
		ok:  "https://calls.okcdn.ru",
	}
}

type vkCallsDoer interface {
	Do(*fhttp.Request) (*fhttp.Response, error)
}

func (r *Runner) getVKCallsCreds(ctx context.Context, hash string) (*Credentials, error) {
	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
	)
	if err != nil {
		return nil, fmt.Errorf("create VKCalls TLS client: %w", err)
	}
	defer client.CloseIdleConnections()

	return getVKCallsCredsWithClient(ctx, client, defaultVKCallsEndpoints(), hash)
}

func getVKCallsCredsWithClient(ctx context.Context, client vkCallsDoer, endpoints vkCallsEndpoints, hash string) (*Credentials, error) {
	hash = normalizeVKCallHash(hash)
	if hash == "" {
		return nil, fmt.Errorf("empty VK call hash")
	}
	if client == nil {
		return nil, fmt.Errorf("nil VKCalls HTTP client")
	}

	deviceID := uuid.NewString()
	guestName := vkCallsGuestName(deviceID)
	joinURL := "https://vk.com/call/join/" + hash

	do := func(step, baseURL string, query neturl.Values) (map[string]interface{}, error) {
		u, err := neturl.Parse(baseURL)
		if err != nil {
			return nil, fmt.Errorf("%s URL: %w", step, err)
		}
		u.RawQuery = query.Encode()
		req, err := fhttp.NewRequestWithContext(ctx, fhttp.MethodPost, u.String(), bytes.NewReader(nil))
		if err != nil {
			return nil, fmt.Errorf("%s request: %w", step, err)
		}
		req.Header.Set("User-Agent", vkCallsUserAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		req.Header.Set("Accept-Language", "en-GB,en;q=0.9")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s HTTP: %w", step, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("%s read: %w", step, err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("%s HTTP status %d", step, resp.StatusCode)
		}
		var out map[string]interface{}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("%s JSON: %w", step, err)
		}
		if err := vkCallsResponseError(out); err != nil {
			return nil, fmt.Errorf("%s: %w", step, err)
		}
		return out, nil
	}

	step1, err := do("auth.getAnonymToken", endpoints.api+"/method/auth.getAnonymToken", neturl.Values{
		"v":          {vkCallsAPIVersion},
		"client_id":  {vkCallsClientID},
		"link":       {joinURL},
		"device_id":  {deviceID},
		"anonymName": {guestName},
		"lang":       {"en"},
	})
	if err != nil {
		return nil, err
	}
	anonymousToken, err := vkCallsString(step1, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("auth.getAnonymToken response: %w", err)
	}

	step2, err := do("messages.getCallPreview", endpoints.api+"/method/messages.getCallPreview", neturl.Values{
		"v":               {vkCallsAPIVersion},
		"anonymous_token": {anonymousToken},
		"device_id":       {deviceID},
		"extended":        {"1"},
		"fields":          {"first_name,last_name,photo_200"},
		"lang":            {"en"},
		"link":            {joinURL},
	})
	if err != nil {
		return nil, err
	}
	userID, err := vkCallsNumberString(step2, "response", "user_id")
	if err != nil {
		return nil, fmt.Errorf("messages.getCallPreview user_id: %w", err)
	}
	secret, err := vkCallsString(step2, "response", "secret")
	if err != nil {
		return nil, fmt.Errorf("messages.getCallPreview secret: %w", err)
	}

	step3, err := do("messages.getAnonymCallToken", endpoints.api+"/method/messages.getAnonymCallToken", neturl.Values{
		"v":               {vkCallsAPIVersion},
		"anonymous_token": {anonymousToken},
		"device_id":       {deviceID},
		"link":            {joinURL},
		"name":            {guestName},
		"user_id":         {userID},
		"secret":          {secret},
		"lang":            {"en"},
	})
	if err != nil {
		return nil, err
	}
	callToken, err := vkCallsString(step3, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("messages.getAnonymCallToken response: %w", err)
	}

	okDeviceID := uuid.NewString()
	sessionData, err := json.Marshal(map[string]interface{}{
		"version":        2,
		"device_id":      okDeviceID,
		"client_version": "1.0.1",
	})
	if err != nil {
		return nil, fmt.Errorf("auth.anonymLogin session_data: %w", err)
	}
	step4, err := do("auth.anonymLogin", endpoints.ok+"/fb.do", neturl.Values{
		"session_data":    {string(sessionData)},
		"method":          {"auth.anonymLogin"},
		"format":          {"JSON"},
		"application_key": {vkCallsOKAppKey},
	})
	if err != nil {
		return nil, err
	}
	sessionKey, err := vkCallsString(step4, "session_key")
	if err != nil {
		return nil, fmt.Errorf("auth.anonymLogin response: %w", err)
	}

	step5, err := do("vchat.joinConversationByLink", endpoints.ok+"/fb.do", neturl.Values{
		"joinLink":        {hash},
		"isVideo":         {"false"},
		"protocolVersion": {"5"},
		"anonymToken":     {callToken},
		"method":          {"vchat.joinConversationByLink"},
		"format":          {"JSON"},
		"application_key": {vkCallsOKAppKey},
		"session_key":     {sessionKey},
	})
	if err != nil {
		return nil, err
	}

	user, err := vkCallsString(step5, "turn_server", "username")
	if err != nil {
		return nil, fmt.Errorf("TURN username: %w", err)
	}
	pass, err := vkCallsString(step5, "turn_server", "credential")
	if err != nil {
		return nil, fmt.Errorf("TURN credential: %w", err)
	}
	turnURLs, turnServers, err := vkCallsTURNURLs(step5)
	if err != nil {
		return nil, err
	}
	lifetime := vkCallsLifetime(step5)

	log.Printf("[VKCALLS] anonymous credentials acquired: urls=%d lifetime=%ds", len(turnURLs), lifetime)
	return &Credentials{User: user, Pass: pass, Source: "anonymous-vkcalls", TurnURLs: turnURLs, TurnServers: turnServers, Lifetime: lifetime}, nil
}

func normalizeVKCallHash(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := neturl.Parse(raw); err == nil && u.Host != "" {
		raw = strings.Trim(u.Path, "/")
	}
	if i := strings.LastIndex(raw, "/"); i >= 0 {
		raw = raw[i+1:]
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

func vkCallsGuestName(seed string) string {
	names := [...]string{"Alex", "Anna", "Ivan", "Maria", "Maxim", "Olga", "Pavel", "Sergey"}
	var sum int
	for _, r := range seed {
		sum += int(r)
	}
	return names[sum%len(names)]
}

func vkCallsResponseError(resp map[string]interface{}) error {
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		code := vkCallsInt(errObj["error_code"])
		msg, _ := errObj["error_msg"].(string)
		return fmt.Errorf("VK API error_code=%d message=%q", code, msg)
	}
	if code := vkCallsInt(resp["error_code"]); code != 0 {
		msg, _ := resp["error_msg"].(string)
		return fmt.Errorf("OK API error_code=%d message=%q", code, msg)
	}
	return nil
}

func vkCallsString(resp map[string]interface{}, path ...string) (string, error) {
	var current interface{} = resp
	for _, key := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("path %s is not an object", strings.Join(path, "."))
		}
		current, ok = m[key]
		if !ok {
			return "", fmt.Errorf("path %s is missing", strings.Join(path, "."))
		}
	}
	value, ok := current.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("path %s is not a non-empty string", strings.Join(path, "."))
	}
	return value, nil
}

func vkCallsNumberString(resp map[string]interface{}, path ...string) (string, error) {
	var current interface{} = resp
	for _, key := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("path %s is not an object", strings.Join(path, "."))
		}
		current, ok = m[key]
		if !ok {
			return "", fmt.Errorf("path %s is missing", strings.Join(path, "."))
		}
	}
	switch value := current.(type) {
	case float64:
		return strconv.FormatInt(int64(value), 10), nil
	case string:
		if strings.TrimSpace(value) != "" {
			return value, nil
		}
	}
	return "", fmt.Errorf("path %s is not numeric", strings.Join(path, "."))
}

func vkCallsTURNURLs(resp map[string]interface{}) ([]string, []TurnServer, error) {
	turn, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("turn_server is missing")
	}
	rawURLs, ok := turn["urls"].([]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("turn_server.urls is missing")
	}
	urls := make([]string, 0, len(rawURLs))
	servers := make([]TurnServer, 0, len(rawURLs))
	for _, raw := range rawURLs {
		s, ok := raw.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		scheme := "turn"
		if strings.HasPrefix(s, "turns:") {
			scheme = "turns"
			s = strings.TrimPrefix(s, "turns:")
		} else {
			s = strings.TrimPrefix(s, "turn:")
		}
		addr, rawQuery, _ := strings.Cut(s, "?")
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		urls = append(urls, addr)
		host, portText, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port <= 0 {
			continue
		}
		transport := ""
		if query, err := neturl.ParseQuery(rawQuery); err == nil {
			transport = strings.ToLower(strings.TrimSpace(query.Get("transport")))
		}
		if transport != "udp" && transport != "tcp" {
			if scheme == "turns" {
				transport = "tcp"
			}
		}
		servers = append(servers, TurnServer{Host: host, Port: port, Scheme: scheme, Transport: transport})
	}
	if len(urls) == 0 {
		return nil, nil, fmt.Errorf("turn_server.urls is empty")
	}
	return urls, servers, nil
}

func vkCallsLifetime(resp map[string]interface{}) int {
	turn, _ := resp["turn_server"].(map[string]interface{})
	for _, key := range []string{"lifetime", "ttl"} {
		if lifetime := vkCallsInt(turn[key]); lifetime > 0 {
			return lifetime
		}
	}
	return 600
}

func vkCallsInt(value interface{}) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	default:
		return 0
	}
}
