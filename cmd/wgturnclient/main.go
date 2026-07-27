package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/funnybones69/tamizdat/internal/wgturnclient"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	host := flag.String("turn", "", "переопределить IP TURN")
	port := flag.String("port", "", "переопределить порт TURN")
	listen := flag.String("listen", "127.0.0.1:9000", "локальный адрес")
	vkHash := flag.String("vk", "", "хеши VK-звонков (через запятую)")
	secondaryHash := flag.String("vk2", "", "запасной VK хеш")
	peerAddr := flag.String("peer", "", "адрес:порт VPS сервера")
	numW := flag.Int("n", 24, "количество воркеров (кратно 12)")
	useTCP := flag.Bool("tcp", false, "TURN через TCP")
	useUDP := flag.Bool("udp", false, "TURN через UDP")
	splitTunnel := flag.Bool("split", false, "split tunneling")
	sni := flag.String("sni", "", "SNI для DTLS")
	noDns := flag.Bool("nodns", false, "отключить DNS Яндекса")

	appID := flag.String("vk-app-id", "6287487", "VK App ID")
	appSecret := flag.String("vk-app-secret", "QbYic1K3lEV5kTGiqlq2", "VK App Secret")

	deviceID := flag.String("device-id", "unknown", "уникальный ID устройства")
	userAgent := flag.String("user-agent", "", "User-Agent строка устройства")
	connPassword := flag.String("password", "", "пароль подключения")
	captchaMode := flag.String("captcha-mode", "rjs", "режим капчи: rjs или wv")
	credsFile := flag.String("creds-file", "", "путь к JSON-файлу с готовыми TURN-кредами (формат iOS-лога: username/password/turn_servers/lifetime_sec). Если задано — VK API не вызывается, hash может быть фиктивным.")

	flag.Parse()

	rawVKHash := *vkHash
	var preloadedCreds *wgturnclient.Credentials
	if *credsFile != "" {
		creds, turnCount, lifetime, err := loadPreloadedCreds(*credsFile)
		if err != nil {
			log.Fatalf("[КЛИЕНТ] -creds-file: %v", err)
		}
		preloadedCreds = creds
		log.Printf("[КЛИЕНТ] Преднагружены креды из %s (%d TURN серверов, lifetime=%ds)",
			*credsFile, turnCount, lifetime)
		if rawVKHash == "" {
			rawVKHash = "preloaded"
		}
	}

	if *peerAddr == "" || rawVKHash == "" {
		log.Fatal("[КЛИЕНТ] Нужны -peer и -vk")
	}

	hashes := wgturnclient.ParseHashes(rawVKHash)
	if len(hashes) == 0 {
		log.Fatal("[КЛИЕНТ] Нет хешей VK")
	}

	runner, err := wgturnclient.New(wgturnclient.Config{
		Listen:         *listen,
		PeerAddr:       *peerAddr,
		Workers:        *numW,
		UseUDP:         *useUDP,
		UseTCP:         *useTCP,
		VKHashes:       hashes,
		SecondaryHash:  *secondaryHash,
		DeviceID:       *deviceID,
		ConnPassword:   *connPassword,
		VKAppID:        *appID,
		VKAppSecret:    *appSecret,
		UserAgent:      *userAgent,
		CaptchaMode:    *captchaMode,
		NoDNS:          *noDns,
		PreloadedCreds: preloadedCreds,
		OnConfig:       printAndSaveConfig,
		TurnHost:       *host,
		TurnPort:       *port,
		SNI:            *sni,
		SplitTunnel:    *splitTunnel,
	})
	if err != nil {
		log.Fatalf("[КЛИЕНТ] %v", err)
	}
	defer runner.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	installSignalHandler(ctx, cancel)
	go readControlInput(ctx, cancel, runner)

	if err := runner.Start(ctx); err != nil {
		log.Fatalf("[КЛИЕНТ] %v", err)
	}
}

func loadPreloadedCreds(path string) (*wgturnclient.Credentials, int, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, err
	}
	var wire struct {
		Username    string   `json:"username"`
		Password    string   `json:"password"`
		TurnServers []string `json:"turn_servers"`
		LifetimeSec int      `json:"lifetime_sec"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, 0, 0, fmt.Errorf("парсинг: %w", err)
	}
	if wire.Username == "" || wire.Password == "" || len(wire.TurnServers) == 0 {
		return nil, 0, 0, fmt.Errorf("пустые username/password/turn_servers")
	}
	lifetime := wire.LifetimeSec
	if lifetime <= 0 {
		lifetime = 3600
	}
	return &wgturnclient.Credentials{
		User:     wire.Username,
		Pass:     wire.Password,
		TurnURLs: wire.TurnServers,
		Lifetime: lifetime,
	}, len(wire.TurnServers), lifetime, nil
}

func installSignalHandler(ctx context.Context, cancel context.CancelFunc) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case s := <-sig:
			log.Printf("[КЛИЕНТ] Сигнал %v, завершаю...", s)
			cancel()
		case <-ctx.Done():
			return
		}
		select {
		case s := <-sig:
			log.Printf("[КЛИЕНТ] Повторный %v, принудительный выход", s)
			os.Exit(1)
		case <-ctx.Done():
		}
	}()
}

func readControlInput(ctx context.Context, cancel context.CancelFunc, runner *wgturnclient.Runner) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, "error:tunnel stopped") {
			log.Printf("[STDIN] %s", line)
		}
		switch {
		case line == "PAUSE":
			runner.SetPaused(true)
		case line == "RESUME":
			runner.SetPaused(false)
		case line == "STOP":
			cancel()
			return
		case strings.HasPrefix(line, "CAPTCHA_RESULT|"):
			result := strings.TrimPrefix(line, "CAPTCHA_RESULT|")
			runner.SubmitCaptchaResult(result)
			log.Printf("[КАПЧА] Результат от Kotlin записан в канал")
		}
	}
}

func printAndSaveConfig(finalConf string) {
	fmt.Println()
	fmt.Println("╔══════════════ WireGuard Конфиг ══════════════╗")
	for _, line := range strings.Split(finalConf, "\n") {
		fmt.Printf("║ %-44s ║\n", line)
	}
	fmt.Println("╚══════════════════════════════════════════════╝")
	if err := os.WriteFile("wg-turn.conf", []byte(finalConf+"\n"), 0600); err != nil {
		log.Printf("[КОНФИГ] Ошибка сохранения: %v", err)
	} else {
		log.Println("[КОНФИГ] Сохранён в wg-turn.conf")
	}
}
