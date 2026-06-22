package vkcreds

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"strings"
)

var firstNames = []string{
	"Александр", "Дмитрий", "Максим", "Андрей", "Алексей", "Артём", "Илья",
	"Кирилл", "Михаил", "Никита", "Матвей", "Роман", "Егор", "Арсений", "Иван",
	"Денис", "Даниил", "Тимофей", "Владислав", "Павел", "Руслан", "Марк", "Тимур",
	"Олег", "Виктор", "Юрий", "Николай", "Антон", "Владимир", "Григорий", "Степан",
	"Фёдор", "Игнат", "Леонид", "Борис", "Георгий", "Валентин", "Артур", "Анатолий",
	"Анна", "Мария", "Елена", "Дарья", "Анастасия", "Екатерина", "Виктория", "Ольга",
	"Наталья", "Юлия", "Татьяна", "Светлана", "Ирина", "Ксения", "Алина", "Елизавета",
	"Полина", "Софья", "Маргарита", "Вероника", "Диана", "Валерия", "Кристина",
}

var lastNames = []string{
	"Иванов", "Смирнов", "Кузнецов", "Попов", "Васильев", "Петров", "Соколов", "Михайлов",
	"Новиков", "Федоров", "Морозов", "Волков", "Алексеев", "Лебедев", "Семенов", "Егоров",
	"Павлов", "Козлов", "Степанов", "Николаев", "Орлов", "Андреев", "Макаров", "Никитин",
	"Захаров", "Зайцев", "Соловьев", "Борисов", "Яковлев", "Григорьев", "Романов", "Воробьев",
	"Калинин", "Гусев", "Титов", "Белов", "Комаров", "Орлов", "Киселёв", "Макаров",
}

// BotProfile holds all generated device/behavioral fingerprint data for
// a single VK API session.
type BotProfile struct {
	UserAgent     string
	Name          string
	BrowserFP     string
	DeviceJSON    string
	CursorJSON    string
	Accelerometer string
	Gyroscope     string
	Motion        string
	Taps          string
	Downlink      string
	DebugInfo     string
	BatteryLevel  string
	TouchSupport  string
	CanvasFP      string
	WebGLFP       string
	AudioFP       string
}

func generateDebugInfo(deviceID string) string {
	hash := sha256.Sum256([]byte(deviceID + "_debug_info_static_salt_v2"))
	return hex.EncodeToString(hash[:])
}

// GenerateBotProfile creates a deterministic-looking device profile from
// baseDeviceID (hardware traits) and actionSeed (behavioral traits like
// name, cursor, taps). The realUserAgent is forwarded as-is.
func GenerateBotProfile(realUserAgent, baseDeviceID string, actionSeed uint64) BotProfile {
	hwHash := sha256.Sum256([]byte(baseDeviceID + "hardware_salt"))
	hwSeed := binary.BigEndian.Uint64(hwHash[:8])
	hwRng := rand.New(rand.NewSource(int64(hwSeed)))

	actionRng := rand.New(rand.NewSource(int64(actionSeed)))

	wChoices := []int{720, 1080, 1440}
	w := wChoices[hwRng.Intn(len(wChoices))]

	ratio := 1.77 + hwRng.Float64()*0.56
	h := int(float64(w) * ratio)

	availW := w
	availH := h - (60 + hwRng.Intn(80))
	innerW := w
	innerH := availH - (hwRng.Intn(40))

	dprChoices := []float64{2.0, 2.5, 2.75, 3.0, 3.5}
	dpr := dprChoices[hwRng.Intn(len(dprChoices))]

	hwThreads := []int{4, 6, 8, 8, 8}[hwRng.Intn(5)]
	mem := []int{4, 6, 8, 12}[hwRng.Intn(4)]

	tzOffsets := []int{-180, -120, -240, -300, -360, -420, -480, -540, -600, -660}
	tzOffset := tzOffsets[hwRng.Intn(len(tzOffsets))]

	deviceJSON := fmt.Sprintf(
		`{"screenWidth":%d,"screenHeight":%d,"screenAvailWidth":%d,"screenAvailHeight":%d,"innerWidth":%d,"innerHeight":%d,"devicePixelRatio":%g,"language":"ru-RU","languages":["ru-RU","en-US"],"webdriver":false,"hardwareConcurrency":%d,"deviceMemory":%d,"connectionEffectiveType":"4g","notificationsPermission":"%s","timezoneOffset":%d,"platform":"Linux aarch64","productSub":"20030107","vendor":"Google Inc."}`,
		w, h, availW, availH, innerW, innerH, dpr, hwThreads, mem,
		"default", tzOffset,
	)

	browserFP := fmt.Sprintf("%016x%016x%016x%016x",
		hwRng.Uint64(), hwRng.Uint64(), hwRng.Uint64(), hwRng.Uint64())

	canvasFP := fmt.Sprintf("%08x", hwRng.Uint32())

	gpuChoices := []string{"Mali-G610", "Mali-G710", "Adreno (TM) 643", "Adreno (TM) 650", "Adreno (TM) 730", "Xclipse 920"}
	gpuName := gpuChoices[hwRng.Intn(len(gpuChoices))]
	webglFP := fmt.Sprintf("%s|%08x", gpuName, hwRng.Uint32())

	audioFP := fmt.Sprintf("%.6f", 124.0+hwRng.Float64()*12.0)

	debugInfo := generateDebugInfo(baseDeviceID)

	batteryLevel := 0.35 + hwRng.Float64()*0.65

	touchSupport := fmt.Sprintf(`{"maxTouchPoints":%d,"touchEvent":true,"touchStart":true}`, 5+hwRng.Intn(6))

	fn := firstNames[actionRng.Intn(len(firstNames))]
	ln := lastNames[actionRng.Intn(len(lastNames))]
	var name string
	if actionRng.Float32() < 0.3 {
		name = fn
	} else {
		lastChar := fn[len(fn)-2:]
		if lastChar == "на" || lastChar == "ия" || lastChar == "да" || lastChar == "ра" {
			ln = ln + "а"
		}
		name = fn + " " + ln
	}

	cursor := "[]"

	taps := generateMobileTaps(actionRng, w, h)

	accel, gyro, motion := generateMobileSensors(hwRng, actionRng)

	dl := generateDownlink(actionRng)

	return BotProfile{
		UserAgent:     realUserAgent,
		Name:          name,
		BrowserFP:     browserFP,
		DeviceJSON:    deviceJSON,
		CursorJSON:    cursor,
		Accelerometer: accel,
		Gyroscope:     gyro,
		Motion:        motion,
		Taps:          taps,
		Downlink:      dl,
		DebugInfo:     debugInfo,
		BatteryLevel:  fmt.Sprintf("%.2f", batteryLevel),
		TouchSupport:  touchSupport,
		CanvasFP:      canvasFP,
		WebGLFP:       webglFP,
		AudioFP:       audioFP,
	}
}

func generateMobileTaps(rng *rand.Rand, width, height int) string {
	scenario := rng.Intn(10)
	var n int
	switch {
	case scenario < 2:
		n = 0
	case scenario < 4:
		n = 1
	case scenario < 7:
		n = 2 + rng.Intn(2)
	default:
		n = 4 + rng.Intn(3)
	}

	if n == 0 {
		return "[]"
	}

	taps := make([]string, n)
	baseTime := 500 + rng.Intn(1500)

	for i := 0; i < n; i++ {
		tapX := float64(width) * (0.15 + rng.Float64()*0.7)
		tapY := float64(height) * (0.3 + rng.Float64()*0.6)

		duration := 50 + rng.Intn(150)

		if i > 0 {
			baseTime += 300 + rng.Intn(1700)
		}

		taps[i] = fmt.Sprintf(`{"x":%.1f,"y":%.1f,"duration":%d,"time":%d}`, tapX, tapY, duration, baseTime)
	}
	return "[" + strings.Join(taps, ",") + "]"
}

func generateMobileSensors(hwRng, actionRng *rand.Rand) (string, string, string) {
	baseY := 4.0 + hwRng.Float64()*3.0
	baseZ := 8.0 + hwRng.Float64()*1.5
	baseX := -1.0 + hwRng.Float64()*2.0

	n := 1 + actionRng.Intn(5)

	accelEvents := make([]string, n)
	gyroEvents := make([]string, n)
	motionEvents := make([]string, n)

	prevAX, prevAY, prevAZ := baseX, baseY, baseZ
	prevGX, prevGY, prevGZ := 0.0, 0.0, 0.0

	for i := 0; i < n; i++ {
		tremorX := actionRng.Float64()*0.1 - 0.05
		tremorY := actionRng.Float64()*0.1 - 0.05
		tremorZ := actionRng.Float64()*0.1 - 0.05

		drift := 0.3
		ax := prevAX*drift + baseX*(1-drift) + tremorX
		ay := prevAY*drift + baseY*(1-drift) + tremorY
		az := prevAZ*drift + baseZ*(1-drift) + tremorZ

		prevAX, prevAY, prevAZ = ax, ay, az

		accelEvents[i] = fmt.Sprintf(`{"x":%.3f,"y":%.3f,"z":%.3f}`, ax, ay, az)

		gx := prevGX*0.7 + (actionRng.Float64()*0.8-0.4)*0.3
		gy := prevGY*0.7 + (actionRng.Float64()*0.8-0.4)*0.3
		gz := prevGZ*0.7 + (actionRng.Float64()*0.8-0.4)*0.3
		prevGX, prevGY, prevGZ = gx, gy, gz

		gyroEvents[i] = fmt.Sprintf(`{"alpha":%.2f,"beta":%.2f,"gamma":%.2f}`, gx, gy, gz)

		motionEvents[i] = fmt.Sprintf(`{"accelerationIncludingGravity":{"x":%.3f,"y":%.3f,"z":%.3f}}`, ax, ay, az)
	}

	return "[" + strings.Join(accelEvents, ",") + "]",
		"[" + strings.Join(gyroEvents, ",") + "]",
		"[" + strings.Join(motionEvents, ",") + "]"
}

func generateDownlink(rng *rand.Rand) string {
	n := 7 + rng.Intn(10)

	baseDL := 10.0 + rng.Float64()*20.0

	if n == 1 {
		return fmt.Sprintf("[%.1f]", baseDL)
	}

	vals := make([]string, n)

	stabilizeAfter := 2 + rng.Intn(3)

	for i := 0; i < n; i++ {
		var variation float64
		if i < stabilizeAfter {
			variation = baseDL * (0.85 + rng.Float64()*0.3)
		} else {
			variation = baseDL * (0.98 + rng.Float64()*0.04)
		}
		vals[i] = fmt.Sprintf("%.1f", variation)
	}
	return "[" + strings.Join(vals, ",") + "]"
}

// GenerateCaptchaCursor produces a JSON array of cursor movement points
// simulating a Bezier-curved mouse path toward the captcha checkbox.
func GenerateCaptchaCursor(rng *rand.Rand) string {
	startX := 200 + rng.Float64()*1520
	startY := 200 + rng.Float64()*680

	targetX := 960.0 + (rng.Float64()-0.5)*200
	targetY := 540.0 + (rng.Float64()-0.5)*100 + 30

	cp1x := startX + (rng.Float64()-0.5)*500
	cp1y := startY + (rng.Float64()-0.5)*300
	cp2x := targetX + (rng.Float64()-0.5)*150
	cp2y := targetY + (rng.Float64()-0.5)*80

	np := 6 + rng.Intn(7)
	points := make([]string, np)

	for i := 0; i < np; i++ {
		t := float64(i) / float64(np-1)
		mt := 1 - t

		x := mt*mt*mt*startX + 3*mt*mt*t*cp1x + 3*mt*t*t*cp2x + t*t*t*targetX
		y := mt*mt*mt*startY + 3*mt*mt*t*cp1y + 3*mt*t*t*cp2y + t*t*t*targetY

		x += rng.Float64()*3 - 1.5
		y += rng.Float64()*3 - 1.5

		points[i] = fmt.Sprintf(`{"x":%.1f,"y":%.1f}`, x, y)
	}
	return "[" + strings.Join(points, ",") + "]"
}

// CaptchaSessionTiming holds human-like delays between captcha flow steps.
type CaptchaSessionTiming struct {
	FetchPowMs            int
	ReadCaptchaMs         int
	SettingsToComponentMs int
	ComponentToCheckMs    int
	CheckToEndMs          int
	EndSessionMs          int
	ExtraPauseMs          int
}

// GenerateCaptchaTiming produces randomised but realistic inter-step
// delays for a captcha solving session. Total duration is clamped to
// roughly 5--10 seconds.
func GenerateCaptchaTiming(rng *rand.Rand) CaptchaSessionTiming {
	fetchPow := 600 + rng.Intn(800)

	readCaptcha := 700 + rng.Intn(1200)

	settingsToComponent := 800 + rng.Intn(1200)

	componentToCheck := 1500 + rng.Intn(2000)

	checkToEnd := 400 + rng.Intn(800)

	endSession := 100 + rng.Intn(200)

	var extraPause int
	if rng.Float32() < 0.10 {
		extraPause = 800 + rng.Intn(1500)
	}

	total := fetchPow + readCaptcha + settingsToComponent + componentToCheck + checkToEnd + endSession + extraPause

	if total < 5000 {
		deficit := 5000 - total + rng.Intn(1000)
		componentToCheck += deficit * 40 / 100
		settingsToComponent += deficit * 25 / 100
		readCaptcha += deficit * 20 / 100
		checkToEnd += deficit * 15 / 100
	}

	if total > 10000 {
		excess := total - 10000
		componentToCheck -= excess * 40 / 100
		settingsToComponent -= excess * 25 / 100
		readCaptcha -= excess * 20 / 100
		checkToEnd -= excess * 15 / 100

		if componentToCheck < 1200 {
			componentToCheck = 1200
		}
		if settingsToComponent < 600 {
			settingsToComponent = 600
		}
		if readCaptcha < 500 {
			readCaptcha = 500
		}
		if checkToEnd < 300 {
			checkToEnd = 300
		}
	}

	return CaptchaSessionTiming{
		FetchPowMs:            fetchPow,
		ReadCaptchaMs:         readCaptcha,
		SettingsToComponentMs: settingsToComponent,
		ComponentToCheckMs:    componentToCheck,
		CheckToEndMs:          checkToEnd,
		EndSessionMs:          endSession,
		ExtraPauseMs:          extraPause,
	}
}

// GenerateCaptchaDownlink produces a JSON array of simulated network
// downlink measurements for the captcha telemetry.
func GenerateCaptchaDownlink(rng *rand.Rand) string {
	n := 8 + rng.Intn(9)
	baseDL := 50.0 + rng.Float64()*150.0

	vals := make([]string, n)
	stab := 2 + rng.Intn(2)
	for i := 0; i < n; i++ {
		var v float64
		if i < stab {
			v = baseDL * (0.9 + rng.Float64()*0.2)
		} else {
			v = baseDL * (0.99 + rng.Float64()*0.02)
		}
		vals[i] = fmt.Sprintf("%.1f", v)
	}
	return "[" + strings.Join(vals, ",") + "]"
}

// GenerateCaptchaConnectionRtt produces a JSON array of simulated RTT
// measurements for the captcha telemetry.
func GenerateCaptchaConnectionRtt(rng *rand.Rand) string {
	n := 7 + rng.Intn(5)
	baseRTT := 3.0 + rng.Float64()*12.0
	vals := make([]string, n)
	for i := 0; i < n; i++ {
		vals[i] = fmt.Sprintf("%.1f", baseRTT*(0.9+rng.Float64()*0.2))
	}
	return "[" + strings.Join(vals, ",") + "]"
}

// GaussianRand returns a normally distributed random value with the given
// mean and standard deviation, using the Box-Muller transform.
func GaussianRand(rng *rand.Rand, mean, stddev float64) float64 {
	u1 := rng.Float64()
	u2 := rng.Float64()
	z := math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2.0*math.Pi*u2)
	return mean + stddev*z
}
