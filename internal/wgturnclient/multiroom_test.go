package wgturnclient

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestBuildWorkerGroupPlansFourRoomsTwentyEach(t *testing.T) {
	plans := buildWorkerGroupPlans(80, 4, 20)
	if len(plans) != 80 {
		t.Fatalf("groups=%d want=80", len(plans))
	}
	total := 0
	perRoom := make([]int, 4)
	for i := range plans {
		wantRoom := i / 20
		if plans[i].hashIndex != wantRoom || plans[i].roomID != wantRoom || plans[i].workerCount != 1 {
			t.Fatalf("plan[%d]=%v want room=%d count=1", i, plans[i], wantRoom)
		}
		total += plans[i].workerCount
		perRoom[plans[i].hashIndex] += plans[i].workerCount
	}
	if total != 80 {
		t.Fatalf("total=%d want=80", total)
	}
	for room, count := range perRoom {
		if count != 20 {
			t.Fatalf("room %d workers=%d want=20", room, count)
		}
	}
}

func TestBuildWorkerGroupPlansSingleRoomKeepsLegacyBatching(t *testing.T) {
	plans := buildWorkerGroupPlans(20, 1, 20)
	want := []workerGroupPlan{{hashIndex: 0, roomID: 0, workerCount: 12}, {hashIndex: 0, roomID: 0, workerCount: 8}}
	if !reflect.DeepEqual(plans, want) {
		t.Fatalf("plans=%v want=%v", plans, want)
	}
}

func TestBuildWorkerGroupPlansLegacyTwenty(t *testing.T) {
	plans := buildWorkerGroupPlans(20, 1, 0)
	want := []workerGroupPlan{{hashIndex: 0, roomID: 0, workerCount: 12}, {hashIndex: 0, roomID: 0, workerCount: 8}}
	if len(plans) != len(want) || plans[0] != want[0] || plans[1] != want[1] {
		t.Fatalf("plans=%v want=%v", plans, want)
	}
}

func TestNewMultiRoomPreservesLegacyLimit(t *testing.T) {
	legacy, err := New(Config{PeerAddr: "127.0.0.1:443", Workers: 80, VKHashes: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.cfg.Workers != 20 {
		t.Fatalf("legacy workers=%d want=20", legacy.cfg.Workers)
	}
	multi, err := New(Config{PeerAddr: "127.0.0.1:443", WorkersPerRoom: 20, VKHashes: []string{"a", "b", "c", "d"}})
	if err != nil {
		t.Fatal(err)
	}
	if multi.cfg.Workers != 80 {
		t.Fatalf("multi workers=%d want=80", multi.cfg.Workers)
	}
}

func TestPreloadedRoomCredentialsAndLiveUpdateStayScoped(t *testing.T) {
	a := &Credentials{User: "a", Pass: "pa", TurnURLs: []string{"a.example:3478"}, Lifetime: 600}
	b := &Credentials{User: "b", Pass: "pb", TurnURLs: []string{"b.example:3478"}, Lifetime: 600}
	r, err := New(Config{
		PeerAddr: "127.0.0.1:443", WorkersPerRoom: 20, VKHashes: []string{"room-a", "room-b"},
		PreloadedCredsByHash: map[string]*Credentials{"room-a": a},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.currentRoomCreds("room-a"); got == nil || got.User != "a" {
		t.Fatalf("missing preloaded room a: %#v", got)
	}
	if got := r.currentRoomCreds("room-b"); got != nil {
		t.Fatalf("unexpected room b credentials: %#v", got)
	}
	if err := r.UpdatePreloadedCredsByHash(map[string]*Credentials{"room-b": b}); err != nil {
		t.Fatal(err)
	}
	if got := r.currentRoomCreds("room-b"); got == nil || got.User != "b" {
		t.Fatalf("missing updated room b: %#v", got)
	}
	if err := r.UpdatePreloadedCredsByHash(map[string]*Credentials{"unknown": a}); err == nil {
		t.Fatal("accepted credentials for an unconfigured room")
	}
}

func TestNewMultiRoomValidation(t *testing.T) {
	if _, err := New(Config{PeerAddr: "127.0.0.1:443", WorkersPerRoom: 21, VKHashes: []string{"a"}}); err == nil {
		t.Fatal("expected workers-per-room limit error")
	}
	if _, err := New(Config{PeerAddr: "127.0.0.1:443", WorkersPerRoom: 20, VKHashes: []string{"a", "b"}, SecondaryHash: "fallback"}); err == nil {
		t.Fatal("expected secondary-hash multi-room error")
	}
}

func TestNormalizeVKCallHashesDeduplicates(t *testing.T) {
	got := NormalizeVKCallHashes([]string{"https://vk.com/call/join/abc", "abc", " def "})
	if len(got) != 2 || got[0] != "abc" || got[1] != "def" {
		t.Fatalf("normalized hashes=%v want=[abc def]", got)
	}
}

func TestConfigBrokerRetriesAndStopsAfterDelivery(t *testing.T) {
	b := &configBroker{ch: make(chan string, 1)}
	if !b.claim() {
		t.Fatal("first claim failed")
	}
	if b.claim() {
		t.Fatal("concurrent claim succeeded")
	}
	b.complete(false)
	if !b.claim() {
		t.Fatal("retry claim failed")
	}
	b.complete(true)
	if b.claim() {
		t.Fatal("claim succeeded after config delivery")
	}
	b.requestRecovery()
	if !b.claim() {
		t.Fatal("owner recovery claim failed")
	}
	if b.claim() {
		t.Fatal("concurrent owner recovery claim succeeded")
	}
	b.complete(false)
	b.requestRecovery()
	if !b.claim() {
		t.Fatal("owner recovery retry claim failed")
	}
	b.complete(true)
	if b.claim() {
		t.Fatal("owner recovery remained armed after delivery")
	}
}

func TestCredentialLocksArePerRoom(t *testing.T) {
	multi, err := New(Config{PeerAddr: "127.0.0.1:443", WorkersPerRoom: 20, VKHashes: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if multi.credentialLock("a") != multi.credentialLock("a") {
		t.Fatal("same room received different credential locks")
	}
	if multi.credentialLock("a") == multi.credentialLock("b") {
		t.Fatal("different rooms share one credential lock")
	}
	legacy, err := New(Config{PeerAddr: "127.0.0.1:443", Workers: 20, VKHashes: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.credentialLock("a") != legacy.credentialLock("b") {
		t.Fatal("legacy mode no longer uses its global serialization lock")
	}
}

func TestInvalidateRoomCredsIsScopedToRoom(t *testing.T) {
	r, err := New(Config{PeerAddr: "127.0.0.1:443", WorkersPerRoom: 20, VKHashes: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	r.updateRoomCreds("a", testRoomCreds("a"))
	r.updateRoomCreds("b", testRoomCreds("b"))
	r.invalidateRoomCreds("a")
	if got := r.currentRoomCreds("a"); got != nil {
		t.Fatalf("invalidated room credentials still cached: %#v", got)
	}
	if got := r.currentRoomCreds("b"); got == nil {
		t.Fatal("invalidating one room removed another room's credentials")
	}
}

func TestDispatcherDropsStaleWorkerCountNotifications(t *testing.T) {
	d := &Dispatcher{}
	var mu sync.Mutex
	var got []int
	d.onWorkerCount = func(count int) {
		mu.Lock()
		got = append(got, count)
		mu.Unlock()
	}
	d.notifyWorkerCount(2, 2)
	d.notifyWorkerCount(1, 1)
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("notifications=%v want=[2]", got)
	}
}

func TestRoomCredentialCacheIsolationAndClone(t *testing.T) {
	r, err := New(Config{PeerAddr: "127.0.0.1:443", WorkersPerRoom: 20, VKHashes: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	a := &Credentials{User: "room-a", Pass: "a-pass", TurnURLs: []string{"a.example:3478"}, Lifetime: 600}
	b := &Credentials{User: "room-b", Pass: "b-pass", TurnURLs: []string{"b.example:3478"}, Lifetime: 600}
	r.updateRoomCreds("a", a)
	r.updateRoomCreds("b", b)
	gotA := r.currentRoomCreds("a")
	gotB := r.currentRoomCreds("b")
	if gotA == nil || gotA.User != "room-a" || gotB == nil || gotB.User != "room-b" {
		t.Fatalf("cache crossed rooms: a=%#v b=%#v", gotA, gotB)
	}
	if gotA.Lifetime < 598 || gotA.Lifetime > 600 {
		t.Fatalf("cached remaining lifetime=%d want about 600", gotA.Lifetime)
	}
	gotA.TurnURLs[0] = "mutated"
	if again := r.currentRoomCreds("a"); again.TurnURLs[0] != "a.example:3478" {
		t.Fatalf("cache returned aliased slices: %#v", again)
	}
	r.roomCredsMu.Lock()
	entry := r.roomCreds["a"]
	entry.expiresAt = time.Now().Add(-time.Second)
	r.roomCreds["a"] = entry
	r.roomCredsMu.Unlock()
	if expired := r.currentRoomCreds("a"); expired != nil {
		t.Fatalf("expired credentials returned: %#v", expired)
	}
	if live := r.currentRoomCreds("b"); live == nil {
		t.Fatal("expiring room a removed room b")
	}
}
