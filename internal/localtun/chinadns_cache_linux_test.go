//go:build linux

package localtun

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestParseChinaDNSCacheKeepsOnlyLiveAddressQuestions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	data := appendChinaDNSCacheRecord(nil, now.Add(-10*time.Second), 60, "ChatGPT.com", 1)
	data = appendChinaDNSCacheRecord(data, now.Add(-10*time.Second), 60, "chatgpt.com", 28)
	data = appendChinaDNSCacheRecord(data, now.Add(-10*time.Second), 60, "ChatGPT.com", 1)
	data = appendChinaDNSCacheRecord(data, now.Add(-2*time.Minute), 60, "expired.example", 1)
	data = appendChinaDNSCacheRecord(data, now, 60, "txt.example", 16)

	got, err := parseChinaDNSCache(data, now)
	if err != nil {
		t.Fatalf("parseChinaDNSCache() error = %v", err)
	}
	want := []chinaDNSCacheQuery{
		{Name: "ChatGPT.com", QType: 1},
		{Name: "chatgpt.com", QType: 28},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseChinaDNSCache() = %#v, want %#v", got, want)
	}
}

func TestParseChinaDNSCacheRejectsTruncatedRecord(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	data := appendChinaDNSCacheRecord(nil, now, 60, "chatgpt.com", 1)
	data = data[:len(data)-1]
	if _, err := parseChinaDNSCache(data, now); err == nil {
		t.Fatal("parseChinaDNSCache() accepted a truncated record")
	}
}

func TestPrepareChinaDNSCachePreservesMatchingAndInvalidatesChangedFingerprint(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cache.db")
	metaPath := filepath.Join(dir, "cache.meta")
	data := appendChinaDNSCacheRecord(nil, now, 60, "chatgpt.com", 1)
	if err := os.WriteFile(cachePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, []byte("same\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	queries, err := prepareChinaDNSCache(cachePath, metaPath, "same", now)
	if err != nil {
		t.Fatalf("prepare matching cache: %v", err)
	}
	if want := []chinaDNSCacheQuery{{Name: "chatgpt.com", QType: 1}}; !reflect.DeepEqual(queries, want) {
		t.Fatalf("matching queries = %#v, want %#v", queries, want)
	}
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %o, want 600", info.Mode().Perm())
	}

	queries, err = prepareChinaDNSCache(cachePath, metaPath, "changed", now)
	if err != nil {
		t.Fatalf("prepare changed cache: %v", err)
	}
	if len(queries) != 0 {
		t.Fatalf("changed queries = %#v, want empty", queries)
	}
	info, err = os.Stat(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("invalidated cache size = %d, want 0", info.Size())
	}
	meta, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(meta) != "changed\n" {
		t.Fatalf("metadata = %q, want %q", meta, "changed\\n")
	}
}

func TestWarmManagedDNSCacheReplaysQuestions(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	want := []chinaDNSCacheQuery{
		{Name: "ChatGPT.com", QType: 1},
		{Name: "api.openai.com", QType: 28},
	}
	received := make(chan []chinaDNSCacheQuery, 1)
	go func() {
		got := make([]chinaDNSCacheQuery, 0, len(want))
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		for range want {
			n, addr, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				break
			}
			name, qtype, parseErr := parseTestDNSQuestion(buf[:n])
			if parseErr == nil {
				got = append(got, chinaDNSCacheQuery{Name: name, QType: qtype})
			}
			reply := append([]byte(nil), buf[:n]...)
			reply[2] |= 0x80
			_, _ = conn.WriteToUDP(reply, addr)
		}
		received <- got
	}()

	if err := warmManagedDNSCache(context.Background(), port, want); err != nil {
		t.Fatalf("warmManagedDNSCache() error = %v", err)
	}
	got := <-received
	sort.Slice(got, func(i, j int) bool {
		if got[i].Name != got[j].Name {
			return got[i].Name < got[j].Name
		}
		return got[i].QType < got[j].QType
	})
	sortedWant := append([]chinaDNSCacheQuery(nil), want...)
	sort.Slice(sortedWant, func(i, j int) bool {
		if sortedWant[i].Name != sortedWant[j].Name {
			return sortedWant[i].Name < sortedWant[j].Name
		}
		return sortedWant[i].QType < sortedWant[j].QType
	})
	if !reflect.DeepEqual(got, sortedWant) {
		t.Fatalf("replayed questions = %#v, want %#v", got, sortedWant)
	}
}

func appendChinaDNSCacheRecord(dst []byte, updatedAt time.Time, ttl int32, name string, qtype uint16) []byte {
	question, _, err := buildDNSQuestion(chinaDNSCacheQuery{Name: name, QType: 1})
	if err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint16(question[len(question)-4:len(question)-2], qtype)
	qnameLen := len(question) - chinaDNSMessageHeaderLen - 4
	header := make([]byte, chinaDNSCacheHeaderLen)
	binary.NativeEndian.PutUint64(header[0:8], uint64(updatedAt.Unix()))
	binary.NativeEndian.PutUint32(header[12:16], uint32(ttl))
	binary.NativeEndian.PutUint16(header[20:22], uint16(len(question)))
	header[22] = byte(qnameLen)
	dst = append(dst, header...)
	return append(dst, question...)
}

func parseTestDNSQuestion(packet []byte) (string, uint16, error) {
	offset := chinaDNSMessageHeaderLen
	for offset < len(packet) {
		length := int(packet[offset])
		offset++
		if length == 0 {
			name, err := decodeDNSQName(packet[chinaDNSMessageHeaderLen:offset])
			if err != nil {
				return "", 0, err
			}
			return name, binary.BigEndian.Uint16(packet[offset : offset+2]), nil
		}
		offset += length
	}
	return "", 0, os.ErrInvalid
}
