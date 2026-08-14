//go:build linux

package localtun

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	chinaDNSCacheHeaderLen     = 24 // native CacheMsg.Header size on supported targets
	chinaDNSMessageHeaderLen   = 12
	managedDNSCacheSchema      = "tamizdat-chinadns-cache-v1"
	managedDNSCacheMaxEntries  = 10000
	managedDNSCacheReplayLimit = 10 * time.Second
	managedDNSCacheWorkers     = 16
)

type chinaDNSCacheQuery struct {
	Name  string
	QType uint16
}

var managedDNSQueryID atomic.Uint32

// managedDNSCacheFingerprint covers only resolver-answer semantics. Routing
// group changes deliberately do not invalidate the cache: a replayed question
// is matched against the current ChinaDNS groups and is inserted into the new
// nft set. Changing the upstream or cache semantics must produce a fresh DB.
func managedDNSCacheFingerprint() string {
	material := strings.Join([]string{
		managedDNSCacheSchema,
		"china-dns=" + localDNSUpstream,
		"trust-dns=" + localDNSUpstream,
		"default-tag=chn",
		"cache-stale=0",
	}, "\n")
	sum := sha256.Sum256([]byte(material))
	return fmt.Sprintf("%x", sum[:])
}

func prepareManagedDNSCache(now time.Time) ([]chinaDNSCacheQuery, error) {
	if err := os.Remove(localDNSOldCache); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove legacy ChinaDNS cache: %w", err)
	}
	return prepareChinaDNSCache(localDNSCache, localDNSCacheMeta, managedDNSCacheFingerprint(), now)
}

func prepareChinaDNSCache(cachePath, metaPath, fingerprint string, now time.Time) ([]chinaDNSCacheQuery, error) {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
		return nil, fmt.Errorf("create ChinaDNS cache directory: %w", err)
	}

	meta, metaErr := os.ReadFile(metaPath)
	if metaErr != nil && !errors.Is(metaErr, os.ErrNotExist) {
		return nil, fmt.Errorf("read ChinaDNS cache metadata: %w", metaErr)
	}
	if strings.TrimSpace(string(meta)) != fingerprint {
		if err := os.Remove(cachePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("invalidate ChinaDNS cache: %w", err)
		}
		if err := writeAtomic(metaPath, []byte(fingerprint+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("write ChinaDNS cache metadata: %w", err)
		}
	}

	file, err := os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open ChinaDNS cache: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close ChinaDNS cache: %w", err)
	}
	if err := os.Chmod(cachePath, 0o600); err != nil {
		return nil, fmt.Errorf("chmod ChinaDNS cache: %w", err)
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, fmt.Errorf("read ChinaDNS cache: %w", err)
	}
	queries, err := parseChinaDNSCache(data, now)
	if err == nil {
		return queries, nil
	}

	// ChinaDNS intentionally does not validate cache-db while loading it. A
	// truncated file must be reset before the process starts, otherwise it may
	// consume malformed native headers. Losing warm state is safer than failing
	// DNS or restoring an untrusted answer.
	if truncateErr := os.WriteFile(cachePath, nil, 0o600); truncateErr != nil {
		return nil, errors.Join(fmt.Errorf("parse ChinaDNS cache: %w", err), fmt.Errorf("reset ChinaDNS cache: %w", truncateErr))
	}
	log.Printf("WARN reset invalid ChinaDNS cache: %v", err)
	return nil, nil
}

func parseChinaDNSCache(data []byte, now time.Time) ([]chinaDNSCacheQuery, error) {
	seen := make(map[chinaDNSCacheQuery]struct{})
	nowUnix := now.Unix()
	for offset, entries := 0, 0; offset < len(data); entries++ {
		if entries >= managedDNSCacheMaxEntries {
			return nil, fmt.Errorf("ChinaDNS cache exceeds %d entries", managedDNSCacheMaxEntries)
		}
		if len(data)-offset < chinaDNSCacheHeaderLen {
			return nil, fmt.Errorf("truncated ChinaDNS cache header at byte %d", offset)
		}
		header := data[offset : offset+chinaDNSCacheHeaderLen]
		updatedAt := int64(binary.NativeEndian.Uint64(header[0:8]))
		ttl := int64(int32(binary.NativeEndian.Uint32(header[12:16])))
		msgLen := int(binary.NativeEndian.Uint16(header[20:22]))
		qnameLen := int(header[22])
		if msgLen < chinaDNSMessageHeaderLen+qnameLen+4 || qnameLen < 2 || msgLen > 65535 {
			return nil, fmt.Errorf("invalid ChinaDNS cache lengths at byte %d: msg=%d qname=%d", offset, msgLen, qnameLen)
		}
		start := offset + chinaDNSCacheHeaderLen
		end := start + msgLen
		if end > len(data) {
			return nil, fmt.Errorf("truncated ChinaDNS cache message at byte %d", offset)
		}
		msg := data[start:end]
		qnameEnd := chinaDNSMessageHeaderLen + qnameLen
		name, err := decodeDNSQName(msg[chinaDNSMessageHeaderLen:qnameEnd])
		if err != nil {
			return nil, fmt.Errorf("decode ChinaDNS cache qname at byte %d: %w", offset, err)
		}
		qtype := binary.BigEndian.Uint16(msg[qnameEnd : qnameEnd+2])

		elapsed := int64(0)
		if nowUnix > updatedAt {
			elapsed = nowUnix - updatedAt
		}
		if ttl-elapsed > 0 && (qtype == 1 || qtype == 28) {
			seen[chinaDNSCacheQuery{Name: name, QType: qtype}] = struct{}{}
		}
		offset = end
	}

	queries := make([]chinaDNSCacheQuery, 0, len(seen))
	for query := range seen {
		queries = append(queries, query)
	}
	sort.Slice(queries, func(i, j int) bool {
		if queries[i].Name != queries[j].Name {
			return queries[i].Name < queries[j].Name
		}
		return queries[i].QType < queries[j].QType
	})
	return queries, nil
}

func decodeDNSQName(wire []byte) (string, error) {
	labels := make([]string, 0, 4)
	for offset := 0; offset < len(wire); {
		length := int(wire[offset])
		offset++
		if length == 0 {
			if offset != len(wire) || len(labels) == 0 {
				return "", errors.New("invalid terminal label")
			}
			// Preserve the original wire case. ChinaDNS keys its cache by the
			// complete raw question, so lower-casing here would miss mixed-case
			// cache entries and unnecessarily query the upstream again.
			name := strings.Join(labels, ".")
			if normalizeIngressDomain(name) == "" {
				return "", errors.New("invalid domain name")
			}
			return name, nil
		}
		if length > 63 || length&0xc0 != 0 || offset+length > len(wire) {
			return "", errors.New("invalid DNS label")
		}
		labels = append(labels, string(wire[offset:offset+length]))
		offset += length
	}
	return "", errors.New("unterminated DNS name")
}

func warmManagedDNSCache(parent context.Context, port int, queries []chinaDNSCacheQuery) error {
	if len(queries) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, managedDNSCacheReplayLimit)
	defer cancel()

	workers := managedDNSCacheWorkers
	if len(queries) < workers {
		workers = len(queries)
	}
	jobs := make(chan chinaDNSCacheQuery)
	var succeeded, failed atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for query := range jobs {
				if err := queryManagedDNSCache(ctx, port, query); err != nil {
					failed.Add(1)
				} else {
					succeeded.Add(1)
				}
			}
		}()
	}

sendLoop:
	for _, query := range queries {
		select {
		case jobs <- query:
		case <-ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()

	if err := parent.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cache replay timed out after %s (%d/%d restored)", managedDNSCacheReplayLimit, succeeded.Load(), len(queries))
	}
	log.Printf("local DNS cache replay: restored=%d failed=%d", succeeded.Load(), failed.Load())
	return nil
}

func queryManagedDNSCache(parent context.Context, port int, query chinaDNSCacheQuery) error {
	packet, id, err := buildDNSQuestion(query)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(packet); err != nil {
		return err
	}
	reply := make([]byte, 4096)
	n, err := conn.Read(reply)
	if err != nil {
		return err
	}
	if n < chinaDNSMessageHeaderLen || binary.BigEndian.Uint16(reply[0:2]) != id || reply[2]&0x80 == 0 {
		return errors.New("invalid ChinaDNS cache replay response")
	}
	return nil
}

func buildDNSQuestion(query chinaDNSCacheQuery) ([]byte, uint16, error) {
	name := strings.TrimSuffix(strings.TrimSpace(query.Name), ".")
	if normalizeIngressDomain(name) == "" || (query.QType != 1 && query.QType != 28) {
		return nil, 0, errors.New("invalid ChinaDNS cache question")
	}
	id := uint16(managedDNSQueryID.Add(1))
	packet := make([]byte, chinaDNSMessageHeaderLen)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 0, 0, 1)
	binary.BigEndian.PutUint16(packet[len(packet)-4:len(packet)-2], query.QType)
	return packet, id, nil
}
