package wgturnclient

import (
	"fmt"
	"time"
)

type workerGroupPlan struct {
	hashIndex   int
	roomID      int
	workerCount int
}

type roomCredentialCacheEntry struct {
	creds      *Credentials
	expiresAt  time.Time
	validUntil time.Time
}

func buildWorkerGroupPlans(totalWorkers, roomCount, workersPerRoom int) []workerGroupPlan {
	if roomCount < 1 {
		return nil
	}
	var plans []workerGroupPlan
	if workersPerRoom > 0 {
		// Explicit per-room mode is the canonical OpenWrt path. One allocation
		// per lifecycle group makes every replacement kill-one-add-one for both
		// single-room and multi-room configurations.
		groupSize := multiRoomGroupSize
		for room := 0; room < roomCount; room++ {
			remaining := workersPerRoom
			for remaining > 0 {
				count := remaining
				if count > groupSize {
					count = groupSize
				}
				plans = append(plans, workerGroupPlan{hashIndex: room, roomID: room, workerCount: count})
				remaining -= count
			}
		}
		return plans
	}

	remaining := totalWorkers
	for group := 0; remaining > 0; group++ {
		count := remaining
		if count > workersPerGroup {
			count = workersPerGroup
		}
		hashIndex := group % roomCount
		plans = append(plans, workerGroupPlan{hashIndex: hashIndex, roomID: hashIndex, workerCount: count})
		remaining -= count
	}
	return plans
}

func (r *Runner) UpdatePreloadedCredsByHash(credsByHash map[string]*Credentials) error {
	if r.cfg.WorkersPerRoom <= 0 {
		return fmt.Errorf("room-scoped credentials require multi-room mode")
	}
	configured := make(map[string]struct{}, len(r.cfg.VKHashes))
	for _, hash := range r.cfg.VKHashes {
		configured[hash] = struct{}{}
	}
	for hash, creds := range credsByHash {
		if _, ok := configured[hash]; !ok {
			return fmt.Errorf("credentials contain an unconfigured room")
		}
		if creds == nil {
			return fmt.Errorf("credentials contain an empty room entry")
		}
	}
	for hash, creds := range credsByHash {
		r.updateRoomCreds(hash, creds)
	}
	return nil
}

func cloneCredentials(creds *Credentials) *Credentials {
	if creds == nil {
		return nil
	}
	dup := *creds
	dup.TurnURLs = append([]string(nil), creds.TurnURLs...)
	dup.TurnServers = append([]TurnServer(nil), creds.TurnServers...)
	return &dup
}

func (r *Runner) updateRoomCreds(hash string, creds *Credentials) {
	if creds == nil {
		return
	}
	r.roomCredsMu.Lock()
	now := time.Now()
	lifetime := creds.Lifetime
	if lifetime <= 0 {
		lifetime = 600
	}
	r.roomCreds[hash] = roomCredentialCacheEntry{
		creds:      cloneCredentials(creds),
		expiresAt:  now.Add(credentialReuseDuration(creds)),
		validUntil: now.Add(time.Duration(lifetime) * time.Second),
	}
	r.roomCredsMu.Unlock()
}

// invalidateRoomCreds forces the next lifecycle for a room to acquire fresh
// TURN material. A full allocation quota means the cached credential batch is
// not usable; retrying it forever leaves that room permanently at zero.
func (r *Runner) invalidateRoomCreds(hash string) {
	r.roomCredsMu.Lock()
	delete(r.roomCreds, hash)
	r.roomCredsMu.Unlock()
}

func (r *Runner) currentRoomCreds(hash string) *Credentials {
	r.roomCredsMu.Lock()
	defer r.roomCredsMu.Unlock()
	entry, ok := r.roomCreds[hash]
	if !ok {
		return nil
	}
	if !entry.expiresAt.IsZero() && !time.Now().Before(entry.expiresAt) {
		delete(r.roomCreds, hash)
		return nil
	}
	dup := cloneCredentials(entry.creds)
	if !entry.validUntil.IsZero() {
		remaining := int(time.Until(entry.validUntil).Seconds())
		if remaining <= 0 {
			delete(r.roomCreds, hash)
			return nil
		}
		dup.Lifetime = remaining
	}
	return dup
}

// credentialsForAttempt reads the latest published generation before every
// retry. A sibling lifecycle group or external refresher may replace TURN
// credentials while this worker batch remains alive.
func (r *Runner) credentialsForAttempt(hash string, fallback *Credentials) *Credentials {
	if r.cfg.WorkersPerRoom > 0 {
		if current := r.currentRoomCreds(hash); current != nil {
			return current
		}
	} else if current := r.currentPreloadedCreds(); current != nil {
		return current
	}
	return fallback
}

func sameCredentialGeneration(a, b *Credentials) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.User == b.User && a.Pass == b.Pass
}

// invalidateCredentials removes only the generation that received TURN 486.
// It cannot delete a newer generation already published by a sibling group.
func (r *Runner) invalidateCredentials(hash string, stale *Credentials) {
	if r.cfg.WorkersPerRoom > 0 {
		r.roomCredsMu.Lock()
		defer r.roomCredsMu.Unlock()
		entry, ok := r.roomCreds[hash]
		if !ok || entry.creds == nil || !sameCredentialGeneration(entry.creds, stale) {
			return
		}
		delete(r.roomCreds, hash)
		return
	}

	r.preloadedCredsMu.Lock()
	defer r.preloadedCredsMu.Unlock()
	current := r.preloadedCreds.Load()
	if current == nil || !sameCredentialGeneration(current, stale) {
		return
	}
	r.preloadedCreds.Store(nil)
	r.preloadedCredsExpiry.Store(0)
}
