// SPDX-License-Identifier: MPL-2.0

// Package abuse provides application-classified request enforcement. It does
// not guess which routes or probes are malicious for an application.
package abuse

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"gamertan.com/web/requestmeta"
)

type Severity uint8

const (
	Ignore Severity = iota
	Strike
	ImmediateBlock
	PermanentBlock
)

var ErrCapacity = errors.New("abuse: store capacity exhausted")

type Signal struct {
	Severity Severity
	Reason   string
}

type Decision struct {
	BlockedUntil time.Time
	Permanent    bool
	Reason       string
	Strikes      int
}

func (decision Decision) Blocked(now time.Time) bool {
	return decision.Permanent || decision.BlockedUntil.After(now)
}

type Store interface {
	Lookup(context.Context, string, time.Time) (Decision, error)
	Record(context.Context, string, Signal, time.Time, Policy) (Decision, error)
	Pardon(context.Context, string, time.Time) error
	Cleanup(context.Context, time.Time, time.Duration, int) error
}

type Policy struct {
	Threshold     int
	Window        time.Duration
	BlockDuration time.Duration
	Retention     time.Duration
	MaxClients    int
}

func (policy Policy) Validate() error {
	if policy.Threshold < 1 || policy.Threshold > 1000 || policy.Window < time.Second || policy.Window > 24*time.Hour || policy.BlockDuration < time.Second || policy.BlockDuration > 365*24*time.Hour || policy.Retention < policy.Window || policy.Retention > 10*365*24*time.Hour || policy.MaxClients < 1 || policy.MaxClients > 1000000 {
		return errors.New("abuse: invalid policy")
	}
	return nil
}

type Classifier func(*http.Request) Signal

type Engine struct {
	Store    Store
	Policy   Policy
	Classify Classifier
	Now      func() time.Time
	OnError  func(error)
}

func (engine Engine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if engine.Store == nil || engine.Policy.Validate() != nil {
			http.Error(response, "security policy unavailable", http.StatusServiceUnavailable)
			return
		}
		now := time.Now().UTC()
		if engine.Now != nil {
			now = engine.Now().UTC()
		}
		metadata, ok := requestmeta.FromContext(request.Context())
		if !ok || !metadata.ClientIP.IsValid() {
			http.Error(response, "request identity unavailable", http.StatusServiceUnavailable)
			return
		}
		key := metadata.ClientIP.String()
		decision, err := engine.Store.Lookup(request.Context(), key, now)
		if err != nil {
			engine.fail(response, err)
			return
		}
		if decision.Blocked(now) {
			block(response, decision, now)
			return
		}
		signal := Signal{}
		if engine.Classify != nil {
			signal = engine.Classify(request)
		}
		if signal.Severity != Ignore {
			decision, err = engine.Store.Record(request.Context(), key, signal, now, engine.Policy)
			if err != nil {
				engine.fail(response, err)
				return
			}
			if decision.Blocked(now) {
				block(response, decision, now)
				return
			}
		}
		next.ServeHTTP(response, request)
	})
}

func (engine Engine) fail(response http.ResponseWriter, err error) {
	if engine.OnError != nil {
		engine.OnError(errors.New("abuse: persistence unavailable"))
	}
	response.Header().Set("Cache-Control", "no-store")
	http.Error(response, "security policy unavailable", http.StatusServiceUnavailable)
}

func block(response http.ResponseWriter, decision Decision, now time.Time) {
	response.Header().Set("Cache-Control", "no-store")
	if decision.Permanent {
		http.Error(response, "forbidden", http.StatusForbidden)
		return
	}
	seconds := int64(decision.BlockedUntil.Sub(now).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	response.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	http.Error(response, "too many requests", http.StatusTooManyRequests)
}

// MemoryStore is a bounded single-process reference implementation and test
// adapter. Durable applications should implement Store with private storage.
type MemoryStore struct {
	mu      sync.Mutex
	clients map[string]client
}
type client struct {
	first, last time.Time
	strikes     int
	decision    Decision
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{clients: make(map[string]client)} }

func (store *MemoryStore) Lookup(_ context.Context, key string, now time.Time) (Decision, error) {
	if key == "" || len(key) > 128 || now.IsZero() {
		return Decision{}, errors.New("abuse: invalid lookup")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, exists := store.clients[key]
	if !exists {
		return Decision{}, nil
	}
	if !entry.decision.Permanent && !entry.decision.BlockedUntil.After(now) {
		entry.decision.BlockedUntil = time.Time{}
		store.clients[key] = entry
	}
	return entry.decision, nil
}

func (store *MemoryStore) Record(_ context.Context, key string, signal Signal, now time.Time, policy Policy) (Decision, error) {
	if key == "" || len(key) > 128 || signal.Severity < Strike || signal.Severity > PermanentBlock || signal.Reason == "" || len(signal.Reason) > 256 || now.IsZero() || policy.Validate() != nil {
		return Decision{}, errors.New("abuse: invalid record")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, exists := store.clients[key]
	if !exists && len(store.clients) >= policy.MaxClients && !store.evictOldest() {
		return Decision{}, ErrCapacity
	}
	if entry.first.IsZero() || now.Sub(entry.first) > policy.Window {
		entry.first, entry.strikes = now, 0
	}
	entry.last = now
	entry.strikes++
	entry.decision.Strikes, entry.decision.Reason = entry.strikes, signal.Reason
	if signal.Severity == PermanentBlock {
		entry.decision.Permanent = true
	}
	if (signal.Severity == ImmediateBlock || entry.strikes >= policy.Threshold) && !entry.decision.Permanent {
		entry.decision.BlockedUntil = now.Add(policy.BlockDuration)
	}
	store.clients[key] = entry
	return entry.decision, nil
}

func (store *MemoryStore) Pardon(_ context.Context, key string, _ time.Time) error {
	if key == "" || len(key) > 128 {
		return errors.New("abuse: invalid pardon")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.clients, key)
	return nil
}

func (store *MemoryStore) Cleanup(_ context.Context, now time.Time, retention time.Duration, max int) error {
	if now.IsZero() || retention <= 0 || max < 1 {
		return errors.New("abuse: invalid cleanup")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for key, entry := range store.clients {
		if !entry.decision.Permanent && now.Sub(entry.last) > retention {
			delete(store.clients, key)
		}
	}
	for len(store.clients) > max {
		if !store.evictOldest() {
			return ErrCapacity
		}
	}
	return nil
}

func (store *MemoryStore) evictOldest() bool {
	var selected string
	var oldest time.Time
	for key, entry := range store.clients {
		if entry.decision.Permanent {
			continue
		}
		if selected == "" || entry.last.Before(oldest) {
			selected, oldest = key, entry.last
		}
	}
	if selected != "" {
		delete(store.clients, selected)
		return true
	}
	return false
}
