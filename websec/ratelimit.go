// SPDX-License-Identifier: MPL-2.0

package websec

import (
	"sync"
	"time"
)

// Limiter is a bounded in-memory token bucket intended for one process. A
// distributed application should provide a different limiter at its boundary.
type Limiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	maxEntries int
	entries    map[string]bucket
	now        func() time.Time
}

type bucket struct {
	tokens  float64
	updated time.Time
}

type LimitConfig struct {
	RatePerSecond float64
	Burst         int
	MaxEntries    int
	Now           func() time.Time
}

func NewLimiter(config LimitConfig) (*Limiter, error) {
	if config.RatePerSecond <= 0 || config.RatePerSecond > 100000 || config.Burst < 1 || config.Burst > 100000 || config.MaxEntries < 1 || config.MaxEntries > 1000000 {
		return nil, ErrInvalidLimit
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Limiter{rate: config.RatePerSecond, burst: float64(config.Burst), maxEntries: config.MaxEntries, entries: make(map[string]bucket), now: config.Now}, nil
}

var ErrInvalidLimit = limitError("websec: invalid rate-limit configuration")

type limitError string

func (err limitError) Error() string { return string(err) }

func (limiter *Limiter) Allow(key string) bool {
	if key == "" || len(key) > 512 {
		return false
	}
	now := limiter.now()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	current, exists := limiter.entries[key]
	if !exists {
		if len(limiter.entries) >= limiter.maxEntries {
			limiter.evictOldest()
		}
		current = bucket{tokens: limiter.burst, updated: now}
	}
	elapsed := now.Sub(current.updated).Seconds()
	if elapsed > 0 {
		current.tokens = min(limiter.burst, current.tokens+elapsed*limiter.rate)
		current.updated = now
	}
	if current.tokens < 1 {
		limiter.entries[key] = current
		return false
	}
	current.tokens--
	limiter.entries[key] = current
	return true
}

func (limiter *Limiter) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, value := range limiter.entries {
		if oldestKey == "" || value.updated.Before(oldest) {
			oldestKey, oldest = key, value.updated
		}
	}
	delete(limiter.entries, oldestKey)
}
