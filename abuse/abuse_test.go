// SPDX-License-Identifier: MPL-2.0

package abuse

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"gamertan.com/web/requestmeta"
)

func TestEngineUsesApplicationClassifier(t *testing.T) {
	now := time.Unix(100, 0)
	resolver, _ := requestmeta.New(requestmeta.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Random: strings.NewReader(strings.Repeat("a", 64))})
	engine := Engine{Store: NewMemoryStore(), Policy: Policy{Threshold: 2, Window: time.Minute, BlockDuration: time.Hour, Retention: time.Hour, MaxClients: 10}, Now: func() time.Time { return now }, Classify: func(request *http.Request) Signal {
		if request.URL.Path == "/application-known-bad" {
			return Signal{Severity: Strike, Reason: "application policy"}
		}
		return Signal{}
	}}
	called := 0
	handler := resolver.Middleware(engine.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called++ })))
	for index := 0; index < 2; index++ {
		request := httptest.NewRequest(http.MethodGet, "http://example.test/application-known-bad", nil)
		request.RemoteAddr = "127.0.0.1:1000"
		request.Header.Set("X-Forwarded-For", "203.0.113.8")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if index == 0 && response.Code != 200 {
			t.Fatalf("first status=%d", response.Code)
		}
		if index == 1 && response.Code != 429 {
			t.Fatalf("second status=%d", response.Code)
		}
	}
	if called != 1 {
		t.Fatalf("called=%d", called)
	}
}

func TestImmediateBlockAndPardon(t *testing.T) {
	store := NewMemoryStore()
	now := time.Unix(100, 0)
	policy := Policy{Threshold: 10, Window: time.Minute, BlockDuration: time.Hour, Retention: time.Hour, MaxClients: 10}
	decision, err := store.Record(t.Context(), "192.0.2.1", Signal{Severity: ImmediateBlock, Reason: "credential probe"}, now, policy)
	if err != nil || decision.Permanent || !decision.Blocked(now) {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if err = store.Pardon(t.Context(), "192.0.2.1", now); err != nil {
		t.Fatal(err)
	}
	decision, _ = store.Lookup(t.Context(), "192.0.2.1", now)
	if decision.Blocked(now) {
		t.Fatal("pardon did not clear block")
	}
}

func TestPermanentCapacityFailsClosed(t *testing.T) {
	store := NewMemoryStore()
	now := time.Unix(100, 0)
	policy := Policy{Threshold: 10, Window: time.Minute, BlockDuration: time.Hour, Retention: time.Hour, MaxClients: 1}
	decision, err := store.Record(t.Context(), "192.0.2.1", Signal{Severity: PermanentBlock, Reason: "operator decision"}, now, policy)
	if err != nil || !decision.Permanent {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if _, err = store.Record(t.Context(), "192.0.2.2", Signal{Severity: Strike, Reason: "probe"}, now, policy); !errors.Is(err, ErrCapacity) {
		t.Fatalf("err=%v", err)
	}
	if decision, _ = store.Lookup(t.Context(), "192.0.2.1", now); !decision.Permanent {
		t.Fatal("capacity handling evicted permanent decision")
	}
}

func TestLookupDoesNotAllocateUnseenClients(t *testing.T) {
	store := NewMemoryStore()
	now := time.Unix(100, 0)
	for index := 0; index < 100; index++ {
		if _, err := store.Lookup(t.Context(), "192.0.2."+strconv.Itoa(index), now); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.clients) != 0 {
		t.Fatalf("lookups allocated %d entries", len(store.clients))
	}
}
