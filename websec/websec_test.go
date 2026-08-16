// SPDX-License-Identifier: MPL-2.0

package websec

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSameOriginRejectsCrossSiteAndContradiction(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://example.test/change", nil)
	request.Header.Set("Origin", "https://example.test")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	if !SameOrigin(request, "https://example.test") {
		t.Fatal("same origin rejected")
	}
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	if SameOrigin(request, "https://example.test") {
		t.Fatal("cross-site accepted")
	}
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Origin", "https://attacker.test")
	if SameOrigin(request, "https://example.test") {
		t.Fatal("foreign origin accepted")
	}
}

func TestCSRFIsPurposeBound(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	token, err := CSRFToken(secret, "account:update")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCSRF(secret, "account:update", token) {
		t.Fatal("valid token rejected")
	}
	if VerifyCSRF(secret, "account:delete", token) {
		t.Fatal("cross-purpose token accepted")
	}
}

func TestSafeLocalRedirect(t *testing.T) {
	for _, unsafe := range []string{"https://attacker.test/", "//attacker.test/", "/\\attacker", "javascript:alert(1)"} {
		if got := SafeLocalRedirect(unsafe, "/home"); got != "/home" {
			t.Fatalf("%q => %q", unsafe, got)
		}
	}
	if got := SafeLocalRedirect("/items?page=2", "/"); got != "/items?page=2" {
		t.Fatalf("got=%q", got)
	}
}

func TestLimiterRefillsAndStaysBounded(t *testing.T) {
	now := time.Unix(100, 0)
	limiter, err := NewLimiter(LimitConfig{RatePerSecond: 1, Burst: 2, MaxEntries: 2, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !limiter.Allow("a") || !limiter.Allow("a") || limiter.Allow("a") {
		t.Fatal("unexpected initial budget")
	}
	now = now.Add(time.Second)
	if !limiter.Allow("a") {
		t.Fatal("token did not refill")
	}
	_ = limiter.Allow("b")
	_ = limiter.Allow("c")
	if len(limiter.entries) != 2 {
		t.Fatalf("entries=%d", len(limiter.entries))
	}
}
