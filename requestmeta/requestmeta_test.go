// SPDX-License-Identifier: MPL-2.0

package requestmeta

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestResolverUsesRightmostUntrustedHop(t *testing.T) {
	resolver, err := New(Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}, Random: strings.NewReader(strings.Repeat("a", 16))})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.20, 203.0.113.9, 10.0.0.4")
	request.Header.Set("X-Forwarded-Proto", "https")
	metadata, err := resolver.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if got := metadata.ClientIP.String(); got != "203.0.113.9" {
		t.Fatalf("client=%s", got)
	}
	if metadata.Scheme != "https" || metadata.ClientIPSource != "forwarded" {
		t.Fatalf("metadata=%+v", metadata)
	}
}

func TestResolverIgnoresUntrustedForwarding(t *testing.T) {
	resolver, _ := New(Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Random: strings.NewReader(strings.Repeat("b", 16))})
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "198.51.100.4:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	metadata, err := resolver.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if got := metadata.ClientIP.String(); got != "198.51.100.4" || metadata.ClientIPSource != "peer" {
		t.Fatalf("metadata=%+v", metadata)
	}
}

func TestResolverRejectsMalformedTrustedForwarding(t *testing.T) {
	resolver, _ := New(Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Random: strings.NewReader(strings.Repeat("c", 16))})
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", "not-an-address")
	if _, err := resolver.Resolve(request); !errors.Is(err, ErrInvalidForwarding) {
		t.Fatalf("err=%v", err)
	}
}

func TestResolverRejectsAmbiguousTrustedForwarding(t *testing.T) {
	resolver, _ := New(Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Random: strings.NewReader(strings.Repeat("d", 16))})
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header["X-Forwarded-Proto"] = []string{"https", "http"}
	if _, err := resolver.Resolve(request); !errors.Is(err, ErrInvalidForwarding) {
		t.Fatalf("err=%v", err)
	}
}

func TestMiddlewareReportsBadForwardingAsBadRequest(t *testing.T) {
	resolver, _ := New(Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Random: strings.NewReader(strings.Repeat("e", 16))})
	handler := resolver.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler ran") }))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", "invalid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestMiddlewareFailsClosedOnEntropyError(t *testing.T) {
	resolver, _ := New(Config{Random: failingReader{}})
	called := false
	handler := resolver.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	handler.ServeHTTP(response, request)
	if called || response.Code != http.StatusServiceUnavailable {
		t.Fatalf("called=%v status=%d", called, response.Code)
	}
}
