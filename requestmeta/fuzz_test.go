// SPDX-License-Identifier: MPL-2.0

package requestmeta

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func FuzzForwardedChain(f *testing.F) {
	f.Add("203.0.113.1, 127.0.0.2")
	f.Add("not-an-address")
	f.Fuzz(func(t *testing.T, forwarded string) {
		if len(forwarded) > 8192 {
			t.Skip()
		}
		resolver, _ := New(Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Random: zeroReader{}})
		request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		request.RemoteAddr = "127.0.0.1:1234"
		request.Header.Set("X-Forwarded-For", forwarded)
		metadata, err := resolver.Resolve(request)
		if err == nil && !metadata.ClientIP.IsValid() {
			t.Fatal("successful resolution returned invalid client")
		}
	})
}

type zeroReader struct{}

func (zeroReader) Read(body []byte) (int, error) { clear(body); return len(body), nil }
