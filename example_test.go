// SPDX-License-Identifier: MPL-2.0

package web_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"gamertan.com/web/requestlog"
	"gamertan.com/web/requestmeta"
	"gamertan.com/web/websec"
)

func Example() {
	resolver, err := requestmeta.New(requestmeta.Config{})
	if err != nil {
		panic(err)
	}

	router := http.NewServeMux()
	router.HandleFunc("GET /", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})

	var handler http.Handler = router
	handler = requestlog.Middleware(nil, requestlog.Policy{
		Route: func(*http.Request) string { return "home" },
	})(handler)
	handler = websec.Headers(func(*http.Request) websec.HeaderPolicy {
		return websec.HeaderPolicy{
			ContentSecurityPolicy: "default-src 'none'; frame-ancestors 'none'",
			ReferrerPolicy:        "no-referrer",
			FrameOptions:          "DENY",
		}
	})(handler)
	handler = resolver.Middleware(handler)

	request := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	request.RemoteAddr = "192.0.2.10:43120"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	fmt.Println(response.Code)
	fmt.Println(response.Header().Get("X-Request-ID") != "")
	fmt.Println(response.Header().Get("X-Content-Type-Options"))
	// Output:
	// 204
	// true
	// nosniff
}
