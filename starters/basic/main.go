// SPDX-License-Identifier: 0BSD

package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"gamertan.com/web/requestlog"
	"gamertan.com/web/requestmeta"
	"gamertan.com/web/websec"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "loopback listen address")
	logPath := flag.String("request-log", "", "optional absolute private JSONL path")
	flag.Parse()

	resolver, err := requestmeta.New(requestmeta.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}})
	if err != nil {
		log.Fatal(err)
	}

	var sink requestlog.Sink
	var jsonl *requestlog.JSONL
	if *logPath != "" {
		jsonl, err = requestlog.OpenJSONL(*logPath)
		if err != nil {
			log.Fatal(err)
		}
		defer jsonl.Close()
		sink = jsonl
	}

	router := http.NewServeMux()
	router.HandleFunc("GET /", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = response.Write([]byte("hello from Gamertan Web Foundations\n"))
	})
	router.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = response.Write([]byte("ok\n"))
	})

	var handler http.Handler = router
	handler = requestlog.Middleware(sink, requestlog.Policy{Route: func(request *http.Request) string {
		if request.URL.Path == "/healthz" {
			return "health"
		}
		return "home"
	}, OnSinkError: func(error) { log.Print("request log unavailable") }})(handler)
	handler = websec.Headers(func(*http.Request) websec.HeaderPolicy {
		return websec.HeaderPolicy{ContentSecurityPolicy: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'", ReferrerPolicy: "no-referrer", FrameOptions: "DENY"}
	})(handler)
	handler = resolver.Middleware(handler)

	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
