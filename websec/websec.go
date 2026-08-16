// SPDX-License-Identifier: MPL-2.0

// Package websec supplies small browser and HTTP security primitives without
// taking ownership of application routes or authorization policy.
package websec

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"gamertan.com/web/requestmeta"
)

type HeaderPolicy struct {
	ContentSecurityPolicy string
	ReferrerPolicy        string
	FrameOptions          string
	PermissionsPolicy     string
	HSTS                  string
}

func Headers(policy func(*http.Request) HeaderPolicy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			selected := HeaderPolicy{}
			if policy != nil {
				selected = policy(request)
			}
			header := response.Header()
			header.Set("X-Content-Type-Options", "nosniff")
			if selected.ContentSecurityPolicy != "" {
				header.Set("Content-Security-Policy", selected.ContentSecurityPolicy)
			}
			if selected.ReferrerPolicy != "" {
				header.Set("Referrer-Policy", selected.ReferrerPolicy)
			}
			if selected.FrameOptions != "" {
				header.Set("X-Frame-Options", selected.FrameOptions)
			}
			if selected.PermissionsPolicy != "" {
				header.Set("Permissions-Policy", selected.PermissionsPolicy)
			}
			if selected.HSTS != "" {
				header.Set("Strict-Transport-Security", selected.HSTS)
			}
			next.ServeHTTP(response, request)
		})
	}
}

func IsHTTPS(request *http.Request) bool {
	if metadata, ok := requestmeta.FromContext(request.Context()); ok {
		return metadata.Scheme == "https"
	}
	return request.TLS != nil
}

func RequireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !IsHTTPS(request) {
			response.Header().Set("Cache-Control", "no-store")
			http.Error(response, "HTTPS required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(response, request)
	})
}

// SameOrigin accepts browser requests that are demonstrably same-origin. It
// rejects contradictory fetch metadata even when Origin is absent.
func SameOrigin(request *http.Request, allowedOrigin string) bool {
	if site := strings.ToLower(strings.TrimSpace(request.Header.Get("Sec-Fetch-Site"))); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	want, err := url.Parse(allowedOrigin)
	if err != nil || want.Scheme == "" || want.Host == "" || want.Path != "" {
		return false
	}
	got, err := url.Parse(origin)
	return err == nil && strings.EqualFold(got.Scheme, want.Scheme) && strings.EqualFold(got.Host, want.Host) && got.Path == "" && got.RawQuery == "" && got.Fragment == ""
}

// CSRFToken binds a purpose to opaque session secret material.
func CSRFToken(sessionSecret []byte, purpose string) (string, error) {
	if len(sessionSecret) < 16 || purpose == "" || len(purpose) > 128 || strings.ContainsAny(purpose, "\x00\r\n") {
		return "", errors.New("websec: invalid CSRF input")
	}
	mac := hmac.New(sha256.New, sessionSecret)
	_, _ = io.WriteString(mac, purpose)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifyCSRF(sessionSecret []byte, purpose, candidate string) bool {
	want, err := CSRFToken(sessionSecret, purpose)
	if err != nil || len(candidate) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(want)) == 1
}

func SafeLocalRedirect(value, fallback string) string {
	if !safePath(fallback) {
		fallback = "/"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !safePath(parsed.Path) || strings.HasPrefix(value, "//") || parsed.User != nil {
		return fallback
	}
	return parsed.RequestURI()
}

func safePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && !strings.ContainsAny(value, "\x00\r\n\\")
}

func LimitBody(response http.ResponseWriter, request *http.Request, bytes int64) error {
	if bytes <= 0 {
		return errors.New("websec: body limit must be positive")
	}
	request.Body = http.MaxBytesReader(response, request.Body, bytes)
	return nil
}
