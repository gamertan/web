// SPDX-License-Identifier: MPL-2.0

// Package authhttp connects auth sessions to secure browser cookies and
// request context without owning login pages or application routes.
package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"gamertan.com/web/auth"
	"gamertan.com/web/websec"
)

type CookieConfig struct {
	Name     string
	Lifetime time.Duration
	SameSite http.SameSite
}

func (config CookieConfig) Validate() error {
	if !strings.HasPrefix(config.Name, "__Host-") || len(config.Name) > 128 || strings.ContainsAny(config.Name, "\x00\r\n\t ;,") {
		return errors.New("authhttp: cookie name must use the __Host- prefix")
	}
	if config.Lifetime < 5*time.Minute || config.Lifetime > 30*24*time.Hour {
		return errors.New("authhttp: invalid cookie lifetime")
	}
	if config.SameSite == 0 {
		config.SameSite = http.SameSiteLaxMode
	}
	if config.SameSite != http.SameSiteLaxMode && config.SameSite != http.SameSiteStrictMode {
		return errors.New("authhttp: SameSite must be Lax or Strict")
	}
	return nil
}

func SetSession(response http.ResponseWriter, config CookieConfig, token string, now time.Time) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if len(token) < 32 || len(token) > 128 {
		return errors.New("authhttp: invalid session token")
	}
	sameSite := config.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(response, &http.Cookie{Name: config.Name, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: sameSite, Expires: now.UTC().Add(config.Lifetime), MaxAge: int(config.Lifetime.Seconds())})
	return nil
}

func ClearSession(response http.ResponseWriter, config CookieConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	sameSite := config.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(response, &http.Cookie{Name: config.Name, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: sameSite, Expires: time.Unix(1, 0), MaxAge: -1})
	return nil
}

func SessionToken(request *http.Request, config CookieConfig) (string, bool) {
	if config.Validate() != nil {
		return "", false
	}
	cookie, err := request.Cookie(config.Name)
	if err != nil || len(cookie.Value) < 32 || len(cookie.Value) > 128 {
		return "", false
	}
	return cookie.Value, true
}

func Optional(service *auth.Service, config CookieConfig) func(http.Handler) http.Handler {
	configurationValid := service != nil && config.Validate() == nil
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if !configurationValid {
				response.Header().Set("Cache-Control", "no-store")
				http.Error(response, "authentication unavailable", http.StatusServiceUnavailable)
				return
			}
			if token, ok := SessionToken(request, config); ok {
				if principal, err := service.Session(request.Context(), token); err == nil {
					request = request.WithContext(auth.WithPrincipal(request.Context(), principal))
				} else if !errors.Is(err, auth.ErrSessionNotFound) && !errors.Is(err, auth.ErrInactiveUser) {
					response.Header().Set("Cache-Control", "no-store")
					http.Error(response, "authentication unavailable", http.StatusServiceUnavailable)
					return
				}
			}
			next.ServeHTTP(response, request)
		})
	}
}

func Require(permission string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := auth.PrincipalFromContext(request.Context())
		if !ok {
			response.Header().Set("Cache-Control", "no-store")
			http.Error(response, "authentication required", http.StatusUnauthorized)
			return
		}
		if permission != "" && !principal.Has(permission) {
			response.Header().Set("Cache-Control", "no-store")
			http.Error(response, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func CSRFToken(sessionToken, purpose string) (string, error) {
	return websec.CSRFToken([]byte(sessionToken), purpose)
}
func VerifyCSRF(sessionToken, purpose, candidate string) bool {
	return websec.VerifyCSRF([]byte(sessionToken), purpose, candidate)
}
