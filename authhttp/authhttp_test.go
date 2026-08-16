// SPDX-License-Identifier: MPL-2.0

package authhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gamertan.com/web/auth"
)

func TestSessionCookieContract(t *testing.T) {
	config := CookieConfig{Name: "__Host-app_session", Lifetime: time.Hour, SameSite: http.SameSiteStrictMode}
	response := httptest.NewRecorder()
	if err := SetSession(response, config, strings.Repeat("x", 43), time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie=%+v", cookie)
	}
}

func TestCookieRequiresHostPrefix(t *testing.T) {
	if err := (CookieConfig{Name: "session", Lifetime: time.Hour}).Validate(); err == nil {
		t.Fatal("weak cookie name accepted")
	}
}

func TestCSRFUsesSessionAndPurpose(t *testing.T) {
	token := strings.Repeat("s", 43)
	csrf, err := CSRFToken(token, "profile:update")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCSRF(token, "profile:update", csrf) || VerifyCSRF(token, "profile:delete", csrf) {
		t.Fatal("csrf binding failed")
	}
}

func TestOptionalFailsClosedWhenSessionStorageIsUnavailable(t *testing.T) {
	service, err := auth.New(authHTTPRepository{err: errors.New("storage offline")}, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	config := CookieConfig{Name: "__Host-app_session", Lifetime: time.Hour}
	handler := Optional(service, config)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler ran while authentication state was unknown")
	}))
	request := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	request.AddCookie(&http.Cookie{Name: config.Name, Value: strings.Repeat("x", 43)})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}
}

type authHTTPRepository struct{ err error }

func (authHTTPRepository) CreateUser(context.Context, auth.User, string) error { return nil }
func (authHTTPRepository) CredentialByIdentifier(context.Context, string) (auth.User, string, error) {
	return auth.User{}, "", auth.ErrUserNotFound
}
func (authHTTPRepository) UpdateLastLogin(context.Context, string, time.Time) error { return nil }
func (authHTTPRepository) CreateSession(context.Context, auth.Session) error        { return nil }
func (repository authHTTPRepository) PrincipalBySession(context.Context, [32]byte, time.Time) (auth.Principal, auth.Session, error) {
	return auth.Principal{}, auth.Session{}, repository.err
}
func (authHTTPRepository) TouchSession(context.Context, [32]byte, time.Time) error { return nil }
func (authHTTPRepository) DeleteSession(context.Context, [32]byte) error           { return nil }
func (authHTTPRepository) RevokeUserSessions(context.Context, string) error        { return nil }
func (authHTTPRepository) SeedPolicy(context.Context, auth.PolicySeed) error       { return nil }
func (authHTTPRepository) GrantRole(context.Context, string, string, time.Time) error {
	return nil
}
func (authHTTPRepository) AppendAudit(context.Context, auth.AuditEvent) error { return nil }
