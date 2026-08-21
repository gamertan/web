// SPDX-License-Identifier: MPL-2.0

package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gamertan.com/web/authwebauthn"
)

func TestPasskeyJSONBoundary(t *testing.T) {
	result := authwebauthn.BeginResult{CeremonyToken: strings.Repeat("a", 43), PublicKey: []byte(`{"challenge":"example"}`), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	recorder := httptest.NewRecorder()
	if err := WritePasskeyBegin(recorder, result); err != nil {
		t.Fatal(err)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("headers=%v", recorder.Header())
	}

	request := httptest.NewRequest(http.MethodPost, "https://tend.gamertan.com/passkey/finish", strings.NewReader(`{"ceremony_token":"`+strings.Repeat("b", 43)+`","credential":{"id":"x"}}`))
	request.Header.Set("Content-Type", "application/json")
	finish, err := ReadPasskeyFinish(request)
	if err != nil {
		t.Fatal(err)
	}
	if finish.CeremonyToken == "" || string(finish.Credential) != `{"id":"x"}` {
		t.Fatalf("finish=%+v", finish)
	}
}

func TestPasskeyJSONRejectsWrongMethodUnknownFieldsAndOversize(t *testing.T) {
	for name, request := range map[string]*http.Request{
		"method":  httptest.NewRequest(http.MethodGet, "https://tend.gamertan.com/", nil),
		"unknown": httptest.NewRequest(http.MethodPost, "https://tend.gamertan.com/", strings.NewReader(`{"ceremony_token":"`+strings.Repeat("b", 43)+`","credential":{},"extra":true}`)),
		"large":   httptest.NewRequest(http.MethodPost, "https://tend.gamertan.com/", strings.NewReader(strings.Repeat("x", maxPasskeyBodyBytes+1))),
	} {
		t.Run(name, func(t *testing.T) {
			request.Header.Set("Content-Type", "application/json")
			if _, err := ReadPasskeyFinish(request); err == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
}
