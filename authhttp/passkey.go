// SPDX-License-Identifier: MPL-2.0

package authhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"gamertan.com/web/authwebauthn"
)

const maxPasskeyBodyBytes = 160 << 10

type PasskeyFinish struct {
	CeremonyToken string          `json:"ceremony_token"`
	Credential    json.RawMessage `json:"credential"`
}

func WritePasskeyBegin(response http.ResponseWriter, result authwebauthn.BeginResult) error {
	if len(result.CeremonyToken) < 32 || len(result.PublicKey) == 0 || !json.Valid(result.PublicKey) || result.ExpiresAt.IsZero() {
		return errors.New("authhttp: invalid passkey ceremony")
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	encoder := json.NewEncoder(response)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(result)
}

func ReadPasskeyFinish(request *http.Request) (PasskeyFinish, error) {
	if request == nil || request.Method != http.MethodPost {
		return PasskeyFinish{}, errors.New("authhttp: passkey response requires POST")
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return PasskeyFinish{}, errors.New("authhttp: passkey response requires application/json")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxPasskeyBodyBytes+1))
	if err != nil || len(body) > maxPasskeyBodyBytes {
		return PasskeyFinish{}, errors.New("authhttp: invalid passkey response")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var input PasskeyFinish
	if err = decoder.Decode(&input); err != nil {
		return PasskeyFinish{}, errors.New("authhttp: invalid passkey response")
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PasskeyFinish{}, errors.New("authhttp: passkey response contains trailing data")
	}
	input.CeremonyToken = strings.TrimSpace(input.CeremonyToken)
	input.Credential = bytes.TrimSpace(input.Credential)
	if len(input.CeremonyToken) < 32 || len(input.CeremonyToken) > 128 || len(input.Credential) == 0 || len(input.Credential) > maxPasskeyBodyBytes || !json.Valid(input.Credential) {
		return PasskeyFinish{}, errors.New("authhttp: invalid passkey response")
	}
	return input, nil
}
