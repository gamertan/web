// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestPasswordRoundTripAndBounds(t *testing.T) {
	hash, err := HashPasswordWithRandom("correct horse battery staple", strings.NewReader(strings.Repeat("s", 16)))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") || VerifyPassword(hash, "wrong password") {
		t.Fatal("password verification mismatch")
	}
	if err = ValidatePassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestPasswordEntropyFailsClosed(t *testing.T) {
	_, err := HashPasswordWithRandom("correct horse battery staple", errorReader{})
	if err == nil {
		t.Fatal("entropy failure accepted")
	}
}

func TestTemporaryPasswordUsesBoundedCryptographicEntropy(t *testing.T) {
	password, err := GenerateTemporaryPassword(strings.NewReader(strings.Repeat("t", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 43 || ValidatePassword(password) != nil || strings.ContainsAny(password, " \t\r\n") {
		t.Fatalf("temporary password length=%d", len(password))
	}
	if _, err = GenerateTemporaryPassword(errorReader{}); err == nil {
		t.Fatal("temporary password accepted entropy failure")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }
