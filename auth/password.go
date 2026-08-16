// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	passwordMemory  = 32 * 1024
	passwordTime    = 3
	passwordThreads = 1
	passwordKeyLen  = 32
	passwordSaltLen = 16
)

func ValidatePassword(password string) error {
	if len(password) < 12 {
		return errors.New("auth: password must contain at least 12 characters")
	}
	if len(password) > 1024 {
		return errors.New("auth: password is too long")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	return HashPasswordWithRandom(password, rand.Reader)
}

func HashPasswordWithRandom(password string, random io.Reader) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	if random == nil {
		return "", errors.New("auth: password entropy source is nil")
	}
	salt := make([]byte, passwordSaltLen)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", fmt.Errorf("auth: generate password salt: %w", err)
	}
	return encodePassword(password, salt, passwordTime, passwordMemory, passwordThreads, passwordKeyLen), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	parameters := map[string]uint64{}
	for _, value := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(value, "=", 2)
		if len(pair) != 2 {
			return false
		}
		parsed, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil {
			return false
		}
		parameters[pair[0]] = parsed
	}
	memory, iterations, threads := parameters["m"], parameters["t"], parameters["p"]
	if len(parameters) != 3 || memory < 8*1024 || memory > 256*1024 || iterations < 1 || iterations > 10 || threads < 1 || threads > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func encodePassword(password string, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) string {
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, threads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash))
}

var dummyPasswordHash = encodePassword("this-account-does-not-exist", []byte("gamertan-web-dummy-salt"), passwordTime, passwordMemory, passwordThreads, passwordKeyLen)
