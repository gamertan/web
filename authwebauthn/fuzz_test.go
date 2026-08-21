// SPDX-License-Identifier: MPL-2.0

package authwebauthn

import (
	"testing"

	"gamertan.com/web/internal/webauthnvendored/protocol"
)

func FuzzPasskeyResponseParsers(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"id":"credential","rawId":"Y3JlZGVudGlhbA","type":"public-key","response":{}}`))
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > maxResponseBytes {
			t.Skip()
		}
		_, _ = protocol.ParseCredentialCreationResponseBytes(value)
		_, _ = protocol.ParseCredentialRequestResponseBytes(value)
	})
}
