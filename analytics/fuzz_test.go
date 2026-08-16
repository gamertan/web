// SPDX-License-Identifier: MPL-2.0

package analytics

import (
	"bytes"
	"testing"
)

func FuzzJSONL(f *testing.F) {
	f.Add([]byte(`{"version":1,"timestamp":"2026-01-01T00:00:00Z","method":"GET","route":"home","status":200}` + "\n"))
	f.Add([]byte("{bad}\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			t.Skip()
		}
		records, err := ReadJSONL(bytes.NewReader(body), 100)
		if err == nil && len(records) > 100 {
			t.Fatal("record bound exceeded")
		}
	})
}
