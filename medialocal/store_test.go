// SPDX-License-Identifier: MPL-2.0

package medialocal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gamertan.com/web/media"
)

func TestStoreRoundTripAndIdempotentPut(t *testing.T) {
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	store, err := Open(filepath.Join(t.TempDir(), "media"), Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	prefix := []byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	pdf := append(prefix, []byte(fmt.Sprintf("xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(prefix)))...)
	prepared, err := media.Prepare(bytes.NewReader(pdf), "fixture.pdf", media.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Put(t.Context(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Put(t.Context(), prepared)
	if err != nil || second.Key != first.Key || second.Size != first.Size {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	reader, object, err := store.Open(t.Context(), first.Key)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(data, prepared.Data) || object.Size != int64(len(data)) {
		t.Fatalf("round trip object=%+v read=%v close=%v", object, readErr, closeErr)
	}
	if err = store.Delete(t.Context(), first.Key); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Open(t.Context(), first.Key); !errors.Is(err, media.ErrNotFound) {
		t.Fatalf("missing err=%v", err)
	}
}

func TestOpenRejectsSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, Options{}); err == nil {
		t.Fatal("symlink root accepted")
	}
}
