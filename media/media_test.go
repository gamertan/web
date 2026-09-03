// SPDX-License-Identifier: MPL-2.0

package media

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"strings"
	"testing"
)

func TestPrepareReencodesRasterAndStripsTrailingData(t *testing.T) {
	var source bytes.Buffer
	value := image.NewRGBA(image.Rect(0, 0, 3, 2))
	value.Set(1, 1, color.RGBA{R: 220, G: 20, B: 50, A: 255})
	if err := jpeg.Encode(&source, value, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	source.WriteString("secret trailing metadata")
	prepared, err := Prepare(bytes.NewReader(source.Bytes()), " portrait.jpg ", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Kind != KindImage || prepared.MediaType != "image/jpeg" || prepared.Width != 3 || prepared.Height != 2 || prepared.OriginalName != "portrait.jpg" {
		t.Fatalf("prepared=%+v", prepared)
	}
	if bytes.Contains(prepared.Data, []byte("secret trailing metadata")) || prepared.Key() == strings.Repeat("0", 64) {
		t.Fatal("image source data was not sanitized")
	}
}

func TestPreparePDFIsAttachment(t *testing.T) {
	pdf := minimalPDF()
	prepared, err := Prepare(bytes.NewReader(pdf), "guide.pdf", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Kind != KindAttachment || prepared.MediaType != "application/pdf" {
		t.Fatalf("prepared=%+v", prepared)
	}
}

func TestPrepareRejectsMalformedPDF(t *testing.T) {
	for _, source := range []string{
		"%PDF-1.7\nsmall fixture",
		"%PDF-9.9\nxref\ntrailer\nstartxref\n9\n%%EOF",
		"%PDF-1.7\nxref\ntrailer\nstartxref\n999999\n%%EOF",
	} {
		if _, err := Prepare(strings.NewReader(source), "broken.pdf", Limits{}); !errors.Is(err, ErrInvalidMedia) {
			t.Fatalf("malformed PDF error=%v source=%q", err, source)
		}
	}
}

func TestPrepareRejectsActiveAndOversizedInput(t *testing.T) {
	if _, err := Prepare(strings.NewReader("<svg><script/></svg>"), "bad.svg", Limits{}); !errors.Is(err, ErrInvalidMedia) {
		t.Fatalf("svg err=%v", err)
	}
	if _, err := Prepare(strings.NewReader(strings.Repeat("x", 1025)), "large.png", Limits{MaxBytes: 1024, MaxWidth: 10, MaxHeight: 10, MaxPixels: 100}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("large err=%v", err)
	}
}

func minimalPDF() []byte {
	prefix := []byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	offset := len(prefix)
	return append(prefix, []byte(fmt.Sprintf("xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", offset))...)
}
