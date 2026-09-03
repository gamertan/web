// SPDX-License-Identifier: MPL-2.0

package media

import (
	"bytes"
	"errors"
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
	prepared, err := Prepare(strings.NewReader("%PDF-1.7\nsmall fixture"), "guide.pdf", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Kind != KindAttachment || prepared.MediaType != "application/pdf" {
		t.Fatalf("prepared=%+v", prepared)
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
