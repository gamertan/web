// SPDX-License-Identifier: MPL-2.0

// Package media defines bounded media preparation and storage-neutral blob
// interfaces. Applications retain authorization, references, lifecycle, and
// presentation policy.
package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	KindImage      = "image"
	KindAttachment = "attachment"
)

var (
	ErrInvalidMedia = errors.New("media: invalid media")
	ErrTooLarge     = errors.New("media: upload exceeds its size limit")
	ErrNotFound     = errors.New("media: object not found")
)

type Limits struct {
	MaxBytes  int64
	MaxWidth  int
	MaxHeight int
	MaxPixels int64
}

func (limits Limits) withDefaults() Limits {
	if limits.MaxBytes == 0 {
		limits.MaxBytes = 10 << 20
	}
	if limits.MaxWidth == 0 {
		limits.MaxWidth = 8192
	}
	if limits.MaxHeight == 0 {
		limits.MaxHeight = 8192
	}
	if limits.MaxPixels == 0 {
		limits.MaxPixels = 40_000_000
	}
	return limits
}

func (limits Limits) validate() error {
	if limits.MaxBytes < 1024 || limits.MaxBytes > 100<<20 || limits.MaxWidth < 1 || limits.MaxWidth > 32768 || limits.MaxHeight < 1 || limits.MaxHeight > 32768 || limits.MaxPixels < 1 || limits.MaxPixels > 250_000_000 {
		return errors.New("media: invalid limits")
	}
	return nil
}

// Prepared is a sanitized, bounded object ready for durable storage. Raster
// images are decoded and re-encoded so source metadata and unparsed trailing
// bytes are not retained. PDFs are attachments and are never inline media.
type Prepared struct {
	Digest       [32]byte
	Data         []byte
	MediaType    string
	Kind         string
	OriginalName string
	Width        int
	Height       int
}

func (prepared Prepared) Key() string { return hex.EncodeToString(prepared.Digest[:]) }

type Object struct {
	Key       string
	Size      int64
	MediaType string
	CreatedAt time.Time
}

type Store interface {
	Put(context.Context, Prepared) (Object, error)
	Open(context.Context, string) (io.ReadCloser, Object, error)
	Delete(context.Context, string) error
}

// Prepare reads at most the configured bound and accepts JPEG, PNG, GIF, or a
// PDF attachment. Animated images are deliberately flattened to the decoded
// first frame. The returned byte slice is owned by the caller.
func Prepare(reader io.Reader, originalName string, limits Limits) (Prepared, error) {
	if reader == nil {
		return Prepared{}, ErrInvalidMedia
	}
	limits = limits.withDefaults()
	if err := limits.validate(); err != nil {
		return Prepared{}, err
	}
	name, err := boundedName(originalName)
	if err != nil {
		return Prepared{}, err
	}
	data, err := io.ReadAll(io.LimitReader(reader, limits.MaxBytes+1))
	if err != nil {
		return Prepared{}, fmt.Errorf("media: read upload: %w", err)
	}
	if int64(len(data)) > limits.MaxBytes {
		return Prepared{}, ErrTooLarge
	}
	if len(data) == 0 {
		return Prepared{}, ErrInvalidMedia
	}

	detected := http.DetectContentType(data)
	if detected == "application/pdf" && bytes.HasPrefix(data, []byte("%PDF-")) {
		result := Prepared{Data: append([]byte(nil), data...), MediaType: "application/pdf", Kind: KindAttachment, OriginalName: name}
		result.Digest = sha256.Sum256(result.Data)
		return result, nil
	}

	imageValue, format, err := image.Decode(bytes.NewReader(data))
	if err != nil || format != "jpeg" && format != "png" && format != "gif" {
		return Prepared{}, ErrInvalidMedia
	}
	bounds := imageValue.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width < 1 || height < 1 || width > limits.MaxWidth || height > limits.MaxHeight || int64(width) > limits.MaxPixels/int64(height) {
		return Prepared{}, ErrTooLarge
	}

	var output bytes.Buffer
	mediaType := "image/png"
	if format == "jpeg" {
		mediaType = "image/jpeg"
		err = jpeg.Encode(&output, imageValue, &jpeg.Options{Quality: 90})
	} else {
		err = png.Encode(&output, imageValue)
	}
	if err != nil {
		return Prepared{}, fmt.Errorf("media: sanitize image: %w", err)
	}
	if int64(output.Len()) > limits.MaxBytes {
		return Prepared{}, ErrTooLarge
	}
	result := Prepared{Data: output.Bytes(), MediaType: mediaType, Kind: KindImage, OriginalName: name, Width: width, Height: height}
	result.Digest = sha256.Sum256(result.Data)
	return result, nil
}

func Extension(mediaType string) string {
	switch mediaType {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "application/pdf":
		return ".pdf"
	default:
		values, _ := mime.ExtensionsByType(mediaType)
		if len(values) > 0 {
			return values[0]
		}
		return ""
	}
}

func ValidKey(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func boundedName(value string) (string, error) {
	value = strings.TrimSpace(filepath.Base(value))
	if value == "." || value == "" || !utf8.ValidString(value) || len(value) > 240 || strings.ContainsAny(value, "\x00\r\n") {
		return "", ErrInvalidMedia
	}
	return value, nil
}
