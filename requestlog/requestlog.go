// SPDX-License-Identifier: MPL-2.0

// Package requestlog records bounded, versioned HTTP request observations.
package requestlog

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"gamertan.com/web/requestmeta"
)

const RecordVersion = 1

const (
	maxRecordBytes          int64 = 1 << 40
	maxRecordDurationMicros int64 = int64((7 * 24 * time.Hour) / time.Microsecond)
)

// Record is deliberately stable and append-log friendly. Sensitive fields are
// populated only when explicitly enabled by Policy.
type Record struct {
	Version        int       `json:"version"`
	Timestamp      time.Time `json:"timestamp"`
	RequestID      string    `json:"request_id,omitempty"`
	Method         string    `json:"method"`
	Route          string    `json:"route"`
	Status         int       `json:"status"`
	Bytes          int64     `json:"bytes"`
	DurationMicros int64     `json:"duration_micros"`
	ClientIP       string    `json:"client_ip,omitempty"`
	Path           string    `json:"path,omitempty"`
	Query          string    `json:"query,omitempty"`
	Referer        string    `json:"referer,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	SessionID      string    `json:"session_id,omitempty"`
}

// Validate rejects records that cannot have been produced by this package's
// bounded middleware contract.
func (record Record) Validate() error {
	if record.Version != RecordVersion || record.Timestamp.IsZero() || !boundedField(record.Method, 16, false) || !boundedField(record.Route, 256, false) || record.Status < 100 || record.Status > 999 || record.Bytes < 0 || record.Bytes > maxRecordBytes || record.DurationMicros < 0 || record.DurationMicros > maxRecordDurationMicros {
		return errors.New("requestlog: invalid record")
	}
	fields := []struct {
		value string
		limit int
	}{
		{record.RequestID, 64}, {record.ClientIP, 64}, {record.Path, 2048},
		{record.Query, 4096}, {record.Referer, 2048}, {record.UserAgent, 1024},
		{record.SessionID, 256},
	}
	for _, field := range fields {
		if !boundedField(field.value, field.limit, true) {
			return errors.New("requestlog: invalid record")
		}
	}
	return nil
}

// Sink receives complete records after a handler returns.
type Sink interface {
	WriteRecord(context.Context, Record) error
}

// SensitiveFields must be opted into field by field.
type SensitiveFields struct {
	ClientIP  bool
	Path      bool
	Query     bool
	Referer   bool
	UserAgent bool
	SessionID bool
}

// Policy controls classification and collection. Route must return a low-cardinality
// route label; nil produces "unclassified" rather than recording a raw path.
type Policy struct {
	Route       func(*http.Request) string
	SessionID   func(*http.Request) string
	Sensitive   SensitiveFields
	OnSinkError func(error)
	Now         func() time.Time
}

func Middleware(sink Sink, policy Policy) func(http.Handler) http.Handler {
	if policy.Now == nil {
		policy.Now = time.Now
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			started := policy.Now()
			capture := &responseCapture{ResponseWriter: response, status: http.StatusOK}
			defer func() {
				recovered := recover()
				if recovered != nil && !capture.wroteHeader {
					capture.status = http.StatusInternalServerError
				}
				record := makeRecord(request, capture, policy, started, policy.Now())
				if sink != nil {
					if err := sink.WriteRecord(context.WithoutCancel(request.Context()), record); err != nil && policy.OnSinkError != nil {
						policy.OnSinkError(errors.New("requestlog: sink write failed"))
					}
				}
				if recovered != nil {
					panic(recovered)
				}
			}()
			next.ServeHTTP(capture, request)
		})
	}
}

func makeRecord(request *http.Request, capture *responseCapture, policy Policy, started, finished time.Time) Record {
	route := "unclassified"
	if policy.Route != nil {
		route = bounded(policy.Route(request), 256)
		if route == "" {
			route = "unclassified"
		}
	}
	duration := finished.Sub(started).Microseconds()
	if duration < 0 {
		duration = 0
	}
	record := Record{Version: RecordVersion, Timestamp: finished.UTC(), Method: bounded(request.Method, 16), Route: route, Status: capture.status, Bytes: capture.bytes, DurationMicros: duration}
	if metadata, ok := requestmeta.FromContext(request.Context()); ok {
		record.RequestID = metadata.RequestID
		if policy.Sensitive.ClientIP && metadata.ClientIP.IsValid() {
			record.ClientIP = metadata.ClientIP.String()
		}
	}
	if policy.Sensitive.Path {
		record.Path = bounded(request.URL.EscapedPath(), 2048)
	}
	if policy.Sensitive.Query {
		record.Query = bounded(request.URL.RawQuery, 4096)
	}
	if policy.Sensitive.Referer {
		record.Referer = bounded(request.Referer(), 2048)
	}
	if policy.Sensitive.UserAgent {
		record.UserAgent = bounded(request.UserAgent(), 1024)
	}
	if policy.Sensitive.SessionID && policy.SessionID != nil {
		record.SessionID = bounded(policy.SessionID(request), 256)
	}
	return record
}

func boundedField(value string, limit int, emptyOK bool) bool {
	if (!emptyOK && value == "") || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' {
			return false
		}
	}
	return true
}

func bounded(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(r rune) rune {
		if r == 0 || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, value)
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

type responseCapture struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (capture *responseCapture) WriteHeader(status int) {
	if capture.wroteHeader {
		return
	}
	capture.wroteHeader = true
	capture.status = status
	capture.ResponseWriter.WriteHeader(status)
}

func (capture *responseCapture) Write(body []byte) (int, error) {
	if !capture.wroteHeader {
		capture.WriteHeader(http.StatusOK)
	}
	written, err := capture.ResponseWriter.Write(body)
	capture.bytes += int64(written)
	return written, err
}

func (capture *responseCapture) Unwrap() http.ResponseWriter { return capture.ResponseWriter }
