// SPDX-License-Identifier: MPL-2.0

package requestlog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gamertan.com/web/requestmeta"
)

type memorySink struct {
	records []Record
	err     error
	ctxErr  error
}

func (sink *memorySink) WriteRecord(ctx context.Context, record Record) error {
	sink.records = append(sink.records, record)
	sink.ctxErr = ctx.Err()
	return sink.err
}

func TestSafePolicyOmitsSensitiveFields(t *testing.T) {
	resolver, _ := requestmeta.New(requestmeta.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Random: strings.NewReader(strings.Repeat("a", 16))})
	sink := &memorySink{}
	now := time.Unix(100, 0)
	handler := resolver.Middleware(Middleware(sink, Policy{Route: func(*http.Request) string { return "item.show" }, Now: func() time.Time { now = now.Add(time.Millisecond); return now }})(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte("ok"))
	})))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/private?id=secret", nil)
	request.RemoteAddr = "127.0.0.1:1000"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Header.Set("User-Agent", "private-agent")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if len(sink.records) != 1 {
		t.Fatalf("records=%d", len(sink.records))
	}
	record := sink.records[0]
	if record.Route != "item.show" || record.Status != 201 || record.Bytes != 2 || record.RequestID == "" {
		t.Fatalf("record=%+v", record)
	}
	if record.ClientIP != "" || record.Path != "" || record.Query != "" || record.UserAgent != "" {
		t.Fatalf("sensitive leak: %+v", record)
	}
}

func TestSensitivePolicyIsExplicitAndBounded(t *testing.T) {
	sink := &memorySink{}
	handler := Middleware(sink, Policy{Sensitive: SensitiveFields{Path: true, Query: true, Referer: true, UserAgent: true, SessionID: true}, SessionID: func(*http.Request) string { return "session" }})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/path?q=value", nil)
	request.Header.Set("Referer", "https://ref.example/")
	request.Header.Set("User-Agent", "browser")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	record := sink.records[0]
	if record.Path != "/path" || record.Query != "q=value" || record.Referer == "" || record.UserAgent != "browser" || record.SessionID != "session" {
		t.Fatalf("record=%+v", record)
	}
}

func TestJSONLRoundTripAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.jsonl")
	sink, err := OpenJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = sink.WriteRecord(context.Background(), Record{Version: 1, Timestamp: time.Unix(100, 0), Method: "GET", Route: "home", Status: 200}); err != nil {
		t.Fatal(err)
	}
	if err = sink.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record Record
	if err = json.Unmarshal([]byte(strings.TrimSpace(string(body))), &record); err != nil {
		t.Fatal(err)
	}
	if record.Route != "home" || record.Version != 1 {
		t.Fatalf("record=%+v", record)
	}
}

func TestJSONLAllowsExplicitCollectorGroupRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.jsonl")
	sink, err := OpenJSONLWithOptions(path, JSONLOptions{FileMode: 0o640})
	if err != nil {
		t.Fatal(err)
	}
	if err = sink.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o640 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestJSONLRejectsOverlyPermissiveMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o620, 0o644, 0o660, 0o666} {
		path := filepath.Join(t.TempDir(), "access.jsonl")
		if _, err := OpenJSONLWithOptions(path, JSONLOptions{FileMode: mode}); err == nil {
			t.Fatalf("accepted mode %o", mode)
		}
	}
}

func TestPanicIsRecordedAndRepanicked(t *testing.T) {
	sink := &memorySink{}
	handler := Middleware(sink, Policy{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("expected") }))
	defer func() {
		if recover() == nil {
			t.Fatal("panic was swallowed")
		}
		if len(sink.records) != 1 || sink.records[0].Status != http.StatusInternalServerError {
			t.Fatalf("records=%+v", sink.records)
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
}

func TestCanceledRequestStillRecordsEvidence(t *testing.T) {
	sink := &memorySink{}
	handler := Middleware(sink, Policy{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	handler.ServeHTTP(httptest.NewRecorder(), request.WithContext(ctx))
	if len(sink.records) != 1 || sink.ctxErr != nil {
		t.Fatalf("records=%d ctxErr=%v", len(sink.records), sink.ctxErr)
	}
}

func TestJSONLRejectsInvalidRecord(t *testing.T) {
	sink, err := OpenJSONL(filepath.Join(t.TempDir(), "access.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err = sink.WriteRecord(context.Background(), Record{Version: 99}); err == nil {
		t.Fatal("invalid record accepted")
	}
}

func TestRecordRejectsUnboundedNumericFields(t *testing.T) {
	base := Record{Version: RecordVersion, Timestamp: time.Unix(100, 0), Method: "GET", Route: "home", Status: 200}
	tooManyBytes := base
	tooManyBytes.Bytes = maxRecordBytes + 1
	if err := tooManyBytes.Validate(); err == nil {
		t.Fatal("unbounded byte count accepted")
	}
	tooLong := base
	tooLong.DurationMicros = maxRecordDurationMicros + 1
	if err := tooLong.Validate(); err == nil {
		t.Fatal("unbounded duration accepted")
	}
}

func TestJSONLRejectsSymlinkDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privilege-dependent on Windows")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "access.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJSONL(link); err == nil {
		t.Fatal("symlink destination accepted")
	}
}

func TestResponseStatusUsesFirstHeader(t *testing.T) {
	sink := &memorySink{}
	handler := Middleware(sink, Policy{})(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
		response.WriteHeader(http.StatusInternalServerError)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	if sink.records[0].Status != http.StatusNoContent {
		t.Fatalf("status=%d", sink.records[0].Status)
	}
}
