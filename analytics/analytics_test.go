// SPDX-License-Identifier: MPL-2.0

package analytics

import (
	"strings"
	"testing"
	"time"

	"gamertan.com/web/requestlog"
)

func TestSafeProjectionExcludesOperatorAndSensitiveEvidence(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	records := []requestlog.Record{
		{Version: 1, Timestamp: now, Method: "GET", Route: "home", Status: 200, Bytes: 100, DurationMicros: 10, ClientIP: "private", Query: "secret"},
		{Version: 1, Timestamp: now, Method: "GET", Route: "admin.analytics", Status: 200, Bytes: 200, DurationMicros: 20, ClientIP: "operator"},
		{Version: 1, Timestamp: now, Method: "GET", Route: "home", Status: 500, Bytes: 50, DurationMicros: 30},
	}
	classifier := func(record requestlog.Record) TrafficClass {
		if strings.HasPrefix(record.Route, "admin.") {
			return Operator
		}
		return Public
	}
	report, err := Safe(records, Query{Classify: classifier})
	if err != nil {
		t.Fatal(err)
	}
	if report.Requests != 2 || report.Errors != 1 || report.Bytes != 150 || len(report.Routes) != 1 {
		t.Fatalf("report=%+v", report)
	}
	sensitive, err := Sensitive(records, Query{Classify: classifier, IncludeOperator: true})
	if err != nil {
		t.Fatal(err)
	}
	if sensitive.Safe.Requests != 3 || len(sensitive.Recent) != 3 || sensitive.Recent[0].ClientIP != "private" {
		t.Fatalf("sensitive=%+v", sensitive)
	}
}

func TestReadJSONLFailsClosed(t *testing.T) {
	if _, err := ReadJSONL(strings.NewReader("{not json}\n"), 10); err == nil {
		t.Fatal("malformed record accepted")
	}
	if _, err := ReadJSONL(strings.NewReader(`{"version":99}`+"\n"), 10); err == nil {
		t.Fatal("unsupported record accepted")
	}
}

func TestSafeRejectsInvalidTimeRange(t *testing.T) {
	now := time.Unix(100, 0)
	if _, err := Safe(nil, Query{From: now, Until: now}); err == nil {
		t.Fatal("empty time range accepted")
	}
}
