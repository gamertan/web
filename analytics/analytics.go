// SPDX-License-Identifier: MPL-2.0

// Package analytics produces bounded typed projections from requestlog records.
// It does not expose HTTP routes or decide who may view sensitive evidence.
package analytics

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"gamertan.com/web/requestlog"
)

type TrafficClass string

const (
	Public    TrafficClass = "public"
	Operator  TrafficClass = "operator"
	Health    TrafficClass = "health"
	Automated TrafficClass = "automated"
)

type Classifier func(requestlog.Record) TrafficClass

type Query struct {
	From, Until     time.Time
	IncludeOperator bool
	MaxRecords      int
	Classify        Classifier
}

type RouteSummary struct {
	Route          string `json:"route"`
	Requests       int    `json:"requests"`
	Errors         int    `json:"errors"`
	Bytes          int64  `json:"bytes"`
	DurationMicros int64  `json:"duration_micros"`
}
type StatusSummary struct {
	Status   int `json:"status"`
	Requests int `json:"requests"`
}

type SafeReport struct {
	From, Until                     time.Time
	Requests, Errors                int
	Bytes                           int64
	P50Micros, P95Micros, P99Micros int64
	Routes                          []RouteSummary
	Statuses                        []StatusSummary
	Truncated                       bool
}

type SensitiveRecord struct {
	Timestamp                                                       time.Time
	RequestID, ClientIP, Path, Query, Referer, UserAgent, SessionID string
	Status                                                          int
	DurationMicros                                                  int64
}
type SensitiveReport struct {
	Safe   SafeReport
	Recent []SensitiveRecord
}

func Safe(records []requestlog.Record, query Query) (SafeReport, error) {
	report, _, err := aggregate(records, query, false)
	return report, err
}
func Sensitive(records []requestlog.Record, query Query) (SensitiveReport, error) {
	safe, recent, err := aggregate(records, query, true)
	return SensitiveReport{Safe: safe, Recent: recent}, err
}

func aggregate(records []requestlog.Record, query Query, includeSensitive bool) (SafeReport, []SensitiveRecord, error) {
	if query.MaxRecords == 0 {
		query.MaxRecords = 100000
	}
	if query.MaxRecords < 1 || query.MaxRecords > 1000000 {
		return SafeReport{}, nil, errors.New("analytics: invalid record limit")
	}
	if !query.From.IsZero() && !query.Until.IsZero() && !query.From.Before(query.Until) {
		return SafeReport{}, nil, errors.New("analytics: invalid time range")
	}
	report := SafeReport{From: query.From.UTC(), Until: query.Until.UTC()}
	routeMap := map[string]*RouteSummary{}
	statusMap := map[int]int{}
	durations := make([]int64, 0, min(len(records), query.MaxRecords))
	recent := make([]SensitiveRecord, 0, 100)
	processed := 0
	for _, record := range records {
		if err := record.Validate(); err != nil {
			return SafeReport{}, nil, errors.New("analytics: invalid request record")
		}
		if !query.From.IsZero() && record.Timestamp.Before(query.From) || !query.Until.IsZero() && !record.Timestamp.Before(query.Until) {
			continue
		}
		class := Public
		if query.Classify != nil {
			class = query.Classify(record)
		}
		if class == Health || class == Operator && !query.IncludeOperator {
			continue
		}
		if processed >= query.MaxRecords {
			report.Truncated = true
			break
		}
		processed++
		report.Requests++
		report.Bytes += record.Bytes
		if record.Status >= 400 {
			report.Errors++
		}
		statusMap[record.Status]++
		route := routeMap[record.Route]
		if route == nil {
			route = &RouteSummary{Route: record.Route}
			routeMap[record.Route] = route
		}
		route.Requests++
		route.Bytes += record.Bytes
		route.DurationMicros += record.DurationMicros
		if record.Status >= 400 {
			route.Errors++
		}
		durations = append(durations, record.DurationMicros)
		if includeSensitive {
			recent = append(recent, SensitiveRecord{Timestamp: record.Timestamp, RequestID: record.RequestID, ClientIP: record.ClientIP, Path: record.Path, Query: record.Query, Referer: record.Referer, UserAgent: record.UserAgent, SessionID: record.SessionID, Status: record.Status, DurationMicros: record.DurationMicros})
			if len(recent) > 100 {
				recent = recent[len(recent)-100:]
			}
		}
	}
	for _, route := range routeMap {
		report.Routes = append(report.Routes, *route)
	}
	sort.Slice(report.Routes, func(i, j int) bool {
		if report.Routes[i].Requests == report.Routes[j].Requests {
			return report.Routes[i].Route < report.Routes[j].Route
		}
		return report.Routes[i].Requests > report.Routes[j].Requests
	})
	for status, count := range statusMap {
		report.Statuses = append(report.Statuses, StatusSummary{Status: status, Requests: count})
	}
	sort.Slice(report.Statuses, func(i, j int) bool { return report.Statuses[i].Status < report.Statuses[j].Status })
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	report.P50Micros = percentile(durations, 50)
	report.P95Micros = percentile(durations, 95)
	report.P99Micros = percentile(durations, 99)
	return report, recent, nil
}

func ReadJSONL(reader io.Reader, maxRecords int) ([]requestlog.Record, error) {
	if maxRecords < 1 || maxRecords > 1000000 {
		return nil, errors.New("analytics: invalid record limit")
	}
	scanner := bufio.NewScanner(io.LimitReader(reader, 1<<30))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	records := make([]requestlog.Record, 0, min(maxRecords, 4096))
	for scanner.Scan() {
		if len(records) >= maxRecords {
			return nil, errors.New("analytics: record limit exceeded")
		}
		var record requestlog.Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, errors.New("analytics: invalid JSONL record")
		}
		if err := record.Validate(); err != nil {
			return nil, errors.New("analytics: invalid JSONL record")
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func percentile(values []int64, percent int) int64 {
	if len(values) == 0 {
		return 0
	}
	index := (len(values)*percent+99)/100 - 1
	if index < 0 {
		index = 0
	}
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}
