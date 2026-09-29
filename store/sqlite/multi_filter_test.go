package sqlite

import (
	"context"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
)

// filterSeed is one event's filterable fields. The set below mixes every
// category, action, resource, severity and outcome value so each filter has
// events it must keep and events it must drop.
type filterSeed struct {
	category, action, resource, severity, outcome string
}

var filterSeeds = []filterSeed{
	{"auth", "login", "user", audit.SeverityInfo, audit.OutcomeSuccess},
	{"auth", "logout", "user", audit.SeverityInfo, audit.OutcomeSuccess},
	{"auth", "login", "user", audit.SeverityWarning, audit.OutcomeFailure},
	{"billing", "charge", "invoice", audit.SeverityInfo, audit.OutcomeSuccess},
	{"billing", "refund", "invoice", audit.SeverityCritical, audit.OutcomeDenied},
	{"data", "read", "record", audit.SeverityInfo, audit.OutcomeSuccess},
	{"data", "delete", "record", audit.SeverityCritical, audit.OutcomeFailure},
	{"access", "access.grant", "role", audit.SeverityWarning, audit.OutcomeSuccess},
}

var filterBase = time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

// seedFilterEvents appends filterSeeds in order and returns the stored IDs,
// index-aligned with filterSeeds.
func seedFilterEvents(t *testing.T, s *Store) []string {
	t.Helper()
	ctx := context.Background()
	streamID := seedStream(t, s, "app", "")

	ids := make([]string, len(filterSeeds))
	for i, fs := range filterSeeds {
		ev := testEvent(streamID, "app", "", "u1", fs.category, filterBase.Add(time.Duration(i)*time.Second))
		ev.Action = fs.action
		ev.Resource = fs.resource
		ev.Severity = fs.severity
		ev.Outcome = fs.outcome
		if err := s.Append(ctx, ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		ids[i] = ev.ID.String()
	}
	return ids
}

// TestQueryMultiValueFilters runs every multi-value filter with one value and
// with several. Before whereIn, sqlitedriver rejected all of these, the
// single-value case included, with "unsupported type []string". The expected
// set comes from a predicate over the seeds so a hand count can't drift.
func TestQueryMultiValueFilters(t *testing.T) {
	s := newTestStore(t)
	ids := seedFilterEvents(t, s)

	tests := []struct {
		name  string
		query audit.Query
		keep  func(filterSeed) bool
	}{
		{"category one", audit.Query{Categories: []string{"auth"}},
			func(f filterSeed) bool { return f.category == "auth" }},
		{"category many", audit.Query{Categories: []string{"auth", "billing"}},
			func(f filterSeed) bool { return f.category == "auth" || f.category == "billing" }},
		{"action one", audit.Query{Actions: []string{"login"}},
			func(f filterSeed) bool { return f.action == "login" }},
		{"action many", audit.Query{Actions: []string{"login", "refund", "delete"}},
			func(f filterSeed) bool { return slices.Contains([]string{"login", "refund", "delete"}, f.action) }},
		{"resource one", audit.Query{Resources: []string{"invoice"}},
			func(f filterSeed) bool { return f.resource == "invoice" }},
		{"resource many", audit.Query{Resources: []string{"invoice", "role"}},
			func(f filterSeed) bool { return f.resource == "invoice" || f.resource == "role" }},
		{"severity one", audit.Query{Severity: []string{audit.SeverityCritical}},
			func(f filterSeed) bool { return f.severity == audit.SeverityCritical }},
		{"severity many", audit.Query{Severity: []string{audit.SeverityWarning, audit.SeverityCritical}},
			func(f filterSeed) bool { return f.severity != audit.SeverityInfo }},
		{"outcome one", audit.Query{Outcome: []string{audit.OutcomeFailure}},
			func(f filterSeed) bool { return f.outcome == audit.OutcomeFailure }},
		{"outcome many", audit.Query{Outcome: []string{audit.OutcomeFailure, audit.OutcomeDenied}},
			func(f filterSeed) bool { return f.outcome != audit.OutcomeSuccess }},
		{"filters combine with AND", audit.Query{
			Categories: []string{"auth", "data"},
			Severity:   []string{audit.SeverityWarning, audit.SeverityCritical},
		}, func(f filterSeed) bool {
			return (f.category == "auth" || f.category == "data") && f.severity != audit.SeverityInfo
		}},
		{"empty slices apply no filter", audit.Query{
			Categories: []string{}, Actions: []string{}, Resources: []string{},
			Severity: []string{}, Outcome: []string{},
		}, func(filterSeed) bool { return true }},
		{"no match", audit.Query{Categories: []string{"nope"}},
			func(filterSeed) bool { return false }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want []string
			for i, fs := range filterSeeds {
				if tt.keep(fs) {
					want = append(want, ids[i])
				}
			}

			q := tt.query
			q.Limit = 100
			res, err := s.Query(context.Background(), &q)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}

			got := make([]string, len(res.Events))
			for i, e := range res.Events {
				got[i] = e.ID.String()
			}
			sort.Strings(got)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("events = %v, want %v", got, want)
			}
			// The count runs as a separate query over the same filters, so it
			// has to agree with the rows returned.
			if res.Total != int64(len(want)) {
				t.Errorf("Total = %d, want %d", res.Total, len(want))
			}
		})
	}
}

// TestQueryMultiValueFilterCountSurvivesPaging checks that Total reports every
// match under a filter, not just the page that came back.
func TestQueryMultiValueFilterCountSurvivesPaging(t *testing.T) {
	s := newTestStore(t)
	seedFilterEvents(t, s)

	res, err := s.Query(context.Background(), &audit.Query{
		Categories: []string{"auth", "billing"},
		Limit:      2,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Events) != 2 {
		t.Errorf("page has %d events, want 2", len(res.Events))
	}
	if res.Total != 5 {
		t.Errorf("Total = %d, want 5 (three auth, two billing)", res.Total)
	}
	if !res.HasMore {
		t.Error("HasMore = false with three matches left")
	}
}

// TestSOC2ReportOnSQLite generates a SOC2 report end to end through the
// compliance engine. Every SOC2 section filters by category, action or
// severity, so on sqlite this failed outright before whereIn.
func TestSOC2ReportOnSQLite(t *testing.T) {
	s := newTestStore(t)
	seedFilterEvents(t, s)
	ctx := context.Background()

	engine := compliance.NewEngine(s, s, s, nil)
	report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period: compliance.DateRange{
			From: filterBase.Add(-time.Hour),
			To:   filterBase.Add(time.Hour),
		},
		AppID:       "app",
		GeneratedBy: "test",
	})
	if err != nil {
		t.Fatalf("SOC2: %v", err)
	}

	// Section title -> events it should match from filterSeeds.
	wantMatched := map[string]int64{
		"CC6.1 Logical Access":        4, // auth login/logout x3, access.grant
		"CC6.2 Authentication Events": 3, // every auth event
		"CC6.3 Data Access":           2, // data read, data delete
		"CC7.2 Security Incidents":    4, // two warning, two critical
		"CC8.1 Change Management":     0, // no config or deployment events
	}
	if len(report.Sections) != len(wantMatched) {
		t.Fatalf("got %d sections, want %d", len(report.Sections), len(wantMatched))
	}
	for _, sec := range report.Sections {
		want, ok := wantMatched[sec.Title]
		if !ok {
			t.Errorf("unexpected section %q", sec.Title)
			continue
		}
		if sec.MatchedEvents != want || int64(len(sec.Events)) != want {
			t.Errorf("%s: matched=%d events=%d, want %d", sec.Title, sec.MatchedEvents, len(sec.Events), want)
		}
	}

	if report.Stats == nil {
		t.Fatal("report has no stats")
	}
	if got := report.Stats; got.TotalEvents != 8 || got.CriticalEvents != 2 ||
		got.FailedEvents != 2 || got.DeniedEvents != 1 {
		t.Errorf("stats = %+v, want total 8, critical 2, failed 2, denied 1", *got)
	}

	if _, err := s.GetReport(ctx, report.ID); err != nil {
		t.Errorf("report was not saved: %v", err)
	}
}
