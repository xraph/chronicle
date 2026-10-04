package sqlite

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
)

// Timestamps are TEXT on sqlite and every range filter and ORDER BY compares
// them as strings. time.RFC3339Nano drops the fraction on an exact second and
// trims trailing zeros otherwise, and '.' (0x2E) sorts before 'Z' (0x5A), so
// under that format "00:00:00.5Z" < "00:00:00Z" even though it is half a
// second later. These tests pin the order at both window edges and in ORDER BY.

var edgeBase = time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

// edgeSeeds are keyed by label. Each event's category is its label, so a
// category-grouped Aggregate reports which events a window matched.
var edgeSeeds = map[string]time.Time{
	"whole": edgeBase,                                  // 00:00:00Z
	"nanos": edgeBase.Add(123456789 * time.Nanosecond), // 00:00:00.123456789Z
	"half":  edgeBase.Add(500 * time.Millisecond),      // 00:00:00.5Z
}

func seedEdgeEvents(t *testing.T, s *Store, seeds map[string]time.Time) {
	t.Helper()
	streamID := seedStream(t, s, "app-ts", "t1")
	events := make([]*audit.Event, 0, len(seeds))
	for label, ts := range seeds {
		// AppendBatch stores the sequence it is given, so each seed needs its own.
		e := testEvent(streamID, "app-ts", "t1", "u1", label, ts)
		e.Sequence = uint64(len(events) + 1)
		events = append(events, e)
	}
	if err := s.AppendBatch(context.Background(), events); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}
}

func labelsOf(events []*audit.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Category)
	}
	return out
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// windowMatches runs the same [after, before] window through every sqlite API
// that filters on timestamp and returns the matched labels per API.
func windowMatches(t *testing.T, s *Store, after, before time.Time) map[string][]string {
	t.Helper()
	ctx := context.Background()
	got := map[string][]string{}

	qr, err := s.Query(ctx, &audit.Query{AppID: "app-ts", TenantID: "t1", After: after, Before: before})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	got["Query"] = sorted(labelsOf(qr.Events))
	if qr.Total != int64(len(qr.Events)) {
		t.Errorf("Query total %d disagrees with %d events returned", qr.Total, len(qr.Events))
	}

	br, err := s.ByUser(ctx, "u1", audit.TimeRange{AppID: "app-ts", TenantID: "t1", After: after, Before: before})
	if err != nil {
		t.Fatalf("ByUser: %v", err)
	}
	got["ByUser"] = sorted(labelsOf(br.Events))

	ar, err := s.Aggregate(ctx, &audit.AggregateQuery{
		AppID: "app-ts", TenantID: "t1", After: after, Before: before, GroupBy: []string{"category"},
	})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	agg := make([]string, 0, len(ar.Groups))
	for _, g := range ar.Groups {
		agg = append(agg, g.Category)
	}
	got["Aggregate"] = sorted(agg)

	// Count has no per-event breakdown, so compare it against the Query set.
	n, err := s.Count(ctx, &audit.CountQuery{AppID: "app-ts", TenantID: "t1", After: after, Before: before})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != int64(len(got["Query"])) {
		t.Errorf("Count = %d, want %d (the Query result %v)", n, len(got["Query"]), got["Query"])
	}

	return got
}

func TestTimeWindowEdgesAreChronological(t *testing.T) {
	s := newTestStore(t)
	seedEdgeEvents(t, s, edgeSeeds)

	cases := []struct {
		name          string
		after, before time.Time
		want          []string
	}{
		{
			// The fractional events are later than After and must be kept.
			name:  "After on the whole second keeps the fractional events",
			after: edgeBase,
			want:  []string{"half", "nanos", "whole"},
		},
		{
			name:  "After between the events drops the earlier ones",
			after: edgeBase.Add(200 * time.Millisecond),
			want:  []string{"half"},
		},
		{
			// The fractional events are later than Before and must be dropped.
			name:   "Before on the whole second drops the fractional events",
			before: edgeBase,
			want:   []string{"whole"},
		},
		{
			name:   "Before between the events keeps the earlier ones",
			before: edgeBase.Add(200 * time.Millisecond),
			want:   []string{"nanos", "whole"},
		},
		{
			// A bound one nanosecond short of an event must exclude it: the
			// comparison has to be exact to the nanosecond, not the millisecond.
			name:  "After one nanosecond past an event excludes it",
			after: edgeBase.Add(123456790 * time.Nanosecond),
			want:  []string{"half"},
		},
		{
			name:   "Before one nanosecond short of an event excludes it",
			before: edgeBase.Add(123456788 * time.Nanosecond),
			want:   []string{"whole"},
		},
		{
			name:   "Bounds equal to an event include it",
			after:  edgeBase.Add(123456789 * time.Nanosecond),
			before: edgeBase.Add(123456789 * time.Nanosecond),
			want:   []string{"nanos"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for api, labels := range windowMatches(t, s, tc.after, tc.before) {
				if !reflect.DeepEqual(labels, tc.want) {
					t.Errorf("%s matched %v, want %v", api, labels, tc.want)
				}
			}
		})
	}
}

func TestEventsOlderThanIsChronological(t *testing.T) {
	s := newTestStore(t)
	seedEdgeEvents(t, s, edgeSeeds)

	cases := []struct {
		name   string
		before time.Time
		want   []string // in the order EventsOlderThan returns them (oldest first)
	}{
		{"strictly before the whole second", edgeBase, []string{}},
		{"cutoff between events", edgeBase.Add(200 * time.Millisecond), []string{"whole", "nanos"}},
		{"cutoff equal to an event is exclusive", edgeBase.Add(500 * time.Millisecond), []string{"whole", "nanos"}},
		{"cutoff past every event", edgeBase.Add(time.Second), []string{"whole", "nanos", "half"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.EventsOlderThan(context.Background(), retention.PurgeQuery{
				Scope:    retention.Scope{AppID: "app-ts", TenantID: "t1"},
				Category: "*",
				Before:   tc.before,
			})
			if err != nil {
				t.Fatalf("EventsOlderThan: %v", err)
			}
			if labels := labelsOf(got); !reflect.DeepEqual(labels, tc.want) {
				t.Errorf("EventsOlderThan = %v, want %v", labels, tc.want)
			}
		})
	}
}

func TestOrderByMixesFractionalAndWholeSeconds(t *testing.T) {
	s := newTestStore(t)
	seedEdgeEvents(t, s, map[string]time.Time{
		"prev-late": edgeBase.Add(-100 * time.Millisecond), // 23:59:59.9Z the day before
		"whole":     edgeBase,                              // 00:00:00Z
		"nanos":     edgeBase.Add(123456789 * time.Nanosecond),
		"half":      edgeBase.Add(500 * time.Millisecond),
		"next":      edgeBase.Add(time.Second), // 00:00:01Z
		"next-1ns":  edgeBase.Add(time.Second + time.Nanosecond),
	})
	ctx := context.Background()

	asc := []string{"prev-late", "whole", "nanos", "half", "next", "next-1ns"}
	desc := make([]string, len(asc))
	for i, l := range asc {
		desc[len(asc)-1-i] = l
	}

	qa, err := s.Query(ctx, &audit.Query{AppID: "app-ts", TenantID: "t1", Order: "asc"})
	if err != nil {
		t.Fatalf("Query asc: %v", err)
	}
	if got := labelsOf(qa.Events); !reflect.DeepEqual(got, asc) {
		t.Errorf("Query asc = %v, want %v", got, asc)
	}

	qd, err := s.Query(ctx, &audit.Query{AppID: "app-ts", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Query desc: %v", err)
	}
	if got := labelsOf(qd.Events); !reflect.DeepEqual(got, desc) {
		t.Errorf("Query desc = %v, want %v", got, desc)
	}

	bu, err := s.ByUser(ctx, "u1", audit.TimeRange{AppID: "app-ts", TenantID: "t1"})
	if err != nil {
		t.Fatalf("ByUser: %v", err)
	}
	if got := labelsOf(bu.Events); !reflect.DeepEqual(got, desc) {
		t.Errorf("ByUser = %v, want %v", got, desc)
	}

	// Pagination rides on the same ORDER BY, so a page boundary that lands
	// inside one second must not skip or repeat an event.
	var paged []string
	for offset := 0; offset < len(asc); offset += 2 {
		page, queryErr := s.Query(ctx, &audit.Query{AppID: "app-ts", TenantID: "t1", Order: "asc", Limit: 2, Offset: offset})
		if queryErr != nil {
			t.Fatalf("Query page at %d: %v", offset, queryErr)
		}
		paged = append(paged, labelsOf(page.Events)...)
	}
	if !reflect.DeepEqual(paged, asc) {
		t.Errorf("paged asc = %v, want %v", paged, asc)
	}

	old, err := s.EventsOlderThan(ctx, retention.PurgeQuery{
		Scope:    retention.Scope{AppID: "app-ts", TenantID: "t1"},
		Category: "*",
		Before:   edgeBase.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("EventsOlderThan: %v", err)
	}
	if got := labelsOf(old); !reflect.DeepEqual(got, asc) {
		t.Errorf("EventsOlderThan = %v, want %v", got, asc)
	}
}

// TestMigrationNormalizesLegacyTimestamps seeds rows in the old variable-width
// format, then runs the migration that rewrites them. newTestStore cannot cover
// this: it migrates an empty database, so there is never a legacy row to fix.
func TestMigrationNormalizesLegacyTimestamps(t *testing.T) {
	ctx := context.Background()

	dsn := filepath.Join(t.TempDir(), "chronicle_legacy_ts.db")
	sdb := sqlitedriver.New()
	if err := sdb.Open(ctx, dsn); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	executor, err := migrate.NewExecutorFor(sdb)
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}

	all := Migrations.Migrations()
	target := -1
	for i, m := range all {
		if m.Name == "fixed_width_timestamps" {
			target = i
			break
		}
	}
	if target == -1 {
		t.Fatal("migration fixed_width_timestamps not found")
	}
	for _, m := range all[:target] {
		if upErr := m.Up(ctx, executor); upErr != nil {
			t.Fatalf("migration %s: %v", m.Name, upErr)
		}
	}

	streamID := id.NewStreamID()
	if _, err := executor.Exec(ctx,
		`INSERT INTO chronicle_streams (id, app_id, tenant_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		streamID.String(), "app-ts", "t1", "2026-09-20T00:00:00.5Z", "2026-09-20T00:00:00Z",
	); err != nil {
		t.Fatalf("seed stream: %v", err)
	}

	// Exactly what time.RFC3339Nano wrote before the fix.
	legacy := map[string]string{
		"whole": "2026-09-20T00:00:00Z",
		"nanos": "2026-09-20T00:00:00.123456789Z",
		"half":  "2026-09-20T00:00:00.5Z",
	}
	for label, ts := range legacy {
		if _, err := executor.Exec(ctx,
			`INSERT INTO chronicle_events (id, stream_id, sequence, hash, app_id, tenant_id, user_id, action, resource, category, timestamp, created_at, erased_at)
			 VALUES (?, ?, (SELECT COUNT(*) + 1 FROM chronicle_events), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id.NewAuditID().String(), streamID.String(), "h-"+label, "app-ts", "t1", "u1",
			"login", "session", label, ts, ts, ts,
		); err != nil {
			t.Fatalf("seed legacy event %s: %v", label, err)
		}
	}

	for _, m := range all[target:] {
		if upErr := m.Up(ctx, executor); upErr != nil {
			t.Fatalf("migration %s: %v", m.Name, upErr)
		}
	}

	want := map[string]string{
		"whole": "2026-09-20T00:00:00.000000000Z",
		"nanos": "2026-09-20T00:00:00.123456789Z",
		"half":  "2026-09-20T00:00:00.500000000Z",
	}
	for label, w := range want {
		var ts, created, erased string
		if err := sdb.NewRaw(
			`SELECT timestamp, created_at, erased_at FROM chronicle_events WHERE category = ?`, label,
		).Scan(ctx, &ts, &created, &erased); err != nil {
			t.Fatalf("read %s: %v", label, err)
		}
		for col, got := range map[string]string{"timestamp": ts, "created_at": created, "erased_at": erased} {
			if got != w {
				t.Errorf("%s.%s = %q, want %q", label, col, got, w)
			}
		}
	}

	var sc, su string
	if err := sdb.NewRaw(`SELECT created_at, updated_at FROM chronicle_streams WHERE id = ?`, streamID.String()).
		Scan(ctx, &sc, &su); err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if sc != "2026-09-20T00:00:00.500000000Z" || su != "2026-09-20T00:00:00.000000000Z" {
		t.Errorf("stream created_at/updated_at = %q/%q, want fixed-width", sc, su)
	}

	// The rewritten rows must now filter chronologically.
	s := New(db)
	for api, labels := range windowMatches(t, s, time.Time{}, edgeBase) {
		if !reflect.DeepEqual(labels, []string{"whole"}) {
			t.Errorf("after migration, %s with Before=00:00:00Z matched %v, want [whole]", api, labels)
		}
	}

	// Running the migration again must be a no-op on already-normalized rows.
	if upErr := all[target].Up(ctx, executor); upErr != nil {
		t.Fatalf("re-run %s: %v", all[target].Name, upErr)
	}
	var again string
	if err := sdb.NewRaw(`SELECT timestamp FROM chronicle_events WHERE category = 'half'`).Scan(ctx, &again); err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if again != want["half"] {
		t.Errorf("after re-run, half = %q, want %q", again, want["half"])
	}
}
