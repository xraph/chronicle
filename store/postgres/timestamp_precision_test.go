package postgres

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/xraph/grove/drivers/pgdriver/pgmigrate"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/verify"
)

// TestEventTimestampRoundTripsAtFullPrecision covers the model conversion on
// its own, so it runs without a database. TIMESTAMPTZ holds microseconds and
// the digest covers the timestamp to the nanosecond, so the model has to carry
// the rest somewhere and put it back.
func TestEventTimestampRoundTripsAtFullPrecision(t *testing.T) {
	cases := map[string]time.Time{
		"nanoseconds":        time.Date(2026, 9, 29, 12, 0, 0, 123456789, time.UTC),
		"microseconds":       time.Date(2026, 9, 29, 12, 0, 0, 123456000, time.UTC),
		"exact second":       time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
		"one ns below a µs":  time.Date(2026, 9, 29, 12, 0, 0, 999, time.UTC),
		"rounds up as text":  time.Date(2026, 9, 29, 12, 0, 0, 456789500, time.UTC),
		"before the epoch":   time.Date(1969, 12, 31, 23, 59, 59, 987654321, time.UTC),
		"non-UTC input zone": time.Date(2026, 9, 29, 7, 0, 0, 555555555, time.FixedZone("CDT", -5*3600)),
	}

	for name, ts := range cases {
		t.Run(name, func(t *testing.T) {
			floor, rem := splitTimestamp(ts)

			// This is what a TIMESTAMPTZ column keeps.
			if stored := floor.Truncate(time.Microsecond); !stored.Equal(floor) {
				t.Fatalf("split floor %v does not survive a TIMESTAMPTZ (%v)", floor, stored)
			}
			if rem < 0 || rem >= 1000 {
				t.Fatalf("remainder %d outside [0, 1000)", rem)
			}

			got := joinTimestamp(floor, rem)
			if !got.Equal(ts) {
				t.Fatalf("round trip = %v, want %v", got, ts)
			}
			if a, b := got.UTC().Format(time.RFC3339Nano), ts.UTC().Format(time.RFC3339Nano); a != b {
				t.Fatalf("digest input changed: %q, want %q", a, b)
			}
		})
	}
}

// TestChainVerifiesOnPostgres is the regression test for a postgres chain
// reporting tampered. It records events through the public pipeline and
// verifies the chain the way an operator would.
//
// The digest covers the timestamp to the nanosecond, and TIMESTAMPTZ keeps
// microseconds. The timestamps here carry a fixed component below the
// microsecond rather than coming from time.Now(), because a Mac's clock
// usually ticks in whole microseconds and the bug would never show there.
func TestChainVerifiesOnPostgres(t *testing.T) {
	s, _ := openLivePostgres(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(s)),
		chronicle.WithDigestScheme(hash.SchemePlainV4),
	)
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	app := "precision-" + id.NewAuditID().String()
	recCtx := scope.WithAppID(ctx, app)

	// 456789ns past the millisecond: 456µs that TIMESTAMPTZ keeps and 789ns
	// that it doesn't.
	base := time.Now().UTC().Truncate(time.Millisecond).Add(456789 * time.Nanosecond)
	for i := range 6 {
		if recErr := c.Record(recCtx, &audit.Event{
			Action: "touch", Resource: "doc", Category: "auth", UserID: "u",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			Timestamp: base.Add(time.Duration(i) * time.Second),
		}); recErr != nil {
			t.Fatalf("Record %d: %v", i, recErr)
		}
	}

	report, err := c.VerifyChain(ctx, &verify.Input{AppID: app})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid || len(report.Tampered) != 0 || len(report.Gaps) != 0 {
		t.Fatalf("valid=%v tampered=%v gaps=%v; an untouched postgres chain must verify",
			report.Valid, report.Tampered, report.Gaps)
	}

	// And the timestamp a reader gets back is the one that was recorded.
	res, err := s.Query(ctx, &audit.Query{AppID: app, Order: "asc"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Events) != 6 {
		t.Fatalf("got %d events, want 6", len(res.Events))
	}
	for i, e := range res.Events {
		if want := base.Add(time.Duration(i) * time.Second); !e.Timestamp.Equal(want) {
			t.Errorf("event %d timestamp = %v, want %v", i, e.Timestamp, want)
		}
	}
}

// TestTimestampMigrationKeepsExistingRows applies the migration to a table
// that already holds an event, the way an upgrade meets it, and checks the row
// reads back as the value it stored.
func TestTimestampMigrationKeepsExistingRows(t *testing.T) {
	s, dsn := openLivePostgres(t)
	ctx := context.Background()

	exec := pgmigrate.New(s.pg)
	var target *migrate.Migration
	for _, m := range Migrations.Migrations() {
		if m.Name == "keep_event_timestamp_nanoseconds" {
			target = m
			break
		}
		if err := m.Up(ctx, exec); err != nil {
			t.Fatalf("migration %s: %v", m.Name, err)
		}
	}
	if target == nil {
		t.Fatal("migration keep_event_timestamp_nanoseconds not registered")
	}

	streamID := id.NewStreamID()
	eventID := id.NewAuditID()
	stored := time.Date(2026, 9, 29, 12, 0, 0, 456789000, time.UTC)
	liveExec(ctx, t, dsn, `INSERT INTO chronicle_streams (id, app_id) VALUES ($1, 'legacy')`, streamID.String())
	liveExec(ctx, t, dsn, `
INSERT INTO chronicle_events (id, stream_id, sequence, hash, app_id, action, resource, category, timestamp)
VALUES ($1, $2, 1, 'h', 'legacy', 'touch', 'doc', 'auth', $3)`,
		eventID.String(), streamID.String(), stored)

	if err := target.Up(ctx, exec); err != nil {
		t.Fatalf("Up: %v", err)
	}

	got, err := s.Get(ctx, eventID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Timestamp.Equal(stored) {
		t.Fatalf("existing row read back as %v, want %v", got.Timestamp, stored)
	}
}

// TestLegacyRowsKeepTheirVerdict pins what the migration does for rows
// written before it. Such a row has timestamp_sub_us at zero. If its original
// timestamp had nothing below the microsecond, it verifies. If it did, those
// digits are gone and it stays tampered. Nothing is invented for it.
func TestLegacyRowsKeepTheirVerdict(t *testing.T) {
	s, dsn := openLivePostgres(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(s)),
		chronicle.WithDigestScheme(hash.SchemePlainV4),
	)
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	app := "legacy-" + id.NewAuditID().String()
	recCtx := scope.WithAppID(ctx, app)

	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	stamps := []time.Time{
		base.Add(456 * time.Microsecond), // 1: whole microseconds
		base.Add(time.Second),            // 2: whole seconds
		base.Add(2*time.Second + 456789), // 3: 789ns below the microsecond
		base.Add(3*time.Second + 999),    // 4: 999ns below the microsecond
	}
	for i, ts := range stamps {
		if recErr := c.Record(recCtx, &audit.Event{
			Action: "touch", Resource: "doc", Category: "auth", UserID: "u",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			Timestamp: ts,
		}); recErr != nil {
			t.Fatalf("Record %d: %v", i, recErr)
		}
	}

	// What a row written before the column existed looks like after it runs.
	liveExec(ctx, t, dsn, `UPDATE chronicle_events SET timestamp_sub_us = 0 WHERE app_id = $1`, app)

	report, err := c.VerifyChain(ctx, &verify.Input{AppID: app})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid || !slices.Equal(report.Tampered, []uint64{3, 4}) {
		t.Fatalf("valid=%v tampered=%v; want only 3 and 4, the rows that lost digits",
			report.Valid, report.Tampered)
	}
}
