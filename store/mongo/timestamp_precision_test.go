package mongo

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/verify"
)

// TestEventTimestampRoundTripsAtFullPrecision covers the model conversion on
// its own, so it runs without a database. A BSON date holds milliseconds, and
// the digest covers the timestamp to the nanosecond, so the model has to carry
// the rest of it somewhere and put it back.
func TestEventTimestampRoundTripsAtFullPrecision(t *testing.T) {
	cases := map[string]time.Time{
		"nanoseconds":        time.Date(2026, 9, 29, 12, 0, 0, 123456789, time.UTC),
		"microseconds":       time.Date(2026, 9, 29, 12, 0, 0, 123456000, time.UTC),
		"exact millisecond":  time.Date(2026, 9, 29, 12, 0, 0, 123000000, time.UTC),
		"exact second":       time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
		"one ns below a ms":  time.Date(2026, 9, 29, 12, 0, 0, 999999, time.UTC),
		"before the epoch":   time.Date(1969, 12, 31, 23, 59, 59, 987654321, time.UTC),
		"non-UTC input zone": time.Date(2026, 9, 29, 7, 0, 0, 555555555, time.FixedZone("CDT", -5*3600)),
	}

	for name, ts := range cases {
		t.Run(name, func(t *testing.T) {
			ms, rem := splitTimestamp(ts)

			// This is what a BSON date keeps.
			stored := time.UnixMilli(ms.UnixMilli())
			if !stored.Equal(ms) {
				t.Fatalf("split millisecond part %v does not survive a BSON date (%v)", ms, stored)
			}

			got := joinTimestamp(stored, rem)
			if !got.Equal(ts) {
				t.Fatalf("round trip = %v, want %v", got, ts)
			}
			if a, b := got.UTC().Format(time.RFC3339Nano), ts.UTC().Format(time.RFC3339Nano); a != b {
				t.Fatalf("digest input changed: %q, want %q", a, b)
			}
		})
	}
}

// TestLegacyEventWithoutRemainderReadsAsStored pins what happens to a row
// written before the remainder field existed: it reads back as the millisecond
// date it holds, exactly as it did before. Nothing is invented for it.
func TestLegacyEventWithoutRemainderReadsAsStored(t *testing.T) {
	stored := time.Date(2026, 9, 29, 12, 0, 0, 123000000, time.UTC)
	if got := joinTimestamp(stored, 0); !got.Equal(stored) {
		t.Fatalf("legacy row read back as %v, want %v", got, stored)
	}
}

// TestChainVerifiesOnMongo is the regression test for every mongo chain
// reporting tampered. It records events with nanosecond timestamps through
// the public pipeline and verifies the chain the way an operator would.
//
// Before the fix this returned valid=false with every sequence tampered: the
// digest was computed over the nanosecond timestamp and the BSON date handed
// back milliseconds.
func TestChainVerifiesOnMongo(t *testing.T) {
	s, _ := openLiveStore(t)
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

	// A fixed sub-millisecond component, so the test does not depend on how
	// fine this machine's clock happens to be.
	base := time.Now().UTC().Truncate(time.Millisecond).Add(123456 * time.Nanosecond)
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
		t.Fatalf("valid=%v tampered=%v gaps=%v; an untouched mongo chain must verify",
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
