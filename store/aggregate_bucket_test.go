package store_test

import (
	"context"
	"net/url"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
	chroniclepostgres "github.com/xraph/chronicle/store/postgres"
	"github.com/xraph/chronicle/stream"
)

// bucketBackends is the subset of backends(t) (see scope_behaviour_test.go)
// whose Aggregate currently understands the "day" and "hour" group_by
// fields. It grows by one entry per backend commit -- postgres, then
// sqlite, then mongo, then redis -- so `go test ./...` stays green after
// each single-backend commit instead of failing on backends this batch has
// not reached yet. Once every backend is done this equals the full key set
// of backends(t); it stays here afterward as a record of the rollout, not
// because anything still needs filtering out.
var bucketBackends = []string{"postgres", "sqlite"}

// bucketTestBackends returns backends(t) filtered down to bucketBackends.
func bucketTestBackends(t *testing.T) map[string]func(t *testing.T) (store.Store, func(context.Context, id.ID)) {
	t.Helper()
	all := backends(t)
	filtered := make(map[string]func(t *testing.T) (store.Store, func(context.Context, id.ID)), len(bucketBackends))
	for _, name := range bucketBackends {
		if open, ok := all[name]; ok {
			filtered[name] = open
		}
	}
	return filtered
}

// seedScope returns a fresh per-run app id and tenant id, built from
// newRunSuffix (see scope_behaviour_test.go), so repeated runs against a
// persistent database (postgres, mongo, redis) never collide on
// chronicle_streams' UNIQUE(app_id, tenant_id).
func seedScope(t *testing.T) (appID, tenantID string) {
	t.Helper()
	suffix := newRunSuffix(t)
	return "bucket-app-" + suffix, "bucket-tenant-" + suffix
}

// seedEventsAt creates one fresh stream scoped to appID/tenantID and appends
// one event per timestamp, in order, returning the stream ID so the caller
// can register cleanup exactly as seedEventIn's callers do.
//
// Sequence is explicit and increasing (1, 2, 3, ...) rather than left at its
// zero value: sqlite and postgres overwrite event.Sequence with head+1
// inside Append regardless of what is passed, but mongo and redis store
// exactly what they are handed, and mongo rejects a second event at the
// same sequence under UNIQUE(stream_id, sequence).
func seedEventsAt(t *testing.T, s store.Store, appID, tenantID string, timestamps ...time.Time) id.ID {
	t.Helper()
	ctx := context.Background()

	streamID := id.NewStreamID()
	if err := s.CreateStream(ctx, &stream.Stream{
		ID:       streamID,
		AppID:    appID,
		TenantID: tenantID,
	}); err != nil {
		t.Fatalf("create stream for %s/%s: %v", appID, tenantID, err)
	}

	for i, ts := range timestamps {
		event := &audit.Event{
			ID:        id.NewAuditID(),
			StreamID:  streamID,
			Sequence:  uint64(i + 1), //nolint:gosec // i is a small, bounded test loop index
			Hash:      "seed",
			Timestamp: ts,
			AppID:     appID,
			TenantID:  tenantID,
			Action:    "test.seed",
			Resource:  "test.resource",
			Category:  "test",
			Outcome:   audit.OutcomeSuccess,
			Severity:  audit.SeverityInfo,
		}
		if err := s.Append(ctx, event); err != nil {
			t.Fatalf("append event %d for %s/%s at %s: %v", i, appID, tenantID, ts, err)
		}
	}
	return streamID
}

// registerStreamCleanup mirrors the pattern TestEmptyAppIDScopeBehaviour
// uses: cleanupStream is nil for sqlite (temp database, nothing to do) and
// redis (prefix cleanup already registered inside the opener), and non-nil
// for postgres/mongo, which persist across runs.
func registerStreamCleanup(t *testing.T, cleanupStream func(context.Context, id.ID), streamID id.ID) {
	t.Helper()
	if cleanupStream == nil {
		return
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cleanupStream(ctx, streamID)
	})
}

// assertBucketsAgree is the cross-backend assertion a per-package test
// design could not make: every backend must have rendered the exact same
// ordered bucket strings, because the dashboard contract carries a bucket to
// the browser with no per-backend branch.
func assertBucketsAgree(t *testing.T, got map[string][]string) {
	t.Helper()
	var ref string
	var refBuckets []string
	for name, b := range got {
		if ref == "" {
			ref, refBuckets = name, b
			continue
		}
		if !reflect.DeepEqual(b, refBuckets) {
			t.Errorf("backends disagree: %s rendered %v, %s rendered %v", name, b, ref, refBuckets)
		}
	}
}

// All four backends must render a bucket as the identical string, because the
// dashboard contract carries it to the browser with no per-backend branch. A
// test per backend could pass four times while the four disagreed; this one
// runs them side by side and compares them to each other as well as to the
// expected value.
func TestAggregateBucketsAgreeAcrossBackends(t *testing.T) {
	day1 := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	day3 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

	got := map[string][]string{} // backend -> ordered buckets
	for name, open := range bucketTestBackends(t) {
		t.Run(name, func(t *testing.T) {
			s, cleanupStream := open(t)
			appID, tenantID := seedScope(t)
			streamID := seedEventsAt(t, s, appID, tenantID, day1, day1.Add(time.Hour), day3)
			registerStreamCleanup(t, cleanupStream, streamID)

			res, err := s.Aggregate(context.Background(), &audit.AggregateQuery{
				After: day1.Add(-time.Hour), Before: day3.Add(time.Hour),
				AppID: appID, GroupBy: []string{"day"},
			})
			if err != nil {
				t.Fatalf("Aggregate: %v", err)
			}
			// Two groups, not three. The empty day is ABSENT rather than
			// present with count zero, because the dashboard renders that
			// absence as the gap it is looking for.
			if len(res.Groups) != 2 {
				t.Fatalf("%s: %d groups, want 2 (the empty day must be absent, not zero): %+v",
					name, len(res.Groups), res.Groups)
			}
			var buckets []string
			for _, g := range res.Groups {
				buckets = append(buckets, g.Bucket)
			}
			sort.Strings(buckets)
			if buckets[0] != "2026-09-20" || buckets[1] != "2026-09-22" {
				t.Errorf("%s: buckets %v, want [2026-09-20 2026-09-22]", name, buckets)
			}
			got[name] = buckets
		})
	}

	// The cross-backend assertion the per-package design could not make.
	assertBucketsAgree(t, got)
}

// Same shape as TestAggregateBucketsAgreeAcrossBackends, for "hour" instead
// of "day".
func TestAggregateHourBucketsAgreeAcrossBackends(t *testing.T) {
	hour1 := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	hour3 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) // two hours later, nothing between

	got := map[string][]string{}
	for name, open := range bucketTestBackends(t) {
		t.Run(name, func(t *testing.T) {
			s, cleanupStream := open(t)
			appID, tenantID := seedScope(t)
			streamID := seedEventsAt(t, s, appID, tenantID, hour1, hour1.Add(30*time.Minute), hour3)
			registerStreamCleanup(t, cleanupStream, streamID)

			res, err := s.Aggregate(context.Background(), &audit.AggregateQuery{
				After: hour1.Add(-time.Hour), Before: hour3.Add(time.Hour),
				AppID: appID, GroupBy: []string{"hour"},
			})
			if err != nil {
				t.Fatalf("Aggregate: %v", err)
			}
			// Two groups, not three: the empty hour between them is absent.
			if len(res.Groups) != 2 {
				t.Fatalf("%s: %d groups, want 2 (the empty hour must be absent, not zero): %+v",
					name, len(res.Groups), res.Groups)
			}
			var buckets []string
			for _, g := range res.Groups {
				buckets = append(buckets, g.Bucket)
			}
			sort.Strings(buckets)
			want0, want1 := "2026-09-20T10:00:00Z", "2026-09-20T12:00:00Z"
			if buckets[0] != want0 || buckets[1] != want1 {
				t.Errorf("%s: buckets %v, want [%s %s]", name, buckets, want0, want1)
			}
			got[name] = buckets
		})
	}

	assertBucketsAgree(t, got)
}

// sqlite stores timestamp as TEXT written with time.RFC3339Nano (see
// store/sqlite/models.go), which omits the fractional part entirely on an
// exact second and otherwise emits up to nine digits. An hour bucket that
// only reads the Y/m/d/H fields must land the same whether the source
// timestamp carries a fraction or not, on every backend -- the point here is
// that all four agree, not just that sqlite happens to survive its own
// storage format.
func TestAggregateHourBucketHandlesFractionalSeconds(t *testing.T) {
	onTheSecond := time.Date(2026, 9, 20, 14, 0, 3, 0, time.UTC)
	withFraction := time.Date(2026, 9, 20, 14, 0, 3, 123456789, time.UTC)

	got := map[string][]string{}
	for name, open := range bucketTestBackends(t) {
		t.Run(name, func(t *testing.T) {
			s, cleanupStream := open(t)
			appID, tenantID := seedScope(t)
			streamID := seedEventsAt(t, s, appID, tenantID, onTheSecond, withFraction)
			registerStreamCleanup(t, cleanupStream, streamID)

			res, err := s.Aggregate(context.Background(), &audit.AggregateQuery{
				After: onTheSecond.Add(-time.Minute), Before: withFraction.Add(time.Minute),
				AppID: appID, GroupBy: []string{"hour"},
			})
			if err != nil {
				t.Fatalf("Aggregate: %v", err)
			}
			// One group, not two: an exact-second timestamp and its
			// fractional-second sibling fall in the same hour.
			if len(res.Groups) != 1 {
				t.Fatalf("%s: %d groups, want 1 (both timestamps are the same hour): %+v",
					name, len(res.Groups), res.Groups)
			}
			want := "2026-09-20T14:00:00Z"
			if res.Groups[0].Bucket != want {
				t.Errorf("%s: bucket = %q, want %q", name, res.Groups[0].Bucket, want)
			}
			if res.Groups[0].Count != 2 {
				t.Errorf("%s: count = %d, want 2", name, res.Groups[0].Count)
			}
			got[name] = []string{res.Groups[0].Bucket}
		})
	}

	assertBucketsAgree(t, got)
}

// TestAggregatePostgresDayBucketIsUTCNormalized proves store/postgres's day
// bucket expression normalises to UTC rather than to the session's own time
// zone. date_trunc on a TIMESTAMPTZ truncates in whatever time zone the
// connection happens to be in; a naive `date_trunc('day', timestamp)` passes
// every other test in this file -- the containers those run against are all
// UTC -- and then silently shifts day boundaries the first time it runs
// against a server configured for a different zone.
//
// This opens its own postgres store, independent of backends(t)/
// openPostgres in scope_behaviour_test.go, because it needs a DSN carrying a
// non-UTC session time zone rather than the one those helpers dial. If the
// driver does not honour a "timezone" query parameter on the DSN, this test
// fails loudly (naming the session time zone it actually got) rather than
// silently passing as a no-op, so a change in that behaviour is visible
// instead of quietly making this test meaningless.
func TestAggregatePostgresDayBucketIsUTCNormalized(t *testing.T) {
	dsn := os.Getenv("CHRONICLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CHRONICLE_TEST_POSTGRES_DSN not set, skipping postgres time zone test")
	}

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse CHRONICLE_TEST_POSTGRES_DSN: %v", err)
	}
	q := u.Query()
	q.Set("timezone", "America/New_York")
	u.RawQuery = q.Encode()
	tzDSN := u.String()

	ctx := context.Background()
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	drv := pgdriver.New()
	if err := drv.Open(dialCtx, tzDSN); err != nil {
		t.Fatalf("open postgres with a non-UTC session time zone: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove.Open postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := chroniclepostgres.New(db)
	if err := s.Ping(dialCtx); err != nil {
		t.Fatalf("postgres ping failed: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}

	// Confirm the session actually picked up the non-UTC zone, so a failure
	// below is about the bucket expression and not about the DSN parameter
	// being silently ignored by the driver.
	var sessionTZ string
	if err := drv.NewRaw("SHOW timezone").Scan(ctx, &sessionTZ); err != nil {
		t.Fatalf("read session timezone: %v", err)
	}
	if sessionTZ == "UTC" || sessionTZ == "utc" {
		t.Fatalf("driver did not honour the timezone DSN parameter (session timezone is %q); "+
			"this test cannot exercise UTC normalization without a non-UTC session -- see "+
			"this test's doc comment", sessionTZ)
	}

	appID, tenantID := seedScope(t)
	// 2026-09-20T02:00:00Z is 2026-09-19 22:00 in New York (UTC-4 under DST
	// in September): a session that truncates in its own time zone buckets
	// this into 2026-09-19, not 2026-09-20.
	ts := time.Date(2026, 9, 20, 2, 0, 0, 0, time.UTC)
	streamID := seedEventsAt(t, s, appID, tenantID, ts)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, execErr := drv.Exec(cleanupCtx, "DELETE FROM chronicle_events WHERE stream_id = $1", streamID.String()); execErr != nil {
			t.Logf("cleanup: delete events for stream %s: %v", streamID, execErr)
		}
		if _, execErr := drv.Exec(cleanupCtx, "DELETE FROM chronicle_streams WHERE id = $1", streamID.String()); execErr != nil {
			t.Logf("cleanup: delete stream %s: %v", streamID, execErr)
		}
	})

	res, err := s.Aggregate(ctx, &audit.AggregateQuery{
		After: ts.Add(-time.Hour), Before: ts.Add(time.Hour),
		AppID: appID, GroupBy: []string{"day"},
	})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(res.Groups) != 1 {
		t.Fatalf("%d groups, want 1: %+v", len(res.Groups), res.Groups)
	}
	if res.Groups[0].Bucket != "2026-09-20" {
		t.Errorf("bucket = %q, want %q (session timezone is %q; a date_trunc that is not "+
			"normalized to UTC would bucket this into 2026-09-19 instead)",
			res.Groups[0].Bucket, "2026-09-20", sessionTZ)
	}
}
