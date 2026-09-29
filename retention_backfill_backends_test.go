package chronicle_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate" // registers the sqlite migrate executor

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/sink"
	"github.com/xraph/chronicle/store"
	sqlitestore "github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/verify"
)

// TestBackfillOnEachBackend runs an old-style archived purge and a backfill
// against sqlite and against every real backend configured for
// TestRetentionProbeOnEachBackend.
//
// The archive holds events as each backend handed them back, so their
// timestamps and metadata have been through that backend's encoding and then
// through JSON. The backfill only works if the digest still recomputes after
// both, and the record it writes has to verify after its own round trip.
func TestBackfillOnEachBackend(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		drv := sqlitedriver.New()
		if err := drv.Open(context.Background(), filepath.Join(t.TempDir(), "backfill.db")); err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		db, err := grove.Open(drv)
		if err != nil {
			t.Fatalf("grove open: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		s := sqlitestore.New(db)
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		runBackfillProbe(t, s, "backfill-"+id.NewAuditID().String())
	})
	forEachBackend(t, func(t *testing.T, s store.Store) {
		runBackfillProbe(t, s, "backfill-"+id.NewAuditID().String())
	})
}

func runBackfillProbe(t *testing.T, s store.Store, app string) {
	t.Helper()
	ctx := context.Background()
	provider := hmacProvider()
	c := openPinChronicle(t, store.NewAdapter(s), hash.SchemeHMACV5, provider)

	// The SQL backends recompute the digest inside their append transaction,
	// under whatever chain they were given, as the extension wires them.
	if h, ok := s.(interface{ SetHasher(*hash.Chain) }); ok {
		chain, err := hash.NewChain(hash.SchemeHMACV5, provider)
		if err != nil {
			t.Fatalf("NewChain: %v", err)
		}
		h.SetHasher(chain)
	}
	recCtx := scope.WithAppID(ctx, app)

	old := time.Now().Add(-90 * 24 * time.Hour).UTC()
	for i := range 6 {
		cat := "auth"
		if i%2 == 1 {
			cat = "billing"
		}
		err := c.Record(recCtx, &audit.Event{
			Action: "touch", Resource: "doc", Category: cat, UserID: "u",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			Timestamp: old.Add(time.Duration(i) * time.Second),
			// Integers above 2^53 are left out on purpose: sqlite hands them
			// back as float64 and the untouched chain already fails there.
			Metadata: map[string]any{"i": i, "f": 1.5, "tags": []any{"x", "y"}},
		})
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	if pre, err := c.VerifyChain(ctx, &verify.Input{AppID: app}); err != nil || !pre.Valid {
		t.Fatalf("before retention: %+v %v; this backend does not verify an untouched chain", pre, err)
	}

	dir := t.TempDir()
	fs := sink.NewFileSink(dir, "archive")
	t.Cleanup(func() { _ = fs.Close() })
	p := &retention.Policy{ID: id.NewPolicyID(), Category: "auth", Duration: 30 * 24 * time.Hour, Archive: true, AppID: app}
	p.CreatedAt, p.UpdatedAt = time.Now(), time.Now()
	if err := s.SavePolicy(ctx, p); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}
	if _, err := retention.NewEnforcer(s, fs, nil, retention.WithUnrecordedPurge()).
		EnforceScope(ctx, retention.Scope{AppID: app}); err != nil {
		t.Fatalf("EnforceScope: %v", err)
	}

	report, err := c.BackfillRetention(ctx, &chronicle.BackfillInput{AppID: app, Archive: sink.NewFileArchive(dir, "archive")})
	if err != nil {
		t.Fatalf("BackfillRetention: %v", err)
	}
	if got := recoveredSeqs(report); !sameSeqs(got, []uint64{1, 3, 5}) {
		t.Fatalf("recovered = %v, want [1 3 5]; refused=%+v rejected=%+v", got, report.Refused, report.Rejected)
	}

	after, err := c.VerifyChain(ctx, &verify.Input{AppID: app})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !after.Valid || len(after.Gaps) != 0 || len(after.Tampered) != 0 {
		t.Fatalf("valid=%v gaps=%v tampered=%v retained=%v", after.Valid, after.Gaps, after.Tampered, after.Retained)
	}
	if got := retainedSeqs(after); !sameSeqs(got, []uint64{1, 3, 5}) {
		t.Errorf("retained = %v, want [1 3 5]", got)
	}
}
