package chronicle_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/grove/kv"
	"github.com/xraph/grove/kv/drivers/redisdriver"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	mongostore "github.com/xraph/chronicle/store/mongo"
	pgstore "github.com/xraph/chronicle/store/postgres"
	redisstore "github.com/xraph/chronicle/store/redis"
	"github.com/xraph/chronicle/verify"
)

// TestRetentionProbeOnEachBackend runs the original probe against the real
// backends named by CHRONICLE_TEST_POSTGRES_DSN, CHRONICLE_TEST_MONGO_URI and
// CHRONICLE_TEST_REDIS_DSN, skipping each one that is unset.
//
// The memory store keeps a record's metadata as the Go value it was given.
// Every other backend serialises it and hands back something decoded, and the
// record's digest covers that metadata, so the round trip has to reproduce the
// same bytes on each one or every record would read as forged.
//
// Each run writes under a fresh app ID and deletes nothing, so it cannot
// disturb other data in the database. It still refuses the default ports: on
// the machine this was written on, those are another project's live databases.
func TestRetentionProbeOnEachBackend(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s store.Store) {
		runProbe(t, s, "probe-"+id.NewAuditID().String())
	})
}

// forEachBackend runs fn against a migrated store for each backend whose
// environment variable is set, and skips the rest.
func forEachBackend(t *testing.T, fn func(t *testing.T, s store.Store)) {
	t.Helper()
	for _, b := range []struct {
		name, env string
		open      func(t *testing.T, dsn string) store.Store
	}{
		{"postgres", "CHRONICLE_TEST_POSTGRES_DSN", openPostgres},
		{"mongo", "CHRONICLE_TEST_MONGO_URI", openMongo},
		{"redis", "CHRONICLE_TEST_REDIS_DSN", openRedis},
	} {
		t.Run(b.name, func(t *testing.T) {
			dsn := os.Getenv(b.env)
			if dsn == "" {
				t.Skipf("%s not set", b.env)
			}
			for _, live := range []string{":5432/", ":6379", ":27017"} {
				if strings.Contains(dsn, live) {
					t.Fatalf("%s points at a default port (%s); refusing to write to what may be a live database", b.env, live)
				}
			}

			s := b.open(t, dsn)
			if err := s.Migrate(context.Background()); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			fn(t, s)
		})
	}
}

func runProbe(t *testing.T, s store.Store, app string) {
	t.Helper()
	ctx := context.Background()
	c := openPinChronicle(t, store.NewAdapter(s), hash.SchemePlainV4, nil)
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
		})
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	before, err := c.VerifyChain(ctx, &verify.Input{AppID: app})
	if err != nil {
		t.Fatalf("VerifyChain before retention: %v", err)
	}
	if !before.Valid {
		t.Fatalf("before retention: valid=false gaps=%v tampered=%v; this backend does not verify an untouched chain",
			before.Gaps, before.Tampered)
	}

	p := &retention.Policy{ID: id.NewPolicyID(), Category: "auth", Duration: 30 * 24 * time.Hour, AppID: app}
	p.CreatedAt, p.UpdatedAt = time.Now(), time.Now()
	if saveErr := s.SavePolicy(ctx, p); saveErr != nil {
		t.Fatalf("SavePolicy: %v", saveErr)
	}
	res, err := retention.NewEnforcer(s, nil, nil, retention.WithChainRecorder(c)).
		EnforceScope(ctx, retention.Scope{AppID: app})
	if err != nil {
		t.Fatalf("EnforceScope: %v", err)
	}
	if res.Purged != 3 {
		t.Fatalf("purged %d, want 3", res.Purged)
	}

	report, err := c.VerifyChain(ctx, &verify.Input{AppID: app})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid || len(report.Gaps) != 0 || len(report.Tampered) != 0 {
		t.Fatalf("valid=%v gaps=%v tampered=%v retained=%v", report.Valid, report.Gaps, report.Tampered, report.Retained)
	}
	if got := retainedSeqs(report); !sameSeqs(got, []uint64{1, 3, 5}) {
		t.Errorf("retained = %v, want [1 3 5]", got)
	}
}

func openPostgres(t *testing.T, dsn string) store.Store {
	t.Helper()
	drv := pgdriver.New()
	if err := drv.Open(context.Background(), dsn); err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return pgstore.New(db)
}

func openMongo(t *testing.T, uri string) store.Store {
	t.Helper()
	drv := mongodriver.New()
	if err := drv.Open(context.Background(), uri); err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return mongostore.New(db)
}

func openRedis(t *testing.T, dsn string) store.Store {
	t.Helper()
	drv := redisdriver.New()
	if err := drv.Open(context.Background(), dsn); err != nil {
		t.Fatalf("open redis: %v", err)
	}
	kvStore, err := kv.Open(drv)
	if err != nil {
		t.Fatalf("kv open: %v", err)
	}
	t.Cleanup(func() { _ = kvStore.Close() })
	return redisstore.New(kvStore)
}
