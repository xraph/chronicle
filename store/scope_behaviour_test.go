package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate" // registers the sqlite migrate executor
	"github.com/xraph/grove/kv"
	"github.com/xraph/grove/kv/drivers/redisdriver"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
	chroniclemongo "github.com/xraph/chronicle/store/mongo"
	chroniclepostgres "github.com/xraph/chronicle/store/postgres"
	chronicleredis "github.com/xraph/chronicle/store/redis"
	"github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/stream"
)

// backends returns every store backend this test can exercise, keyed by
// name. sqlite needs no external service and always runs. postgres, mongo
// and redis each open against a DSN named by an environment variable
// (CHRONICLE_TEST_POSTGRES_DSN, CHRONICLE_TEST_MONGO_DSN,
// CHRONICLE_TEST_REDIS_DSN) and t.Skip from inside the opener -- not fail --
// when that variable is unset or the service behind it cannot be reached.
// This is what "skipping any backend whose service is not running" means in
// practice: the skip happens per-subtest, so `go test -v` names exactly
// which backends ran and which were skipped, and running with only sqlite
// available is an expected, acceptable result rather than a partial failure.
func backends(t *testing.T) map[string]func(t *testing.T) store.Store {
	t.Helper()
	return map[string]func(t *testing.T) store.Store{
		"sqlite":   openSQLite,
		"postgres": openPostgres,
		"mongo":    openMongo,
		"redis":    openRedis,
	}
}

// openSQLite opens a migrated, file-backed SQLite store in a fresh temp
// directory, so nothing here ever collides with another test's data.
func openSQLite(t *testing.T) store.Store {
	t.Helper()
	ctx := context.Background()

	dsn := filepath.Join(t.TempDir(), "chronicle_scope_behaviour.db")
	drv := sqlitedriver.New()
	if err := drv.Open(ctx, dsn); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove.Open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := sqlite.New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	return s
}

// openPostgres opens a migrated postgres store against
// CHRONICLE_TEST_POSTGRES_DSN (e.g. "postgres://user:pass@localhost:5432/db?sslmode=disable"),
// skipping when that variable is unset or the server is unreachable.
func openPostgres(t *testing.T) store.Store {
	t.Helper()

	dsn := os.Getenv("CHRONICLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CHRONICLE_TEST_POSTGRES_DSN not set, skipping postgres")
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	drv := pgdriver.New()
	if err := drv.Open(dialCtx, dsn); err != nil {
		t.Skipf("postgres unreachable at CHRONICLE_TEST_POSTGRES_DSN: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Skipf("grove.Open postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := chroniclepostgres.New(db)
	if err := s.Ping(dialCtx); err != nil {
		t.Skipf("postgres ping failed: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	return s
}

// openMongo opens a migrated mongo store against CHRONICLE_TEST_MONGO_DSN
// (e.g. "mongodb://localhost:27017/chronicle_test"), skipping when that
// variable is unset or the server is unreachable.
func openMongo(t *testing.T) store.Store {
	t.Helper()

	dsn := os.Getenv("CHRONICLE_TEST_MONGO_DSN")
	if dsn == "" {
		t.Skip("CHRONICLE_TEST_MONGO_DSN not set, skipping mongo")
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	drv := mongodriver.New()
	if err := drv.Open(dialCtx, dsn); err != nil {
		t.Skipf("mongo unreachable at CHRONICLE_TEST_MONGO_DSN: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Skipf("grove.Open mongo: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := chroniclemongo.New(db)
	if err := s.Ping(dialCtx); err != nil {
		t.Skipf("mongo ping failed: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate mongo: %v", err)
	}
	return s
}

// openRedis opens a redis store against CHRONICLE_TEST_REDIS_DSN (e.g.
// "redis://localhost:6379/0"), skipping when that variable is unset or the
// server is unreachable. Redis has no schema to migrate.
func openRedis(t *testing.T) store.Store {
	t.Helper()

	dsn := os.Getenv("CHRONICLE_TEST_REDIS_DSN")
	if dsn == "" {
		t.Skip("CHRONICLE_TEST_REDIS_DSN not set, skipping redis")
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	drv := redisdriver.New()
	if err := drv.Open(dialCtx, dsn); err != nil {
		t.Skipf("redis unreachable at CHRONICLE_TEST_REDIS_DSN: %v", err)
	}
	kvStore, err := kv.Open(drv)
	if err != nil {
		t.Skipf("kv.Open redis: %v", err)
	}
	t.Cleanup(func() { _ = kvStore.Close() })

	s := chronicleredis.New(kvStore)
	if err := s.Ping(dialCtx); err != nil {
		t.Skipf("redis ping failed: %v", err)
	}
	return s
}

// seedEventIn creates a fresh stream scoped to appID/tenantID and appends
// one event into it. Every call mints its own stream ID, so the
// UNIQUE(stream_id, sequence) constraint postgres, sqlite and mongo all
// enforce is satisfied trivially -- two calls never share a stream, so they
// never share a sequence either, regardless of scope.
func seedEventIn(t *testing.T, s store.Store, appID, tenantID string) {
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

	event := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  streamID,
		Sequence:  1,
		Hash:      "seed",
		Timestamp: time.Now().UTC(),
		AppID:     appID,
		TenantID:  tenantID,
		Action:    "test.seed",
		Resource:  "test.resource",
		Category:  "test",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
	}
	if err := s.Append(ctx, event); err != nil {
		t.Fatalf("append event for %s/%s: %v", appID, tenantID, err)
	}
}

// An empty AppID on a query is not "the current app". This pins what each
// backend actually returns for one, because extension/contract/scope.go
// refuses an unresolvable app claim on the strength of it, and a future
// contributor who thinks that refusal is over-strict should be able to find
// out here what the alternative does rather than reason about it.
//
// This asserts observed behaviour, not desired behaviour. If a backend
// changes, this test failing is the notification.
func TestEmptyAppIDScopeBehaviour(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			ctx := context.Background()

			seedEventIn(t, s, "app-1", "tenant-a")
			seedEventIn(t, s, "app-2", "tenant-b")

			res, err := s.Query(ctx, &audit.Query{Limit: 100})
			if err != nil {
				t.Fatalf("Query with empty scope: %v", err)
			}

			apps := map[string]bool{}
			for _, e := range res.Events {
				apps[e.AppID] = true
			}

			// Record the answer plainly. Two apps means an empty AppID
			// matches EVERY app, which is the behaviour the contract's
			// PERMISSION_DENIED exists to prevent reaching.
			if len(apps) == 2 {
				t.Logf("%s: empty AppID returns every app (%d events across %d apps)",
					name, len(res.Events), len(apps))
			} else {
				t.Errorf("%s: empty AppID returned %d apps, not the 2 seeded. "+
					"If this backend now scopes an empty AppID to nothing, that is a "+
					"behaviour change worth knowing about: update this test and check "+
					"whether extension/contract/scope.go's refusal is still needed",
					name, len(apps))
			}

			// The same question for tenant, which is the dimension the
			// contract allows to be empty on purpose.
			res, err = s.Query(ctx, &audit.Query{AppID: "app-1", Limit: 100})
			if err != nil {
				t.Fatalf("Query with empty tenant: %v", err)
			}
			t.Logf("%s: AppID set and TenantID empty returns %d events", name, len(res.Events))
			for _, e := range res.Events {
				if e.AppID != "app-1" {
					t.Errorf("%s: an empty TenantID reached outside its app, to %q. "+
						"That is a cross-app leak, not an app-wide view", name, e.AppID)
				}
			}
		})
	}
}
