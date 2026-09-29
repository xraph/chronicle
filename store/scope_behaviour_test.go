package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate" // registers the sqlite migrate executor
	"github.com/xraph/grove/kv"
	"github.com/xraph/grove/kv/drivers/redisdriver"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/internal/pgtest"
	"github.com/xraph/chronicle/store"
	chroniclemongo "github.com/xraph/chronicle/store/mongo"
	chroniclepostgres "github.com/xraph/chronicle/store/postgres"
	chronicleredis "github.com/xraph/chronicle/store/redis"
	"github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/stream"
)

// chronicleKeyPrefix is every key store/redis writes, per
// store/redis/keys.go (chronicle:evt:, chronicle:str:, chronicle:z:evt:all,
// and the rest -- all of them start here). Duplicated as a literal because
// the individual prefix constants in that package are unexported; this is
// the one string this test relies on staying true of them.
const chronicleKeyPrefix = "chronicle:"

// backends returns every store backend this test can exercise, keyed by
// name, paired with an opener that returns the store plus an optional
// per-stream cleanup func. sqlite needs no external service and always
// runs. postgres, mongo and redis are each gated by an environment
// variable naming a DSN (CHRONICLE_TEST_POSTGRES_DSN,
// CHRONICLE_TEST_MONGO_DSN, CHRONICLE_TEST_REDIS_DSN).
//
// An UNSET variable is the only thing that produces a t.Skip: it means
// nobody asked this backend to run. Once a variable IS set, the caller
// asked for that backend by name, so every failure past that point --
// dial, open, ping, migrate -- calls t.Fatalf, not t.Skip, uniformly (no
// special case for Migrate vs. connect/ping). A skip and a failure look
// identical to `go test ./...` without -v, and a characterization test
// exists to record what a live backend actually does: collapsing "nobody
// asked" and "asked, and it's broken" into the same silent skip would let
// a broken backend pass as merely untested.
//
// The opener's second return value lets the test remove exactly the
// stream (and its one event) seedEventIn just created, by stream ID, on a
// backend that persists across runs (postgres, mongo) -- without it, a
// fixed scope would eventually collide with UNIQUE(app_id, tenant_id) on
// chronicle_streams, which every SQL-shaped backend enforces. It is nil
// where store.Store's own append-only surface (see audit.Store's "no
// Update or Delete exists") is genuinely all there is, or where cleanup
// happens a different way; each opener explains which and why.
func backends(t *testing.T) map[string]func(t *testing.T) (store.Store, func(ctx context.Context, streamID id.ID)) {
	t.Helper()
	return map[string]func(t *testing.T) (store.Store, func(ctx context.Context, streamID id.ID)){
		"sqlite":   openSQLite,
		"postgres": openPostgres,
		"mongo":    openMongo,
		"redis":    openRedis,
	}
}

// openSQLite opens a migrated, file-backed SQLite store in a fresh temp
// directory. t.TempDir() removes it when the test ends, so a run's rows
// never outlive the run and there is nothing for a stream-level cleanup to
// do. Its cleanup func is always nil by design, not omission: every
// backend's opener shares this return shape so backends(t) can hold them in
// one map.
//
//nolint:unparam // see the paragraph above: nil here is deliberate.
func openSQLite(t *testing.T) (store.Store, func(context.Context, id.ID)) {
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
	return s, nil
}

// openPostgres opens a migrated postgres store against
// CHRONICLE_TEST_POSTGRES_DSN, confined to a schema of its own that is
// dropped when the test ends (see internal/pgtest). Skips only when that
// variable is unset; every failure once it is set (dial, open, ping,
// migrate) is a t.Fatalf, per the rule documented on backends.
func openPostgres(t *testing.T) (store.Store, func(context.Context, id.ID)) {
	t.Helper()

	dsn := os.Getenv("CHRONICLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CHRONICLE_TEST_POSTGRES_DSN not set, skipping postgres")
	}
	dsn = pgtest.Schema(t, dsn)

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	drv := pgdriver.New()
	if err := drv.Open(dialCtx, dsn); err != nil {
		t.Fatalf("open postgres at CHRONICLE_TEST_POSTGRES_DSN: %v", err)
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
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}

	// Precise cleanup by stream ID via the raw driver: store.Store itself
	// has no Delete, but the pgdriver.PgDB this store was built on does.
	// Scoped to stream_id, so it can only ever remove rows this run just
	// created, never another run's or another test's.
	cleanup := func(ctx context.Context, streamID id.ID) {
		if _, err := drv.Exec(ctx, "DELETE FROM chronicle_events WHERE stream_id = $1", streamID.String()); err != nil {
			t.Logf("postgres cleanup: delete events for stream %s: %v", streamID, err)
		}
		if _, err := drv.Exec(ctx, "DELETE FROM chronicle_streams WHERE id = $1", streamID.String()); err != nil {
			t.Logf("postgres cleanup: delete stream %s: %v", streamID, err)
		}
	}
	return s, cleanup
}

// openMongo opens a migrated mongo store against CHRONICLE_TEST_MONGO_DSN.
// Skips only when that variable is unset; every failure once it is set
// (dial, open, ping, migrate) is a t.Fatalf, per the rule documented on
// backends.
func openMongo(t *testing.T) (store.Store, func(context.Context, id.ID)) {
	t.Helper()

	dsn := os.Getenv("CHRONICLE_TEST_MONGO_DSN")
	if dsn == "" {
		t.Skip("CHRONICLE_TEST_MONGO_DSN not set, skipping mongo")
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	drv := mongodriver.New()
	if err := drv.Open(dialCtx, dsn); err != nil {
		t.Fatalf("open mongo at CHRONICLE_TEST_MONGO_DSN: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove.Open mongo: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := chroniclemongo.New(db)
	if err := s.Ping(dialCtx); err != nil {
		t.Fatalf("mongo ping failed: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate mongo: %v", err)
	}

	// Precise cleanup by stream ID via the raw driver, same reasoning as
	// openPostgres: store.Store has no Delete, but the *mongo.Collection
	// this store was built on does. The collection and field names below
	// (chronicle_events/chronicle_streams, stream_id, _id) mirror
	// store/mongo/store.go's colEvents/colStreams constants and
	// store/mongo/models.go's bson tags; they are unexported there, so
	// this is a deliberate, narrow duplication rather than an import.
	cleanup := func(ctx context.Context, streamID id.ID) {
		if _, err := drv.Collection("chronicle_events").DeleteMany(ctx, bson.M{"stream_id": streamID.String()}); err != nil {
			t.Logf("mongo cleanup: delete events for stream %s: %v", streamID, err)
		}
		if _, err := drv.Collection("chronicle_streams").DeleteMany(ctx, bson.M{"_id": streamID.String()}); err != nil {
			t.Logf("mongo cleanup: delete stream %s: %v", streamID, err)
		}
	}
	return s, cleanup
}

// openRedis opens a redis store against CHRONICLE_TEST_REDIS_DSN. Skips
// only when that variable is unset; every failure once it is set (dial,
// open, ping) is a t.Fatalf, per the rule documented on backends. Redis
// has no schema to migrate. Its cleanup func is always nil by design:
// redis cleans up via a prefix-scoped delete registered below instead of a
// per-stream func -- see the comments further down in this function.
//
// Before returning, this refuses (t.Fatalf) to proceed at all if the
// target database holds any key outside chronicle's own "chronicle:"
// prefix, and its cleanup only ever deletes keys under that same prefix --
// never a whole-database flush. Both checks are enforced in code, not
// merely documented: see requireOnlyChronicleKeys and deleteByPrefix.
func openRedis(t *testing.T) (store.Store, func(context.Context, id.ID)) {
	t.Helper()

	dsn := os.Getenv("CHRONICLE_TEST_REDIS_DSN")
	if dsn == "" {
		t.Skip("CHRONICLE_TEST_REDIS_DSN not set, skipping redis")
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	drv := redisdriver.New()
	if err := drv.Open(dialCtx, dsn); err != nil {
		t.Fatalf("open redis at CHRONICLE_TEST_REDIS_DSN: %v", err)
	}
	kvStore, err := kv.Open(drv)
	if err != nil {
		t.Fatalf("kv.Open redis: %v", err)
	}
	t.Cleanup(func() { _ = kvStore.Close() })

	s := chronicleredis.New(kvStore)
	if err := s.Ping(dialCtx); err != nil {
		t.Fatalf("redis ping failed: %v", err)
	}

	// Refuse to touch this database at all if it holds anything this test
	// did not write itself. Cleanup below deletes every key under
	// "chronicle:", so before writing a single byte, confirm that prefix
	// is the only thing here -- the default DSN a developer reaches for
	// first, redis://localhost:6379/0, is on THIS machine an unrelated
	// project's live redis, and this guard is what stops that from being
	// silently emptied.
	rdb := redisdriver.UnwrapClient(kvStore)
	requireOnlyChronicleKeys(dialCtx, t, rdb, dsn)

	// Cleanup is prefix-bounded, not a whole-database flush: SCAN for
	// "chronicle:*" and DEL exactly what comes back. Even if the guard
	// above were somehow bypassed, this can still never remove a
	// non-chronicle key -- the two safeguards are independent, not one
	// relying on the other.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		deleteByPrefix(cleanupCtx, t, rdb, chronicleKeyPrefix)
	})

	return s, nil
}

// requireOnlyChronicleKeys scans the database dialCtx/rdb is connected to
// and t.Fatalf's, naming the DSN's host, port and db index (never its
// password), the moment it finds one key that does not start with
// chronicleKeyPrefix. It stops at the first foreign key rather than
// scanning to completion, so a misdirected DSN pointed at a large,
// unrelated database fails fast instead of paying for a full scan.
func requireOnlyChronicleKeys(ctx context.Context, t *testing.T, rdb goredis.UniversalClient, dsn string) {
	t.Helper()

	opts, err := goredis.ParseURL(dsn)
	if err != nil {
		t.Fatalf("parse CHRONICLE_TEST_REDIS_DSN: %v", err)
	}

	var cursor uint64
	for {
		keys, next, err := rdb.Scan(ctx, cursor, "*", 1000).Result()
		if err != nil {
			t.Fatalf("scan redis %s db %d for foreign keys: %v", opts.Addr, opts.DB, err)
		}
		for _, key := range keys {
			if !strings.HasPrefix(key, chronicleKeyPrefix) {
				t.Fatalf("refusing to run against redis %s db %d: found a non-chronicle key %q. "+
					"This test's cleanup deletes everything under the %q prefix in whatever "+
					"database CHRONICLE_TEST_REDIS_DSN names, so it will not run against one "+
					"that already holds something else. Point CHRONICLE_TEST_REDIS_DSN at a "+
					"redis database dedicated to chronicle testing.",
					opts.Addr, opts.DB, key, chronicleKeyPrefix)
			}
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}

// deleteByPrefix scans for every key starting with prefix and deletes
// exactly those, using SCAN (not KEYS, which blocks the server) so this
// stays safe to run against a live instance.
func deleteByPrefix(ctx context.Context, t *testing.T, rdb goredis.UniversalClient, prefix string) {
	t.Helper()

	var cursor uint64
	for {
		keys, next, err := rdb.Scan(ctx, cursor, prefix+"*", 1000).Result()
		if err != nil {
			t.Logf("redis cleanup: scan %q: %v", prefix+"*", err)
			return
		}
		if len(keys) > 0 {
			if err := rdb.Del(ctx, keys...).Err(); err != nil {
				t.Logf("redis cleanup: del %d keys: %v", len(keys), err)
			}
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}

// seedEventIn creates a fresh stream scoped to appID/tenantID and appends
// one event into it, returning the stream ID so the caller can register
// cleanup. Every call mints its own stream ID, so the UNIQUE(stream_id,
// sequence) constraint postgres, sqlite and mongo all enforce is satisfied
// trivially -- two calls never share a stream, so they never share a
// sequence either, regardless of scope.
func seedEventIn(t *testing.T, s store.Store, appID, tenantID string) id.ID {
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
	return streamID
}

// newRunSuffix returns a short, random hex token unique to this call, so
// two runs against the same persistent database (postgres, mongo, redis)
// never seed the same app/tenant scope. Without it, a fixed "app-1"/
// "tenant-a" pair collides with UNIQUE(app_id, tenant_id) on
// chronicle_streams on the second run: CreateStream fails with a
// duplicate-key error during setup, before the query this test is actually
// about is ever reached, and a persistent backend fails this test every
// time after the first for a reason that has nothing to do with what it
// records.
func newRunSuffix(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate run suffix: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// An empty AppID on a query is not "the current app". This pins what each
// backend actually returns for one, because extension/contract/scope.go
// refuses an unresolvable app claim on the strength of it, and a future
// contributor who thinks that refusal is over-strict should be able to find
// out here what the alternative does rather than reason about it.
//
// This asserts observed behaviour, not desired behaviour. If a backend
// changes, this test failing is the notification.
//
// The seeded app and tenant ids carry a per-run random suffix (see
// newRunSuffix) rather than fixed literals, and every check below matches
// against those variables rather than hardcoded strings. On a persistent
// backend (postgres, mongo, redis, once pointed at a real service) the
// store already holds rows from prior runs by the time this one seeds its
// own two events, so "empty AppID matches every app" is checked by asking
// whether THIS run's two apps both came back -- not by counting how many
// distinct apps are visible in total, which would drift upward with every
// run that ever touched the database and prove nothing about what an empty
// AppID does. The same discipline applies to every t.Logf below: each
// count it prints describes this run's own rows, never a running total.
func TestEmptyAppIDScopeBehaviour(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			s, cleanupStream := open(t)
			ctx := context.Background()

			suffix := newRunSuffix(t)
			app1, tenant1 := "app-1-"+suffix, "tenant-a-"+suffix
			app2, tenant2 := "app-2-"+suffix, "tenant-b-"+suffix

			stream1 := seedEventIn(t, s, app1, tenant1)
			stream2 := seedEventIn(t, s, app2, tenant2)
			if cleanupStream != nil {
				t.Cleanup(func() {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					cleanupStream(cleanupCtx, stream1)
					cleanupStream(cleanupCtx, stream2)
				})
			}

			res, err := s.Query(ctx, &audit.Query{Limit: 100})
			if err != nil {
				t.Fatalf("Query with empty scope: %v", err)
			}

			// Count only whether THIS run's two apps came back, not how
			// many distinct apps the result carries in total -- a
			// persistent backend can carry other apps from other runs,
			// and that total says nothing about what an empty AppID does.
			seenApp1, seenApp2 := false, false
			matched := 0
			for _, e := range res.Events {
				switch e.AppID {
				case app1:
					seenApp1 = true
					matched++
				case app2:
					seenApp2 = true
					matched++
				}
			}

			// Record the answer plainly. Both apps coming back means an
			// empty AppID matches EVERY app, which is the behaviour the
			// contract's PERMISSION_DENIED exists to prevent reaching.
			if seenApp1 && seenApp2 {
				t.Logf("%s: empty AppID returns every app (this run's %d seeded events, across its 2 apps, both came back)",
					name, matched)
			} else {
				t.Errorf("%s: empty AppID did not return both of this run's seeded apps "+
					"(app1 seen=%v, app2 seen=%v, %d of this run's events matched). "+
					"If this backend now scopes an empty AppID to nothing, that is a "+
					"behaviour change worth knowing about: update this test and check "+
					"whether extension/contract/scope.go's refusal is still needed",
					name, seenApp1, seenApp2, matched)
			}

			// The same question for tenant, which is the dimension the
			// contract allows to be empty on purpose. app1 carries this
			// run's random suffix, so this count is always this run's own
			// single seeded event -- it cannot pick up another run's rows.
			res, err = s.Query(ctx, &audit.Query{AppID: app1, Limit: 100})
			if err != nil {
				t.Fatalf("Query with empty tenant: %v", err)
			}
			t.Logf("%s: AppID set and TenantID empty returns %d events for this run's app", name, len(res.Events))
			for _, e := range res.Events {
				if e.AppID != app1 {
					t.Errorf("%s: an empty TenantID reached outside its app, to %q. "+
						"That is a cross-app leak, not an app-wide view", name, e.AppID)
				}
			}
		})
	}
}
