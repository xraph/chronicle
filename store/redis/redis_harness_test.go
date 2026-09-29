package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/xraph/grove/kv"
	"github.com/xraph/grove/kv/drivers/redisdriver"

	"github.com/xraph/chronicle/internal/redistest"
)

// chronicleKeyPrefix is the prefix every key in keys.go starts with. The
// guard and the cleanup below both lean on it staying true.
const chronicleKeyPrefix = "chronicle:"

// openTestStore opens a Store against CHRONICLE_TEST_REDIS_DSN, or skips when
// that variable is unset. Once it is set, every failure is fatal: a skip and a
// failure look the same without -v, and a broken backend must not pass as
// untested.
//
// It refuses to run against a database holding any key outside "chronicle:",
// and its cleanup deletes only keys under that prefix, never the whole
// database. On the machine this was written on, the DSN a developer reaches
// for first (localhost:6379) is another project's live redis. The two guards
// are independent so that neither one failing can empty it.
//
// migrate controls whether Migrate runs before the store is handed back. The
// migration tests need a store that has not been migrated yet, so they can
// seed the old key format first.
func openTestStore(t *testing.T, migrate bool) (*Store, goredis.UniversalClient) {
	t.Helper()

	dsn := os.Getenv("CHRONICLE_TEST_REDIS_DSN")
	if dsn == "" {
		t.Skip("CHRONICLE_TEST_REDIS_DSN not set, skipping redis")
	}
	// A database of this package's own: see redistest.
	dsn = redistest.PackageDSN(t, dsn, redistest.OffsetStoreRedis)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	drv := redisdriver.New()
	if err := drv.Open(ctx, dsn); err != nil {
		t.Fatalf("open redis at CHRONICLE_TEST_REDIS_DSN: %v", err)
	}
	kvStore, err := kv.Open(drv)
	if err != nil {
		t.Fatalf("kv.Open redis: %v", err)
	}
	t.Cleanup(func() { _ = kvStore.Close() })

	s := New(kvStore)
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("redis ping failed: %v", err)
	}

	requireOnlyChronicleKeys(ctx, t, s.rdb, dsn)

	// Start from an empty chronicle keyspace and leave one behind. Migrate
	// looks at every stream, event and policy in the database, so a leftover
	// from an earlier test would leak into the next test's result.
	deleteByPrefix(ctx, t, s.rdb, chronicleKeyPrefix)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		deleteByPrefix(cleanupCtx, t, s.rdb, chronicleKeyPrefix)
	})

	if migrate {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	return s, s.rdb
}

// requireOnlyChronicleKeys fails the test the moment it finds a key outside
// chronicleKeyPrefix. The message names host, port and db, never the password.
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
					"These tests delete everything under %q in whatever database "+
					"CHRONICLE_TEST_REDIS_DSN names. Point it at a redis database "+
					"dedicated to chronicle testing.",
					opts.Addr, opts.DB, key, chronicleKeyPrefix)
			}
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}

// deleteByPrefix deletes exactly the keys starting with prefix. It uses SCAN
// rather than KEYS so it never blocks the server.
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

// runSuffix returns a random hex token, so app and tenant IDs from one run
// never meet those of another.
func runSuffix(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate run suffix: %v", err)
	}
	return hex.EncodeToString(b[:])
}
