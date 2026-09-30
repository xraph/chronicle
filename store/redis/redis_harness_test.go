package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/xraph/grove/kv"
	"github.com/xraph/grove/kv/drivers/redisdriver"

	"github.com/xraph/chronicle/internal/redistest"
)

// openTestStore opens a Store against CHRONICLE_TEST_REDIS_DSN, or skips when
// that variable is unset. Once it is set, every failure is fatal: a skip and a
// failure look the same without -v, and a broken backend must not pass as
// untested.
//
// The store's keys sit under a prefix no other test uses (see
// redistest.Isolate), so tests running at the same time, from this package,
// another package or another checkout, never see or delete each other's keys.
// Migrate and every count stay inside that prefix too, so each store starts
// empty.
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

	if err := kvStore.Ping(ctx); err != nil {
		t.Fatalf("redis ping failed: %v", err)
	}
	rdb := redisdriver.UnwrapClient(kvStore)
	s := New(kvStore, WithKeyPrefix(redistest.Isolate(ctx, t, rdb, dsn)))

	if migrate {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	return s, rdb
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
