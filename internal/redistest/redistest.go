// Package redistest keeps each test that runs against a live redis inside a
// key prefix of its own.
//
// `go test ./...` runs packages in parallel, and two checkouts can run against
// the same redis at once. A redis store sees every key under its prefix:
// Migrate walks them all and the indexes are one set per prefix. So each test
// store gets a fresh prefix through store/redis.WithKeyPrefix, and deletes only
// that prefix when it ends.
package redistest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Root is the prefix every key a test writes starts with. It matches
// store/redis.DefaultKeyPrefix, which this package can't import: the redis
// package's own tests import this one.
const Root = "chronicle:"

// Isolate returns a key prefix under Root that no other test uses, and
// deletes every key under it when t ends. Pass the result to
// store/redis.WithKeyPrefix.
//
// Before handing it back, it refuses (t.Fatalf) a database holding any key
// outside Root. On the machine these tests were written on, the DSN a
// developer reaches for first (localhost:6379) is another project's live
// redis. The guard and the prefix-scoped delete are independent, so neither
// one failing can empty it. dsn is only used to name the database in that
// message, without its password.
func Isolate(ctx context.Context, t testing.TB, rdb goredis.UniversalClient, dsn string) string {
	t.Helper()

	requireOnlyRootKeys(ctx, t, rdb, dsn)

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("random redis key prefix: %v", err)
	}
	prefix := Root + "test-" + hex.EncodeToString(b[:]) + ":"

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		deleteByPrefix(cleanupCtx, t, rdb, prefix)
	})
	return prefix
}

// requireOnlyRootKeys fails the test the moment it finds a key outside Root.
// It stops at the first one, so a DSN pointed at a large unrelated database
// fails fast instead of paying for a full scan.
func requireOnlyRootKeys(ctx context.Context, t testing.TB, rdb goredis.UniversalClient, dsn string) {
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
			if !strings.HasPrefix(key, Root) {
				t.Fatalf("refusing to run against redis %s db %d: found a non-chronicle key %q. "+
					"These tests write under %q in whatever database CHRONICLE_TEST_REDIS_DSN "+
					"names. Point it at a redis database dedicated to chronicle testing.",
					opts.Addr, opts.DB, key, Root)
			}
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}

// deleteByPrefix deletes exactly the keys starting with prefix, using SCAN
// rather than KEYS so it never blocks the server. The prefixes Isolate makes
// are hex, so none holds a glob character.
func deleteByPrefix(ctx context.Context, t testing.TB, rdb goredis.UniversalClient, prefix string) {
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
