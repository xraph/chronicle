// Package redistest gives each package that tests against a live redis a
// logical database of its own.
//
// `go test ./...` runs packages in parallel. The redis store keeps its keys
// under fixed names (one "chronicle:z:evt:all" set per database) and Migrate
// walks every key it owns, so two packages sharing a database read each
// other's events and delete each other's keys. A key prefix per test cannot
// fix that; a database per package can.
package redistest

import (
	"net/url"
	"strconv"
	"testing"

	goredis "github.com/redis/go-redis/v9"
)

// Offsets from the database CHRONICLE_TEST_REDIS_DSN names, one per package.
// Keep them distinct: two packages on one offset collide again.
const (
	OffsetStoreRedis = 0 // store/redis
	OffsetStore      = 1 // store
	OffsetChronicle  = 2 // the root chronicle package
)

// PackageDSN returns dsn pointed offset databases past the one it names. With
// redis://host:port/0 and offset 2 that is redis://host:port/2. A DSN it
// cannot parse fails the test.
func PackageDSN(t testing.TB, dsn string, offset int) string {
	t.Helper()

	opts, err := goredis.ParseURL(dsn)
	if err != nil {
		t.Fatalf("parse CHRONICLE_TEST_REDIS_DSN: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse CHRONICLE_TEST_REDIS_DSN: %v", err)
	}
	u.Path = "/" + strconv.Itoa(opts.DB+offset)
	return u.String()
}
