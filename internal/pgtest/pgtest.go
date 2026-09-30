// Package pgtest confines each test that writes to a live PostgreSQL to a
// schema of its own.
//
// `go test ./...` runs packages in parallel, and more than one of them opens
// the database CHRONICLE_TEST_POSTGRES_DSN names. Store.Migrate runs every
// migration's ALTER TABLE on each call, so two packages migrating and
// appending in the shared public schema at once can deadlock each other. A
// schema per test gives each one tables nobody else touches.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Schema creates a randomly named schema in the database dsn names, drops it
// again when the test ends, and returns dsn with search_path pinned to it. The
// migrations create their tables unqualified, so they land inside it.
//
// Open the pool on the returned DSN after calling Schema. Cleanups run last
// registered first, so the pool's close then fires before the drop, which
// would otherwise block on the pool's open connections.
//
// It refuses the default port. On the machine these tests were written on,
// that is another project's live database.
func Schema(t testing.TB, dsn string) string {
	t.Helper()

	if strings.Contains(dsn, ":5432") {
		t.Fatalf("CHRONICLE_TEST_POSTGRES_DSN points at the default port; refusing to write to what may be a live database")
	}

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("random schema suffix: %v", err)
	}
	schema := "chronicle_test_" + hex.EncodeToString(b[:])
	quoted := pgx.Identifier{schema}.Sanitize()

	exec(t, dsn, "CREATE SCHEMA "+quoted)
	t.Cleanup(func() { exec(t, dsn, "DROP SCHEMA IF EXISTS "+quoted+" CASCADE") })

	scoped, err := pinSearchPath(dsn, schema)
	if err != nil {
		t.Fatalf("pin CHRONICLE_TEST_POSTGRES_DSN to schema %s: %v", schema, err)
	}
	return scoped
}

// exec runs one statement on a throwaway connection.
func exec(t testing.TB, dsn, stmt string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, stmt); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}

// pinSearchPath sets search_path in whichever DSN spelling pgx was handed. It
// is not a libpq keyword, so pgx passes it through as a runtime parameter.
func pinSearchPath(dsn, schema string) (string, error) {
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		return dsn + " search_path=" + schema, nil
	}

	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
