package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"
)

// dsnEnv points these tests at a live PostgreSQL. Set it and they run; leave
// it unset and they skip, so `go test ./...` still passes on a machine with no
// database anywhere near it.
//
//	CHRONICLE_TEST_POSTGRES_DSN=postgres://chronicle:chronicle@localhost:5432/chronicle_test go test ./store/postgres/...
const dsnEnv = "CHRONICLE_TEST_POSTGRES_DSN"

// newTestStore opens a migrated Postgres store confined to a schema of its own.
//
// The sqlite tests get a brand new file out of t.TempDir every time. There is
// no equivalent here: every test in a run shares whatever database the DSN
// names, and that database may well be one you also poke at by hand. So each
// test creates a schema, puts that schema alone on the connection's
// search_path, and drops it on the way out. The migrations say CREATE TABLE
// with no schema qualifier, so the tables land inside it, and no two tests (or
// two runs, or two people) ever read each other's rows.
func newTestStore(t *testing.T) *Store {
	t.Helper()

	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("%s is not set; point it at a PostgreSQL to run these", dsnEnv)
	}

	ctx := context.Background()
	schema := newSchemaName(t)
	quoted := pgx.Identifier{schema}.Sanitize()

	adminExec(ctx, t, dsn, "CREATE SCHEMA "+quoted)
	// Cleanups run last registered first, so this one fires after the pool
	// below has closed. Dropping a schema out from under live connections
	// would block on their locks.
	t.Cleanup(func() {
		adminExec(context.Background(), t, dsn, "DROP SCHEMA "+quoted+" CASCADE")
	})

	scoped, err := withSearchPath(dsn, schema)
	if err != nil {
		t.Fatalf("scope %s to schema %s: %v", dsnEnv, schema, err)
	}

	pdb := pgdriver.New()
	if err = pdb.Open(ctx, scoped); err != nil {
		t.Fatalf("open postgres: %v", err)
	}

	db, err := grove.Open(pdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// newSchemaName returns an identifier no other test will pick. Random rather
// than derived from t.Name() because a crashed run leaves its schema behind,
// and the next run of the same test should not trip over it.
func newSchemaName(t *testing.T) string {
	t.Helper()

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("random schema suffix: %v", err)
	}
	return "chronicle_test_" + hex.EncodeToString(b[:])
}

// adminExec runs one statement on a throwaway connection to the unscoped DSN.
// Creating and dropping the schema cannot go through the pooled store, which
// is already pinned to the schema in question.
func adminExec(ctx context.Context, t *testing.T, dsn, stmt string) {
	t.Helper()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to %s: %v", dsnEnv, err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, stmt); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}

// withSearchPath pins search_path to schema, in whichever of the two DSN
// spellings pgx was handed. search_path is not a libpq keyword, so pgx passes
// it through as a startup runtime parameter either way.
func withSearchPath(dsn, schema string) (string, error) {
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
