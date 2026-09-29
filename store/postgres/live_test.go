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

// liveDSNEnv names the PostgreSQL the live tests write to. Unset, they skip,
// so `go test ./...` passes on a machine with no database.
//
//	CHRONICLE_TEST_POSTGRES_DSN=postgres://chronicle:chronicle@localhost:55432/chronicle_test go test ./store/postgres/...
const liveDSNEnv = "CHRONICLE_TEST_POSTGRES_DSN"

// openLivePostgres returns an unmigrated store confined to a schema of its
// own, dropped again when the test ends, along with the DSN pinned to that
// schema. It skips when the variable is unset.
//
// It refuses the default port. On the machine these tests were written on,
// that is another project's live database.
//
// Every test in a run shares whatever database the DSN names, so each one
// creates a random schema and puts it alone on the search_path. The
// migrations create their tables unqualified, so the tables land inside it.
func openLivePostgres(t *testing.T) (*Store, string) {
	t.Helper()

	dsn := os.Getenv(liveDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set", liveDSNEnv)
	}
	if strings.Contains(dsn, ":5432") {
		t.Fatalf("%s points at the default port; refusing to write to what may be a live database", liveDSNEnv)
	}

	ctx := context.Background()

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("random schema suffix: %v", err)
	}
	schema := "chronicle_test_" + hex.EncodeToString(b[:])
	quoted := pgx.Identifier{schema}.Sanitize()

	liveExec(ctx, t, dsn, "CREATE SCHEMA "+quoted)
	// Cleanups run last registered first, so this fires after the pool below
	// has closed. Dropping a schema under live connections blocks on them.
	t.Cleanup(func() {
		liveExec(context.Background(), t, dsn, "DROP SCHEMA "+quoted+" CASCADE")
	})

	scoped, err := pinSearchPath(dsn, schema)
	if err != nil {
		t.Fatalf("pin %s to schema %s: %v", liveDSNEnv, schema, err)
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

	return New(db), scoped
}

// liveExec runs one statement on a throwaway connection.
func liveExec(ctx context.Context, t *testing.T, dsn, stmt string, args ...any) {
	t.Helper()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, stmt, args...); err != nil {
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
