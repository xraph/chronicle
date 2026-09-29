package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"

	"github.com/xraph/chronicle/internal/retentiontest"
)

// purgeScopeDSNEnv names the database the purge scope test runs against, e.g.
//
//	CHRONICLE_TEST_POSTGRES_DSN=postgres://chronicle:chronicle@localhost:55432/chronicle_test?sslmode=disable
const purgeScopeDSNEnv = "CHRONICLE_TEST_POSTGRES_DSN"

func TestEventsOlderThanMatchesScopeExactly(t *testing.T) {
	s, run := openPurgeScopeStore(t)
	retentiontest.PurgeScope(t, s, run)
}

// openPurgeScopeStore migrates a fresh schema and returns a store pinned to it,
// or skips when purgeScopeDSNEnv is unset. The schema is dropped on cleanup, so
// the test never reads or deletes rows it did not create.
func openPurgeScopeStore(t *testing.T) (*Store, string) {
	t.Helper()

	dsn := os.Getenv(purgeScopeDSNEnv)
	if dsn == "" {
		t.Skip(purgeScopeDSNEnv + " not set, skipping postgres")
	}

	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate schema suffix: %v", err)
	}
	run := hex.EncodeToString(b[:])
	schema := "chronicle_purge_scope_" + run

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pgAdminExec(ctx, t, dsn, "CREATE SCHEMA "+schema)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pgAdminExec(cleanupCtx, t, dsn, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", purgeScopeDSNEnv, err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	pdb := pgdriver.New()
	if openErr := pdb.Open(ctx, u.String()); openErr != nil {
		t.Fatalf("open postgres: %v", openErr)
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
	return s, run
}

// pgAdminExec runs one statement on its own connection to the unpinned DSN.
func pgAdminExec(ctx context.Context, t *testing.T, dsn, stmt string) {
	t.Helper()

	pdb := pgdriver.New()
	if err := pdb.Open(ctx, dsn); err != nil {
		t.Fatalf("open postgres for %q: %v", stmt, err)
	}
	defer func() { _ = pdb.Close() }()

	if _, err := pdb.Exec(ctx, stmt); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}
