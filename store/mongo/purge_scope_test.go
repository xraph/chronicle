package mongo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"

	"github.com/xraph/chronicle/internal/retentiontest"
)

// purgeScopeURIEnv names the server the purge scope test runs against, e.g.
//
//	CHRONICLE_TEST_MONGO_URI=mongodb://localhost:57017
const purgeScopeURIEnv = "CHRONICLE_TEST_MONGO_URI"

func TestEventsOlderThanMatchesScopeExactly(t *testing.T) {
	s, run := openPurgeScopeStore(t)
	retentiontest.PurgeScope(t, s, run)
}

// openPurgeScopeStore returns a migrated store on a database created for this
// test, or skips when purgeScopeURIEnv is unset. Only that database is dropped
// on cleanup, whatever the URI's own path names.
func openPurgeScopeStore(t *testing.T) (*Store, string) {
	t.Helper()

	uri := os.Getenv(purgeScopeURIEnv)
	if uri == "" {
		t.Skip(purgeScopeURIEnv + " not set, skipping mongo")
	}

	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate database suffix: %v", err)
	}
	run := hex.EncodeToString(b[:])

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mdb := mongodriver.New()
	if err := mdb.Open(ctx, uri, mongodriver.WithDatabase("chronicle_purge_scope_"+run)); err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	db, err := grove.Open(mdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := mdb.Database().Drop(cleanupCtx); err != nil {
			t.Logf("drop %s: %v", mdb.DatabaseName(), err)
		}
		_ = db.Close()
	})

	s := New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s, run
}
