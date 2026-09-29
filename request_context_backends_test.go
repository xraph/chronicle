package chronicle_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate" // registers the sqlite migrate executor

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	sqlitestore "github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/verify"
)

// TestRequestContextVerifiesOnEachBackend records events carrying a user
// agent, request ID and session ID, mixed with events carrying none, under
// both writable schemes, and verifies the chain.
//
// The digest covers those fields whenever any of them is set, so every store
// has to hand them back exactly as they went in, and the SQL stores, which
// recompute the digest inside their own transaction, have to have them on the
// row before they do.
func TestRequestContextVerifiesOnEachBackend(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		runRequestContextProbe(t, memory.New())
	})
	t.Run("sqlite", func(t *testing.T) {
		drv := sqlitedriver.New()
		if err := drv.Open(context.Background(), filepath.Join(t.TempDir(), "rc.db")); err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		db, err := grove.Open(drv)
		if err != nil {
			t.Fatalf("grove open: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		s := sqlitestore.New(db)
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		runRequestContextProbe(t, s)
	})
	forEachBackend(t, runRequestContextProbe)
}

func runRequestContextProbe(t *testing.T, s store.Store) {
	t.Helper()
	for _, scheme := range []hash.Scheme{hash.SchemePlainV4, hash.SchemeHMACV5} {
		t.Run(string(scheme), func(t *testing.T) {
			ctx := context.Background()
			app := "rc-" + id.NewAuditID().String()

			var provider keys.Provider
			if hash.Keyed(scheme) {
				provider = hmacProvider()
			}
			c := openPinChronicle(t, store.NewAdapter(s), scheme, provider)
			if h, ok := s.(interface{ SetHasher(*hash.Chain) }); ok {
				chain, err := hash.NewChain(scheme, provider)
				if err != nil {
					t.Fatalf("NewChain: %v", err)
				}
				h.SetHasher(chain)
			}

			recCtx := scope.WithAppID(ctx, app)
			withRequest := scope.WithRequestID(scope.WithUserAgent(recCtx, "Mozilla/5.0 (X11; Linux) \"quoted\" é"), "req-42")
			for i, rctx := range []context.Context{withRequest, recCtx, withRequest, recCtx} {
				e := &audit.Event{
					Action: "touch", Resource: "doc", Category: "auth", UserID: "u",
					Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
				}
				if i == 2 {
					e.SessionID = "sess-7"
				}
				if err := c.Record(rctx, e); err != nil {
					t.Fatalf("Record %d: %v", i, err)
				}
			}

			report, err := c.VerifyChain(ctx, &verify.Input{AppID: app})
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			if !report.Valid || report.Verified != 4 {
				t.Fatalf("valid=%v verified=%d gaps=%v tampered=%v", report.Valid, report.Verified, report.Gaps, report.Tampered)
			}

			res, err := s.Query(ctx, &audit.Query{AppID: app, SessionID: "sess-7"})
			if err != nil {
				t.Fatalf("Query by session: %v", err)
			}
			if len(res.Events) != 1 || res.Events[0].RequestID != "req-42" || res.Events[0].UserAgent == "" {
				t.Errorf("query by session = %+v, want the one event with its request fields", res.Events)
			}
		})
	}
}
