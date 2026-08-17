package handler_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/handler"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store/memory"
)

// recordingGuard builds a Guard whose middleware records the routes it saw and
// rejects when deny is true.
type recordingGuard struct {
	mu     sync.Mutex
	seen   []string
	deny   bool
	status int
}

func (g *recordingGuard) guard(name string) handler.Guard {
	return handler.Guard{
		Provider: "test-provider",
		Scopes:   []string{"chronicle:" + name},
		Middleware: func(next forge.Handler) forge.Handler {
			return func(ctx forge.Context) error {
				g.mu.Lock()
				g.seen = append(g.seen, name+" "+ctx.Request().Method+" "+ctx.Request().URL.Path)
				denied := g.deny
				g.mu.Unlock()

				if denied {
					status := g.status
					if status == 0 {
						status = http.StatusForbidden
					}
					return ctx.String(status, "denied")
				}
				return next(ctx)
			}
		},
	}
}

func (g *recordingGuard) classFor(method, path string) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	want := method + " " + path
	for _, entry := range g.seen {
		if strings.HasSuffix(entry, " "+want) {
			return strings.SplitN(entry, " ", 2)[0]
		}
	}
	return ""
}

// newGuardedSetup builds a handler whose three route classes are guarded.
func newGuardedSetup(t *testing.T, g *recordingGuard) *testSetup {
	t.Helper()

	store := memory.New()
	logger := log.NewNoopLogger()
	engine := compliance.NewEngine(store, store, store, logger)
	enforcer := retention.NewEnforcer(store, nil, logger)

	router := forge.NewRouter()
	api := handler.New(handler.Dependencies{
		AuditStore:     store,
		VerifyStore:    store,
		StreamStore:    store,
		ErasureStore:   store,
		RetentionStore: store,
		ReportStore:    store,
		Compliance:     engine,
		Retention:      enforcer,
		Logger:         logger,
		Guards: handler.Guards{
			Read:  g.guard("read"),
			Write: g.guard("write"),
			Admin: g.guard("admin"),
		},
	}, router)
	api.RegisterRoutes(router)

	events := seedEvents(t, store)

	return &testSetup{handler: router.Handler(), store: store, events: events}
}

// TestGuardsBlockEveryRoute pins that a denying guard actually blocks, on every
// route class. forge's WithAuth options only write OpenAPI metadata, so guarding
// has to run as middleware — this test is what proves the wiring enforces.
func TestGuardsBlockEveryRoute(t *testing.T) {
	g := &recordingGuard{deny: true, status: http.StatusForbidden}
	ts := newGuardedSetup(t, g)

	routes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/v1/events", nil},
		{http.MethodGet, "/v1/stats", nil},
		{http.MethodPost, "/v1/events/aggregate", map[string]any{"group_by": []string{"category"}}},
		{http.MethodGet, "/v1/erasures", nil},
		{http.MethodGet, "/v1/retention", nil},
		{http.MethodGet, "/v1/retention/archives", nil},
		{http.MethodGet, "/v1/reports", nil},
		{http.MethodPost, "/v1/retention", map[string]any{"category": "auth", "duration": "1h"}},
		{
			http.MethodPost, "/v1/erasures",
			map[string]any{"subject_id": "s1", "reason": "r", "requested_by": "u"},
		},
		{http.MethodPost, "/v1/retention/enforce", nil},
	}

	for _, r := range routes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			rec := ts.do(t, r.method, r.path, r.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; the guard did not block this route (body %q)",
					rec.Code, rec.Body.String())
			}
		})
	}
}

// TestDestructiveRoutesUseTheAdminGuard pins the classification: the operations
// that destroy or irreversibly alter audit data must sit behind admin, not read.
func TestDestructiveRoutesUseTheAdminGuard(t *testing.T) {
	g := &recordingGuard{}
	ts := newGuardedSetup(t, g)

	cases := []struct {
		method string
		path   string
		body   any
		want   string
	}{
		// Irreversible: purges events, drops a policy, flags a subject erased.
		{http.MethodPost, "/v1/retention/enforce", nil, "admin"},
		{
			http.MethodPost, "/v1/erasures",
			map[string]any{"subject_id": "s1", "reason": "r", "requested_by": "u"}, "admin",
		},

		// Creates records but destroys nothing.
		{http.MethodPost, "/v1/retention", map[string]any{"category": "auth", "duration": "1h"}, "write"},

		// Observation only.
		{http.MethodGet, "/v1/events", nil, "read"},
		{http.MethodGet, "/v1/stats", nil, "read"},
		{http.MethodGet, "/v1/retention", nil, "read"},
		{http.MethodGet, "/v1/erasures", nil, "read"},
		{http.MethodGet, "/v1/retention/archives", nil, "read"},
		{http.MethodGet, "/v1/reports", nil, "read"},
		{http.MethodPost, "/v1/events/aggregate", map[string]any{"group_by": []string{"category"}}, "read"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			ts.do(t, tc.method, tc.path, tc.body)

			got := g.classFor(tc.method, tc.path)
			if got == "" {
				t.Fatalf("%s %s ran through no guard at all", tc.method, tc.path)
			}
			if got != tc.want {
				t.Fatalf("%s %s is guarded as %q, want %q", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

// TestDeletePolicyUsesTheAdminGuard covers the DELETE route separately, since it
// needs a policy to exist first.
func TestDeletePolicyUsesTheAdminGuard(t *testing.T) {
	g := &recordingGuard{}
	ts := newGuardedSetup(t, g)

	rec := ts.do(t, http.MethodPost, "/v1/retention", map[string]any{
		"category": "auth", "duration": "1h",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("savePolicy status = %d: %s", rec.Code, rec.Body.String())
	}

	policies, err := ts.store.ListPolicies(context.Background(), retention.ListPoliciesOpts{})
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}

	path := "/v1/retention/" + policies[0].ID.String()
	ts.do(t, http.MethodDelete, path, nil)

	if got := g.classFor(http.MethodDelete, path); got != "admin" {
		t.Fatalf("DELETE %s is guarded as %q, want %q", path, got, "admin")
	}
}

// TestUnguardedSetupStillServes keeps the zero-Guards case working, since the
// extension is what decides whether an unguarded API may be mounted.
func TestUnguardedSetupStillServes(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/events", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestGuardsUnprotectedNamesEveryEmptyClass(t *testing.T) {
	var none handler.Guards
	if got := none.Unprotected(); len(got) != 3 {
		t.Fatalf("Unprotected() = %v, want all three classes", got)
	}
	if !none.IsZero() {
		t.Fatal("a zero Guards should report IsZero")
	}

	g := &recordingGuard{}
	partial := handler.Guards{Read: g.guard("read")}
	got := partial.Unprotected()
	if len(got) != 2 {
		t.Fatalf("Unprotected() = %v, want write and admin", got)
	}
	if partial.IsZero() {
		t.Fatal("a partially configured Guards should not report IsZero")
	}
}
