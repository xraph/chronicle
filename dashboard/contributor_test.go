package dashboard_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contributor"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	chronicledash "github.com/xraph/chronicle/dashboard"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store/memory"
)

const (
	viewerApp    = "app_viewer"
	viewerTenant = "tenant_viewer"
	otherApp     = "app_other"
)

type dashSetup struct {
	contributor *chronicledash.Contributor
	store       *memory.Store
}

// newDashSetup builds a contributor over an in-memory store. mutations mirrors
// the operator's explicit opt-in.
func newDashSetup(t *testing.T, mutations bool) *dashSetup {
	t.Helper()

	mem := memory.New()
	logger := log.NewNoopLogger()
	engine := compliance.NewEngine(mem, mem, mem, logger)
	enforcer := retention.NewEnforcer(mem, nil, logger)

	c := chronicledash.New(
		chronicledash.NewManifest(),
		mem,
		engine,
		enforcer,
		chronicledash.Config{AllowMutations: mutations},
	)

	return &dashSetup{contributor: c, store: mem}
}

// viewerCtx is a request context scoped to the viewing tenant.
func viewerCtx() context.Context {
	ctx := scope.WithAppID(context.Background(), viewerApp)
	return scope.WithTenantID(ctx, viewerTenant)
}

// seedEvent appends one event. The category is fixed at "auth" because that is
// what the retention policies in these tests match on.
func seedEvent(t *testing.T, mem *memory.Store, appID, tenantID string, age time.Duration) *audit.Event {
	t.Helper()

	e := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  id.NewStreamID(),
		Sequence:  1,
		Hash:      "h",
		AppID:     appID,
		TenantID:  tenantID,
		Action:    "test",
		Resource:  "r",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Timestamp: time.Now().UTC().Add(-age),
	}
	if err := mem.Append(context.Background(), e); err != nil {
		t.Fatalf("append: %v", err)
	}
	return e
}

// TestDashboardPolicyCarriesViewerScope is the critical one. A policy created
// through the dashboard used to carry no AppID at all, and an empty scope means
// "every app" to the purge query — so one operator's dashboard policy would
// delete every tenant's audit history.
func TestDashboardPolicyCarriesViewerScope(t *testing.T) {
	ts := newDashSetup(t, true)

	_, err := ts.contributor.RenderPage(viewerCtx(), "/retention", contributor.Params{
		FormData: map[string]string{
			"action":   "create_policy",
			"category": "auth",
			"duration": "1h",
		},
	})
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	policies, err := ts.store.ListPolicies(context.Background(), retention.ListPoliciesOpts{})
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}

	if policies[0].AppID != viewerApp {
		t.Fatalf("policy AppID = %q, want %q; an empty AppID purges every tenant",
			policies[0].AppID, viewerApp)
	}
	if policies[0].TenantID != viewerTenant {
		t.Fatalf("policy TenantID = %q, want %q", policies[0].TenantID, viewerTenant)
	}
}

// TestDashboardPolicyDoesNotPurgeOtherTenants is the end-to-end consequence.
func TestDashboardPolicyDoesNotPurgeOtherTenants(t *testing.T) {
	ts := newDashSetup(t, true)

	victim := seedEvent(t, ts.store, otherApp, "tenant_other", 48*time.Hour)
	mine := seedEvent(t, ts.store, viewerApp, viewerTenant, 48*time.Hour)

	// Create an aggressive policy, then enforce it, both via the dashboard.
	if _, err := ts.contributor.RenderPage(viewerCtx(), "/retention", contributor.Params{
		FormData: map[string]string{
			"action":   "create_policy",
			"category": "auth",
			"duration": "1h",
		},
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	if _, err := ts.contributor.RenderPage(viewerCtx(), "/retention", contributor.Params{
		QueryParams: map[string]string{"action": "enforce"},
	}); err != nil {
		t.Fatalf("enforce: %v", err)
	}

	if _, err := ts.store.Get(context.Background(), victim.ID); err != nil {
		t.Fatalf("another tenant's event was purged by a dashboard policy: %v", err)
	}
	if _, err := ts.store.Get(context.Background(), mine.ID); err == nil {
		t.Fatal("the viewer's own matching event should have been purged")
	}
}

// TestDashboardDeleteChecksOwnership pins that a policy cannot be deleted by ID
// alone from the dashboard's query string.
func TestDashboardDeleteChecksOwnership(t *testing.T) {
	ts := newDashSetup(t, true)
	ctx := context.Background()

	foreign := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: time.Hour,
		AppID:    otherApp,
		TenantID: "tenant_other",
	}
	foreign.CreatedAt = time.Now()
	foreign.UpdatedAt = time.Now()
	if err := ts.store.SavePolicy(ctx, foreign); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	if _, err := ts.contributor.RenderPage(viewerCtx(), "/retention", contributor.Params{
		QueryParams: map[string]string{"action": "delete", "id": foreign.ID.String()},
	}); err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	if _, err := ts.store.GetPolicy(ctx, foreign.ID); err != nil {
		t.Fatalf("another tenant's policy was deleted from the dashboard: %v", err)
	}
}

func TestDashboardDeleteRemovesOwnPolicy(t *testing.T) {
	ts := newDashSetup(t, true)
	ctx := context.Background()

	own := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: time.Hour,
		AppID:    viewerApp,
		TenantID: viewerTenant,
	}
	own.CreatedAt = time.Now()
	own.UpdatedAt = time.Now()
	if err := ts.store.SavePolicy(ctx, own); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	if _, err := ts.contributor.RenderPage(viewerCtx(), "/retention", contributor.Params{
		QueryParams: map[string]string{"action": "delete", "id": own.ID.String()},
	}); err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	if _, err := ts.store.GetPolicy(ctx, own.ID); err == nil {
		t.Fatal("the viewer's own policy should have been deleted")
	}
}

// TestDashboardReportsAreScoped pins that a generated report describes only the
// viewer's scope and is saved under it, rather than aggregating every tenant.
func TestDashboardReportsAreScoped(t *testing.T) {
	ts := newDashSetup(t, true)

	seedEvent(t, ts.store, otherApp, "tenant_other", time.Hour)
	seedEvent(t, ts.store, viewerApp, viewerTenant, time.Hour)

	if _, err := ts.contributor.RenderPage(viewerCtx(), "/reports", contributor.Params{
		QueryParams: map[string]string{"action": "generate_soc2"},
	}); err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	reports, err := ts.store.ListReports(context.Background(), compliance.ListOpts{})
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}

	r := reports[0]
	if r.AppID != viewerApp || r.TenantID != viewerTenant {
		t.Fatalf("report scope = (%q, %q), want (%q, %q)",
			r.AppID, r.TenantID, viewerApp, viewerTenant)
	}
	if r.Stats.TotalEvents != 1 {
		t.Fatalf("report counted %d events, want 1; it must not aggregate other tenants",
			r.Stats.TotalEvents)
	}
}

// TestDashboardMutationsDeniedByDefault pins the fail-closed gate: without an
// explicit opt-in the dashboard is read-only, because chronicle cannot verify
// who is driving it.
func TestDashboardMutationsDeniedByDefault(t *testing.T) {
	ts := newDashSetup(t, false)
	ctx := context.Background()

	if _, err := ts.contributor.RenderPage(viewerCtx(), "/retention", contributor.Params{
		FormData: map[string]string{
			"action":   "create_policy",
			"category": "auth",
			"duration": "1h",
		},
	}); err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	policies, err := ts.store.ListPolicies(ctx, retention.ListPoliciesOpts{})
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("a policy was created with mutations disabled: %+v", policies[0])
	}
}

func TestDashboardEnforceDeniedByDefault(t *testing.T) {
	ts := newDashSetup(t, false)

	mine := seedEvent(t, ts.store, viewerApp, viewerTenant, 48*time.Hour)

	policy := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: time.Hour,
		AppID:    viewerApp,
		TenantID: viewerTenant,
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	if err := ts.store.SavePolicy(context.Background(), policy); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	if _, err := ts.contributor.RenderPage(viewerCtx(), "/retention", contributor.Params{
		QueryParams: map[string]string{"action": "enforce"},
	}); err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	if _, err := ts.store.Get(context.Background(), mine.ID); err != nil {
		t.Fatalf("enforcement ran with mutations disabled: %v", err)
	}
}

// TestDashboardReadsStillWorkWithMutationsDisabled keeps the read-only dashboard
// useful.
func TestDashboardReadsStillWorkWithMutationsDisabled(t *testing.T) {
	ts := newDashSetup(t, false)
	seedEvent(t, ts.store, viewerApp, viewerTenant, time.Hour)

	for _, route := range []string{"/", "/events", "/retention", "/erasures", "/reports"} {
		t.Run(route, func(t *testing.T) {
			if _, err := ts.contributor.RenderPage(viewerCtx(), route, contributor.Params{}); err != nil {
				t.Fatalf("RenderPage(%s): %v", route, err)
			}
		})
	}
}
