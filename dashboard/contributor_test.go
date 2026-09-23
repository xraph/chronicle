package dashboard_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contributor"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	chronicledash "github.com/xraph/chronicle/dashboard"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/stream"
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

// TestRenderVerificationDetectsSchemeDowngrade pins that the dashboard's
// verify page, like POST /v1/verify, actually uses the stream's pin.
//
// The event below carries a correct chronicle/v2 digest (computed with the
// same plain chain the page recomputes under) for a stream pinned to
// chronicle/v3 from sequence 1. Recomputing the digest alone says it matches:
// only cross-checking the claimed scheme against the stream's pin exposes
// that it was written under a weaker algorithm than the stream promises,
// which is what hash/chain.go's VerifyWithPin calls a downgrade rather than
// an ordinary tamper. Without the pin wired in, the page reports "Valid";
// with it, "Tampered" (see dashboard/pages/verify_templ.go's boolToStatus,
// which has no separate word for a downgrade).
func TestRenderVerificationDetectsSchemeDowngrade(t *testing.T) {
	ds := newDashSetup(t, false)
	ctx := viewerCtx()

	st := &stream.Stream{
		ID:          id.NewStreamID(),
		AppID:       viewerApp,
		TenantID:    viewerTenant,
		Scheme:      "chronicle/v3",
		SchemeSince: 1,
	}
	if err := ds.store.CreateStream(context.Background(), st); err != nil {
		t.Fatalf("create stream: %v", err)
	}

	event := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  st.ID,
		Sequence:  1,
		Timestamp: time.Now().UTC(),
		AppID:     viewerApp,
		TenantID:  viewerTenant,
		Action:    "login",
		Resource:  "session",
		Category:  "auth",
	}

	plain, err := hash.NewChain(hash.SchemePlainV4, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	digest, _, err := plain.Compute(context.Background(), "", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash = digest
	event.HashScheme = string(hash.SchemePlainV4)

	if appendErr := ds.store.Append(context.Background(), event); appendErr != nil {
		t.Fatalf("append: %v", appendErr)
	}

	component, err := ds.contributor.RenderPage(ctx, "/verify", contributor.Params{
		FormData: map[string]string{
			"action":    "verify",
			"stream_id": st.ID.String(),
			"from_seq":  "1",
			"to_seq":    "1",
		},
	})
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	var buf bytes.Buffer
	if err := component.Render(ctx, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("Tampered")) {
		t.Fatalf("rendered page does not report Tampered; the stream is pinned to chronicle/v3 but event 1's real digest was computed under chronicle/v2, so a pin-aware verifier must flag it as a downgrade. Output:\n%s", buf.String())
	}
}

// stubDashboardKeyProvider mirrors the other stub key providers in this
// codebase (chronicle_test.go, hash/scheme_test.go, store/sqlite/scheme_test.go,
// handler/handler_test.go, extension/tamper_evidence_test.go): a fixed key
// behind keys.Provider.
type stubDashboardKeyProvider struct {
	key      []byte
	activeID string
}

func (s stubDashboardKeyProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return s.key, s.activeID, nil
}

func (s stubDashboardKeyProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != s.activeID {
		return nil, keys.ErrKeyNotFound
	}
	return s.key, nil
}

// renderVerifyWithChain builds a fresh contributor over mem with the given
// HashChain (nil is valid: New defaults it to a plain, unkeyed chain) and
// renders /verify for the given stream/range, returning the rendered HTML.
func renderVerifyWithChain(t *testing.T, mem *memory.Store, chain *hash.Chain, streamID string) []byte {
	t.Helper()

	logger := log.NewNoopLogger()
	engine := compliance.NewEngine(mem, mem, mem, logger)
	enforcer := retention.NewEnforcer(mem, nil, logger)

	c := chronicledash.New(
		chronicledash.NewManifest(),
		mem, engine, enforcer,
		chronicledash.Config{HashChain: chain},
	)

	ctx := viewerCtx()
	component, err := c.RenderPage(ctx, "/verify", contributor.Params{
		FormData: map[string]string{
			"action":    "verify",
			"stream_id": streamID,
			"from_seq":  "1",
			"to_seq":    "1",
		},
	})
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	var buf bytes.Buffer
	if renderErr := component.Render(ctx, &buf); renderErr != nil {
		t.Fatalf("Render: %v", renderErr)
	}
	return buf.Bytes()
}

// TestRenderVerificationVerifiesUnderTheConfiguredHMACChain closes a gap
// TestRenderVerificationDetectsSchemeDowngrade leaves open: that test's
// downgrade is reported by hash.Chain.VerifyWithPin's rank comparison alone,
// before any digest is recomputed (see hash/chain.go), so it proves the Pin
// reached the verifier but nothing about c.config.HashChain. Reverting
// verify.NewVerifierWithChain back to NewVerifier in
// dashboard/contributor.go's renderVerification leaves it passing.
//
// This test carries a genuine HMAC digest (computed with the same chain the
// "with" case verifies under) on an event whose stream is pinned to the same
// scheme it claims, so Pin's rank comparison alone cannot explain a pass:
// only recomputing under the real keyed chain can.
func TestRenderVerificationVerifiesUnderTheConfiguredHMACChain(t *testing.T) {
	mem := memory.New()
	ctx := context.Background()

	provider := stubDashboardKeyProvider{key: make([]byte, 32), activeID: "hmac-1"}
	chain, err := hash.NewChain(hash.SchemeHMACV5, provider)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	st := &stream.Stream{
		ID:          id.NewStreamID(),
		AppID:       viewerApp,
		TenantID:    viewerTenant,
		Scheme:      "chronicle/v3",
		SchemeSince: 1,
	}
	if createErr := mem.CreateStream(ctx, st); createErr != nil {
		t.Fatalf("create stream: %v", createErr)
	}

	event := &audit.Event{
		ID: id.NewAuditID(), StreamID: st.ID, Sequence: 1, Timestamp: time.Now().UTC(),
		AppID: viewerApp, TenantID: viewerTenant,
		Action: "login", Resource: "session", Category: "auth",
	}
	digest, keyID, err := chain.Compute(ctx, "", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash = digest
	event.HashKeyID = keyID
	event.HashScheme = string(hash.SchemeHMACV5)
	if err := mem.Append(ctx, event); err != nil {
		t.Fatalf("append: %v", err)
	}

	t.Run("with the keyed chain, verification succeeds", func(t *testing.T) {
		out := renderVerifyWithChain(t, mem, chain, st.ID.String())
		if !bytes.Contains(out, []byte("Valid")) || bytes.Contains(out, []byte("Tampered")) {
			t.Fatalf("rendered page did not report Valid with no Tampered. Output:\n%s", out)
		}
	})

	t.Run("without the keyed chain, verification fails or errors", func(t *testing.T) {
		out := renderVerifyWithChain(t, mem, nil, st.ID.String())
		if bytes.Contains(out, []byte("Valid")) {
			t.Fatalf("rendered page reported Valid with a plain chain that has no key provider and cannot recompute an HMAC digest. Output:\n%s", out)
		}
	})
}
