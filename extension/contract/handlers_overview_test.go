package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
)

// ──────────────────────────────────────────────────
// Test doubles. Each is named for the group it serves, so it cannot collide
// with another group's in this package.
// ──────────────────────────────────────────────────

// overviewScopeSpy is a store.Store that records every audit.AggregateQuery
// it was asked, in order, and the scope of every CountErasures call. It
// exists to prove overview.stats stamps the viewer's own AppID and TenantID
// onto EVERY store call it makes, not just the first: applyQuery cannot help
// here (AggregateQuery and erasure.Scope are stamped by hand), and Chronicle's
// stores treat an empty AppID as matching every app.
type overviewScopeSpy struct {
	stubStore
	aggregateCalls []*audit.AggregateQuery
	erasureCalls   []erasure.Scope
}

func (s *overviewScopeSpy) Aggregate(_ context.Context, q *audit.AggregateQuery) (*audit.AggregateResult, error) {
	s.aggregateCalls = append(s.aggregateCalls, q)
	return &audit.AggregateResult{}, nil
}

func (s *overviewScopeSpy) CountErasures(_ context.Context, sc erasure.Scope) (int64, error) {
	s.erasureCalls = append(s.erasureCalls, sc)
	return 0, nil
}

// overviewSeedEvent appends one app-level event carrying the given category,
// outcome and severity, so a test can build a scope with a deliberate mix of
// both.
func overviewSeedEvent(
	t *testing.T, s store.Store, streamID id.ID, appID, category, outcome, severity string, ts time.Time,
) {
	t.Helper()
	ev := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  streamID,
		Hash:      "hash-" + appID + "-" + ts.Format(time.RFC3339Nano),
		AppID:     appID,
		UserID:    "user-1",
		Action:    "test.action",
		Resource:  "test",
		Category:  category,
		Outcome:   outcome,
		Severity:  severity,
		Timestamp: ts,
	}
	if err := s.Append(context.Background(), ev); err != nil {
		t.Fatalf("append event: %v", err)
	}
}

// overviewSeedErasure records one erasure for the given app/tenant.
func overviewSeedErasure(t *testing.T, s store.Store, appID, tenantID string) {
	t.Helper()
	now := time.Now().UTC()
	rec := &erasure.Erasure{
		Entity:         chronicle.NewEntity(),
		ID:             id.NewErasureID(),
		SubjectID:      "subject-1",
		Reason:         "gdpr request",
		RequestedBy:    "operator-1",
		EventsAffected: 1,
		AppID:          appID,
		TenantID:       tenantID,
	}
	rec.CreatedAt = now
	rec.UpdatedAt = now
	if err := s.RecordErasure(context.Background(), rec); err != nil {
		t.Fatalf("record erasure %s/%s: %v", appID, tenantID, err)
	}
}

// ──────────────────────────────────────────────────
// overview.stats
// ──────────────────────────────────────────────────

// The templ overview ran four separate queries and counted criticals by
// fetching them. One Aggregate answers the breakdowns, and its own Total
// answers TotalEvents without a separate count.
func TestOverviewStatsUsesAggregateRatherThanCountingFetchedRows(t *testing.T) {
	spy := &aggregateSpy{result: &audit.AggregateResult{
		Groups: []audit.AggregateGroup{
			{Severity: "critical", Count: 3},
			{Severity: "info", Count: 900},
		},
		Total: 903,
	}}
	h := overviewStatsHandler(Deps{Store: spy})
	out, err := h(context.Background(), struct{}{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("overview.stats: %v", err)
	}
	if spy.last == nil {
		t.Fatal("overview.stats did not call Aggregate")
	}
	if out.CriticalEvents != 3 {
		t.Errorf("CriticalEvents = %d, want 3", out.CriticalEvents)
	}
	if out.TotalEvents != 903 {
		t.Errorf("TotalEvents = %d, want 903", out.TotalEvents)
	}
}

// Total deliberately does NOT equal the sum of the listed groups here, the
// way it would not on a real backend if some rows carried a severity value
// these fixture groups do not enumerate. TotalEvents must reflect the
// store's own Total field, not a sum a handler computed from the groups it
// happened to receive, or it would silently undercount the moment a row's
// severity or outcome falls outside what the breakdown lists.
func TestOverviewStatsTotalEventsComesFromAggregateTotalNotFromSummingGroups(t *testing.T) {
	spy := &aggregateSpy{result: &audit.AggregateResult{
		Groups: []audit.AggregateGroup{
			{Severity: "critical", Count: 3},
			{Severity: "info", Count: 900},
		},
		Total: 950,
	}}
	h := overviewStatsHandler(Deps{Store: spy})
	out, err := h(context.Background(), struct{}{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("overview.stats: %v", err)
	}
	if out.TotalEvents != 950 {
		t.Errorf("TotalEvents = %d, want 950 (the store's Total; sum(groups) is 903)", out.TotalEvents)
	}
}

func TestOverviewStatsRefusesAPrincipalWithNoApp(t *testing.T) {
	h := overviewStatsHandler(Deps{Store: newStubStore()})
	if _, err := h(context.Background(), struct{}{}, principalWith(nil)); err == nil {
		t.Fatal("overview served a principal with no app scope")
	}
}

// A principal with no app is refused before the store is ever touched.
func TestOverviewStatsRefusesAPrincipalWithNoAppBeforeTouchingTheStore(t *testing.T) {
	spy := &overviewScopeSpy{}
	h := overviewStatsHandler(Deps{Store: spy})
	_, err := h(context.Background(), struct{}{}, principalWith(nil))
	if !errors.Is(err, fcontract.ErrPermissionDenied) {
		t.Fatalf("err = %v, want PERMISSION_DENIED", err)
	}
	if len(spy.aggregateCalls) != 0 || len(spy.erasureCalls) != 0 {
		t.Fatalf("handler touched the store before refusing: aggregates=%d erasures=%d",
			len(spy.aggregateCalls), len(spy.erasureCalls))
	}
}

// Every store call overview.stats makes must carry the viewer's own AppID
// and TenantID: three Aggregate calls (category, severity, outcome) and one
// CountErasures. AggregateQuery and erasure.Scope are both stamped by hand,
// not through applyQuery, so this is the only thing that catches a dropped
// field on any one of the four.
func TestOverviewStatsStampsTheViewersScopeOnEveryCall(t *testing.T) {
	spy := &overviewScopeSpy{}
	h := overviewStatsHandler(Deps{Store: spy})
	_, err := h(context.Background(), struct{}{},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))
	if err != nil {
		t.Fatalf("overview.stats: %v", err)
	}

	if len(spy.aggregateCalls) != 3 {
		t.Fatalf("Aggregate called %d times, want 3 (category, severity, outcome)", len(spy.aggregateCalls))
	}
	for i, q := range spy.aggregateCalls {
		if q.AppID != "app-1" || q.TenantID != "tenant-a" {
			t.Errorf("aggregate call %d scope = %q/%q, want app-1/tenant-a", i, q.AppID, q.TenantID)
		}
	}

	if len(spy.erasureCalls) != 1 {
		t.Fatalf("CountErasures called %d times, want 1", len(spy.erasureCalls))
	}
	if got := spy.erasureCalls[0]; got.AppID != "app-1" || got.TenantID != "tenant-a" {
		t.Errorf("CountErasures scope = %q/%q, want app-1/tenant-a", got.AppID, got.TenantID)
	}
}

// A scope with no events and no erasures at all answers zeros and empty
// breakdowns, not an error: an aggregation with nothing to group is a normal
// empty result on every backend.
func TestOverviewStatsOnAnEmptyScopeReturnsZeros(t *testing.T) {
	s := newSQLiteStore(t)
	h := overviewStatsHandler(Deps{Store: s})
	out, err := h(context.Background(), struct{}{}, principalWith(map[string]any{"app_id": "app-empty"}))
	if err != nil {
		t.Fatalf("overview.stats: %v", err)
	}
	if out.TotalEvents != 0 || out.CriticalEvents != 0 || out.FailedEvents != 0 ||
		out.DeniedEvents != 0 || out.ErasureCount != 0 {
		t.Fatalf("out = %+v, want all zeros", out)
	}
	if len(out.Categories) != 0 || len(out.Severities) != 0 || len(out.Outcomes) != 0 {
		t.Fatalf("out = %+v, want empty breakdowns", out)
	}
}

// Real sqlite, two apps: the scope hazard end to end, plus the derived
// counts. FailedEvents is failure only, the same as the report stats, and
// DeniedEvents is its own count.
func TestOverviewStatsCountsOnlyTheViewersAppOnSQLite(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()

	streamOne := eventsSeedStream(t, s, "app-1", "")
	streamTwo := eventsSeedStream(t, s, "app-2", "")

	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	// app-1: 8 events, a deliberate mix of severities and outcomes.
	//   severity: info x3, warning x2, critical x3
	//   outcome:  success x4, denied x2, failure x2
	overviewSeedEvent(t, s, streamOne, "app-1", "auth", audit.OutcomeSuccess, audit.SeverityInfo, base)
	overviewSeedEvent(t, s, streamOne, "app-1", "auth", audit.OutcomeSuccess, audit.SeverityInfo, base.Add(time.Minute))
	overviewSeedEvent(t, s, streamOne, "app-1", "auth", audit.OutcomeFailure, audit.SeverityCritical, base.Add(2*time.Minute))
	overviewSeedEvent(t, s, streamOne, "app-1", "billing", audit.OutcomeDenied, audit.SeverityCritical, base.Add(3*time.Minute))
	overviewSeedEvent(t, s, streamOne, "app-1", "billing", audit.OutcomeDenied, audit.SeverityInfo, base.Add(4*time.Minute))
	overviewSeedEvent(t, s, streamOne, "app-1", "billing", audit.OutcomeSuccess, audit.SeverityWarning, base.Add(5*time.Minute))
	overviewSeedEvent(t, s, streamOne, "app-1", "auth", audit.OutcomeFailure, audit.SeverityWarning, base.Add(6*time.Minute))
	overviewSeedEvent(t, s, streamOne, "app-1", "billing", audit.OutcomeSuccess, audit.SeverityCritical, base.Add(7*time.Minute))
	overviewSeedErasure(t, s, "app-1", "")
	overviewSeedErasure(t, s, "app-1", "")

	// app-2: events and an erasure that must never be counted for app-1.
	overviewSeedEvent(t, s, streamTwo, "app-2", "auth", audit.OutcomeFailure, audit.SeverityCritical, base)
	overviewSeedEvent(t, s, streamTwo, "app-2", "auth", audit.OutcomeDenied, audit.SeverityCritical, base.Add(time.Minute))
	overviewSeedEvent(t, s, streamTwo, "app-2", "auth", audit.OutcomeDenied, audit.SeverityCritical, base.Add(2*time.Minute))
	overviewSeedErasure(t, s, "app-2", "")

	h := overviewStatsHandler(Deps{Store: s})
	out, err := h(ctx, struct{}{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("overview.stats: %v", err)
	}

	if out.TotalEvents != 8 {
		t.Errorf("TotalEvents = %d, want 8", out.TotalEvents)
	}
	if out.CriticalEvents != 3 {
		t.Errorf("CriticalEvents = %d, want 3", out.CriticalEvents)
	}
	// failure(2) only. Denied(2) is reported in its own field, so failedEvents
	// means the same here as in the compliance report stats.
	if out.FailedEvents != 2 {
		t.Errorf("FailedEvents = %d, want 2 (failure only, not failure + denied)", out.FailedEvents)
	}
	if out.DeniedEvents != 2 {
		t.Errorf("DeniedEvents = %d, want 2", out.DeniedEvents)
	}
	if out.ErasureCount != 2 {
		t.Errorf("ErasureCount = %d, want 2", out.ErasureCount)
	}

	var categoryTotal, severityTotal, outcomeTotal int64
	for _, g := range out.Categories {
		categoryTotal += g.Count
	}
	for _, g := range out.Severities {
		severityTotal += g.Count
	}
	for _, g := range out.Outcomes {
		outcomeTotal += g.Count
	}
	if categoryTotal != 8 || severityTotal != 8 || outcomeTotal != 8 {
		t.Errorf("breakdown totals = category %d, severity %d, outcome %d, want 8 each",
			categoryTotal, severityTotal, outcomeTotal)
	}
}
