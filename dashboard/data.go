package dashboard

import (
	"context"
	"time"

	"github.com/xraph/forge"
	"golang.org/x/sync/errgroup"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
)

// readOnlyMessage is shown when a mutating dashboard action is attempted while
// Config.AllowMutations is false.
const readOnlyMessage = "This dashboard is read-only. " +
	"Set the chronicle extension's dashboard_mutations option to enable " +
	"creating policies, running retention, and generating reports."

// viewScope is the app/tenant a dashboard render is confined to.
type viewScope struct {
	AppID    string
	TenantID string
}

// resolveScope reads the viewer's scope off the request context.
//
// Security-critical: every dashboard fetch must be scoped through this. The
// dashboard renders audit events, erasure subject IDs, retention policies and
// archives, so an unscoped fetch shows a tenant-scoped viewer other tenants'
// data — the exact leak the HTTP layer takes care to prevent.
//
// forge's dashboard passes the request context straight through to RenderPage,
// so both forge.Scope and any chronicle scope values are reachable here. An
// empty scope means no scope middleware ran on the dashboard route, which is
// the single-app operator view, and matches how scope.ApplyToQuery behaves on
// the API.
func resolveScope(ctx context.Context) viewScope {
	if s, ok := forge.ScopeFrom(ctx); ok {
		return viewScope{AppID: s.AppID(), TenantID: s.OrgID()}
	}

	info := scope.FromContext(ctx)
	return viewScope{AppID: info.AppID, TenantID: info.TenantID}
}

// inScope reports whether a record fetched by ID belongs to the viewer.
//
// Detail pages resolve a record by ID, which bypasses every list filter, so
// each one must check ownership before rendering. An empty TenantID on the
// record is treated as belonging to the app.
func inScope(ctx context.Context, appID, tenantID string) bool {
	v := resolveScope(ctx)
	if v.AppID != "" && appID != v.AppID {
		return false
	}
	if v.TenantID != "" && tenantID != "" && tenantID != v.TenantID {
		return false
	}
	return true
}

// apply sets the scope on an event query.
func (v viewScope) apply(q *audit.Query) *audit.Query {
	q.AppID = v.AppID
	q.TenantID = v.TenantID
	return q
}

func (v viewScope) erasure() erasure.Scope {
	return erasure.Scope{AppID: v.AppID, TenantID: v.TenantID}
}

func (v viewScope) retention() retention.Scope {
	return retention.Scope{AppID: v.AppID, TenantID: v.TenantID}
}

// overviewCounts holds the scalar tiles on the overview page and widget.
type overviewCounts struct {
	TotalEvents    int64
	CriticalEvents int64
	FailedEvents   int64
	ErasureCount   int64
}

// fetchOverviewCounts loads the four overview tiles concurrently.
//
// These are four independent round trips; running them in sequence made the
// overview page as slow as their sum. A failing tile reports 0 rather than
// failing the whole page, matching the previous per-tile behaviour.
func fetchOverviewCounts(ctx context.Context, s store.Store, v viewScope) overviewCounts {
	var counts overviewCounts

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		counts.TotalEvents = fetchTotalEventCount(gctx, s, v)
		return nil
	})
	g.Go(func() error {
		counts.CriticalEvents = fetchCriticalEventCount(gctx, s, v)
		return nil
	})
	g.Go(func() error {
		counts.FailedEvents = fetchFailedEventCount(gctx, s, v)
		return nil
	})
	g.Go(func() error {
		counts.ErasureCount = fetchErasureCount(gctx, s, v)
		return nil
	})

	_ = g.Wait() // every task swallows its own error and reports 0
	return counts
}

// fetchTotalEventCount returns the total number of audit events in scope.
func fetchTotalEventCount(ctx context.Context, s store.Store, v viewScope) int64 {
	count, err := s.Count(ctx, &audit.CountQuery{
		AppID:    v.AppID,
		TenantID: v.TenantID,
	})
	if err != nil {
		return 0
	}
	return count
}

// fetchCriticalEventCount returns the number of critical events in the last 30 days.
func fetchCriticalEventCount(ctx context.Context, s store.Store, v viewScope) int64 {
	now := time.Now()
	result, err := s.Query(ctx, v.apply(&audit.Query{
		After:    now.AddDate(0, 0, -30),
		Before:   now,
		Severity: []string{"critical"},
		Limit:    1,
	}))
	if err != nil {
		return 0
	}
	return result.Total
}

// fetchFailedEventCount returns the number of failed/denied events in the last 30 days.
func fetchFailedEventCount(ctx context.Context, s store.Store, v viewScope) int64 {
	now := time.Now()
	result, err := s.Query(ctx, v.apply(&audit.Query{
		After:   now.AddDate(0, 0, -30),
		Before:  now,
		Outcome: []string{"failure", "denied"},
		Limit:   1,
	}))
	if err != nil {
		return 0
	}
	return result.Total
}

// fetchErasureCount returns the number of erasure records in scope.
func fetchErasureCount(ctx context.Context, s store.Store, v viewScope) int64 {
	count, err := s.CountErasures(ctx, v.erasure())
	if err != nil {
		return 0
	}
	return count
}

// fetchRecentEvents returns the most recent audit events in scope.
func fetchRecentEvents(ctx context.Context, s store.Store, v viewScope, limit int) []*audit.Event {
	result, err := s.Query(ctx, v.apply(&audit.Query{
		Limit: limit,
		Order: "desc",
	}))
	if err != nil {
		return nil
	}
	return result.Events
}

// fetchRecentCriticalEvents returns the most recent critical severity events in scope.
func fetchRecentCriticalEvents(ctx context.Context, s store.Store, v viewScope, limit int) []*audit.Event {
	result, err := s.Query(ctx, v.apply(&audit.Query{
		Severity: []string{"critical"},
		Limit:    limit,
		Order:    "desc",
	}))
	if err != nil {
		return nil
	}
	return result.Events
}

// fetchEvents returns events matching the given query, restricted to scope.
func fetchEvents(
	ctx context.Context, s store.Store, v viewScope, q *audit.Query,
) ([]*audit.Event, int64, error) {
	result, err := s.Query(ctx, v.apply(q))
	if err != nil {
		return nil, 0, err
	}
	return result.Events, result.Total, nil
}

// fetchErasures returns erasure records in scope.
func fetchErasures(
	ctx context.Context, s store.Store, v viewScope, limit, offset int,
) ([]*erasure.Erasure, error) {
	return s.ListErasures(ctx, erasure.ListOpts{
		Scope:  v.erasure(),
		Limit:  limit,
		Offset: offset,
	})
}

// fetchPolicies returns the retention policies in scope.
func fetchPolicies(ctx context.Context, s store.Store, v viewScope) ([]*retention.Policy, error) {
	return s.ListPolicies(ctx, retention.ListPoliciesOpts{Scope: v.retention()})
}

// fetchArchives returns archive records in scope.
func fetchArchives(
	ctx context.Context, s store.Store, v viewScope, limit, offset int,
) ([]*retention.Archive, error) {
	return s.ListArchives(ctx, retention.ListOpts{
		Scope:  v.retention(),
		Limit:  limit,
		Offset: offset,
	})
}

// fetchReports returns compliance reports in scope.
func fetchReports(
	ctx context.Context, s store.Store, v viewScope, limit, offset int,
) ([]*compliance.Report, error) {
	return s.ListReports(ctx, compliance.ListOpts{
		AppID:    v.AppID,
		TenantID: v.TenantID,
		Limit:    limit,
		Offset:   offset,
	})
}
