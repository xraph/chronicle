package contract

import (
	"context"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure"
)

// OverviewStats answers overview.stats: the count tiles and breakdowns on
// the dashboard's landing page. Every number here is a claim an operator
// reads at a glance, so each is derived from a scoped store call rather than
// from a bounded list's length.
type OverviewStats struct {
	TotalEvents    int64 `json:"totalEvents"`
	CriticalEvents int64 `json:"criticalEvents"`

	// FailedEvents counts events whose outcome is "failure" and nothing else,
	// which is what the compliance report stats call failedEvents too, so the
	// same key means the same thing on every page. DeniedEvents counts
	// "denied" separately. The templ overview this replaces showed one
	// "failed" tile that was failure plus denied; the React page sums the two
	// fields for that tile, and labels it accordingly.
	FailedEvents int64 `json:"failedEvents"`
	DeniedEvents int64 `json:"deniedEvents"`

	ErasureCount int64 `json:"erasureCount"`

	Categories []AggregateGroupDTO `json:"categories"`
	Severities []AggregateGroupDTO `json:"severities"`
	Outcomes   []AggregateGroupDTO `json:"outcomes"`
}

func overviewRegistrations() []registration {
	return []registration{
		query("overview.stats", overviewStatsHandler),
	}
}

// projectAggregateGroups turns a store aggregation's groups into their wire
// shape. events.aggregate does the same projection inline; this is pulled
// out because overview.stats does it three times over.
func projectAggregateGroups(groups []audit.AggregateGroup) []AggregateGroupDTO {
	out := make([]AggregateGroupDTO, 0, len(groups))
	for _, g := range groups {
		out = append(out, AggregateGroupDTO{
			Bucket:   g.Bucket,
			Category: g.Category,
			Action:   g.Action,
			Outcome:  g.Outcome,
			Severity: g.Severity,
			Resource: g.Resource,
			Count:    g.Count,
		})
	}
	return out
}

// overviewStatsHandler answers overview.stats.
//
// It aggregates once per breakdown (category, severity, outcome) rather than
// running the four separate filtered queries the templ overview used to, and
// reads CriticalEvents, FailedEvents and DeniedEvents off the groups it
// already has instead of issuing more queries to count them. ErasureCount
// comes from CountErasures, which exists precisely so a caller does not have
// to count a list that is bounded by its own limit.
//
// TotalEvents comes from the severity aggregation's Total, not from summing
// the Severities breakdown: every backend's Aggregate computes Total as the
// count of every row matching the query's scope (and time bounds, here
// unset), independent of what each row's grouped field holds -- see
// store/sqlite/audit.go's Aggregate, which accumulates total from every
// group's Count including a group keyed on an empty string. Summing the
// breakdown by hand would happen to land on the same number today, but it
// would silently stop matching the true total the moment a row carried a
// severity or outcome value this handler does not otherwise expect, so the
// store's own Total is used directly instead.
//
// A scope with no events at all produces empty groups and a Total of zero on
// every call here, not an error: an aggregation with nothing to group is a
// normal, empty result on every backend, not a failure.
func overviewStatsHandler(deps Deps) func(context.Context, struct{}, fcontract.Principal) (OverviewStats, error) {
	return func(ctx context.Context, _ struct{}, p fcontract.Principal) (OverviewStats, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return OverviewStats{}, err
		}

		severities, err := deps.Store.Aggregate(ctx, &audit.AggregateQuery{
			AppID:    v.AppID,
			TenantID: v.TenantID,
			GroupBy:  []string{"severity"},
		})
		if err != nil {
			return OverviewStats{}, deps.mapStoreError("overview.stats", err)
		}

		categories, err := deps.Store.Aggregate(ctx, &audit.AggregateQuery{
			AppID:    v.AppID,
			TenantID: v.TenantID,
			GroupBy:  []string{"category"},
		})
		if err != nil {
			return OverviewStats{}, deps.mapStoreError("overview.stats", err)
		}

		outcomes, err := deps.Store.Aggregate(ctx, &audit.AggregateQuery{
			AppID:    v.AppID,
			TenantID: v.TenantID,
			GroupBy:  []string{"outcome"},
		})
		if err != nil {
			return OverviewStats{}, deps.mapStoreError("overview.stats", err)
		}

		erasureCount, err := deps.Store.CountErasures(ctx, erasure.Scope{AppID: v.AppID, TenantID: v.TenantID})
		if err != nil {
			return OverviewStats{}, deps.mapStoreError("overview.stats", err)
		}

		out := OverviewStats{
			TotalEvents:  severities.Total,
			ErasureCount: erasureCount,
			Categories:   projectAggregateGroups(categories.Groups),
			Severities:   projectAggregateGroups(severities.Groups),
			Outcomes:     projectAggregateGroups(outcomes.Groups),
		}

		for _, g := range severities.Groups {
			if g.Severity == audit.SeverityCritical {
				out.CriticalEvents += g.Count
			}
		}
		for _, g := range outcomes.Groups {
			switch g.Outcome {
			case audit.OutcomeFailure:
				out.FailedEvents += g.Count
			case audit.OutcomeDenied:
				out.DeniedEvents += g.Count
			}
		}

		return out, nil
	}
}
