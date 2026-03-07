package handler

import (
	"net/http"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/scope"
)

// getStats handles GET /v1/stats.
func (a *API) getStats(ctx forge.Context) error {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return err
	}

	c, span := a.tracer.Start(c, "chronicle.getStats")
	defer span.End()

	info := scope.FromContext(c)

	// Count total events.
	countQ := &audit.CountQuery{
		AppID: info.AppID,
	}
	if info.TenantID != "" {
		countQ.TenantID = info.TenantID
	}

	total, err := a.deps.AuditStore.Count(c, countQ)
	if err != nil {
		a.deps.Logger.Error("failed to count events", log.Error(err))
		return forge.NewHTTPError(http.StatusInternalServerError, "failed to get stats")
	}

	// Aggregate by category.
	catQ := &audit.AggregateQuery{
		GroupBy: []string{"category"},
	}
	scope.ApplyToAggregateQuery(c, catQ)
	catResult, err := a.deps.AuditStore.Aggregate(c, catQ)
	if err != nil {
		a.deps.Logger.Error("failed to aggregate by category", log.Error(err))
		return forge.NewHTTPError(http.StatusInternalServerError, "failed to get stats")
	}

	// Aggregate by severity.
	sevQ := &audit.AggregateQuery{
		GroupBy: []string{"severity"},
	}
	scope.ApplyToAggregateQuery(c, sevQ)
	sevResult, err := a.deps.AuditStore.Aggregate(c, sevQ)
	if err != nil {
		a.deps.Logger.Error("failed to aggregate by severity", log.Error(err))
		return forge.NewHTTPError(http.StatusInternalServerError, "failed to get stats")
	}

	// Aggregate by outcome.
	outQ := &audit.AggregateQuery{
		GroupBy: []string{"outcome"},
	}
	scope.ApplyToAggregateQuery(c, outQ)
	outResult, err := a.deps.AuditStore.Aggregate(c, outQ)
	if err != nil {
		a.deps.Logger.Error("failed to aggregate by outcome", log.Error(err))
		return forge.NewHTTPError(http.StatusInternalServerError, "failed to get stats")
	}

	// Get recent events (last 10).
	recentQ := &audit.Query{
		Limit: 10,
		Order: "desc",
	}
	scope.ApplyToQuery(c, recentQ)
	recentResult, err := a.deps.AuditStore.Query(c, recentQ)
	if err != nil {
		a.deps.Logger.Error("failed to query recent events", log.Error(err))
		return forge.NewHTTPError(http.StatusInternalServerError, "failed to get stats")
	}

	resp := StatsResponse{
		TotalEvents:  total,
		Categories:   catResult.Groups,
		Severities:   sevResult.Groups,
		Outcomes:     outResult.Groups,
		RecentEvents: recentResult.Events,
	}

	return ctx.JSON(http.StatusOK, resp)
}
