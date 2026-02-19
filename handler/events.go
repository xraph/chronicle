package handler

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xraph/forge"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/scope"
)

// listEvents handles GET /v1/events.
func (a *API) listEvents(ctx forge.Context, req *ListEventsRequest) (*audit.QueryResult, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	c, span := a.tracer.Start(c, "chronicle.listEvents",
		trace.WithAttributes(attribute.String("category", req.Category)))
	defer span.End()

	q := &audit.Query{
		Order: "desc",
	}

	if req.Category != "" {
		q.Categories = strings.Split(req.Category, ",")
	}
	if req.Action != "" {
		q.Actions = strings.Split(req.Action, ",")
	}
	if req.Severity != "" {
		q.Severity = strings.Split(req.Severity, ",")
	}
	if req.Outcome != "" {
		q.Outcome = strings.Split(req.Outcome, ",")
	}
	if req.After != "" {
		if t, err := time.Parse(time.RFC3339, req.After); err == nil {
			q.After = t
		}
	}
	if req.Before != "" {
		if t, err := time.Parse(time.RFC3339, req.Before); err == nil {
			q.Before = t
		}
	}
	if req.Order != "" {
		q.Order = req.Order
	}

	q.Limit = defaultLimit(req.Limit)
	q.Offset = defaultOffset(req.Offset)

	// Security-critical: enforce scope on the query.
	scope.ApplyToQuery(c, q)

	result, err := a.deps.AuditStore.Query(c, q)
	if err != nil {
		a.deps.Logger.ErrorContext(c, "failed to query events", "error", err)
		return nil, fmt.Errorf("list events: %w", err)
	}

	return result, ctx.JSON(http.StatusOK, result)
}

// getEvent handles GET /v1/events/:id.
func (a *API) getEvent(ctx forge.Context, _ *GetEventRequest) (*audit.Event, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	c, span := a.tracer.Start(c, "chronicle.getEvent")
	defer span.End()

	eventID, err := id.ParseAuditID(ctx.Param("id"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid event ID: %v", err))
	}

	event, err := a.deps.AuditStore.Get(c, eventID)
	if err != nil {
		return nil, mapStoreError(err)
	}

	// Verify the event belongs to the caller's scope.
	info := scope.FromContext(c)
	if info.AppID != "" && event.AppID != info.AppID {
		return nil, forge.NotFound("event not found")
	}
	if info.TenantID != "" && event.TenantID != info.TenantID {
		return nil, forge.NotFound("event not found")
	}

	return event, ctx.JSON(http.StatusOK, event)
}

// eventsByUser handles GET /v1/events/user/:userId.
func (a *API) eventsByUser(ctx forge.Context, req *EventsByUserRequest) (*audit.QueryResult, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	userID := ctx.Param("userId")
	if userID == "" {
		return nil, forge.BadRequest("userId is required")
	}

	c, span := a.tracer.Start(c, "chronicle.eventsByUser",
		trace.WithAttributes(attribute.String("user_id", userID)))
	defer span.End()

	var opts audit.TimeRange
	if req.After != "" {
		if t, err := time.Parse(time.RFC3339, req.After); err == nil {
			opts.After = t
		}
	}
	if req.Before != "" {
		if t, err := time.Parse(time.RFC3339, req.Before); err == nil {
			opts.Before = t
		}
	}

	result, err := a.deps.AuditStore.ByUser(c, userID, opts)
	if err != nil {
		a.deps.Logger.ErrorContext(c, "failed to query events by user", "user_id", userID, "error", err)
		return nil, fmt.Errorf("events by user: %w", err)
	}

	return result, ctx.JSON(http.StatusOK, result)
}

// aggregateEvents handles POST /v1/events/aggregate.
func (a *API) aggregateEvents(ctx forge.Context, req *audit.AggregateQuery) (*audit.AggregateResult, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	c, span := a.tracer.Start(c, "chronicle.aggregateEvents")
	defer span.End()

	// Security-critical: enforce scope on the aggregate query.
	scope.ApplyToAggregateQuery(c, req)

	result, err := a.deps.AuditStore.Aggregate(c, req)
	if err != nil {
		a.deps.Logger.ErrorContext(c, "failed to aggregate events", "error", err)
		return nil, fmt.Errorf("aggregate events: %w", err)
	}

	return result, ctx.JSON(http.StatusOK, result)
}
