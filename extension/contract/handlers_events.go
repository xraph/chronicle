package contract

import (
	"context"
	"fmt"
	"time"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// defaultEventListLimit and maxEventListLimit mirror handler/requests.go's
// defaultLimit exactly, so the contract path and the REST path clamp a
// caller's limit to the same page size.
const (
	defaultEventListLimit = 50
	maxEventListLimit     = 1000
)

// EventSummary is one row of the log. Metadata is deliberately absent: it is
// freeform and can be large, and sending it for every row of a virtualised
// table would dominate the response. events.detail carries it.
type EventSummary struct {
	ID         string `json:"id"`
	Timestamp  string `json:"timestamp"`
	Sequence   uint64 `json:"sequence"`
	Action     string `json:"action"`
	Resource   string `json:"resource"`
	ResourceID string `json:"resourceId,omitempty"`
	Category   string `json:"category"`
	Outcome    string `json:"outcome"`
	Severity   string `json:"severity"`
	UserID     string `json:"userId,omitempty"`
	IP         string `json:"ip,omitempty"`
	Erased     bool   `json:"erased"`
}

// EventDetail adds what the detail page needs: the payload, the chain
// position, and the scheme provenance that tells an operator which level
// THIS event was written under, which is not necessarily the level the chain
// is pinned to now.
//
// A field on this type equal to crypto.ErasedMarker ("[ERASED]") means the
// value was destroyed by an erasure, not that it was ever recorded that way.
// The event is readable either way: erasure replaces the sealed fields with
// the marker rather than making the row unreadable, and that substitution
// already happened upstream, on the store this Deps was configured with,
// before the event ever reached this handler.
type EventDetail struct {
	EventSummary
	StreamID   string         `json:"streamId"`
	Hash       string         `json:"hash"`
	PrevHash   string         `json:"prevHash"`
	HashScheme string         `json:"hashScheme,omitempty"`
	HashKeyID  string         `json:"hashKeyId,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	SubjectID  string         `json:"subjectId,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	ErasedAt   string         `json:"erasedAt,omitempty"`
	ErasureID  string         `json:"erasureId,omitempty"`
}

// EventListInput is audit.Query's filter set on the wire. Every filter is
// multi-value except the time bounds, matching the Go type.
//
// There is no appId or tenantId field, on purpose. Scope comes from the
// principal, through viewScope.applyQuery, and never from the request.
type EventListInput struct {
	After      string   `json:"after,omitempty"`
	Before     string   `json:"before,omitempty"`
	UserID     string   `json:"userId,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	Resources  []string `json:"resources,omitempty"`
	Severity   []string `json:"severity,omitempty"`
	Outcome    []string `json:"outcome,omitempty"`
	Limit      int      `json:"limit,omitempty"`
	Offset     int      `json:"offset,omitempty"`
	Order      string   `json:"order,omitempty"`
}

// EventListResponse is one page of the log. Total and HasMore always come
// from the store's own QueryResult, never from len(Events): the page caption
// reads "50 of 12,431 events", and counting the rows on screen would make
// that caption a lie on every page after the first.
type EventListResponse struct {
	Events  []EventSummary `json:"events"`
	Total   int64          `json:"total"`
	HasMore bool           `json:"hasMore"`
}

// GetEventInput names one event by ID.
type GetEventInput struct {
	ID string `json:"id"`
}

// EventsByUserInput requests one user's events within a time bound, scoped to
// the viewer's own app and tenant.
//
// RULING 1: events.byUser is served by Store.Query with UserID set, NOT by
// Store.ByUser. ByUser's Total is only the length of the page it returns --
// see store/sqlite/audit.go's ByUser and store/redis/audit.go's ByUser,
// both of which set Total: int64(len(events)) -- so it is not a count, and a
// caption built on it ("N of total") would state a false number the moment
// more rows exist than fit on the page. Query's Total is a real count on
// sqlite, postgres and mongo, each of which runs a separate count query
// alongside the page (store/sqlite/audit.go's Query builds countQuery and
// calls countQuery.Count(ctx) before the page select). See RULING 2 in
// task-10-report.md for confirmation that redis's Query also counts the full
// matching set, not just the page.
type EventsByUserInput struct {
	UserID string `json:"userId"`
	After  string `json:"after,omitempty"`
	Before string `json:"before,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// AggregateInput bounds an events.aggregate call. GroupBy is validated
// against audit.ResolveGroupBy before the store is ever touched -- see
// RULING 3 on eventsAggregateHandler.
type AggregateInput struct {
	After   string   `json:"after,omitempty"`
	Before  string   `json:"before,omitempty"`
	GroupBy []string `json:"groupBy"`
}

// AggregateGroupDTO is one group of an aggregation result on the wire. Tasks
// 11 and 13 consume this type too, so it is declared here once and must not
// be declared a second time.
type AggregateGroupDTO struct {
	Bucket   string `json:"bucket,omitempty"`
	Category string `json:"category,omitempty"`
	Action   string `json:"action,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
	Severity string `json:"severity,omitempty"`
	Resource string `json:"resource,omitempty"`
	Count    int64  `json:"count"`
}

// AggregateResponse is the result of events.aggregate.
type AggregateResponse struct {
	Groups []AggregateGroupDTO `json:"groups"`
	Total  int64               `json:"total"`
}

func eventsRegistrations() []registration {
	return []registration{
		query("events.list", eventsListHandler),
		query("events.detail", eventsDetailHandler),
		query("events.aggregate", eventsAggregateHandler),
		query("events.byUser", eventsByUserHandler),
	}
}

// projectEventSummary turns a stored event into its wire summary. Metadata is
// left off on purpose -- see EventSummary's doc comment.
func projectEventSummary(e *audit.Event) EventSummary {
	return EventSummary{
		ID:         e.ID.String(),
		Timestamp:  formatTime(e.Timestamp),
		Sequence:   e.Sequence,
		Action:     e.Action,
		Resource:   e.Resource,
		ResourceID: e.ResourceID,
		Category:   e.Category,
		Outcome:    e.Outcome,
		Severity:   e.Severity,
		UserID:     e.UserID,
		IP:         e.IP,
		Erased:     e.Erased,
	}
}

// projectEventDetail turns a stored event into its wire detail, adding the
// fields EventSummary omits.
func projectEventDetail(e *audit.Event) EventDetail {
	out := EventDetail{
		EventSummary: projectEventSummary(e),
		StreamID:     e.StreamID.String(),
		Hash:         e.Hash,
		PrevHash:     e.PrevHash,
		HashScheme:   e.HashScheme,
		HashKeyID:    e.HashKeyID,
		Reason:       e.Reason,
		SubjectID:    e.SubjectID,
		Metadata:     e.Metadata,
		ErasureID:    e.ErasureID,
	}
	if e.ErasedAt != nil {
		out.ErasedAt = formatTime(*e.ErasedAt)
	}
	return out
}

// parseEventTimeBound parses an RFC3339 wire timestamp for the named field.
// An empty value means "unbounded on that side" and parses to the zero time.
// A non-empty value that fails to parse is refused with CodeBadRequest rather
// than silently treated as the zero time, which would widen the query to the
// beginning of time instead of narrowing it.
func parseEventTimeBound(field, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, &fcontract.Error{
			Code:    fcontract.CodeBadRequest,
			Message: fmt.Sprintf("%s is not a valid RFC3339 timestamp", field),
		}
	}
	return t, nil
}

// clampEventListLimit mirrors handler/requests.go's defaultLimit: zero or
// less becomes the default page size, and anything above the cap is capped.
func clampEventListLimit(limit int) int {
	if limit <= 0 {
		return defaultEventListLimit
	}
	if limit > maxEventListLimit {
		return maxEventListLimit
	}
	return limit
}

// badGroupByError maps a audit.ResolveGroupBy failure to CodeBadRequest,
// carrying the error's own text: ResolveGroupBy's errors name only the
// field that was wrong ("unsupported group_by field: \"week\""), never
// anything store-internal, so it is safe to hand to the browser verbatim.
func badGroupByError(err error) error {
	return &fcontract.Error{Code: fcontract.CodeBadRequest, Message: err.Error()}
}

func eventsListHandler(deps Deps) func(context.Context, EventListInput, fcontract.Principal) (EventListResponse, error) {
	return func(ctx context.Context, in EventListInput, p fcontract.Principal) (EventListResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return EventListResponse{}, err
		}

		if in.Offset < 0 {
			return EventListResponse{}, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: "offset cannot be negative"}
		}

		order := in.Order
		switch order {
		case "":
			order = "desc"
		case "asc", "desc":
			// carry through
		default:
			return EventListResponse{}, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: `order must be "asc" or "desc"`}
		}

		after, err := parseEventTimeBound("after", in.After)
		if err != nil {
			return EventListResponse{}, err
		}
		before, err := parseEventTimeBound("before", in.Before)
		if err != nil {
			return EventListResponse{}, err
		}

		q := v.applyQuery(&audit.Query{
			After:      after,
			Before:     before,
			UserID:     in.UserID,
			Categories: in.Categories,
			Actions:    in.Actions,
			Resources:  in.Resources,
			Severity:   in.Severity,
			Outcome:    in.Outcome,
			Limit:      clampEventListLimit(in.Limit),
			Offset:     in.Offset,
			Order:      order,
		})

		result, err := deps.Store.Query(ctx, q)
		if err != nil {
			return EventListResponse{}, deps.mapStoreError("events.list", err)
		}

		out := EventListResponse{
			Events:  make([]EventSummary, 0, len(result.Events)),
			Total:   result.Total,
			HasMore: result.HasMore,
		}
		for _, e := range result.Events {
			if e == nil {
				continue
			}
			out.Events = append(out.Events, projectEventSummary(e))
		}
		return out, nil
	}
}

func eventsDetailHandler(deps Deps) func(context.Context, GetEventInput, fcontract.Principal) (EventDetail, error) {
	return func(ctx context.Context, in GetEventInput, p fcontract.Principal) (EventDetail, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return EventDetail{}, err
		}

		eventID, err := id.ParseAuditID(in.ID)
		if err != nil {
			// An ID that does not even parse cannot name a real event.
			// Answering the same NOT_FOUND as a real miss tells a prober
			// nothing about which is true, and the store is never touched.
			return EventDetail{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		event, err := deps.Store.Get(ctx, eventID)
		if err != nil {
			return EventDetail{}, deps.mapStoreError("events.detail", err)
		}

		// Security-critical: a detail intent resolves by ID and bypasses
		// every list filter, so without this a caller could read another
		// tenant's event by guessing its ID. CodeNotFound, not
		// CodePermissionDenied, so the answer does not confirm the ID names
		// a real event outside the caller's scope.
		if !v.owns(event.AppID, event.TenantID) {
			return EventDetail{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		return projectEventDetail(event), nil
	}
}

// eventsAggregateHandler answers events.aggregate.
//
// RULING 3: a bad group_by is the caller's mistake, not the store's, so
// GroupBy is validated against audit.ResolveGroupBy before deps.Store.
// Aggregate is ever called. Every backend also validates GroupBy on its own
// (see store/redis/audit.go's Aggregate, which calls ResolveGroupBy itself
// before touching redis), so skipping this check here would not let bad
// input reach a backend unchecked -- but routing that failure through
// deps.mapStoreError would map it to CodeInternal, "the audit store could
// not complete this request", misrepresenting a caller error as a store
// failure. Validating here answers CodeBadRequest with the actual reason
// instead, before the store ever sees the request.
func eventsAggregateHandler(deps Deps) func(context.Context, AggregateInput, fcontract.Principal) (AggregateResponse, error) {
	return func(ctx context.Context, in AggregateInput, p fcontract.Principal) (AggregateResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return AggregateResponse{}, err
		}

		if _, err := audit.ResolveGroupBy(in.GroupBy); err != nil {
			return AggregateResponse{}, badGroupByError(err)
		}

		after, err := parseEventTimeBound("after", in.After)
		if err != nil {
			return AggregateResponse{}, err
		}
		before, err := parseEventTimeBound("before", in.Before)
		if err != nil {
			return AggregateResponse{}, err
		}

		// applyQuery only takes *audit.Query; AggregateQuery's scope is
		// stamped by hand here, from the same viewScope, so the outgoing
		// aggregate can never be widened to another app or tenant.
		q := &audit.AggregateQuery{
			After:    after,
			Before:   before,
			AppID:    v.AppID,
			TenantID: v.TenantID,
			GroupBy:  in.GroupBy,
		}

		result, err := deps.Store.Aggregate(ctx, q)
		if err != nil {
			return AggregateResponse{}, deps.mapStoreError("events.aggregate", err)
		}

		out := AggregateResponse{
			Groups: make([]AggregateGroupDTO, 0, len(result.Groups)),
			Total:  result.Total,
		}
		for _, g := range result.Groups {
			out.Groups = append(out.Groups, AggregateGroupDTO{
				Bucket:   g.Bucket,
				Category: g.Category,
				Action:   g.Action,
				Outcome:  g.Outcome,
				Severity: g.Severity,
				Resource: g.Resource,
				Count:    g.Count,
			})
		}
		return out, nil
	}
}

// eventsByUserHandler answers events.byUser. See RULING 1 on
// EventsByUserInput for why this goes through Store.Query rather than
// Store.ByUser.
func eventsByUserHandler(deps Deps) func(context.Context, EventsByUserInput, fcontract.Principal) (EventListResponse, error) {
	return func(ctx context.Context, in EventsByUserInput, p fcontract.Principal) (EventListResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return EventListResponse{}, err
		}

		if in.UserID == "" {
			return EventListResponse{}, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: "userId is required"}
		}

		after, err := parseEventTimeBound("after", in.After)
		if err != nil {
			return EventListResponse{}, err
		}
		before, err := parseEventTimeBound("before", in.Before)
		if err != nil {
			return EventListResponse{}, err
		}

		q := v.applyQuery(&audit.Query{
			After:  after,
			Before: before,
			UserID: in.UserID,
			Limit:  clampEventListLimit(in.Limit),
			Order:  "desc",
		})

		result, err := deps.Store.Query(ctx, q)
		if err != nil {
			return EventListResponse{}, deps.mapStoreError("events.byUser", err)
		}

		out := EventListResponse{
			Events:  make([]EventSummary, 0, len(result.Events)),
			Total:   result.Total,
			HasMore: result.HasMore,
		}
		for _, e := range result.Events {
			if e == nil {
				continue
			}
			out.Events = append(out.Events, projectEventSummary(e))
		}
		return out, nil
	}
}
