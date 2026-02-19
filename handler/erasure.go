package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/scope"
)

// requestErasure handles POST /v1/erasures.
func (a *API) requestErasure(ctx forge.Context, req *RequestErasureRequest) (*erasure.Result, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if req.SubjectID == "" {
		return nil, forge.BadRequest("subject_id is required")
	}
	if req.Reason == "" {
		return nil, forge.BadRequest("reason is required")
	}
	if req.RequestedBy == "" {
		return nil, forge.BadRequest("requested_by is required")
	}

	c, span := a.tracer.Start(c, "chronicle.requestErasure",
		trace.WithAttributes(attribute.String("subject_id", req.SubjectID)))
	defer span.End()

	info := scope.FromContext(c)

	// Count affected events before recording.
	affected, err := a.deps.ErasureStore.CountBySubject(c, req.SubjectID)
	if err != nil {
		a.deps.Logger.ErrorContext(c, "failed to count events by subject", "subject_id", req.SubjectID, "error", err)
		return nil, fmt.Errorf("count affected events: %w", err)
	}

	erasureID := id.NewErasureID()
	now := time.Now().UTC()

	rec := &erasure.Erasure{
		Entity:         chronicle.NewEntity(),
		ID:             erasureID,
		SubjectID:      req.SubjectID,
		Reason:         req.Reason,
		RequestedBy:    req.RequestedBy,
		EventsAffected: affected,
		AppID:          info.AppID,
		TenantID:       info.TenantID,
	}
	rec.CreatedAt = now
	rec.UpdatedAt = now

	if recordErr := a.deps.ErasureStore.RecordErasure(c, rec); recordErr != nil {
		a.deps.Logger.ErrorContext(c, "failed to record erasure", "error", recordErr)
		return nil, fmt.Errorf("record erasure: %w", recordErr)
	}

	// Mark affected events as erased.
	marked, err := a.deps.ErasureStore.MarkErased(c, req.SubjectID, erasureID)
	if err != nil {
		a.deps.Logger.ErrorContext(c, "failed to mark events as erased", "error", err)
		return nil, fmt.Errorf("mark events as erased: %w", err)
	}

	result := &erasure.Result{
		ID:             erasureID,
		SubjectID:      req.SubjectID,
		EventsAffected: marked,
	}

	return result, ctx.JSON(http.StatusCreated, result)
}

// listErasures handles GET /v1/erasures.
func (a *API) listErasures(ctx forge.Context) error {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return err
	}

	c, span := a.tracer.Start(c, "chronicle.listErasures")
	defer span.End()

	opts := erasure.ListOpts{
		Limit:  defaultLimit(queryInt(ctx, "limit")),
		Offset: defaultOffset(queryInt(ctx, "offset")),
	}

	records, err := a.deps.ErasureStore.ListErasures(c, opts)
	if err != nil {
		a.deps.Logger.ErrorContext(c, "failed to list erasures", "error", err)
		return fmt.Errorf("list erasures: %w", err)
	}

	return ctx.JSON(http.StatusOK, records)
}

// getErasure handles GET /v1/erasures/:id.
func (a *API) getErasure(ctx forge.Context, _ *GetErasureRequest) (*erasure.Erasure, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	c, span := a.tracer.Start(c, "chronicle.getErasure")
	defer span.End()

	erasureID, err := parseErasureID(ctx.Param("id"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid erasure ID: %v", err))
	}

	rec, err := a.deps.ErasureStore.GetErasure(c, erasureID)
	if err != nil {
		return nil, mapStoreError(err)
	}

	return rec, ctx.JSON(http.StatusOK, rec)
}
