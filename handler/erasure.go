package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"
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

	// Security-critical: the subject is resolved within the caller's scope, so
	// an erasure request can only count and mark that app and tenant's events.
	// Unscoped, any caller could both learn how many events another tenant holds
	// on a subject and flag them all as erased.
	subject := erasure.SubjectQuery{
		Scope:     erasure.Scope{AppID: info.AppID, TenantID: info.TenantID},
		SubjectID: req.SubjectID,
	}

	// Prefer the erasure service: it destroys the subject's encryption key, which
	// is what makes the payload unrecoverable. The store-only path below can only
	// flag events, and is correct only when nothing encrypted them.
	if a.deps.Erasure != nil {
		result, svcErr := a.deps.Erasure.Erase(c, &erasure.Input{
			SubjectID:   req.SubjectID,
			Reason:      req.Reason,
			RequestedBy: req.RequestedBy,
		}, info.AppID, info.TenantID)
		if svcErr != nil {
			a.deps.Logger.Error("failed to erase subject",
				log.String("subject_id", req.SubjectID), log.Error(svcErr))
			return nil, fmt.Errorf("erase subject: %w", svcErr)
		}

		return nil, ctx.JSON(http.StatusCreated, result)
	}

	// Count affected events before recording.
	affected, err := a.deps.ErasureStore.CountBySubject(c, subject)
	if err != nil {
		a.deps.Logger.Error("failed to count events by subject", log.String("subject_id", req.SubjectID), log.Error(err))
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
		a.deps.Logger.Error("failed to record erasure", log.Error(recordErr))
		return nil, fmt.Errorf("record erasure: %w", recordErr)
	}

	// Mark affected events as erased.
	marked, err := a.deps.ErasureStore.MarkErased(c, subject, erasureID)
	if err != nil {
		a.deps.Logger.Error("failed to mark events as erased", log.Error(err))
		return nil, fmt.Errorf("mark events as erased: %w", err)
	}

	result := &erasure.Result{
		ID:             erasureID,
		SubjectID:      req.SubjectID,
		EventsAffected: marked,
	}

	// forge writes http.StatusOK for any non-nil first return, so a 201 has to
	// be written here with a nil body returned so forge does not write again.
	return nil, ctx.JSON(http.StatusCreated, result)
}

// listErasures handles GET /v1/erasures.
func (a *API) listErasures(ctx forge.Context) error {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return err
	}

	c, span := a.tracer.Start(c, "chronicle.listErasures")
	defer span.End()

	// Security-critical: erasure records carry subject IDs, reasons and
	// requesters. Scope is applied by the store, before LIMIT/OFFSET.
	info := scope.FromContext(c)
	opts := erasure.ListOpts{
		Scope:  erasure.Scope{AppID: info.AppID, TenantID: info.TenantID},
		Limit:  defaultLimit(queryInt(ctx, "limit")),
		Offset: defaultOffset(queryInt(ctx, "offset")),
	}

	records, err := a.deps.ErasureStore.ListErasures(c, opts)
	if err != nil {
		a.deps.Logger.Error("failed to list erasures", log.Error(err))
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

	// Security-critical: a record must not be readable by ID alone.
	if !ownedByCaller(c, rec.AppID, rec.TenantID) {
		return nil, forge.NotFound("erasure not found")
	}

	return rec, nil
}
