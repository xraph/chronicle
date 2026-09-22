package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/scope"
)

// listCheckpoints handles GET /v1/checkpoints.
func (a *API) listCheckpoints(ctx forge.Context) error {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return err
	}

	if a.deps.CheckpointStore == nil {
		return forge.NewHTTPError(http.StatusServiceUnavailable, "checkpoints are not configured")
	}

	c, span := a.tracer.Start(c, "chronicle.listCheckpoints")
	defer span.End()

	info := scope.FromContext(c)
	opts := checkpoint.ListOpts{
		Limit:  defaultLimit(queryInt(ctx, "limit")),
		Offset: defaultOffset(queryInt(ctx, "offset")),
	}

	cps, err := a.checkpointsForScope(c, info.AppID, info.TenantID, opts)
	if err != nil {
		a.deps.Logger.Error("failed to list checkpoints", log.Error(err))
		return fmt.Errorf("list checkpoints: %w", err)
	}

	// Security-critical: filtered again here even though both paths
	// checkpointsForScope can take already scope by (appID, tenantID), so a
	// bug in either one cannot by itself leak another tenant's checkpoint.
	filtered := make([]*checkpoint.Checkpoint, 0, len(cps))
	for _, cp := range cps {
		if ownedByCaller(c, cp.AppID, cp.TenantID) {
			filtered = append(filtered, cp)
		}
	}

	return ctx.JSON(http.StatusOK, filtered)
}

// checkpointsForScope returns every checkpoint belonging to (appID, tenantID).
//
// checkpoint.Store has no scope-wide query: every method on it but
// GetCheckpoint and AppendCheckpoint takes a streamID, because a checkpoint is
// fundamentally a per-stream artifact (see checkpoint/checkpoint.go's package
// doc). Every app+tenant pair owns exactly one stream (see stream/doc.go), so
// resolving that stream through StreamStore and listing its checkpoints is
// the only path available, and a complete one.
//
// That routes a checkpoint's visibility through its stream row, which is the
// wrong dependency direction for an artifact whose whole purpose is to
// outlive and testify about that stream: a checkpoint whose stream row was
// somehow removed would become invisible here even though the signed record
// itself is untouched. No stream-deletion path exists anywhere in this
// repository today, so this is latent, not reachable -- flagged here for
// whoever adds one.
func (a *API) checkpointsForScope(
	ctx context.Context, appID, tenantID string, opts checkpoint.ListOpts,
) ([]*checkpoint.Checkpoint, error) {
	if a.deps.StreamStore == nil {
		return nil, nil
	}
	st, err := a.deps.StreamStore.GetStreamByScope(ctx, appID, tenantID)
	if err != nil {
		// isNotFound alone is not enough on every backend. GetStreamByScope's
		// groveError mapping (store/sqlite, store/postgres) checks
		// errors.Is(err, grove.ErrNoRows) and the literal string "no rows in
		// result set", but this driver's actual not-found error is
		// sql.ErrNoRows, whose message carries a "sql: " prefix that literal
		// never matches -- so groveError returns the raw driver error instead
		// of chronicle.ErrStreamNotFound. Recognizing sql.ErrNoRows directly
		// here, rather than fixing groveError, avoids reaching into a shared
		// helper that is broken in a second, unrelated way (the postgres
		// half) and needs its own fix outside this task.
		if isNotFound(err) || errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return a.deps.CheckpointStore.ListCheckpoints(ctx, st.ID, opts)
}

// getCheckpoint handles GET /v1/checkpoints/:id.
func (a *API) getCheckpoint(ctx forge.Context, _ *GetCheckpointRequest) (*checkpoint.Checkpoint, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if a.deps.CheckpointStore == nil {
		return nil, forge.NewHTTPError(http.StatusServiceUnavailable, "checkpoints are not configured")
	}

	c, span := a.tracer.Start(c, "chronicle.getCheckpoint")
	defer span.End()

	checkpointID, err := parseCheckpointID(ctx.Param("id"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid checkpoint ID: %v", err))
	}

	cp, err := a.deps.CheckpointStore.GetCheckpoint(c, checkpointID)
	if err != nil {
		return nil, mapStoreError(err)
	}

	// Security-critical: a checkpoint must not be readable by ID alone.
	if !ownedByCaller(c, cp.AppID, cp.TenantID) {
		return nil, forge.NotFound("checkpoint not found")
	}

	return cp, nil
}

// forceCheckpoint handles POST /v1/checkpoints.
func (a *API) forceCheckpoint(ctx forge.Context, req *ForceCheckpointRequest) (*checkpoint.Checkpoint, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if a.deps.Checkpointer == nil {
		return nil, forge.NewHTTPError(http.StatusServiceUnavailable, "checkpointing is not configured")
	}

	if req.StreamID == "" {
		return nil, forge.BadRequest("stream_id is required")
	}
	streamID, err := parseStreamID(req.StreamID)
	if err != nil {
		return nil, forge.BadRequest("invalid stream_id")
	}

	c, span := a.tracer.Start(c, "chronicle.forceCheckpoint",
		trace.WithAttributes(attribute.String("stream_id", req.StreamID)))
	defer span.End()

	// Security-critical: confirm the caller owns the stream before signing a
	// checkpoint over it. Without this, any caller could force a checkpoint
	// on another tenant's stream, which is a write, not just a read.
	if a.deps.StreamStore == nil {
		return nil, forge.NewHTTPError(
			http.StatusServiceUnavailable,
			"stream store not configured; checkpointing cannot confirm stream ownership",
		)
	}

	st, err := a.deps.StreamStore.GetStream(c, streamID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	if !ownedByCaller(c, st.AppID, st.TenantID) {
		return nil, forge.NotFound("stream not found")
	}

	cp, err := a.deps.Checkpointer.CheckpointStream(c, checkpoint.StreamHead{
		ID:       st.ID,
		AppID:    st.AppID,
		TenantID: st.TenantID,
		HeadSeq:  st.HeadSeq,
		HeadHash: st.HeadHash,
	})
	if err != nil {
		if errors.Is(err, checkpoint.ErrNothingToCheckpoint) {
			return nil, forge.NewHTTPError(http.StatusConflict, err.Error())
		}
		a.deps.Logger.Error("failed to force checkpoint", log.String("stream_id", req.StreamID), log.Error(err))
		return nil, fmt.Errorf("force checkpoint: %w", err)
	}

	return nil, ctx.JSON(http.StatusCreated, cp)
}
