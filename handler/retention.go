package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
)

// listPolicies handles GET /v1/retention.
func (a *API) listPolicies(ctx forge.Context) error {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return err
	}

	c, span := a.tracer.Start(c, "chronicle.listPolicies")
	defer span.End()

	// Security-critical: scope is applied by the store, before LIMIT/OFFSET.
	// Filtering after pagination returned an empty page whenever another
	// tenant's policies filled the first page.
	policies, err := a.deps.RetentionStore.ListPolicies(c, retention.ListPoliciesOpts{
		Scope:  retentionScope(c),
		Limit:  defaultLimit(queryInt(ctx, "limit")),
		Offset: defaultOffset(queryInt(ctx, "offset")),
	})
	if err != nil {
		a.deps.Logger.Error("failed to list retention policies", log.Error(err))
		return fmt.Errorf("list policies: %w", err)
	}

	return ctx.JSON(http.StatusOK, policies)
}

// savePolicy handles POST /v1/retention.
func (a *API) savePolicy(ctx forge.Context, req *SavePolicyRequest) (*retention.Policy, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if req.Category == "" {
		return nil, forge.BadRequest("category is required")
	}
	if req.Duration == "" {
		return nil, forge.BadRequest("duration is required")
	}

	dur, err := time.ParseDuration(req.Duration)
	if err != nil {
		return nil, forge.BadRequest("invalid duration format")
	}

	c, span := a.tracer.Start(c, "chronicle.savePolicy")
	defer span.End()

	info := scope.FromContext(c)

	policy := &retention.Policy{
		Entity:   chronicle.NewEntity(),
		ID:       id.NewPolicyID(),
		Category: req.Category,
		Duration: dur,
		Archive:  req.Archive,
		AppID:    info.AppID,
		TenantID: info.TenantID,
	}

	if err := a.deps.RetentionStore.SavePolicy(c, policy); err != nil {
		a.deps.Logger.Error("failed to save retention policy", log.Error(err))
		return nil, fmt.Errorf("save policy: %w", err)
	}

	// forge writes http.StatusOK for any non-nil first return, so a 201 has to
	// be written here with a nil body returned so forge does not write again.
	return nil, ctx.JSON(http.StatusCreated, policy)
}

// deletePolicy handles DELETE /v1/retention/:id.
func (a *API) deletePolicy(ctx forge.Context, _ *DeletePolicyRequest) (*struct{}, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	policyID, err := parsePolicyID(ctx.Param("id"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid policy ID: %v", err))
	}

	c, span := a.tracer.Start(c, "chronicle.deletePolicy")
	defer span.End()

	// Security-critical: confirm ownership before deleting. Without this any
	// caller could disable another tenant's retention by guessing an ID.
	existing, err := a.deps.RetentionStore.GetPolicy(c, policyID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	if !ownedByCaller(c, existing.AppID, existing.TenantID) {
		return nil, forge.NotFound("policy not found")
	}

	if err := a.deps.RetentionStore.DeletePolicy(c, policyID); err != nil {
		return nil, mapStoreError(err)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

// enforceRetention handles POST /v1/retention/enforce.
func (a *API) enforceRetention(ctx forge.Context) error {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return err
	}

	if a.deps.Retention == nil {
		return forge.NewHTTPError(http.StatusServiceUnavailable, "retention enforcer not configured")
	}

	c, span := a.tracer.Start(c, "chronicle.enforceRetention")
	defer span.End()

	// Security-critical: run only the caller's own policies. Enforce() covers
	// every app and belongs to the background scheduler, not to a request.
	result, err := a.deps.Retention.EnforceScope(c, retentionScope(c))
	if err != nil {
		a.deps.Logger.Error("failed to enforce retention", log.Error(err))
		return fmt.Errorf("enforce retention: %w", err)
	}

	return ctx.JSON(http.StatusOK, result)
}

// listArchives handles GET /v1/retention/archives.
func (a *API) listArchives(ctx forge.Context) error {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return err
	}

	c, span := a.tracer.Start(c, "chronicle.listArchives")
	defer span.End()

	opts := retention.ListOpts{
		Scope:  retentionScope(c),
		Limit:  defaultLimit(queryInt(ctx, "limit")),
		Offset: defaultOffset(queryInt(ctx, "offset")),
	}

	archives, err := a.deps.RetentionStore.ListArchives(c, opts)
	if err != nil {
		a.deps.Logger.Error("failed to list archives", log.Error(err))
		return fmt.Errorf("list archives: %w", err)
	}

	return ctx.JSON(http.StatusOK, archives)
}
