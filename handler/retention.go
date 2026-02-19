package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"

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

	policies, err := a.deps.RetentionStore.ListPolicies(c)
	if err != nil {
		a.deps.Logger.ErrorContext(c, "failed to list retention policies", "error", err)
		return fmt.Errorf("list policies: %w", err)
	}

	// Filter by app scope.
	info := scope.FromContext(c)
	filtered := make([]*retention.Policy, 0, len(policies))
	for _, p := range policies {
		if p.AppID == info.AppID {
			filtered = append(filtered, p)
		}
	}

	return ctx.JSON(http.StatusOK, filtered)
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
	}

	if err := a.deps.RetentionStore.SavePolicy(c, policy); err != nil {
		a.deps.Logger.ErrorContext(c, "failed to save retention policy", "error", err)
		return nil, fmt.Errorf("save policy: %w", err)
	}

	return policy, ctx.JSON(http.StatusCreated, policy)
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

	result, err := a.deps.Retention.Enforce(c)
	if err != nil {
		a.deps.Logger.ErrorContext(c, "failed to enforce retention", "error", err)
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
		Limit:  defaultLimit(queryInt(ctx, "limit")),
		Offset: defaultOffset(queryInt(ctx, "offset")),
	}

	archives, err := a.deps.RetentionStore.ListArchives(c, opts)
	if err != nil {
		a.deps.Logger.ErrorContext(c, "failed to list archives", "error", err)
		return fmt.Errorf("list archives: %w", err)
	}

	return ctx.JSON(http.StatusOK, archives)
}
