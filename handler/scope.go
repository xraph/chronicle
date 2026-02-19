package handler

import (
	"context"

	"github.com/xraph/forge"

	"github.com/xraph/chronicle/scope"
)

// scopedContext bridges forge.Scope from the forge.Context into chronicle's
// scope context values. This allows all downstream code (scope.ApplyToQuery,
// scope.FromContext, etc.) to work transparently.
//
// When forge.Scope is present on the context, it maps:
//
//	forge.Scope.AppID()  → scope.WithAppID
//	forge.Scope.OrgID() → scope.WithTenantID  (OrgID maps to TenantID)
//
// Any existing chronicle scope values already on the context are preserved.
func scopedContext(ctx forge.Context) context.Context {
	c := ctx.Context()

	// Try to extract forge.Scope from the context.
	s, ok := forge.ScopeFrom(c)
	if !ok {
		// No forge scope present — check if chronicle scope is already set.
		return c
	}

	// Map forge scope to chronicle scope context values.
	if appID := s.AppID(); appID != "" {
		c = scope.WithAppID(c, appID)
	}
	if orgID := s.OrgID(); orgID != "" {
		c = scope.WithTenantID(c, orgID)
	}

	return c
}

// requireScope checks that the context has a valid app scope set.
// Returns a forge error if scope is missing.
func requireScope(ctx context.Context) error {
	info := scope.FromContext(ctx)
	if info.AppID == "" {
		return forge.NewHTTPError(401, "missing app scope")
	}
	return nil
}
