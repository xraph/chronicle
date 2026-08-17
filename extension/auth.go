package extension

import (
	"fmt"

	"github.com/xraph/forge"
	"github.com/xraph/forge/extensions/auth"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle/handler"
)

// buildGuards turns the auth config into enforcing middleware for each route
// class.
//
// Returning zero Guards is only valid when the operator set
// auth.allow_unauthenticated; [AuthConfig.Validate] enforces that before this is
// called. If a provider is named but the registry is missing, this fails rather
// than mounting unprotected routes — a misconfiguration must not silently
// degrade into an open API.
func (e *Extension) buildGuards(fapp forge.App) (handler.Guards, error) {
	cfg := e.config.Auth

	if !cfg.Configured() {
		// Validate has already confirmed this is deliberate.
		e.Logger().Warn("chronicle: admin API mounted without authentication; " +
			"any caller reaching these routes can purge audit history")
		return handler.Guards{}, nil
	}

	registry, err := vessel.Inject[auth.Registry](fapp.Container())
	if err != nil {
		return handler.Guards{}, fmt.Errorf("%w: %w", ErrAuthProviderUnavailable, err)
	}

	if !registry.Has(cfg.Provider) {
		return handler.Guards{}, fmt.Errorf(
			"chronicle: auth provider %q is not registered; available providers: %v",
			cfg.Provider, registry.List(),
		)
	}

	guard := func(scopes []string) handler.Guard {
		return handler.Guard{
			// MiddlewareWithScopes authenticates via the provider and rejects a
			// caller lacking any required scope. This is the enforcing layer;
			// forge's WithAuth route options only annotate the OpenAPI spec.
			Middleware: registry.MiddlewareWithScopes(cfg.Provider, scopes...),
			Provider:   cfg.Provider,
			Scopes:     scopes,
		}
	}

	e.Logger().Info("chronicle: admin API protected",
		forge.F("provider", cfg.Provider),
		forge.F("read_scopes", cfg.ReadScopes),
		forge.F("write_scopes", cfg.WriteScopes),
		forge.F("admin_scopes", cfg.AdminScopes),
	)

	return handler.Guards{
		Read:  guard(cfg.ReadScopes),
		Write: guard(cfg.WriteScopes),
		Admin: guard(cfg.AdminScopes),
	}, nil
}
