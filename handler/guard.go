package handler

import (
	"github.com/xraph/forge"
)

// Guard protects one class of routes.
//
// Middleware does the enforcing; Provider and Scopes exist so the generated
// OpenAPI spec describes the same requirement. A zero Guard leaves its routes
// unprotected, which is why [Guards.Validate] exists — the extension refuses to
// mount an unguarded API unless the operator opts in explicitly.
type Guard struct {
	// Middleware authenticates the caller and rejects insufficient permissions.
	// Nil means the route class is unprotected.
	Middleware forge.Middleware

	// Provider names the OpenAPI security scheme this guard authenticates with.
	Provider string

	// Scopes are the permissions Middleware enforces, recorded for documentation.
	Scopes []string
}

// IsZero reports whether the guard enforces nothing.
func (g Guard) IsZero() bool { return g.Middleware == nil }

// routeOptions returns the forge options that apply this guard to a route.
//
// The middleware is what actually blocks a request. WithRequiredAuth only writes
// metadata that the OpenAPI generator reads, so it documents the requirement and
// must never be relied on alone — in forge v1.9.5 nothing enforces that metadata
// at request time.
func (g Guard) routeOptions() []forge.RouteOption {
	if g.IsZero() {
		return nil
	}

	opts := []forge.RouteOption{forge.WithMiddleware(g.Middleware)}
	if g.Provider != "" {
		opts = append(opts, forge.WithRequiredAuth(g.Provider, g.Scopes...))
	}
	return opts
}

// Guards holds one guard per operation class, graded by blast radius.
//
//   - Read covers everything that only observes: listing and fetching events,
//     stats, reports, policies, archives, and chain verification.
//   - Write covers creating records that do not destroy anything: saving a
//     retention policy, generating a compliance report.
//   - Admin covers the irreversible operations: enforcing retention (which
//     purges events), deleting a policy, and requesting an erasure.
type Guards struct {
	Read  Guard
	Write Guard
	Admin Guard
}

// Unprotected returns the names of the route classes that enforce nothing.
// The extension uses this to decide whether it may mount the API.
func (g Guards) Unprotected() []string {
	var names []string
	if g.Read.IsZero() {
		names = append(names, "read")
	}
	if g.Write.IsZero() {
		names = append(names, "write")
	}
	if g.Admin.IsZero() {
		names = append(names, "admin")
	}
	return names
}

// IsZero reports whether no class is protected at all.
func (g Guards) IsZero() bool {
	return g.Read.IsZero() && g.Write.IsZero() && g.Admin.IsZero()
}

// read returns opts with the read guard's options prepended.
//
// Read covers observation: listing and fetching events, stats, reports,
// policies and archives, plus chain verification.
func (a *API) read(opts ...forge.RouteOption) []forge.RouteOption {
	return append(a.deps.Guards.Read.routeOptions(), opts...)
}

// write returns opts with the write guard's options prepended.
//
// Write covers creating records without destroying anything: saving a retention
// policy, generating a compliance report.
func (a *API) write(opts ...forge.RouteOption) []forge.RouteOption {
	return append(a.deps.Guards.Write.routeOptions(), opts...)
}

// admin returns opts with the admin guard's options prepended.
//
// Admin covers the irreversible operations: enforcing retention, which purges
// events; deleting a policy, which silently disables retention; and requesting
// an erasure, which flags a subject's events and cannot be undone.
func (a *API) admin(opts ...forge.RouteOption) []forge.RouteOption {
	return append(a.deps.Guards.Admin.routeOptions(), opts...)
}
