// Package scope provides context-based scope extraction for audit events and queries.
//
// When running inside Forge, it extracts AppID, TenantID, UserID, and IP
// from forge.Scope and authsome.User in the context. When running standalone,
// it gracefully handles missing scope values.
package scope

import (
	"context"
	"net/http"

	"github.com/xraph/chronicle/audit"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	appIDKey    contextKey = iota
	tenantIDKey contextKey = iota
	userIDKey   contextKey = iota
	ipKey       contextKey = iota
)

// Info holds extracted scope information from the context.
type Info struct {
	AppID    string
	TenantID string
	UserID   string
	IP       string
}

// WithAppID returns a context with the given app ID.
func WithAppID(ctx context.Context, appID string) context.Context {
	return context.WithValue(ctx, appIDKey, appID)
}

// WithTenantID returns a context with the given tenant ID.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// WithUserID returns a context with the given user ID.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// WithIP returns a context with the given IP address.
func WithIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ipKey, ip)
}

// WithInfo returns a context with all scope info set at once.
func WithInfo(ctx context.Context, info Info) context.Context {
	if info.AppID != "" {
		ctx = WithAppID(ctx, info.AppID)
	}
	if info.TenantID != "" {
		ctx = WithTenantID(ctx, info.TenantID)
	}
	if info.UserID != "" {
		ctx = WithUserID(ctx, info.UserID)
	}
	if info.IP != "" {
		ctx = WithIP(ctx, info.IP)
	}
	return ctx
}

// FromContext extracts scope information from the context.
// It checks for scope values set via With* functions.
// Returns zero Info if no scope is present (standalone mode).
func FromContext(ctx context.Context) Info {
	var info Info

	if v, ok := ctx.Value(appIDKey).(string); ok {
		info.AppID = v
	}
	if v, ok := ctx.Value(tenantIDKey).(string); ok {
		info.TenantID = v
	}
	if v, ok := ctx.Value(userIDKey).(string); ok {
		info.UserID = v
	}
	if v, ok := ctx.Value(ipKey).(string); ok {
		info.IP = v
	}

	return info
}

// FromRequest extracts the client IP from an HTTP request and merges it
// with any existing scope in the request's context.
func FromRequest(r *http.Request) Info {
	info := FromContext(r.Context())
	if info.IP == "" {
		info.IP = clientIP(r)
	}
	return info
}

// ApplyToEvent sets scope fields on an event from context.
// Fields already set on the event are not overwritten.
func ApplyToEvent(ctx context.Context, event *audit.Event) {
	info := FromContext(ctx)

	if event.AppID == "" {
		event.AppID = info.AppID
	}
	if event.TenantID == "" {
		event.TenantID = info.TenantID
	}
	if event.UserID == "" {
		event.UserID = info.UserID
	}
	if event.IP == "" {
		event.IP = info.IP
	}
}

// ApplyToQuery enforces scope on a query. For non-platform callers (those
// with a TenantID in context), the query's TenantID is forcibly set to
// the caller's tenant — preventing cross-tenant data access.
func ApplyToQuery(ctx context.Context, q *audit.Query) {
	info := FromContext(ctx)

	if q.AppID == "" {
		q.AppID = info.AppID
	}

	// Security-critical: enforce tenant scope for non-platform callers.
	// A tenant member's query always gets scoped to their tenant.
	if info.TenantID != "" {
		q.TenantID = info.TenantID
	}
}

// ApplyToAggregateQuery enforces scope on an aggregate query.
func ApplyToAggregateQuery(ctx context.Context, q *audit.AggregateQuery) {
	info := FromContext(ctx)

	if q.AppID == "" {
		q.AppID = info.AppID
	}
	if info.TenantID != "" {
		q.TenantID = info.TenantID
	}
}

// ApplyToCountQuery enforces scope on a count query.
func ApplyToCountQuery(ctx context.Context, q *audit.CountQuery) {
	info := FromContext(ctx)

	if q.AppID == "" {
		q.AppID = info.AppID
	}
	if info.TenantID != "" {
		q.TenantID = info.TenantID
	}
}

// clientIP extracts the client IP from an HTTP request,
// checking X-Forwarded-For and X-Real-IP headers first.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can be a comma-separated list; take the first.
		for i := range len(xff) {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr, stripping port.
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
