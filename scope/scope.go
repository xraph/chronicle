// Package scope provides context-based scope extraction for audit events and queries.
//
// When running inside Forge, it extracts AppID, TenantID, UserID, and IP
// from forge.Scope and authsome.User in the context. When running standalone,
// it gracefully handles missing scope values.
package scope

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

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
//
// Proxy headers are ignored: the IP comes from the connection's peer address.
// X-Forwarded-For and X-Real-IP are set by whoever is talking to you, so
// trusting them lets any caller choose the address written into the audit trail.
// If your service really sits behind a proxy, use [FromRequestWithProxies] with
// that proxy's address range.
func FromRequest(r *http.Request) Info {
	return FromRequestWithProxies(r, nil)
}

// FromRequestWithProxies is [FromRequest] but honours X-Forwarded-For and
// X-Real-IP when the request's peer is one of the trusted proxies.
//
// With a trusted peer, the client-most entry of X-Forwarded-For is used. Build
// trusted from your load balancer's ranges with [ParseTrustedProxies]; passing
// nil disables header trust entirely.
func FromRequestWithProxies(r *http.Request, trusted []netip.Prefix) Info {
	info := FromContext(r.Context())
	if info.IP == "" {
		info.IP = clientIP(r, trusted)
	}
	return info
}

// ParseTrustedProxies converts CIDR blocks or bare addresses into prefixes for
// [FromRequestWithProxies].
//
//	trusted, err := scope.ParseTrustedProxies([]string{"10.0.0.0/8", "192.168.1.1"})
func ParseTrustedProxies(entries []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("scope: trusted proxy %q: %w", entry, err)
			}
			prefixes = append(prefixes, prefix)
			continue
		}

		// A bare address is a single-host prefix.
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("scope: trusted proxy %q: %w", entry, err)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return prefixes, nil
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

// clientIP resolves the address to record for a request.
//
// The peer address is authoritative unless the peer is a trusted proxy, in which
// case the forwarded headers are consulted. A forwarded value that is not a
// valid address falls back to the peer rather than recording garbage.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := peerIP(r.RemoteAddr)

	if len(trusted) == 0 || !isTrusted(peer, trusted) {
		return peer
	}

	// The client-most entry is the left-most, since each hop appends.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := xff
		if i := strings.IndexByte(xff, ','); i >= 0 {
			first = xff[:i]
		}
		if addr, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
			return addr.String()
		}
	}

	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if addr, err := netip.ParseAddr(xri); err == nil {
			return addr.String()
		}
	}

	return peer
}

// peerIP strips the port from a RemoteAddr, handling bracketed IPv6.
func peerIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}

	// No port present; may still be a bare IPv6 in brackets.
	return strings.Trim(remoteAddr, "[]")
}

// isTrusted reports whether addr falls inside any trusted prefix.
func isTrusted(addr string, trusted []netip.Prefix) bool {
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	// Compare on the unmapped form so a 4-in-6 peer matches an IPv4 prefix.
	parsed = parsed.Unmap()

	for _, prefix := range trusted {
		if prefix.Contains(parsed) {
			return true
		}
	}
	return false
}
