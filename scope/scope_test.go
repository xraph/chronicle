package scope_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/scope"
)

func TestFromContextEmpty(t *testing.T) {
	info := scope.FromContext(context.Background())
	if info.AppID != "" || info.TenantID != "" || info.UserID != "" || info.IP != "" {
		t.Fatalf("expected empty info, got %+v", info)
	}
}

func TestFromContextWithValues(t *testing.T) {
	ctx := context.Background()
	ctx = scope.WithAppID(ctx, "app1")
	ctx = scope.WithTenantID(ctx, "tenant1")
	ctx = scope.WithUserID(ctx, "user1")
	ctx = scope.WithIP(ctx, "10.0.0.1")

	info := scope.FromContext(ctx)
	if info.AppID != "app1" {
		t.Errorf("AppID = %q, want %q", info.AppID, "app1")
	}
	if info.TenantID != "tenant1" {
		t.Errorf("TenantID = %q, want %q", info.TenantID, "tenant1")
	}
	if info.UserID != "user1" {
		t.Errorf("UserID = %q, want %q", info.UserID, "user1")
	}
	if info.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want %q", info.IP, "10.0.0.1")
	}
}

func TestWithInfo(t *testing.T) {
	ctx := scope.WithInfo(context.Background(), scope.Info{
		AppID:    "myapp",
		TenantID: "mytenant",
		UserID:   "myuser",
		IP:       "1.2.3.4",
	})

	info := scope.FromContext(ctx)
	if info.AppID != "myapp" || info.TenantID != "mytenant" || info.UserID != "myuser" || info.IP != "1.2.3.4" {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestApplyToEvent(t *testing.T) {
	ctx := scope.WithInfo(context.Background(), scope.Info{
		AppID:    "app1",
		TenantID: "tenant1",
		UserID:   "user1",
		IP:       "10.0.0.1",
	})

	event := &audit.Event{}
	scope.ApplyToEvent(ctx, event)

	if event.AppID != "app1" {
		t.Errorf("AppID = %q, want %q", event.AppID, "app1")
	}
	if event.TenantID != "tenant1" {
		t.Errorf("TenantID = %q, want %q", event.TenantID, "tenant1")
	}
	if event.UserID != "user1" {
		t.Errorf("UserID = %q, want %q", event.UserID, "user1")
	}
	if event.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want %q", event.IP, "10.0.0.1")
	}
}

func TestApplyToEventNoOverwrite(t *testing.T) {
	ctx := scope.WithInfo(context.Background(), scope.Info{
		AppID:    "app1",
		TenantID: "tenant1",
	})

	event := &audit.Event{
		AppID:    "existing-app",
		TenantID: "existing-tenant",
	}
	scope.ApplyToEvent(ctx, event)

	if event.AppID != "existing-app" {
		t.Errorf("AppID should not be overwritten, got %q", event.AppID)
	}
	if event.TenantID != "existing-tenant" {
		t.Errorf("TenantID should not be overwritten, got %q", event.TenantID)
	}
}

func TestApplyToEventNoScope(t *testing.T) {
	event := &audit.Event{AppID: "pre-set"}
	scope.ApplyToEvent(context.Background(), event)

	if event.AppID != "pre-set" {
		t.Errorf("AppID should remain %q, got %q", "pre-set", event.AppID)
	}
}

func TestApplyToQuery(t *testing.T) {
	ctx := scope.WithInfo(context.Background(), scope.Info{
		AppID:    "app1",
		TenantID: "tenant1",
	})

	q := &audit.Query{}
	scope.ApplyToQuery(ctx, q)

	if q.AppID != "app1" {
		t.Errorf("AppID = %q, want %q", q.AppID, "app1")
	}
	if q.TenantID != "tenant1" {
		t.Errorf("TenantID = %q, want %q", q.TenantID, "tenant1")
	}
}

func TestApplyToQueryEnforcesTenantScope(t *testing.T) {
	ctx := scope.WithTenantID(context.Background(), "enforced-tenant")

	q := &audit.Query{TenantID: "hacker-attempt"}
	scope.ApplyToQuery(ctx, q)

	// Tenant scope must be forced, not optional.
	if q.TenantID != "enforced-tenant" {
		t.Errorf("TenantID should be forcibly set to %q, got %q", "enforced-tenant", q.TenantID)
	}
}

func TestApplyToQueryPlatformCaller(t *testing.T) {
	// Platform callers have no TenantID — they can see all tenants.
	ctx := scope.WithAppID(context.Background(), "app1")

	q := &audit.Query{TenantID: "specific-tenant"}
	scope.ApplyToQuery(ctx, q)

	// Platform caller should NOT override the explicit tenant.
	if q.TenantID != "specific-tenant" {
		t.Errorf("TenantID should remain %q for platform caller, got %q", "specific-tenant", q.TenantID)
	}
}

func TestFromRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remoteIP string
		wantIP   string
	}{
		{
			// Proxy headers are client-controlled, so FromRequest ignores
			// them and records the peer. See FromRequestWithProxies for the
			// behind-a-proxy case.
			name:     "X-Forwarded-For single is not trusted",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			remoteIP: "9.9.9.9:1234",
			wantIP:   "9.9.9.9",
		},
		{
			name:     "X-Forwarded-For multiple is not trusted",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
			remoteIP: "9.9.9.9:1234",
			wantIP:   "9.9.9.9",
		},
		{
			name:     "X-Real-IP is not trusted",
			headers:  map[string]string{"X-Real-IP": "10.0.0.1"},
			remoteIP: "9.9.9.9:1234",
			wantIP:   "9.9.9.9",
		},
		{
			name:     "RemoteAddr with port",
			headers:  map[string]string{},
			remoteIP: "192.168.1.1:5678",
			wantIP:   "192.168.1.1",
		},
		{
			name:     "RemoteAddr without port",
			headers:  map[string]string{},
			remoteIP: "192.168.1.1",
			wantIP:   "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteIP
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}

			info := scope.FromRequest(r)
			if info.IP != tt.wantIP {
				t.Errorf("IP = %q, want %q", info.IP, tt.wantIP)
			}
		})
	}
}

func TestFromRequestPreservesContextScope(t *testing.T) {
	ctx := scope.WithAppID(context.Background(), "from-ctx")
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	r.RemoteAddr = "5.5.5.5:8080"

	info := scope.FromRequest(r)
	if info.AppID != "from-ctx" {
		t.Errorf("AppID = %q, want %q", info.AppID, "from-ctx")
	}
	if info.IP != "5.5.5.5" {
		t.Errorf("IP = %q, want %q", info.IP, "5.5.5.5")
	}
}

// ──────────────────────────────────────────────────
// Client IP trust
// ──────────────────────────────────────────────────

// TestFromRequestIgnoresForwardedHeadersByDefault pins that an audit record's IP
// cannot be set by the client.
//
// X-Forwarded-For used to be trusted unconditionally, so any caller could choose
// the address written into the audit trail. "Who did it and from where" is the
// part of an audit record most worth falsifying, so proxy headers are only
// honoured when the peer is a configured trusted proxy.
func TestFromRequestIgnoresForwardedHeadersByDefault(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.7:34512"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")

	got := scope.FromRequest(r).IP
	if got != "198.51.100.7" {
		t.Fatalf("IP = %q, want the peer address 198.51.100.7; a client must not be able to choose it", got)
	}
}

func TestFromRequestStripsPortFromRemoteAddr(t *testing.T) {
	tests := map[string]string{
		"198.51.100.7:34512":  "198.51.100.7",
		"[2001:db8::1]:34512": "2001:db8::1",
		"198.51.100.7":        "198.51.100.7",
	}

	for remote, want := range tests {
		t.Run(remote, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = remote

			if got := scope.FromRequest(r).IP; got != want {
				t.Fatalf("IP = %q, want %q", got, want)
			}
		})
	}
}

// TestFromRequestBehindTrustedProxyUsesForwardedFor covers the deployment where
// the proxy header is the real source of truth.
func TestFromRequestBehindTrustedProxyUsesForwardedFor(t *testing.T) {
	trusted, err := scope.ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:34512"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.1.2.3")

	got := scope.FromRequestWithProxies(r, trusted).IP
	if got != "203.0.113.9" {
		t.Fatalf("IP = %q, want the client-most forwarded address 203.0.113.9", got)
	}
}

// TestFromRequestUntrustedPeerIgnoresForwardedFor is the same call from an
// address outside the trusted set.
func TestFromRequestUntrustedPeerIgnoresForwardedFor(t *testing.T) {
	trusted, err := scope.ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.200:34512"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := scope.FromRequestWithProxies(r, trusted).IP
	if got != "203.0.113.200" {
		t.Fatalf("IP = %q, want the untrusted peer's own address", got)
	}
}

// TestFromRequestTrimsForwardedWhitespace pins that a padded header value does
// not produce a malformed IP.
func TestFromRequestTrimsForwardedWhitespace(t *testing.T) {
	trusted, err := scope.ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:34512"
	r.Header.Set("X-Forwarded-For", "   203.0.113.9   ,  10.1.2.3 ")

	if got := scope.FromRequestWithProxies(r, trusted).IP; got != "203.0.113.9" {
		t.Fatalf("IP = %q, want 203.0.113.9 with surrounding whitespace removed", got)
	}
}

// TestFromRequestRejectsGarbageForwardedValue falls back rather than recording a
// non-address.
func TestFromRequestRejectsGarbageForwardedValue(t *testing.T) {
	trusted, err := scope.ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:34512"
	r.Header.Set("X-Forwarded-For", "not-an-ip")

	if got := scope.FromRequestWithProxies(r, trusted).IP; got != "10.1.2.3" {
		t.Fatalf("IP = %q, want the peer address when the header is not an IP", got)
	}
}

// TestFromRequestPrefersExistingContextIP keeps the existing precedence.
func TestFromRequestPrefersExistingContextIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.7:34512"
	r = r.WithContext(scope.WithIP(r.Context(), "192.0.2.1"))

	if got := scope.FromRequest(r).IP; got != "192.0.2.1" {
		t.Fatalf("IP = %q, want the context value 192.0.2.1", got)
	}
}

func TestParseTrustedProxiesRejectsInvalidCIDR(t *testing.T) {
	if _, err := scope.ParseTrustedProxies([]string{"nonsense"}); err == nil {
		t.Fatal("expected an error for an invalid CIDR")
	}
}

func TestParseTrustedProxiesAcceptsBareAddress(t *testing.T) {
	trusted, err := scope.ParseTrustedProxies([]string{"10.1.2.3"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:34512"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")

	if got := scope.FromRequestWithProxies(r, trusted).IP; got != "203.0.113.9" {
		t.Fatalf("IP = %q, want 203.0.113.9", got)
	}
}
