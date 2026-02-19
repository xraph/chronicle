package scope_test

import (
	"context"
	"net/http"
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
			name:     "X-Forwarded-For single",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			remoteIP: "9.9.9.9:1234",
			wantIP:   "1.2.3.4",
		},
		{
			name:     "X-Forwarded-For multiple",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
			remoteIP: "9.9.9.9:1234",
			wantIP:   "1.2.3.4",
		},
		{
			name:     "X-Real-IP",
			headers:  map[string]string{"X-Real-IP": "10.0.0.1"},
			remoteIP: "9.9.9.9:1234",
			wantIP:   "10.0.0.1",
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
