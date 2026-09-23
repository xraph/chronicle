package contract

import (
	"testing"

	"github.com/xraph/chronicle/audit"
)

// An absent app_id must be refused. An empty AppID does not mean "this app",
// it means every app every operator owns: chronicle's store queries treat an
// empty scope as matching everything, so defaulting here would list another
// customer's audit events and let retention enforcement purge their history.
func TestScopeFromPrincipalRefusesMissingAppID(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"no claims":    nil,
		"empty app_id": {"app_id": ""},
		"wrong type":   {"app_id": 42},
		"nil app_id":   {"app_id": nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scopeFromPrincipal(principalWith(claims)); err == nil {
				t.Fatal("scopeFromPrincipal accepted a principal with no usable app_id")
			}
		})
	}
}

func TestScopeFromPrincipalReadsAppAndTenant(t *testing.T) {
	v, err := scopeFromPrincipal(principalWith(map[string]any{
		"app_id":    "app-1",
		"tenant_id": "tenant-a",
	}))
	if err != nil {
		t.Fatalf("scopeFromPrincipal: %v", err)
	}
	if v.AppID != "app-1" || v.TenantID != "tenant-a" {
		t.Fatalf("got %+v, want app-1/tenant-a", v)
	}
}

// org_id is authsome's spelling for the same dimension. Accepting it keeps a
// deployment that already sets it working without a second convention.
func TestScopeFromPrincipalFallsBackToOrgID(t *testing.T) {
	v, err := scopeFromPrincipal(principalWith(map[string]any{
		"app_id": "app-1",
		"org_id": "tenant-b",
	}))
	if err != nil {
		t.Fatalf("scopeFromPrincipal: %v", err)
	}
	if v.TenantID != "tenant-b" {
		t.Fatalf("TenantID = %q, want tenant-b", v.TenantID)
	}
}

// tenant_id is checked first, so a session carrying both spellings is
// scoped by tenant_id.
func TestScopeFromPrincipalPrefersTenantIDOverOrgID(t *testing.T) {
	v, err := scopeFromPrincipal(principalWith(map[string]any{
		"app_id":    "app-1",
		"tenant_id": "tenant-a",
		"org_id":    "tenant-b",
	}))
	if err != nil {
		t.Fatalf("scopeFromPrincipal: %v", err)
	}
	if v.TenantID != "tenant-a" {
		t.Fatalf("TenantID = %q, want tenant-a", v.TenantID)
	}
}

// An absent tenant is allowed and means an app-wide view. The dashboard
// operator is app-scoped, and TenantID is a dimension inside their own app.
// It cannot widen past the app because AppID is already required.
// The bug this pins: a tenant claim that is PRESENT but unreadable must not
// fall through to app-wide. Absent means an app-wide operator; unreadable
// means a tenant-scoped session whose scoping we failed to parse, and
// widening that one hands them every other tenant in their app.
func TestScopeFromPrincipalRefusesAnUnreadableTenant(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"tenant_id is a number": {"app_id": "app-1", "tenant_id": 42},
		"org_id is a number":    {"app_id": "app-1", "org_id": 42},
		"tenant_id is a list":   {"app_id": "app-1", "tenant_id": []string{"tenant-a"}},
		// A readable org_id must not rescue an unreadable tenant_id. The
		// session said tenant_id and we could not read it; guessing that
		// org_id means the same thing is still guessing.
		"unreadable tenant_id beside a good org_id": {
			"app_id": "app-1", "tenant_id": 42, "org_id": "tenant-b",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scopeFromPrincipal(principalWith(claims)); err == nil {
				t.Fatal("scopeFromPrincipal widened an unreadable tenant claim to app-wide")
			}
		})
	}
}

func TestScopeFromPrincipalAllowsAbsentTenant(t *testing.T) {
	v, err := scopeFromPrincipal(principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("scopeFromPrincipal: %v", err)
	}
	if v.TenantID != "" {
		t.Fatalf("TenantID = %q, want empty", v.TenantID)
	}
}

func TestOwnsRejectsAnotherApp(t *testing.T) {
	v := viewScope{AppID: "app-1", TenantID: "tenant-a"}
	if v.owns("app-2", "tenant-a") {
		t.Error("owns accepted a record from another app")
	}
	if v.owns("app-1", "tenant-b") {
		t.Error("owns accepted a record from another tenant")
	}
	if !v.owns("app-1", "tenant-a") {
		t.Error("owns rejected the viewer's own record")
	}
	if !v.owns("app-1", "") {
		t.Error("owns rejected an app-level record with no tenant")
	}
}

func TestAppWideScopeOwnsEveryTenantInItsApp(t *testing.T) {
	v := viewScope{AppID: "app-1"}
	if !v.owns("app-1", "tenant-a") || !v.owns("app-1", "tenant-b") {
		t.Error("an app-wide viewer should own every tenant in its own app")
	}
	if v.owns("app-2", "tenant-a") {
		t.Error("an app-wide viewer must not reach another app")
	}
}

// A zero viewScope must own nothing. No handler should ever hold one, since
// scopeFromPrincipal refuses to build it, but if one ever leaked through, an
// empty AppID matching an empty record AppID is exactly the widening the
// whole file exists to prevent.
func TestZeroScopeOwnsNothing(t *testing.T) {
	var v viewScope
	if v.owns("", "") || v.owns("app-1", "") {
		t.Error("a zero viewScope owned a record")
	}
}

// applyQuery must overwrite whatever scope the query already carried, not
// fill in blanks. A query built from request input could otherwise arrive
// already pointed at someone else's app.
func TestApplyQueryOverwritesAnyExistingScope(t *testing.T) {
	v := viewScope{AppID: "app-1", TenantID: "tenant-a"}
	q := v.applyQuery(&audit.Query{AppID: "app-2", TenantID: "tenant-z"})
	if q.AppID != "app-1" || q.TenantID != "tenant-a" {
		t.Fatalf("applyQuery left %s/%s, want app-1/tenant-a", q.AppID, q.TenantID)
	}

	wide := viewScope{AppID: "app-1"}
	q = wide.applyQuery(&audit.Query{AppID: "app-2", TenantID: "tenant-z"})
	if q.AppID != "app-1" || q.TenantID != "" {
		t.Fatalf("app-wide applyQuery left %s/%s, want app-1 and no tenant", q.AppID, q.TenantID)
	}
}
