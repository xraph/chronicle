package contract

import (
	"errors"
	"testing"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

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

// tenant_id and org_id are two spellings of one dimension, so a session can
// carry neither (app-wide), one, or both. Both is only accepted when they
// agree. Two different tenants on one session means some layer wrote a tenant
// the upstream did not, and picking either one would be a guess.
func TestScopeFromPrincipalTenantClaimShapes(t *testing.T) {
	cases := []struct {
		name    string
		claims  map[string]any
		want    string
		refused bool
	}{
		{"neither", map[string]any{"app_id": "app-1"}, "", false},
		{"tenant_id only", map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}, "tenant-a", false},
		{"org_id only", map[string]any{"app_id": "app-1", "org_id": "tenant-a"}, "tenant-a", false},
		{"both equal", map[string]any{"app_id": "app-1", "tenant_id": "tenant-a", "org_id": "tenant-a"}, "tenant-a", false},
		{"both different", map[string]any{"app_id": "app-1", "tenant_id": "tenant-a", "org_id": "tenant-b"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := scopeFromPrincipal(principalWith(tc.claims))
			if tc.refused {
				if !errors.Is(err, fcontract.ErrPermissionDenied) {
					t.Fatalf("err = %v (scope %+v), want PERMISSION_DENIED", err, v)
				}
				return
			}
			if err != nil {
				t.Fatalf("scopeFromPrincipal: %v", err)
			}
			if v.AppID != "app-1" || v.TenantID != tc.want {
				t.Fatalf("scope = %+v, want app-1/%q", v, tc.want)
			}
		})
	}
}

// An absent tenant key is allowed and means an app-wide view: the upstream
// never scoped this session to a tenant. The dashboard operator is
// app-scoped, and TenantID is a dimension inside their own app. It cannot
// widen past the app because AppID is already required.
//
// A tenant key that is PRESENT with anything other than a non-empty string
// is the opposite case: the upstream wrote a tenant and its value got lost.
// Widening that session to app-wide would hand one tenant's operator every
// other tenant in their app, so it must be refused. That covers "", nil and
// non-strings alike, on both spellings.
func TestScopeFromPrincipalRefusesAPresentButUnusableTenant(t *testing.T) {
	for _, key := range []string{"tenant_id", "org_id"} {
		for name, value := range map[string]any{
			"empty string": "",
			"nil":          nil,
			"number":       42,
			"list":         []string{"tenant-a"},
		} {
			t.Run(key+" "+name, func(t *testing.T) {
				_, err := scopeFromPrincipal(principalWith(map[string]any{
					"app_id": "app-1",
					key:      value,
				}))
				if !errors.Is(err, fcontract.ErrPermissionDenied) {
					t.Fatalf("scopeFromPrincipal with %s=%#v: err = %v, want PERMISSION_DENIED", key, value, err)
				}
			})
		}
	}
}

// A good value in one spelling must not rescue a bad value in the other.
// The session said that key and we could not read it; guessing the other
// spelling means the same thing is still guessing.
func TestScopeFromPrincipalRefusesABadTenantBesideAGoodOne(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"bad tenant_id, good org_id":   {"app_id": "app-1", "tenant_id": 42, "org_id": "tenant-b"},
		"empty tenant_id, good org_id": {"app_id": "app-1", "tenant_id": "", "org_id": "tenant-b"},
		"good tenant_id, nil org_id":   {"app_id": "app-1", "tenant_id": "tenant-a", "org_id": nil},
		"good tenant_id, empty org_id": {"app_id": "app-1", "tenant_id": "tenant-a", "org_id": ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scopeFromPrincipal(principalWith(claims)); !errors.Is(err, fcontract.ErrPermissionDenied) {
				t.Fatalf("err = %v, want PERMISSION_DENIED", err)
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

// A tenant viewer owns only its own tenant's records. This reverses the
// original brief, which let a tenant viewer own app-level records (TenantID
// ""). applyQuery pins list queries to the viewer's tenant exactly, so every
// list already hides app-level records from a tenant viewer, and a detail
// handler that let owns accept them would show by ID what the lists hide.
func TestOwnsIsStrictForATenantViewer(t *testing.T) {
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
	if v.owns("app-1", "") {
		t.Error("a tenant viewer owned an app-level record that its lists hide")
	}
}

func TestAppWideScopeOwnsEveryTenantInItsApp(t *testing.T) {
	v := viewScope{AppID: "app-1"}
	if !v.owns("app-1", "tenant-a") || !v.owns("app-1", "tenant-b") {
		t.Error("an app-wide viewer should own every tenant in its own app")
	}
	if !v.owns("app-1", "") {
		t.Error("an app-wide viewer should own its app's app-level records")
	}
	if v.owns("app-2", "tenant-a") || v.owns("app-2", "") {
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
