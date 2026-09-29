package contract

import (
	"strings"
	"testing"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// An app claim with no tenant claim is what an operator looks like, and also
// what a tenant member looks like once they clear their active organisation.
// So an app-wide view over a claimed app needs chronicle.admin; a tenant view
// needs no scope; and an app that came from the config, where there are no
// claims to trust or distrust, needs none either.
func TestScopeAppWideViewNeedsTheAdminScopeWhenTheAppIsClaimed(t *testing.T) {
	appOnly := map[string]any{"app_id": "app-1"}

	t.Run("claimed app, no tenant, with chronicle.admin: app-wide", func(t *testing.T) {
		v, err := scopeFromPrincipal(principalWithScopes(appOnly, "chronicle.admin"), Deps{})
		if err != nil {
			t.Fatalf("scopeFromPrincipal: %v", err)
		}
		if v.AppID != "app-1" || v.TenantID != "" {
			t.Fatalf("scope = %+v, want app-1 app-wide", v)
		}
	})

	t.Run("chronicle.admin among other scopes", func(t *testing.T) {
		v, err := scopeFromPrincipal(principalWithScopes(appOnly, "chronicle.read", "chronicle.admin"), Deps{})
		if err != nil || v.AppID != "app-1" || v.TenantID != "" {
			t.Fatalf("scope = %+v, err = %v, want app-1 app-wide", v, err)
		}
	})

	refused := map[string]fcontract.Principal{
		"no scopes":                  principalWithoutScopes(appOnly),
		"only chronicle.write":       principalWithScopes(appOnly, "chronicle.write"),
		"only chronicle.read":        principalWithScopes(appOnly, "chronicle.read"),
		"read and write":             principalWithScopes(appOnly, "chronicle.read", "chronicle.write"),
		"different case":             principalWithScopes(appOnly, "Chronicle.Admin"),
		"longer name":                principalWithScopes(appOnly, "chronicle.admin.x"),
		"predicate spelling":         principalWithScopes(appOnly, "scope:chronicle.admin"),
		"another product's admin":    principalWithScopes(appOnly, "warden.admin"),
		"admin as a role, not scope": {User: &dashauth.UserInfo{Subject: "operator-1", Roles: []string{"chronicle.admin"}}, Claims: appOnly},
	}
	deployments := map[string]Deps{
		"no defaults":                          {},
		"default app, another app":             {DefaultAppID: "app-2"},
		"default app equal, no tenant default": {DefaultAppID: "app-1"},
	}
	for dn, deps := range deployments {
		for pn, p := range refused {
			t.Run("refused/"+dn+"/"+pn, func(t *testing.T) {
				v, err := scopeFromPrincipal(p, deps)
				if !isPermissionDenied(err) {
					t.Fatalf("err = %v (scope %+v), want PERMISSION_DENIED", err, v)
				}
				if !strings.Contains(err.Error(), "chronicle.admin") || !strings.Contains(err.Error(), "tenant") {
					t.Errorf("message %q should say an app-wide view needs chronicle.admin or a tenant claim", err.Error())
				}
			})
		}
	}
}

func TestScopeTenantViewNeedsNoScope(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"org_id":      {"app_id": "app-1", "org_id": "tenant-a"},
		"tenant_id":   {"app_id": "app-1", "tenant_id": "tenant-a"},
		"both, equal": {"app_id": "app-1", "tenant_id": "tenant-a", "org_id": "tenant-a"},
	} {
		for dn, deps := range map[string]Deps{
			"no defaults":        {},
			"default app":        {DefaultAppID: "app-1"},
			"default app+tenant": {DefaultAppID: "app-1", DefaultTenantID: "tenant-default"},
		} {
			t.Run(name+"/"+dn, func(t *testing.T) {
				v, err := scopeFromPrincipal(principalWithoutScopes(claims), deps)
				if err != nil {
					t.Fatalf("scopeFromPrincipal: %v", err)
				}
				if v.AppID != "app-1" || v.TenantID != "tenant-a" {
					t.Fatalf("scope = %+v, want app-1/tenant-a", v)
				}
			})
		}
	}
}

// An app named only by the config is the single-app operator's explicit
// choice. It is app-wide without any scope, with no claims at all or with
// claims that say nothing about the app or tenant.
func TestScopeConfigAppWideViewNeedsNoScope(t *testing.T) {
	deps := Deps{DefaultAppID: "app-1"}
	for name, claims := range map[string]map[string]any{
		"no claims":       nil,
		"unrelated claim": {"other": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := scopeFromPrincipal(principalWithoutScopes(claims), deps)
			if err != nil {
				t.Fatalf("scopeFromPrincipal: %v", err)
			}
			if v.AppID != "app-1" || v.TenantID != "" {
				t.Fatalf("scope = %+v, want app-1 app-wide", v)
			}
		})
	}
}

// A claimed app that equals the configured app takes the configured tenant, so
// it is a tenant view and needs no scope. A claimed app that differs does not
// take it, resolves app-wide, and needs the scope.
func TestScopeClaimedAppEqualToTheConfigAppTakesTheDefaultTenantWithoutAScope(t *testing.T) {
	deps := Deps{DefaultAppID: "app-1", DefaultTenantID: "tenant-default"}

	t.Run("equal app: tenant view, no scope", func(t *testing.T) {
		v, err := scopeFromPrincipal(principalWithoutScopes(map[string]any{"app_id": "app-1"}), deps)
		if err != nil {
			t.Fatalf("scopeFromPrincipal: %v", err)
		}
		if v.AppID != "app-1" || v.TenantID != "tenant-default" {
			t.Fatalf("scope = %+v, want app-1/tenant-default", v)
		}
	})
	t.Run("other app, no scope: refused", func(t *testing.T) {
		_, err := scopeFromPrincipal(principalWithoutScopes(map[string]any{"app_id": "app-2"}), deps)
		if !isPermissionDenied(err) {
			t.Fatalf("err = %v, want PERMISSION_DENIED", err)
		}
	})
	t.Run("other app, with chronicle.admin: app-wide", func(t *testing.T) {
		v, err := scopeFromPrincipal(principalWithScopes(map[string]any{"app_id": "app-2"}, "chronicle.admin"), deps)
		if err != nil || v.AppID != "app-2" || v.TenantID != "" {
			t.Fatalf("scope = %+v, err = %v, want app-2 app-wide", v, err)
		}
	})
}

// The grant is the last check. Identity and the claim refusals answer first,
// so an admin scope never turns one of their refusals into anything else, and
// a refusal for a lost claim never reads as a missing scope.
func TestScopeAppWideGrantComesAfterTheOtherRefusals(t *testing.T) {
	t.Run("no user is UNAUTHENTICATED even with the scope named", func(t *testing.T) {
		p := fcontract.Principal{
			User:   &dashauth.UserInfo{Subject: " ", Scopes: []string{"chronicle.admin"}},
			Claims: map[string]any{"app_id": "app-1"},
		}
		if _, err := scopeFromPrincipal(p, Deps{}); !isUnauthenticated(err) {
			t.Fatalf("err = %v, want UNAUTHENTICATED", err)
		}
	})
	t.Run("an unreadable tenant refuses as unreadable, with or without the scope", func(t *testing.T) {
		claims := map[string]any{"app_id": "app-1", "tenant_id": ""}
		for name, p := range map[string]fcontract.Principal{
			"no scope":   principalWithoutScopes(claims),
			"with scope": principalWith(claims),
		} {
			_, err := scopeFromPrincipal(p, Deps{})
			if !isPermissionDenied(err) || !strings.Contains(err.Error(), "unreadable") {
				t.Errorf("%s: err = %v, want the unreadable-tenant refusal", name, err)
			}
		}
	})
	t.Run("a tenant with no app refuses as such, not as a missing scope", func(t *testing.T) {
		_, err := scopeFromPrincipal(principalWithoutScopes(map[string]any{"org_id": "tenant-a"}), Deps{DefaultAppID: "app-1"})
		if !isPermissionDenied(err) || strings.Contains(err.Error(), "chronicle.admin") {
			t.Fatalf("err = %v, want the tenant-without-app refusal", err)
		}
	})
	t.Run("an unreadable app refuses as unreadable", func(t *testing.T) {
		_, err := scopeFromPrincipal(principalWithoutScopes(map[string]any{"app_id": 42}), Deps{DefaultAppID: "app-1"})
		if !isPermissionDenied(err) || !strings.Contains(err.Error(), "unreadable") {
			t.Fatalf("err = %v, want the unreadable-app refusal", err)
		}
	})
}
