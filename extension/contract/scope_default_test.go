package contract

import (
	"errors"
	"strings"
	"testing"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// defaultsApp is the app the deployments below configure as their default.
const defaultsApp = "app-default"

func isPermissionDenied(err error) bool {
	return errors.Is(err, fcontract.ErrPermissionDenied)
}

// Every cell of the app dimension: a usable claim, a present but unusable
// claim, an absent claim with a default, an absent claim with no default.
func TestScopeAppDimensionTable(t *testing.T) {
	withDefault := Deps{DefaultAppID: defaultsApp}

	cases := []struct {
		name    string
		claims  map[string]any
		deps    Deps
		want    string
		refused bool
	}{
		{"claim usable, no default", map[string]any{"app_id": "app-1"}, Deps{}, "app-1", false},
		{"claim usable beats a different default", map[string]any{"app_id": "app-1"}, withDefault, "app-1", false},
		{"claim empty string, default set", map[string]any{"app_id": ""}, withDefault, "", true},
		{"claim nil, default set", map[string]any{"app_id": nil}, withDefault, "", true},
		{"claim number, default set", map[string]any{"app_id": 42}, withDefault, "", true},
		{"claim list, default set", map[string]any{"app_id": []string{"app-1"}}, withDefault, "", true},
		{"claim empty string, no default", map[string]any{"app_id": ""}, Deps{}, "", true},
		{"claim absent, default set", map[string]any{"other": "x"}, withDefault, defaultsApp, false},
		{"claims nil, default set", nil, withDefault, defaultsApp, false},
		{"claim absent, no default", map[string]any{"other": "x"}, Deps{}, "", true},
		{"claims nil, no default", nil, Deps{}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := scopeFromPrincipal(principalWith(tc.claims), tc.deps)
			if tc.refused {
				if !isPermissionDenied(err) {
					t.Fatalf("err = %v (scope %+v), want PERMISSION_DENIED", err, v)
				}
				return
			}
			if err != nil {
				t.Fatalf("scopeFromPrincipal: %v", err)
			}
			if v.AppID != tc.want {
				t.Fatalf("AppID = %q, want %q", v.AppID, tc.want)
			}
		})
	}
}

// An app that resolves to nothing has to say which setting fixes it, since the
// operator reading the refusal is usually the one who can add it.
func TestScopeUnresolvedAppNamesTheSetting(t *testing.T) {
	_, err := scopeFromPrincipal(principalWith(nil), Deps{})
	if !isPermissionDenied(err) {
		t.Fatalf("err = %v, want PERMISSION_DENIED", err)
	}
	if !strings.Contains(err.Error(), "chronicle.dashboard.app_id") {
		t.Fatalf("message %q does not name chronicle.dashboard.app_id", err.Error())
	}
}

// Every cell of the tenant dimension, under both spellings, with and without a
// configured default tenant. The default is bound to defaultsApp and the
// claims put the session in that same app, so it is eligible to apply.
func TestScopeTenantDimensionTable(t *testing.T) {
	appOnly := Deps{DefaultAppID: defaultsApp}
	appAndTenant := Deps{DefaultAppID: defaultsApp, DefaultTenantID: "tenant-default"}
	claims := func(kv ...any) map[string]any {
		m := map[string]any{"app_id": defaultsApp}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}

	cases := []struct {
		name    string
		claims  map[string]any
		deps    Deps
		want    string
		refused bool
	}{
		// No default configured.
		{"neither, no default: app-wide", claims(), appOnly, "", false},
		{"tenant_id only, no default", claims("tenant_id", "tenant-a"), appOnly, "tenant-a", false},
		{"org_id only, no default", claims("org_id", "tenant-a"), appOnly, "tenant-a", false},
		{"both equal, no default", claims("tenant_id", "tenant-a", "org_id", "tenant-a"), appOnly, "tenant-a", false},
		{"both different, no default", claims("tenant_id", "tenant-a", "org_id", "tenant-b"), appOnly, "", true},
		{"tenant_id empty, no default", claims("tenant_id", ""), appOnly, "", true},
		{"org_id nil, no default", claims("org_id", nil), appOnly, "", true},

		// A default tenant is configured.
		{"neither, default: takes the default", claims(), appAndTenant, "tenant-default", false},
		{"tenant_id only beats a different default", claims("tenant_id", "tenant-a"), appAndTenant, "tenant-a", false},
		{"org_id only beats a different default", claims("org_id", "tenant-a"), appAndTenant, "tenant-a", false},
		{"both equal beat a different default", claims("tenant_id", "tenant-a", "org_id", "tenant-a"), appAndTenant, "tenant-a", false},
		{"both different refuse, default does not break the tie", claims("tenant_id", "tenant-a", "org_id", "tenant-b"), appAndTenant, "", true},
		{"tenant_id empty refuses, default does not cover it", claims("tenant_id", ""), appAndTenant, "", true},
		{"tenant_id nil refuses, default does not cover it", claims("tenant_id", nil), appAndTenant, "", true},
		{"tenant_id number refuses, default does not cover it", claims("tenant_id", 42), appAndTenant, "", true},
		{"org_id empty refuses, default does not cover it", claims("org_id", ""), appAndTenant, "", true},
		{"org_id nil refuses, default does not cover it", claims("org_id", nil), appAndTenant, "", true},
		{"good tenant_id beside bad org_id refuses", claims("tenant_id", "tenant-a", "org_id", 42), appAndTenant, "", true},
		{"bad tenant_id beside good org_id refuses", claims("tenant_id", 42, "org_id", "tenant-a"), appAndTenant, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := scopeFromPrincipal(principalWith(tc.claims), tc.deps)
			if tc.refused {
				if !isPermissionDenied(err) {
					t.Fatalf("err = %v (scope %+v), want PERMISSION_DENIED", err, v)
				}
				return
			}
			if err != nil {
				t.Fatalf("scopeFromPrincipal: %v", err)
			}
			if v.AppID != defaultsApp || v.TenantID != tc.want {
				t.Fatalf("scope = %+v, want %s/%q", v, defaultsApp, tc.want)
			}
		})
	}
}

// Both dimensions can come from the config at once: a session with no claims
// at all, in a deployment that names an app and a tenant.
func TestScopeTakesBothDefaultsWhenClaimsAreAbsent(t *testing.T) {
	v, err := scopeFromPrincipal(principalWith(nil),
		Deps{DefaultAppID: defaultsApp, DefaultTenantID: "tenant-default"})
	if err != nil {
		t.Fatalf("scopeFromPrincipal: %v", err)
	}
	if v.AppID != defaultsApp || v.TenantID != "tenant-default" {
		t.Fatalf("scope = %+v, want %s/tenant-default", v, defaultsApp)
	}
}

// A request with no signed-in user must not be served from the configured app.
// The default exists so a single-app deployment can answer without claims, not
// so an anonymous request can read that app's audit log.
func TestScopeDefaultNeverServesAnUnauthenticatedRequest(t *testing.T) {
	deps := Deps{DefaultAppID: defaultsApp, DefaultTenantID: "tenant-default"}

	for name, p := range map[string]fcontract.Principal{
		"zero principal":  {},
		"nil user":        {Claims: map[string]any{}},
		"empty subject":   {User: &dashauth.UserInfo{}},
		"blank subject":   {User: &dashauth.UserInfo{Subject: ""}, Claims: map[string]any{"x": 1}},
		"claims no user":  {Claims: map[string]any{"other": "x"}},
		"user w/o claims": {User: &dashauth.UserInfo{DisplayName: "someone"}},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := scopeFromPrincipal(p, deps)
			if !isPermissionDenied(err) {
				t.Fatalf("err = %v (scope %+v), want PERMISSION_DENIED", err, v)
			}
		})
	}

	// The tenant default is a default too. A session whose claims name the
	// default app but has no subject must not pick the default tenant up.
	t.Run("app from claim, tenant from default, no subject", func(t *testing.T) {
		p := fcontract.Principal{Claims: map[string]any{"app_id": defaultsApp}}
		v, err := scopeFromPrincipal(p, deps)
		if !isPermissionDenied(err) {
			t.Fatalf("err = %v (scope %+v), want PERMISSION_DENIED", err, v)
		}
	})
}

// The default tenant belongs to the default app. A session whose claims put it
// in some other app is not narrowed to a tenant id chosen for a different app,
// because the same id can name an unrelated tenant there.
func TestScopeDefaultTenantAppliesOnlyInTheDefaultApp(t *testing.T) {
	deps := Deps{DefaultAppID: "app-y", DefaultTenantID: "tenant-t"}

	t.Run("claim app is foreign: no tenant is imposed", func(t *testing.T) {
		v, err := scopeFromPrincipal(principalWith(map[string]any{"app_id": "app-x"}), deps)
		if err != nil {
			t.Fatalf("scopeFromPrincipal: %v", err)
		}
		if v.AppID != "app-x" || v.TenantID != "" {
			t.Fatalf("scope = %+v, want app-x with no tenant", v)
		}
	})

	t.Run("claim app is the default app: the default tenant applies", func(t *testing.T) {
		v, err := scopeFromPrincipal(principalWith(map[string]any{"app_id": "app-y"}), deps)
		if err != nil {
			t.Fatalf("scopeFromPrincipal: %v", err)
		}
		if v.AppID != "app-y" || v.TenantID != "tenant-t" {
			t.Fatalf("scope = %+v, want app-y/tenant-t", v)
		}
	})

	t.Run("claim app is foreign and claims a tenant: the claim stands", func(t *testing.T) {
		v, err := scopeFromPrincipal(principalWith(map[string]any{"app_id": "app-x", "tenant_id": "tenant-a"}), deps)
		if err != nil {
			t.Fatalf("scopeFromPrincipal: %v", err)
		}
		if v.AppID != "app-x" || v.TenantID != "tenant-a" {
			t.Fatalf("scope = %+v, want app-x/tenant-a", v)
		}
	})
}

// A default tenant with no default app is a misconfiguration and Register says
// so, naming both keys.
func TestRegisterRefusesADefaultTenantWithoutADefaultApp(t *testing.T) {
	err := Register(newTestDispatcher(t), fcontract.NewRegistry(), fcontract.NewWardenRegistry(),
		Deps{Store: newStubStore(), DefaultTenantID: "tenant-t"})
	if err == nil {
		t.Fatal("Register accepted a default tenant with no default app")
	}
	for _, key := range []string{"chronicle.dashboard.tenant_id", "chronicle.dashboard.app_id"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not name %s", err.Error(), key)
		}
	}
}

// A configured value is compared exactly as written, so edge whitespace or a
// control character would name a scope that looks right and matches nothing.
func TestRegisterRefusesUnusableDefaultScopeValues(t *testing.T) {
	bad := map[string]string{
		"leading space":    " app-1",
		"trailing space":   "app-1 ",
		"trailing newline": "app-1\n",
		"leading tab":      "\tapp-1",
		"leading nbsp":     " app-1",
		"control char":     "app\x00-1",
		"escape char":      "app\x1b-1",
		"invalid utf8":     "app\xff-1",
	}
	for name, v := range bad {
		t.Run("app_id "+name, func(t *testing.T) {
			err := Register(newTestDispatcher(t), fcontract.NewRegistry(), fcontract.NewWardenRegistry(),
				Deps{Store: newStubStore(), DefaultAppID: v})
			if err == nil || !strings.Contains(err.Error(), "chronicle.dashboard.app_id") {
				t.Fatalf("err = %v, want a refusal naming chronicle.dashboard.app_id", err)
			}
		})
		t.Run("tenant_id "+name, func(t *testing.T) {
			err := Register(newTestDispatcher(t), fcontract.NewRegistry(), fcontract.NewWardenRegistry(),
				Deps{Store: newStubStore(), DefaultAppID: "app-1", DefaultTenantID: v})
			if err == nil || !strings.Contains(err.Error(), "chronicle.dashboard.tenant_id") {
				t.Fatalf("err = %v, want a refusal naming chronicle.dashboard.tenant_id", err)
			}
		})
	}

	t.Run("a plain pair registers", func(t *testing.T) {
		err := Register(newTestDispatcher(t), fcontract.NewRegistry(), fcontract.NewWardenRegistry(),
			Deps{Store: newStubStore(), DefaultAppID: "app-1", DefaultTenantID: "tenant-a b"})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
	})
}
