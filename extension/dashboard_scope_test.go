package extension_test

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/xraph/forge"
	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/extension"
)

const dashScopeApp = "dash-app"

// subjectOnly is what authsome's dashboard auth produces today: a signed-in
// user with a subject and no claims at all.
func subjectOnly() fcontract.Principal {
	return fcontract.Principal{User: &dashauth.UserInfo{Subject: "operator-1"}}
}

// registerScopedExtension starts an extension over a fresh sqlite DB with the
// given dashboard config, records two events in dashScopeApp and one in
// another app, and returns the contract dispatcher's extension.
func registerScopedExtension(t *testing.T, app forge.App, dash extension.DashboardConfig) *extension.Extension {
	t.Helper()

	db := newSQLiteGroveDB(t)
	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}
	ext := extension.New(
		extension.WithUnauthenticatedAPI(),
		extension.WithConfig(extension.Config{
			Auth:      extension.AuthConfig{AllowUnauthenticated: true},
			Dashboard: dash,
		}),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx := context.Background()
	for _, e := range []*audit.Event{
		{AppID: dashScopeApp, Action: "login", Resource: "session", Category: "auth"},
		{AppID: dashScopeApp, Action: "logout", Resource: "session", Category: "auth"},
		{AppID: "someone-else", Action: "login", Resource: "session", Category: "auth"},
	} {
		if err := ext.Chronicle().Record(ctx, e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	return ext
}

func headSeqOfMine(t *testing.T, ext *extension.Extension, p fcontract.Principal) (uint64, error) {
	t.Helper()
	d := registerContract(t, ext)
	data, err := dispatchQuery(d, "streams.mine", p)
	if err != nil {
		return 0, err
	}
	var out struct {
		Stream *struct {
			HeadSeq uint64 `json:"headSeq"`
		} `json:"stream"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	if out.Stream == nil {
		t.Fatalf("no chain in %s", data)
	}
	return out.Stream.HeadSeq, nil
}

// A deployment that sets dashboard.app_id serves a signed-in principal whose
// claims are empty, which is every session authsome produces today. It gets
// the configured app's chain and not the other app's.
func TestDashboardAppIDServesAPrincipalWithNoClaims(t *testing.T) {
	ext := registerScopedExtension(t, forge.New(forge.WithAppName("t")),
		extension.DashboardConfig{AppID: dashScopeApp})

	head, err := headSeqOfMine(t, ext, subjectOnly())
	if err != nil {
		t.Fatalf("streams.mine: %v", err)
	}
	if head != 2 {
		t.Fatalf("headSeq = %d, want 2: the configured app has two events, the other app one", head)
	}
}

// The same deployment still refuses a request with no signed-in user, and a
// deployment that names no app still refuses the subject-only principal.
func TestDashboardAppIDDoesNotOpenTheDashboardToEveryone(t *testing.T) {
	t.Run("no user", func(t *testing.T) {
		ext := registerScopedExtension(t, forge.New(forge.WithAppName("t")),
			extension.DashboardConfig{AppID: dashScopeApp})
		_, err := headSeqOfMine(t, ext, fcontract.Principal{})
		if !errors.Is(err, fcontract.ErrUnauthenticated) {
			t.Fatalf("err = %v, want UNAUTHENTICATED", err)
		}
	})
	t.Run("no app configured", func(t *testing.T) {
		ext := registerScopedExtension(t, forge.New(forge.WithAppName("t")), extension.DashboardConfig{})
		_, err := headSeqOfMine(t, ext, subjectOnly())
		if !errors.Is(err, fcontract.ErrPermissionDenied) {
			t.Fatalf("err = %v, want PERMISSION_DENIED", err)
		}
		if err != nil && !strings.Contains(err.Error(), "chronicle.dashboard.app_id") {
			t.Errorf("error %q does not name chronicle.dashboard.app_id", err.Error())
		}
	})
	t.Run("a claim for another app stands over the configured one", func(t *testing.T) {
		ext := registerScopedExtension(t, forge.New(forge.WithAppName("t")),
			extension.DashboardConfig{AppID: dashScopeApp})
		head, err := headSeqOfMine(t, ext, contractPrincipal(map[string]any{"app_id": "someone-else"}))
		if err != nil {
			t.Fatalf("streams.mine: %v", err)
		}
		if head != 1 {
			t.Fatalf("headSeq = %d, want 1 (the claimed app's own chain)", head)
		}
	})
}

// dashboard.app_id in a YAML file must survive the merge with programmatic
// options, or a working single-app dashboard silently starts refusing every
// session as soon as any chronicle YAML block exists.
func TestDashboardAppIDFromYAMLReachesTheContractPath(t *testing.T) {
	app := appWithConfigFile(t, "chronicle:\n  dashboard:\n    app_id: "+dashScopeApp+"\n")
	ext := registerScopedExtension(t, app, extension.DashboardConfig{})

	head, err := headSeqOfMine(t, ext, subjectOnly())
	if err != nil {
		t.Fatalf("streams.mine: %v", err)
	}
	if head != 2 {
		t.Fatalf("headSeq = %d, want 2", head)
	}
}

// A programmatic dashboard scope fills what the YAML leaves out, field by
// field, the same as every other section.
func TestProgrammaticDashboardScopeSurvivesAYAMLBlock(t *testing.T) {
	app := appWithConfigFile(t, "chronicle:\n  base_path: /audit\n")
	ext := registerScopedExtension(t, app, extension.DashboardConfig{AppID: dashScopeApp})

	head, err := headSeqOfMine(t, ext, subjectOnly())
	if err != nil {
		t.Fatalf("streams.mine: %v", err)
	}
	if head != 2 {
		t.Fatalf("headSeq = %d, want 2", head)
	}
}

// Register refuses a dashboard scope it could not use faithfully: a tenant
// with no app, and any value with edge whitespace or a control character.
// Nothing is trimmed.
func TestRegisterRefusesAnUnusableDashboardScope(t *testing.T) {
	cases := []struct {
		name string
		dash extension.DashboardConfig
		keys []string
	}{
		{"tenant without app", extension.DashboardConfig{TenantID: "t"},
			[]string{"chronicle.dashboard.tenant_id", "chronicle.dashboard.app_id"}},
		{"app with trailing space", extension.DashboardConfig{AppID: "app "},
			[]string{"chronicle.dashboard.app_id"}},
		{"app with leading newline", extension.DashboardConfig{AppID: "\napp"},
			[]string{"chronicle.dashboard.app_id"}},
		{"app with control char", extension.DashboardConfig{AppID: "a\x00pp"},
			[]string{"chronicle.dashboard.app_id"}},
		{"tenant with leading space", extension.DashboardConfig{AppID: "app", TenantID: " t"},
			[]string{"chronicle.dashboard.tenant_id"}},
		{"tenant with control char", extension.DashboardConfig{AppID: "app", TenantID: "t\x07"},
			[]string{"chronicle.dashboard.tenant_id"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newSQLiteGroveDB(t)
			app := forge.New(forge.WithAppName("t"))
			if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
				t.Fatalf("provide grove.DB: %v", err)
			}
			ext := extension.New(extension.WithConfig(extension.Config{
				Auth:      extension.AuthConfig{AllowUnauthenticated: true},
				Dashboard: tc.dash,
			}))
			err := ext.Register(app)
			if err == nil {
				t.Fatal("Register accepted the configuration")
			}
			for _, k := range tc.keys {
				if !strings.Contains(err.Error(), k) {
					t.Errorf("error %q does not name %s", err.Error(), k)
				}
			}
		})
	}
}

// registerTenantedExtension starts an extension with the given dashboard
// config over sqlite and records events for eventApp: two in tenant-x, one in
// tenant-y and one at app level. It is what lets a test tell a session scoped
// to tenant-x (2 events) from an app-wide one (4).
func registerTenantedExtension(t *testing.T, app forge.App, dash extension.DashboardConfig, eventApp string) *extension.Extension {
	t.Helper()

	db := newSQLiteGroveDB(t)
	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}
	ext := extension.New(extension.WithConfig(extension.Config{
		Auth:      extension.AuthConfig{AllowUnauthenticated: true},
		Dashboard: dash,
	}))
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx := context.Background()
	for _, e := range []*audit.Event{
		{AppID: eventApp, TenantID: "tenant-x", Action: "x-1", Resource: "session", Category: "auth"},
		{AppID: eventApp, TenantID: "tenant-x", Action: "x-2", Resource: "session", Category: "auth"},
		{AppID: eventApp, TenantID: "tenant-y", Action: "y-1", Resource: "session", Category: "auth"},
		{AppID: eventApp, Action: "app-level", Resource: "session", Category: "auth"},
	} {
		if err := ext.Chronicle().Record(ctx, e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	return ext
}

// eventActionsSeenBy returns the actions of every event a subject-only session
// can list through events.list.
func eventActionsSeenBy(t *testing.T, ext *extension.Extension) []string {
	t.Helper()
	d := registerContract(t, ext)
	data, err := dispatchQuery(d, "events.list", subjectOnly())
	if err != nil {
		t.Fatalf("events.list: %v", err)
	}
	var out struct {
		Events []struct {
			Action string `json:"action"`
		} `json:"events"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	actions := make([]string, 0, len(out.Events))
	for _, e := range out.Events {
		actions = append(actions, e.Action)
	}
	sort.Strings(actions)
	return actions
}

func wantActions(t *testing.T, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("a subject-only session sees events %v, want %v", got, want)
	}
}

// dashboard.tenant_id has to reach the contract path, or a deployment that
// narrows its dashboard to one tenant silently shows every tenant in the app.
// The same config arrives three ways, and each one has to keep the tenant:
// programmatic alone, programmatic beside an unrelated YAML block (which sends
// it through the merge), and YAML alone.
func TestDashboardTenantIDNarrowsASubjectOnlySession(t *testing.T) {
	dash := extension.DashboardConfig{AppID: dashScopeApp, TenantID: "tenant-x"}

	t.Run("programmatic", func(t *testing.T) {
		ext := registerTenantedExtension(t, forge.New(forge.WithAppName("t")), dash, dashScopeApp)
		wantActions(t, eventActionsSeenBy(t, ext), "x-1", "x-2")
	})
	t.Run("programmatic beside an unrelated YAML block", func(t *testing.T) {
		app := appWithConfigFile(t, "chronicle:\n  base_path: /audit\n")
		ext := registerTenantedExtension(t, app, dash, dashScopeApp)
		wantActions(t, eventActionsSeenBy(t, ext), "x-1", "x-2")
	})
	t.Run("YAML", func(t *testing.T) {
		app := appWithConfigFile(t,
			"chronicle:\n  dashboard:\n    app_id: "+dashScopeApp+"\n    tenant_id: tenant-x\n")
		ext := registerTenantedExtension(t, app, extension.DashboardConfig{}, dashScopeApp)
		wantActions(t, eventActionsSeenBy(t, ext), "x-1", "x-2")
	})
}

// The dashboard section merges as a unit. Code sets an app and a tenant, ops
// YAML sets only a different app: the result is that app, app-wide, and never
// the YAML app narrowed to a tenant that was chosen for the code's app.
func TestYAMLDashboardAppDoesNotInheritAProgrammaticTenant(t *testing.T) {
	app := appWithConfigFile(t, "chronicle:\n  dashboard:\n    app_id: someone-else\n")
	ext := registerTenantedExtension(t, app,
		extension.DashboardConfig{AppID: dashScopeApp, TenantID: "tenant-x"}, "someone-else")

	wantActions(t, eventActionsSeenBy(t, ext), "x-1", "x-2", "y-1", "app-level")
}

// A YAML tenant_id with no app_id is a misconfiguration, and a programmatic
// app_id cannot repair it: the YAML section is the one that stands.
func TestYAMLDashboardTenantWithoutAppIsRefused(t *testing.T) {
	for name, programmatic := range map[string]extension.DashboardConfig{
		"no programmatic scope":    {},
		"programmatic app is set":  {AppID: dashScopeApp},
		"programmatic pair is set": {AppID: dashScopeApp, TenantID: "tenant-y"},
	} {
		t.Run(name, func(t *testing.T) {
			app := appWithConfigFile(t, "chronicle:\n  dashboard:\n    tenant_id: tenant-x\n")
			db := newSQLiteGroveDB(t)
			if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
				t.Fatalf("provide grove.DB: %v", err)
			}
			ext := extension.New(extension.WithConfig(extension.Config{
				Auth:      extension.AuthConfig{AllowUnauthenticated: true},
				Dashboard: programmatic,
			}))
			err := ext.Register(app)
			if err == nil {
				t.Fatal("Register accepted a YAML tenant_id with no app_id")
			}
			for _, k := range []string{"chronicle.dashboard.tenant_id", "chronicle.dashboard.app_id"} {
				if !strings.Contains(err.Error(), k) {
					t.Errorf("error %q does not name %s", err.Error(), k)
				}
			}
		})
	}
}
