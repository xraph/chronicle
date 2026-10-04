package extension_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xraph/forge"
	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/hash"
	sqlitestore "github.com/xraph/chronicle/store/sqlite"
)

// appWithConfigFile builds a forge App whose config manager has actually read a
// YAML file off disk.
//
// This is the gap the rest of the extension suite leaves open. Every other test
// here calls forge.New with no config file at all, which takes
// loadConfiguration's "nothing found" branch and never reaches
// mergeConfigurations. A field the merge forgets to copy is therefore invisible
// to a green suite, and stays invisible until a deployment with a chronicle
// block in its YAML loses the setting in production.
func appWithConfigFile(t *testing.T, yaml string) forge.App {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	app := forge.New(
		forge.WithAppName("chronicle-merge-test"),
		forge.WithEnableConfigAutoDiscovery(true),
		forge.WithEnableAppScopedConfig(false),
		forge.WithConfigSearchPaths(dir),
		forge.WithConfigBaseNames("config.yaml"),
	)

	if !app.Config().IsSet("chronicle") {
		t.Fatal("the config file was not picked up; this test would silently stop covering the merge")
	}
	return app
}

// TestYAMLConfigKeepsTheProgrammaticDigestScheme is the regression test for the
// merge dropping TamperEvidence.
//
// The YAML here says nothing about tamper evidence. It only sets base_path, the
// sort of thing every real deployment has. That alone used to be enough:
// mergeConfigurations rebuilt the config from the YAML side and copied nine
// fields across, TamperEvidence not among them, so WithDigestScheme("hmac")
// became plain. No error, no warning, unkeyed digests under an operator who
// asked for keyed ones.
//
// It asserts on the persisted row rather than on the config struct, because the
// store recomputes the digest on write and the row is what an auditor sees.
func TestYAMLConfigKeepsTheProgrammaticDigestScheme(t *testing.T) {
	db := newSQLiteGroveDB(t)
	app := appWithConfigFile(t, "chronicle:\n  base_path: /audit\n")

	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}

	ext := extension.New(
		extension.WithUnauthenticatedAPI(),
		extension.WithDigestScheme("hmac"),
		extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "hmac-1"}),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx := context.Background()
	event := &audit.Event{
		AppID:    tamperTestAppID,
		Action:   "login",
		Resource: "session",
		Category: "auth",
	}
	if err := ext.Chronicle().Record(ctx, event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := sqlitestore.New(db).Get(ctx, event.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HashScheme != string(hash.SchemeHMACV5) {
		t.Fatalf("HashScheme = %q, want %q; the YAML merge dropped the configured digest scheme",
			got.HashScheme, hash.SchemeHMACV5)
	}
	if got.HashKeyID == "" {
		t.Error("HashKeyID is empty; the digest was written unkeyed")
	}
}

// TestYAMLTamperEvidenceWins pins the precedence direction: where the YAML says
// something about tamper evidence, the YAML is the answer.
func TestYAMLTamperEvidenceWins(t *testing.T) {
	db := newSQLiteGroveDB(t)
	app := appWithConfigFile(t, "chronicle:\n  tamper_evidence:\n    digest: hmac\n")

	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}

	// The programmatic side names no digest at all. Only the YAML does, and the
	// key material arrives through WithKeyProvider the way a KMS-backed
	// deployment supplies it.
	ext := extension.New(
		extension.WithUnauthenticatedAPI(),
		extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "hmac-1"}),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx := context.Background()
	event := &audit.Event{
		AppID:    tamperTestAppID,
		Action:   "login",
		Resource: "session",
		Category: "auth",
	}
	if err := ext.Chronicle().Record(ctx, event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := sqlitestore.New(db).Get(ctx, event.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HashScheme != string(hash.SchemeHMACV5) {
		t.Fatalf("HashScheme = %q, want %q; the YAML digest setting was ignored", got.HashScheme, hash.SchemeHMACV5)
	}
}

// TestYAMLConfigKeepsProgrammaticAuth covers the two fields that were dropped
// the same way and predate this branch.
//
// WithUnauthenticatedAPI is the sharper of the two: losing it makes Register
// fail closed with ErrAuthNotConfigured, which is at least loud. WithAuth
// losing its provider is the quiet one, and it mounts an admin API that can
// purge audit history with nothing in front of it.
func TestYAMLConfigKeepsProgrammaticAuth(t *testing.T) {
	db := newSQLiteGroveDB(t)
	app := appWithConfigFile(t, "chronicle:\n  base_path: /audit\n")

	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}

	ext := extension.New(extension.WithUnauthenticatedAPI())
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v; the YAML merge dropped Auth.AllowUnauthenticated", err)
	}
}

// TestYAMLConfigKeepsProgrammaticAuthProvider is the same field in its
// dangerous direction: a named provider that survives the merge.
func TestYAMLConfigKeepsProgrammaticAuthProvider(t *testing.T) {
	db := newSQLiteGroveDB(t)
	app := appWithConfigFile(t, "chronicle:\n  base_path: /audit\n")

	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}

	ext := extension.New(
		extension.WithAuth("jwt",
			[]string{"chronicle:read"},
			[]string{"chronicle:write"},
			[]string{"chronicle:admin"}),
	)

	// No forge auth registry is in the container, so a provider that survived
	// the merge must be reported as unresolvable. A provider the merge dropped
	// would instead trip ErrAuthNotConfigured, and one that was dropped along
	// with the whole Auth block on an AllowUnauthenticated config would start
	// clean with an open API. The error tells the three apart.
	err := ext.Register(app)
	if err == nil {
		t.Fatal("Register succeeded with a named provider and no auth registry; the provider was dropped")
	}
	if !errors.Is(err, extension.ErrAuthProviderUnavailable) {
		t.Fatalf("Register error = %v, want ErrAuthProviderUnavailable "+
			"(ErrAuthNotConfigured here would mean the merge dropped auth.provider)", err)
	}
}

// TestDashboardMutationsIsANoOp covers the deprecated flag in both of its
// forms. The templ dashboard read it to decide whether its forms could write.
// That dashboard is gone, and writes now depend only on the scopes the signed-in
// user holds, so neither WithDashboardMutations() nor a YAML dashboard_mutations
// key may change what a caller can do. Both still have to load, because dropping
// them would break the build or the start of every deployment that set them.
//
// What is compared is the dispatcher's outcome for retention.savePolicy, once
// for a session with an app claim, no tenant claim and no scope, and once for one
// holding chronicle.admin, with the flag set and without it. The first is refused
// by scopeFromPrincipal's app-wide rule, not by the command's requires: the
// dispatcher never checks requires, forge's HTTP transport does. Either way the
// outcomes must match the deployment that never heard of the flag.
func TestDashboardMutationsIsANoOp(t *testing.T) {
	type outcome struct{ unscoped, admin string }

	run := func(t *testing.T, yaml string, opts ...extension.Option) outcome {
		t.Helper()
		db := newSQLiteGroveDB(t)
		app := appWithConfigFile(t, yaml)
		if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
			t.Fatalf("provide grove.DB: %v", err)
		}
		ext := extension.New(append([]extension.Option{extension.WithUnauthenticatedAPI()}, opts...)...)
		if err := ext.Register(app); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if err := ext.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		d := registerContract(t, ext)

		claims := map[string]any{"app_id": tamperTestAppID}
		payload := map[string]any{"category": "auth", "duration": "1h"}
		describe := func(p fcontract.Principal) string {
			_, err := dispatchIntent(d, fcontract.KindCommand, "retention.savePolicy", payload, p)
			if err == nil {
				return "allowed"
			}
			return err.Error()
		}
		noScope := fcontract.Principal{
			User:   &dashauth.UserInfo{Subject: "operator-1", Claims: claims},
			Claims: claims,
		}
		return outcome{unscoped: describe(noScope), admin: describe(contractPrincipal(claims))}
	}

	base := run(t, "chronicle:\n  base_path: /audit\n")
	if base.admin != "allowed" || base.unscoped == "allowed" {
		t.Fatalf("baseline = %+v, want the admin allowed and the unscoped user refused", base)
	}

	t.Run("programmatic option", func(t *testing.T) {
		got := run(t, "chronicle:\n  base_path: /audit\n", extension.WithDashboardMutations())
		if got != base {
			t.Errorf("WithDashboardMutations changed the outcome: got %+v, baseline %+v", got, base)
		}
	})
	t.Run("yaml key true", func(t *testing.T) {
		got := run(t, "chronicle:\n  base_path: /audit\n  dashboard_mutations: true\n")
		if got != base {
			t.Errorf("dashboard_mutations: true changed the outcome: got %+v, baseline %+v", got, base)
		}
	})
	t.Run("both", func(t *testing.T) {
		got := run(t, "chronicle:\n  dashboard_mutations: true\n", extension.WithDashboardMutations())
		if got != base {
			t.Errorf("both forms together changed the outcome: got %+v, baseline %+v", got, base)
		}
	})
}

// Config.DashboardMutations has to stay for one release so that existing code
// and YAML still compile and load. Removing the field breaks this line.
func TestDashboardMutationsFieldStillCompiles(t *testing.T) {
	_ = extension.Config{DashboardMutations: true}
}
