package extension_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xraph/forge"
	"github.com/xraph/forge/extensions/dashboard/contributor"
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
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
	seedStream(t, db, hash.SchemeHMAC)

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
	if got.HashScheme != string(hash.SchemeHMAC) {
		t.Fatalf("HashScheme = %q, want %q; the YAML merge dropped the configured digest scheme",
			got.HashScheme, hash.SchemeHMAC)
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
	seedStream(t, db, hash.SchemeHMAC)

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
	if got.HashScheme != string(hash.SchemeHMAC) {
		t.Fatalf("HashScheme = %q, want %q; the YAML digest setting was ignored", got.HashScheme, hash.SchemeHMAC)
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

// TestYAMLConfigKeepsDashboardMutations covers the last of the three.
func TestYAMLConfigKeepsDashboardMutations(t *testing.T) {
	db := newSQLiteGroveDB(t)
	app := appWithConfigFile(t, "chronicle:\n  base_path: /audit\n")

	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}

	ext := extension.New(
		extension.WithUnauthenticatedAPI(),
		extension.WithDashboardMutations(),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// There is no getter for the flag, so drive the behaviour it gates: a
	// create-policy submission against the dashboard contributor. With the flag
	// intact the policy is written; with it dropped the render is a no-op and
	// the read-only notice goes up instead.
	ctx := scope.WithTenantID(scope.WithAppID(context.Background(), tamperTestAppID), "")
	if _, err := ext.DashboardContributor().RenderPage(ctx, "/retention", contributor.Params{
		FormData: map[string]string{
			"action":   "create_policy",
			"category": "auth",
			"duration": "1h",
		},
	}); err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	policies, err := sqlitestore.New(db).ListPolicies(context.Background(), retention.ListPoliciesOpts{})
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) == 0 {
		t.Error("no policy was created; dashboard mutations were configured programmatically " +
			"and the YAML merge dropped them")
	}
}
