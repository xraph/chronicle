package contract

import (
	"bytes"
	"context"
	"errors"
	"testing"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
)

// Every intent the manifest declares must have a handler, and every handler
// must be declared. A declared intent with no handler is a page that fails at
// runtime with no compile-time warning; a registered handler with no manifest
// entry is unreachable code nobody notices is dead.
func TestManifestAndHandlersAgree(t *testing.T) {
	m, err := loader.Load(bytes.NewReader(manifestYAML), "manifest.yaml")
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}

	declared := map[string]struct{}{}
	for _, in := range m.Intents {
		declared[in.Name] = struct{}{}
	}

	registered := map[string]intentKind{}
	for _, r := range registrations() {
		if _, dup := registered[r.name]; dup {
			t.Errorf("intent %q is registered twice", r.name)
		}
		registered[r.name] = r.kind
	}

	for name := range declared {
		if _, ok := registered[name]; !ok {
			t.Errorf("intent %q is declared in the manifest but no handler registers it", name)
		}
	}
	for name := range registered {
		if _, ok := declared[name]; !ok {
			t.Errorf("intent %q has a handler but is not declared in the manifest", name)
		}
	}

	// The kinds must agree too. A query registered against an intent the
	// manifest calls a command would pass the name comparison above and then
	// fail the envelope's kind check at runtime, which is a much worse place
	// to find out.
	for _, in := range m.Intents {
		got, ok := registered[in.Name]
		if !ok {
			continue // already reported above
		}
		if string(got) != string(in.Kind) {
			t.Errorf("intent %q: manifest says kind=%s, registration says %s", in.Name, in.Kind, got)
		}
	}
}

// Every command must name the queries its write affects. The React client
// refreshes through meta.invalidates and through nothing else, so a command
// that invalidates nothing looks to an operator like a write that silently
// failed.
func TestEveryCommandDeclaresInvalidations(t *testing.T) {
	m, err := loader.Load(bytes.NewReader(manifestYAML), "manifest.yaml")
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	for _, in := range m.Intents {
		if in.Kind != fcontract.IntentKindCommand {
			continue
		}
		if len(in.Invalidates) == 0 {
			t.Errorf("command %q declares no invalidates", in.Name)
		}
	}
}

// The contributor name is the join key to the React plugin. A typo here
// makes the plugin render nothing, with nothing logged anywhere.
func TestManifestNamesTheChronicleContributor(t *testing.T) {
	m, err := loader.Load(bytes.NewReader(manifestYAML), "manifest.yaml")
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if m.Contributor.Name != "chronicle" || contributorName != "chronicle" {
		t.Fatalf("contributor = %q (const %q), want chronicle", m.Contributor.Name, contributorName)
	}
	// loader.Validate is what Register runs, so a manifest that fails it
	// fails every deployment at startup.
	if err := loader.Validate(m, fcontract.NewWardenRegistry()); err != nil {
		t.Fatalf("validate manifest: %v", err)
	}
}

// The query and command constructors are what tie a registration's name to
// the name the dispatcher binds. Pin that each carries the right kind.
func TestRegistrationConstructorsCarryTheirKind(t *testing.T) {
	noop := func(Deps) func(context.Context, struct{}, fcontract.Principal) (struct{}, error) {
		return func(context.Context, struct{}, fcontract.Principal) (struct{}, error) { return struct{}{}, nil }
	}
	if r := query("x.q", noop); r.kind != kindQuery || r.name != "x.q" {
		t.Errorf("query() built %+v", r)
	}
	if r := command("x.c", noop); r.kind != kindCommand || r.name != "x.c" {
		t.Errorf("command() built %+v", r)
	}
}

// Register is the only path a deployment takes, so drive it end to end:
// load, validate, register the manifest, bind every handler, then dispatch.
// This catches what the handler-level tests cannot, such as a manifest that
// fails loader.Validate or a handler bound under a name the envelope never
// asks for.
func TestRegisterServesStreamsMineThroughTheDispatcher(t *testing.T) {
	d := newTestDispatcher(t)
	reg := fcontract.NewRegistry()
	if err := Register(d, reg, fcontract.NewWardenRegistry(), Deps{Store: newSQLiteStore(t)}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, ok := reg.Contributor("chronicle"); !ok {
		t.Fatal("Register did not register the chronicle contributor")
	}

	req := fcontract.Request{
		Kind:          fcontract.KindQuery,
		Contributor:   "chronicle",
		Intent:        "streams.mine",
		IntentVersion: 1,
	}

	data, _, err := d.Dispatch(context.Background(), req, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("dispatch streams.mine for an app-scoped principal: %v", err)
	}
	if string(data) != "{}" {
		t.Fatalf("streams.mine for a scope with no chain = %s, want {}", data)
	}

	_, _, err = d.Dispatch(context.Background(), req, principalWith(nil))
	if !errors.Is(err, fcontract.ErrPermissionDenied) {
		t.Fatalf("dispatch for a principal with no app = %v, want PERMISSION_DENIED", err)
	}
}

func TestRegisterRefusesDepsWithNoStore(t *testing.T) {
	err := Register(newTestDispatcher(t), fcontract.NewRegistry(), fcontract.NewWardenRegistry(), Deps{})
	if !errors.Is(err, errStoreRequired) {
		t.Fatalf("Register with no store = %v, want errStoreRequired", err)
	}
}
