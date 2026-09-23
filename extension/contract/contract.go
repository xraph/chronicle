package contract

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
)

//go:embed manifest.yaml
var manifestYAML []byte

// contributorName is the join key to the React plugin's `extension` field.
// A mismatch makes the plugin render nothing at all, with nothing logged,
// because that is what an uninstalled extension looks like.
const contributorName = "chronicle"

// intentVersion is the version every intent in this contributor registers at.
const intentVersion = 1

// SurfaceConfig is what settings.detail reports about this deployment.
type SurfaceConfig struct {
	BatchSize           int
	FlushInterval       string
	RetentionInterval   string
	EnableCryptoErasure bool
	BackendName         string
}

// Deps is what the handlers need. Store is required; the rest reflect what
// this deployment configured, and a nil one means the intents that need it
// answer CodeUnavailable rather than panicking.
type Deps struct {
	Store     store.Store
	Chronicle *chronicle.Chronicle
	Engine    *compliance.Engine
	Enforcer  *retention.Enforcer
	Erasure   *erasure.Service

	// Checkpointer, CheckpointStore and CheckpointSigner are nil unless
	// checkpoints.enabled is true. They travel as a set: a checkpoint store
	// without a signer proves nothing, since anyone who could write the row
	// could write a fabricated one.
	Checkpointer     *checkpoint.Checkpointer
	CheckpointStore  checkpoint.Store
	CheckpointSigner checkpoint.Signer

	// HashChain is what verification recomputes digests under. A nil value
	// leaves an unkeyed chain, which cannot check an HMAC deployment at all,
	// so an HMAC deployment must pass its keyed chain here.
	HashChain *hash.Chain

	Config SurfaceConfig

	// Logger receives the underlying cause of every store error that reaches
	// the caller as CodeInternal. The contract error carries only a generic
	// message, so this log line is the one place the cause survives. Nil
	// means a no-op logger.
	Logger log.Logger
}

// logger returns Deps.Logger, or a no-op logger when it is nil.
func (d Deps) logger() log.Logger {
	if d.Logger == nil {
		return log.NewNoopLogger()
	}
	return d.Logger
}

// checkpointingConfigured reports whether this deployment holds checkpoints
// it can authenticate. A store on its own does not count.
func (d Deps) checkpointingConfigured() bool {
	return d.CheckpointStore != nil && d.CheckpointSigner != nil
}

// errStoreRequired is returned by Register when Deps carries no Store.
var errStoreRequired = errors.New("chronicle/contract: Store is required")

// Register loads the manifest, registers the contributor, and binds handlers.
func Register(
	d *dispatcher.Dispatcher,
	reg fcontract.Registry,
	wreg fcontract.WardenRegistry,
	deps Deps,
) error {
	if deps.Store == nil {
		return errStoreRequired
	}

	m, err := loader.Load(bytes.NewReader(manifestYAML), "chronicle/contract/manifest.yaml")
	if err != nil {
		return fmt.Errorf("chronicle/contract: load manifest: %w", err)
	}
	if m.Contributor.Name != contributorName {
		return fmt.Errorf("chronicle/contract: manifest names contributor %q, want %q",
			m.Contributor.Name, contributorName)
	}
	if err := loader.Validate(m, wreg); err != nil {
		return fmt.Errorf("chronicle/contract: validate manifest: %w", err)
	}
	if err := reg.Register(m); err != nil {
		return fmt.Errorf("chronicle/contract: register manifest: %w", err)
	}

	return registerAll(d, deps)
}

// intentKind distinguishes a query from a command at registration time. The
// dispatcher's RegisterQuery and RegisterCommand are aliases for each other,
// so this exists for the manifest parity test rather than for dispatch.
type intentKind string

const (
	kindQuery   intentKind = "query"
	kindCommand intentKind = "command"
)

// registration is one intent and the function that binds it.
type registration struct {
	name string
	kind intentKind
	bind func(*dispatcher.Dispatcher, Deps) error
}

// registrations is every intent this contributor answers. It is the single
// source of truth: registerAll walks it to bind handlers, and the manifest
// parity test walks it to compare against the manifest. Adding an intent in
// one place and forgetting the other is what that test exists to catch, and
// it can only catch it if both read from here.
//
// The dispatcher cannot stand in for this list: it exposes Register,
// RegisterContributor, RegisterSubscription, SetRemoteDispatcher, Dispatch
// and Subscribe, and none of them enumerates what was registered.
func registrations() []registration {
	groups := [][]registration{
		streamsRegistrations(),
		// Each later task adds its group's <group>Registrations() here.
	}

	n := 0
	for _, g := range groups {
		n += len(g)
	}
	out := make([]registration, 0, n)
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// registerAll binds every handler in registrations().
func registerAll(d *dispatcher.Dispatcher, deps Deps) error {
	for _, r := range registrations() {
		if err := r.bind(d, deps); err != nil {
			return fmt.Errorf("chronicle/contract: register %s: %w", r.name, err)
		}
	}
	return nil
}

// query builds the registration for a query intent. It keeps the intent name
// in one place per intent: the name the parity test compares is the name the
// dispatcher binds, because both come from this call.
func query[I, O any](
	name string,
	handler func(Deps) func(ctx context.Context, in I, p fcontract.Principal) (O, error),
) registration {
	return registration{
		name: name,
		kind: kindQuery,
		bind: func(d *dispatcher.Dispatcher, deps Deps) error {
			return dispatcher.RegisterQuery(d, contributorName, name, intentVersion, handler(deps))
		},
	}
}

// command builds the registration for a command intent. See query.
func command[I, O any](
	name string,
	handler func(Deps) func(ctx context.Context, in I, p fcontract.Principal) (O, error),
) registration {
	return registration{
		name: name,
		kind: kindCommand,
		bind: func(d *dispatcher.Dispatcher, deps Deps) error {
			return dispatcher.RegisterCommand(d, contributorName, name, intentVersion, handler(deps))
		},
	}
}
