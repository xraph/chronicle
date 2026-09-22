// Package extension provides a Forge-compatible extension for Chronicle.
// It implements the forge.Extension interface so Chronicle can be mounted
// into any Forge app with automatic route registration, DI injection,
// metrics, and tracing.
//
// Configuration can be provided programmatically via Option functions
// or via YAML configuration files under "extensions.chronicle" or "chronicle" keys.
package extension

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"
	dashboard "github.com/xraph/forge/extensions/dashboard"
	"github.com/xraph/forge/extensions/dashboard/contributor"
	"github.com/xraph/grove"
	"github.com/xraph/grove/kv"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/crypto"
	chronicledash "github.com/xraph/chronicle/dashboard"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/handler"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/sink"
	"github.com/xraph/chronicle/store"
	memorystore "github.com/xraph/chronicle/store/memory"
	mongostore "github.com/xraph/chronicle/store/mongo"
	pgstore "github.com/xraph/chronicle/store/postgres"
	redisstore "github.com/xraph/chronicle/store/redis"
	"github.com/xraph/chronicle/store/sealedstore"
	sqlitestore "github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/stream"
)

// Extension metadata.
const (
	ExtensionName        = "chronicle"
	ExtensionDescription = "Immutable audit trail with hash chains, GDPR erasure, and compliance reporting"
	ExtensionVersion     = "0.1.0"
)

// Ensure Extension implements forge.Extension and dashboard.DashboardAware at compile time.
var (
	_ forge.Extension          = (*Extension)(nil)
	_ dashboard.DashboardAware = (*Extension)(nil)
)

// internalOpts holds non-config options that are set programmatically only.
type internalOpts struct {
	store       store.Store
	archiveSink sink.Sink
	keyStore    crypto.KeyStore
}

// Extension adapts Chronicle as a Forge extension. It implements the
// forge.Extension interface so Chronicle can be mounted into any Forge app.
type Extension struct {
	*forge.BaseExtension

	config         Config
	opts           internalOpts
	chronicle      *chronicle.Chronicle
	engine         *compliance.Engine
	enforcer       *retention.Enforcer
	api            *handler.API
	erasureService *erasure.Service
	store          store.Store
	useGrove       bool
	useGroveKV     bool

	// keyProvider supplies key material for a keyed digest scheme. It can be
	// set directly via [WithKeyProvider], or built from TamperEvidence.Keys
	// during Register when the config names a "file" provider.
	keyProvider keys.Provider

	// hashChain is built once, in Register, before the store is constructed.
	// It is handed to both the SQL store (so Append re-links under the
	// configured scheme instead of quietly downgrading to plain) and to
	// Chronicle (via WithDigestScheme/WithKeyProvider). See buildHashChain.
	hashChain *hash.Chain

	// checkpointer takes signed checkpoints. Built in init, once Checkpoints
	// is validated and the resolved store is confirmed to support them; nil
	// when Checkpoints.Enabled is false, which is what leaves
	// handler.Dependencies.Checkpointer nil for an unconfigured deployment and
	// keeps Start from launching runCheckpointScheduler.
	checkpointer *checkpoint.Checkpointer

	// checkpointSigner is the signer that Checkpointer writes with, kept so
	// the read side can check what the write side signed. It goes to three
	// places, all of them independent of the digest scheme: Chronicle's own
	// VerifyChain, the admin API's POST /v1/verify, and the dashboard's
	// verify page. Nil whenever checkpointer is nil, and the three consumers
	// all fall back to plain chain verification on nil.
	checkpointSigner checkpoint.Signer

	cancel context.CancelFunc
}

// New creates a new Chronicle Forge extension with the given options.
func New(opts ...Option) *Extension {
	e := &Extension{
		BaseExtension: forge.NewBaseExtension(ExtensionName, ExtensionVersion, ExtensionDescription),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Register implements [forge.Extension]. It initializes the store, creates
// the Chronicle instance, wires up all components, and optionally registers
// HTTP routes into the Forge router.
func (e *Extension) Register(fapp forge.App) error {
	if err := e.BaseExtension.Register(fapp); err != nil {
		return err
	}

	if err := e.loadConfiguration(); err != nil {
		return err
	}

	// Captured before store resolution: only a store the operator supplied
	// directly bypasses buildStoreFromGroveDB (and so never received
	// WithHasher). A grove-discovered mongo/redis store never gets one
	// either, but by design -- those backends don't recompute on write -- so
	// the fixup below must not apply to it.
	operatorStore := e.opts.store

	// Build the hash chain before the store, not after Chronicle. The SQL
	// backends re-derive the sequence and prev_hash under a row lock and
	// therefore recompute the digest themselves; if they were left on a
	// default plain chain they would silently overwrite every keyed digest
	// Chronicle computed. So this has to be resolved (and validated) here,
	// once, and shared with both consumers below.
	chain, err := e.buildHashChain()
	if err != nil {
		return err
	}
	e.hashChain = chain

	// Resolve store from grove DI if configured.
	// DB takes precedence over KV when both are configured.
	if e.opts.store == nil && e.useGrove {
		groveDB, err := e.resolveGroveDB(fapp)
		if err != nil {
			return fmt.Errorf("chronicle: %w", err)
		}
		s, err := e.buildStoreFromGroveDB(groveDB)
		if err != nil {
			return err
		}
		e.opts.store = s
	}
	if e.opts.store == nil && e.useGroveKV {
		kvStore, err := e.resolveGroveKV(fapp)
		if err != nil {
			return fmt.Errorf("chronicle: %w", err)
		}
		e.opts.store = redisstore.New(kvStore)
	}
	if e.opts.store == nil {
		if db, err := vessel.Inject[*grove.DB](fapp.Container()); err == nil {
			// Auto-discover default grove.DB from container (matches authsome/cortex pattern).
			s, err := e.buildStoreFromGroveDB(db)
			if err != nil {
				return err
			}
			e.opts.store = s
			e.Logger().Info("chronicle: auto-discovered grove.DB from container",
				forge.F("driver", db.Driver().Name()),
			)
		}
	}

	// An operator-supplied store bypassed buildStoreFromGroveDB, so under an
	// HMAC config it is still sitting on whatever hasher it was built with.
	if operatorStore != nil && e.config.TamperEvidence.Digest == "hmac" {
		if err := e.shareChainWithStore(); err != nil {
			return err
		}
	}

	if err := e.init(fapp); err != nil {
		return err
	}

	// Register the Chronicle Emitter in the DI container so other extensions can use it.
	if err := vessel.Provide(fapp.Container(), func() (chronicle.Emitter, error) {
		return e.chronicle, nil
	}); err != nil {
		return fmt.Errorf("chronicle: register emitter in container: %w", err)
	}

	return nil
}

// shareChainWithStore gives an operator-supplied store the same hash chain
// Chronicle will write with, or refuses if the store needs one and cannot take
// it.
//
// The problem it solves is real but narrow. pg and sqlite re-derive the sequence
// and prev_hash inside their own Append transaction, and the sequence is part of
// the hashed content, so they recompute the digest themselves. Built through
// buildStoreFromGroveDB they get the configured chain via WithHasher. Handed in
// through WithStore they do not, and would silently re-link every event under a
// plain chain while Chronicle wrote keyed ones, with every write still
// succeeding.
//
// Mongo, redis and memory persist whatever digest Chronicle computed. They have
// no hasher because they never needed one, and no WithHasher option either, so
// refusing them used to leave the operator with an error whose instructions
// could not be followed on any backend that produced it.
//
// The split is by backend rather than by capability because there is no
// capability to test: "I recompute the digest on write" is not observable from
// outside, and adding a marker method would only be answered by the same
// in-tree types listed here. So the list is explicit, and the default is to
// refuse. An unfamiliar store might well recompute, and a wrong guess in that
// direction produces exactly the silent unkeyed chain this whole branch exists
// to prevent. Give such a store a SetHasher(*hash.Chain) method and it is
// accepted on the first branch.
func (e *Extension) shareChainWithStore() error {
	switch s := e.opts.store.(type) {
	case interface{ SetHasher(*hash.Chain) }:
		s.SetHasher(e.hashChain)
		return nil

	case *memorystore.Store, *mongostore.Store, *redisstore.Store:
		return nil

	default:
		return fmt.Errorf("%w (store type %T)", ErrStoreCannotReceiveHasher, e.opts.store)
	}
}

// init builds the Chronicle instance and all sub-components.
func (e *Extension) init(fapp forge.App) error {
	// Resolve store.
	s := e.opts.store
	if s == nil {
		return errors.New("chronicle: no store configured (use WithStore option)")
	}
	e.store = s

	// Checkpoints: validate against whatever signing key material is
	// available, probe s (the store as resolved, before any crypto-erasure
	// wrapping below) for checkpoint support, and build the Checkpointer the
	// admin API and scheduler will use. Done on s rather than the possibly
	// sealedstore-wrapped value assigned to e.store further down so a refusal
	// names the real backend type; sealedstore does not override any
	// checkpoint method, so the two are equivalent for everything else.
	checkpointer, checkpointStore, checkpointSigner, err := e.buildCheckpointer(s)
	if err != nil {
		return err
	}
	e.checkpointer, e.checkpointSigner = checkpointer, checkpointSigner

	// Crypto-erasure: build the sealer, then wrap the store so every consumer
	// reads decrypted events. Encryption itself happens in Chronicle.Record,
	// before the hash is computed over the stored bytes.
	var sealer *crypto.Sealer
	if e.config.EnableCryptoErasure {
		if e.opts.keyStore == nil {
			return ErrKeyStoreRequired
		}
		sealer = crypto.NewSealer(e.opts.keyStore)

		// Wrapping here means the admin API, the dashboard, compliance reports and
		// Chronicle's own queries all see readable events without each having to
		// remember to decrypt.
		s = sealedstore.New(s, sealer)
		e.store = s

		e.erasureService = erasure.NewService(s, e.opts.keyStore)
	}

	// Create the store adapter for Chronicle.
	adapter := store.NewAdapter(s)

	// Build Chronicle options.
	chronicleOpts := []chronicle.Option{
		chronicle.WithStore(adapter),
	}
	if sealer != nil {
		chronicleOpts = append(chronicleOpts, chronicle.WithSealer(sealer))
	}
	if e.config.BatchSize > 0 {
		chronicleOpts = append(chronicleOpts, chronicle.WithBatchSize(e.config.BatchSize))
	}
	if e.config.FlushInterval > 0 {
		chronicleOpts = append(chronicleOpts, chronicle.WithFlushInterval(e.config.FlushInterval))
	}
	if e.config.EnableCryptoErasure {
		chronicleOpts = append(chronicleOpts, chronicle.WithCryptoErasure(true))
	}
	// TamperEvidence was already validated and e.keyProvider resolved by
	// buildHashChain in Register, before the store was constructed; this just
	// tells Chronicle the same scheme and provider the store was given.
	if e.config.TamperEvidence.Digest == "hmac" {
		chronicleOpts = append(chronicleOpts,
			chronicle.WithDigestScheme(hash.SchemeHMAC),
			chronicle.WithKeyProvider(e.keyProvider),
		)
	}
	// Checkpoint verification is wired independently of the digest scheme.
	// Checkpointing a plain chain is a coherent choice -- the signature is
	// what makes a later rewrite provable, whether or not the digest under
	// it was keyed -- and a keyed chain may sign its checkpoints from an
	// entirely different keyset. Gate this on the digest and both of those
	// deployments verify without ever fetching the checkpoint they took.
	if e.checkpointSigner != nil {
		chronicleOpts = append(chronicleOpts, chronicle.WithCheckpointSigner(e.checkpointSigner))
	}

	// Create Chronicle.
	c, err := chronicle.New(chronicleOpts...)
	if err != nil {
		return fmt.Errorf("chronicle: create chronicle: %w", err)
	}
	e.chronicle = c

	// Sub-components require log.Logger; use the BaseExtension logger.
	logger := e.Logger()

	// Create compliance engine.
	e.engine = compliance.NewEngine(s, s, s, logger)

	// Create retention enforcer.
	e.enforcer = retention.NewEnforcer(s, e.opts.archiveSink, logger)

	// Security-critical: decide API access before building the handler. The API
	// can purge audit history, so an unauthenticated mount has to be a choice the
	// operator made rather than a default they inherited.
	if authErr := e.config.Auth.Validate(!e.config.DisableRoutes); authErr != nil {
		return authErr
	}

	guards, guardErr := e.buildGuards(fapp)
	if guardErr != nil {
		return guardErr
	}

	// Create the API handler with Forge router.
	e.api = handler.New(handler.Dependencies{
		AuditStore:       s,
		VerifyStore:      s,
		StreamStore:      s,
		ErasureStore:     s,
		Erasure:          e.erasureService,
		RetentionStore:   s,
		ReportStore:      s,
		Compliance:       e.engine,
		Retention:        e.enforcer,
		Logger:           logger,
		Guards:           guards,
		HashChain:        e.hashChain,
		CheckpointStore:  checkpointStore,
		Checkpointer:     e.checkpointer,
		CheckpointSigner: e.checkpointSigner,
	}, fapp.Router())

	// Register HTTP routes unless disabled.
	if !e.config.DisableRoutes {
		basePath := e.config.BasePath
		if basePath == "" {
			basePath = "/chronicle"
		}
		e.api.RegisterRoutes(fapp.Router().Group(basePath))
	}

	e.Logger().Info("chronicle extension registered",
		forge.F("disable_routes", e.config.DisableRoutes),
		forge.F("disable_migrate", e.config.DisableMigrate),
	)

	return nil
}

// Start begins background processing (retention and checkpoint schedulers)
// and runs migrations unless disabled.
func (e *Extension) Start(ctx context.Context) error {
	if e.chronicle == nil {
		return errors.New("chronicle: extension not initialized")
	}

	// Run migrations unless disabled.
	if !e.config.DisableMigrate && e.store != nil {
		if err := e.store.Migrate(ctx); err != nil {
			return fmt.Errorf("chronicle: migration failed: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	// Start retention scheduler if configured.
	if e.config.RetentionInterval > 0 {
		go e.runRetentionScheduler(ctx)
	}

	// Start checkpoint scheduler if configured. e.checkpointer is only
	// non-nil when Checkpoints.Enabled is true (see buildCheckpointer), so
	// this also guards against a zero EveryInterval reaching time.NewTicker.
	if e.config.Checkpoints.Enabled && e.checkpointer != nil {
		go e.runCheckpointScheduler(ctx)
	}

	e.MarkStarted()
	return nil
}

// Stop gracefully shuts down background processing.
func (e *Extension) Stop(_ context.Context) error {
	if e.cancel != nil {
		e.cancel()
	}
	e.MarkStopped()
	return nil
}

// Health implements [forge.Extension].
func (e *Extension) Health(ctx context.Context) error {
	if e.store == nil {
		return errors.New("chronicle: no store configured")
	}
	return e.store.Ping(ctx)
}

// Handler returns the HTTP handler for all API routes.
// Convenience for standalone use outside Forge.
func (e *Extension) Handler() http.Handler {
	if e.api == nil {
		return http.NotFoundHandler()
	}
	return e.api.Handler()
}

// RegisterRoutes registers all Chronicle API routes into a Forge router.
func (e *Extension) RegisterRoutes(router forge.Router) {
	if e.api != nil {
		e.api.RegisterRoutes(router)
	}
}

// Chronicle returns the Chronicle instance for direct API usage.
func (e *Extension) Chronicle() *chronicle.Chronicle {
	return e.chronicle
}

// Emitter returns the Chronicle Emitter for DI injection.
// Other extensions use this to emit audit events without importing Chronicle internals.
func (e *Extension) Emitter() chronicle.Emitter {
	return e.chronicle
}

// ComplianceEngine returns the compliance engine.
func (e *Extension) ComplianceEngine() *compliance.Engine {
	return e.engine
}

// RetentionEnforcer returns the retention enforcer.
func (e *Extension) RetentionEnforcer() *retention.Enforcer {
	return e.enforcer
}

// API returns the API handler.
func (e *Extension) API() *handler.API {
	return e.api
}

// DashboardContributor implements dashboard.DashboardAware. It returns a
// LocalContributor that renders chronicle pages, widgets, and settings in the
// Forge dashboard using templ + ForgeUI.
func (e *Extension) DashboardContributor() contributor.LocalContributor {
	return chronicledash.New(
		chronicledash.NewManifest(),
		e.store,
		e.engine,
		e.enforcer,
		chronicledash.Config{
			BatchSize:           e.config.BatchSize,
			FlushInterval:       e.config.FlushInterval,
			RetentionInterval:   e.config.RetentionInterval,
			EnableCryptoErasure: e.config.EnableCryptoErasure,
			BasePath:            e.config.BasePath,
			AllowMutations:      e.config.DashboardMutations,
			HashChain:           e.hashChain,
			CheckpointStore:     e.checkpointStore(),
			CheckpointSigner:    e.checkpointSigner,
		},
	)
}

func (e *Extension) runRetentionScheduler(ctx context.Context) {
	ticker := time.NewTicker(e.config.RetentionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := e.enforcer.Enforce(ctx)
			if err != nil {
				e.Logger().Error("retention enforcement failed",
					forge.F("error", err.Error()),
				)
				continue
			}
			if result.Archived > 0 || result.Purged > 0 {
				e.Logger().Info("retention enforcement complete",
					forge.F("archived", result.Archived),
					forge.F("purged", result.Purged),
				)
			}
		}
	}
}

// checkpointPollDivisor and checkpointPollFloor choose the checkpoint
// scheduler's base tick from Checkpoints.EveryInterval.
//
// Both triggers -- EveryInterval and EveryEvents -- are evaluated per stream
// on every base tick, so the tick has to be finer than EveryInterval itself
// or EveryEvents could never fire meaningfully ahead of it. 1/12th means the
// documented default (EveryInterval: 1h when left at zero; see
// mergeWithDefaults) polls every 5 minutes: frequent enough that a stream
// crossing EveryEvents is covered within minutes rather than waiting out the
// full hour, without polling so often that ListStreams plus one
// LatestCheckpoint per stream dominates a large deployment. The floor exists
// for a short EveryInterval -- an aggressive operator setting, or a test --
// where EveryInterval/12 alone would poll faster than once a second; nothing
// about EveryEvents (a count, not a rate) argues for going faster than that.
const (
	checkpointPollDivisor = 12
	checkpointPollFloor   = time.Second
)

// checkpointPollInterval derives the scheduler's base tick from
// Checkpoints.EveryInterval. See the constants above for why.
func (e *Extension) checkpointPollInterval() time.Duration {
	d := e.config.Checkpoints.EveryInterval / checkpointPollDivisor
	if d < checkpointPollFloor {
		return checkpointPollFloor
	}
	return d
}

// runCheckpointScheduler evaluates every stream against both of
// Checkpoints' triggers on a base tick finer than EveryInterval (see
// checkpointPollInterval), and follows runRetentionScheduler's shape
// otherwise, including its ctx.Done() handling.
//
// Both triggers are implemented: a stream is checkpointed once the elapsed
// time since its last checkpoint reaches EveryInterval, OR once it has
// gained EveryEvents events since then -- whichever comes first. The
// interval alone is not enough, because the window between checkpoints is
// exactly the span an attacker can still rewrite: a stream doing thousands
// of events a minute should not have to wait out a full EveryInterval (an
// hour, by default) before that window closes again.
func (e *Extension) runCheckpointScheduler(ctx context.Context) {
	ticker := time.NewTicker(e.checkpointPollInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.checkpointAllStreams(ctx)
		}
	}
}

// checkpointAllStreams lists every stream and takes a checkpoint over each
// one that streamCheckpointDue reports as due.
//
// ErrNothingToCheckpoint (a quiet stream) and ErrExists (lost a race with
// another checkpointer -- another process's scheduler tick, or an
// operator-triggered POST /v1/checkpoints landing first) are both ordinary
// outcomes, not faults, and are skipped silently. Anything else is logged and
// the loop moves on to the next stream rather than aborting the whole tick
// over one failure.
func (e *Extension) checkpointAllStreams(ctx context.Context) {
	streams, err := e.store.ListStreams(ctx, stream.ListOpts{})
	if err != nil {
		e.Logger().Error("checkpoint scheduler: list streams failed",
			forge.F("error", err.Error()),
		)
		return
	}

	for _, st := range streams {
		due, dueErr := e.streamCheckpointDue(ctx, st)
		if dueErr != nil {
			e.Logger().Error("checkpoint scheduler: could not determine whether stream is due",
				forge.F("stream_id", st.ID.String()),
				forge.F("error", dueErr.Error()),
			)
			continue
		}
		if !due {
			continue
		}

		_, cpErr := e.checkpointer.CheckpointStream(ctx, checkpoint.StreamHead{
			ID:       st.ID,
			AppID:    st.AppID,
			TenantID: st.TenantID,
			HeadSeq:  st.HeadSeq,
			HeadHash: st.HeadHash,
		})
		switch {
		case cpErr == nil, errors.Is(cpErr, checkpoint.ErrNothingToCheckpoint), errors.Is(cpErr, checkpoint.ErrExists):
			// Taken, quiet, or lost a race: all ordinary, not faults.
		default:
			e.Logger().Error("checkpoint scheduler: checkpoint failed",
				forge.F("stream_id", st.ID.String()),
				forge.F("error", cpErr.Error()),
			)
		}
	}
}

// streamCheckpointDue reports whether st has crossed Checkpoints.EveryInterval
// or Checkpoints.EveryEvents since its last checkpoint, resolving that
// checkpoint (if any) from e.store and deferring the actual decision to
// checkpointDue, a pure function kept separate so the trigger logic can be
// reasoned about (and, from within this package, tested) without a live
// store or a running scheduler.
func (e *Extension) streamCheckpointDue(ctx context.Context, st *stream.Stream) (bool, error) {
	latest, err := e.store.LatestCheckpoint(ctx, st.ID)
	switch {
	case err == nil:
		return checkpointDue(time.Now(), true, latest.CreatedAt, latest.ToSeq, st.HeadSeq, e.config.Checkpoints), nil
	case errors.Is(err, checkpoint.ErrNotFound):
		return checkpointDue(time.Now(), false, time.Time{}, 0, st.HeadSeq, e.config.Checkpoints), nil
	default:
		return false, err
	}
}

// checkpointDue is the pure decision at the heart of the dual-trigger
// scheduler: given now and what the stream's last checkpoint (if any)
// asserted, is this stream due?
//
//   - Never checkpointed (hasCheckpoint false): due immediately. There is no
//     "elapsed since last checkpoint" to measure yet, and CheckpointStream
//     itself returns ErrNothingToCheckpoint cheaply if the stream has no
//     events at all, so attempting on every poll costs nothing on an empty
//     stream and covers a new one within one poll period of its first event
//     rather than waiting out a full EveryInterval.
//   - Otherwise due when either EveryInterval has elapsed since the last
//     checkpoint's CreatedAt, or the stream has gained at least EveryEvents
//     sequences since the last checkpoint's ToSeq.
func checkpointDue(now time.Time, hasCheckpoint bool, lastCreatedAt time.Time, lastToSeq, headSeq uint64, cfg CheckpointConfig) bool {
	if !hasCheckpoint {
		return true
	}
	if now.Sub(lastCreatedAt) >= cfg.EveryInterval {
		return true
	}
	if cfg.EveryEvents > 0 && headSeq > lastToSeq && headSeq-lastToSeq >= uint64(cfg.EveryEvents) {
		return true
	}
	return false
}

// --- Config Loading (mirrors grove/shield extension pattern) ---

// loadConfiguration loads config from YAML files or programmatic sources.
func (e *Extension) loadConfiguration() error {
	programmaticConfig := e.config

	// Try loading from config file.
	fileConfig, configLoaded := e.tryLoadFromConfigFile()

	if !configLoaded {
		if programmaticConfig.RequireConfig {
			return errors.New("chronicle: configuration is required but not found in config files; " +
				"ensure 'extensions.chronicle' or 'chronicle' key exists in your config")
		}

		// Use programmatic config merged with defaults.
		e.config = e.mergeWithDefaults(programmaticConfig)
	} else {
		// Config loaded from YAML -- merge with programmatic options.
		e.config = e.mergeConfigurations(fileConfig, programmaticConfig)
	}

	// Enable grove resolution if YAML config specifies a grove database or KV.
	if e.config.GroveDatabase != "" {
		e.useGrove = true
	}
	if e.config.GroveKV != "" {
		e.useGroveKV = true
	}

	e.Logger().Debug("chronicle: configuration loaded",
		forge.F("disable_routes", e.config.DisableRoutes),
		forge.F("disable_migrate", e.config.DisableMigrate),
		forge.F("base_path", e.config.BasePath),
		forge.F("grove_database", e.config.GroveDatabase),
		forge.F("grove_kv", e.config.GroveKV),
		forge.F("batch_size", e.config.BatchSize),
		forge.F("retention_interval", e.config.RetentionInterval),
	)

	return nil
}

// tryLoadFromConfigFile attempts to load config from YAML files.
func (e *Extension) tryLoadFromConfigFile() (Config, bool) {
	cm := e.App().Config()
	var cfg Config

	// Try "extensions.chronicle" first (namespaced pattern).
	if cm.IsSet("extensions.chronicle") {
		if err := cm.Bind("extensions.chronicle", &cfg); err == nil {
			e.Logger().Debug("chronicle: loaded config from file",
				forge.F("key", "extensions.chronicle"),
			)
			return cfg, true
		}
		e.Logger().Warn("chronicle: failed to bind extensions.chronicle config",
			forge.F("error", "bind failed"),
		)
	}

	// Try legacy "chronicle" key.
	if cm.IsSet("chronicle") {
		if err := cm.Bind("chronicle", &cfg); err == nil {
			e.Logger().Debug("chronicle: loaded config from file",
				forge.F("key", "chronicle"),
			)
			return cfg, true
		}
		e.Logger().Warn("chronicle: failed to bind chronicle config",
			forge.F("error", "bind failed"),
		)
	}

	return Config{}, false
}

// mergeWithDefaults fills zero-valued fields with defaults.
func (e *Extension) mergeWithDefaults(cfg Config) Config {
	defaults := DefaultConfig()
	if cfg.BatchSize == 0 {
		cfg.BatchSize = defaults.BatchSize
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = defaults.FlushInterval
	}
	if cfg.RetentionInterval == 0 {
		cfg.RetentionInterval = defaults.RetentionInterval
	}
	// Defaults below are gated on Enabled: a deployment with no checkpoints
	// block (or one that left it off) must keep recording none, not have an
	// interval and event threshold materialize under it.
	if cfg.Checkpoints.Enabled {
		if cfg.Checkpoints.EveryEvents == 0 {
			cfg.Checkpoints.EveryEvents = 10000
		}
		if cfg.Checkpoints.EveryInterval == 0 {
			cfg.Checkpoints.EveryInterval = time.Hour
		}
	}
	return cfg
}

// mergeConfigurations merges YAML config with programmatic options.
// YAML config takes precedence for most fields; programmatic bool flags fill gaps.
//
// Every field of Config that an Option can set has to appear here. The merge
// rebuilds the config from the YAML side, so a field nobody copies across is a
// field the operator silently loses the moment any chronicle YAML block exists,
// anywhere. That is not a cosmetic loss for the security-bearing ones:
// WithDigestScheme("hmac") vanishing turns a keyed chain back into an unkeyed
// one with no error and no warning, and WithAuth vanishing takes an
// authenticated admin API with it. When you add a field to Config, add it here.
func (e *Extension) mergeConfigurations(yamlConfig, programmaticConfig Config) Config {
	// Programmatic bool flags override when true.
	if programmaticConfig.DisableRoutes {
		yamlConfig.DisableRoutes = true
	}
	if programmaticConfig.DisableMigrate {
		yamlConfig.DisableMigrate = true
	}
	if programmaticConfig.EnableCryptoErasure {
		yamlConfig.EnableCryptoErasure = true
	}
	if programmaticConfig.DashboardMutations {
		yamlConfig.DashboardMutations = true
	}
	if programmaticConfig.Auth.AllowUnauthenticated {
		yamlConfig.Auth.AllowUnauthenticated = true
	}

	// String fields: YAML takes precedence.
	if yamlConfig.BasePath == "" && programmaticConfig.BasePath != "" {
		yamlConfig.BasePath = programmaticConfig.BasePath
	}
	if yamlConfig.GroveDatabase == "" && programmaticConfig.GroveDatabase != "" {
		yamlConfig.GroveDatabase = programmaticConfig.GroveDatabase
	}
	if yamlConfig.GroveKV == "" && programmaticConfig.GroveKV != "" {
		yamlConfig.GroveKV = programmaticConfig.GroveKV
	}

	// Duration/int fields: YAML takes precedence, programmatic fills gaps.
	if yamlConfig.BatchSize == 0 && programmaticConfig.BatchSize != 0 {
		yamlConfig.BatchSize = programmaticConfig.BatchSize
	}
	if yamlConfig.FlushInterval == 0 && programmaticConfig.FlushInterval != 0 {
		yamlConfig.FlushInterval = programmaticConfig.FlushInterval
	}
	if yamlConfig.RetentionInterval == 0 && programmaticConfig.RetentionInterval != 0 {
		yamlConfig.RetentionInterval = programmaticConfig.RetentionInterval
	}

	// Tamper evidence: YAML takes precedence per field, programmatic fills gaps.
	// Field by field rather than struct by struct, so a YAML block that names
	// the digest but leaves the key source to a KMS-backed WithKeyProvider still
	// works, and so does the reverse.
	if yamlConfig.TamperEvidence.Digest == "" && programmaticConfig.TamperEvidence.Digest != "" {
		yamlConfig.TamperEvidence.Digest = programmaticConfig.TamperEvidence.Digest
	}
	if yamlConfig.TamperEvidence.Keys.Provider == "" && programmaticConfig.TamperEvidence.Keys.Provider != "" {
		yamlConfig.TamperEvidence.Keys.Provider = programmaticConfig.TamperEvidence.Keys.Provider
	}
	if yamlConfig.TamperEvidence.Keys.Path == "" && programmaticConfig.TamperEvidence.Keys.Path != "" {
		yamlConfig.TamperEvidence.Keys.Path = programmaticConfig.TamperEvidence.Keys.Path
	}

	// Checkpoints: same rule as TamperEvidence, field by field, so a YAML
	// block that only sets the interval still leaves Enabled and the signer
	// to reach here from WithCheckpoints, and so does the reverse -- a YAML
	// block that turns checkpoints on while the signing key comes from a
	// KMS-backed WithKeyProvider rather than checkpoints.signer.
	if !yamlConfig.Checkpoints.Enabled && programmaticConfig.Checkpoints.Enabled {
		yamlConfig.Checkpoints.Enabled = true
	}
	if yamlConfig.Checkpoints.EveryEvents == 0 && programmaticConfig.Checkpoints.EveryEvents != 0 {
		yamlConfig.Checkpoints.EveryEvents = programmaticConfig.Checkpoints.EveryEvents
	}
	if yamlConfig.Checkpoints.EveryInterval == 0 && programmaticConfig.Checkpoints.EveryInterval != 0 {
		yamlConfig.Checkpoints.EveryInterval = programmaticConfig.Checkpoints.EveryInterval
	}
	if yamlConfig.Checkpoints.Signer.Provider == "" && programmaticConfig.Checkpoints.Signer.Provider != "" {
		yamlConfig.Checkpoints.Signer.Provider = programmaticConfig.Checkpoints.Signer.Provider
	}
	if yamlConfig.Checkpoints.Signer.Path == "" && programmaticConfig.Checkpoints.Signer.Path != "" {
		yamlConfig.Checkpoints.Signer.Path = programmaticConfig.Checkpoints.Signer.Path
	}

	// Auth: same rule again. Dropping these silently is how an admin API that
	// can purge audit history ends up mounted with the authentication its
	// operator configured quietly removed.
	if yamlConfig.Auth.Provider == "" && programmaticConfig.Auth.Provider != "" {
		yamlConfig.Auth.Provider = programmaticConfig.Auth.Provider
	}
	if len(yamlConfig.Auth.ReadScopes) == 0 && len(programmaticConfig.Auth.ReadScopes) > 0 {
		yamlConfig.Auth.ReadScopes = programmaticConfig.Auth.ReadScopes
	}
	if len(yamlConfig.Auth.WriteScopes) == 0 && len(programmaticConfig.Auth.WriteScopes) > 0 {
		yamlConfig.Auth.WriteScopes = programmaticConfig.Auth.WriteScopes
	}
	if len(yamlConfig.Auth.AdminScopes) == 0 && len(programmaticConfig.Auth.AdminScopes) > 0 {
		yamlConfig.Auth.AdminScopes = programmaticConfig.Auth.AdminScopes
	}

	// Fill remaining zeros with defaults.
	return e.mergeWithDefaults(yamlConfig)
}

// resolveGroveDB resolves a *grove.DB from the DI container.
// If GroveDatabase is set, it looks up the named DB; otherwise it uses the default.
func (e *Extension) resolveGroveDB(fapp forge.App) (*grove.DB, error) {
	if e.config.GroveDatabase != "" {
		db, err := vessel.InjectNamed[*grove.DB](fapp.Container(), e.config.GroveDatabase)
		if err != nil {
			return nil, fmt.Errorf("grove database %q not found in container: %w", e.config.GroveDatabase, err)
		}
		return db, nil
	}
	db, err := vessel.Inject[*grove.DB](fapp.Container())
	if err != nil {
		return nil, fmt.Errorf("default grove database not found in container: %w", err)
	}
	return db, nil
}

// resolveGroveKV resolves a *kv.Store from the DI container.
// If GroveKV is set, it looks up the named KV store; otherwise it uses the default.
func (e *Extension) resolveGroveKV(fapp forge.App) (*kv.Store, error) {
	if e.config.GroveKV != "" {
		kvStore, err := vessel.InjectNamed[*kv.Store](fapp.Container(), e.config.GroveKV)
		if err != nil {
			return nil, fmt.Errorf("grove KV store %q not found in container: %w", e.config.GroveKV, err)
		}
		return kvStore, nil
	}
	kvStore, err := vessel.Inject[*kv.Store](fapp.Container())
	if err != nil {
		return nil, fmt.Errorf("default grove KV store not found in container: %w", err)
	}
	return kvStore, nil
}

// buildStoreFromGroveDB constructs the appropriate store backend based on the
// grove driver type (pg, sqlite, mongo).
//
// pg and sqlite recompute the digest inside Append (they re-derive the
// sequence and prev_hash under a row lock, and the sequence is part of the
// hashed content), so they take the same hash chain Chronicle was configured
// with; otherwise they would quietly re-link every event under an unkeyed
// digest. mongo does not recompute on write, so it is not given a hasher.
func (e *Extension) buildStoreFromGroveDB(db *grove.DB) (store.Store, error) {
	driverName := db.Driver().Name()
	switch driverName {
	case "pg":
		return pgstore.New(db, pgstore.WithHasher(e.hashChain)), nil
	case "sqlite":
		return sqlitestore.New(db, sqlitestore.WithHasher(e.hashChain)), nil
	case "mongo":
		return mongostore.New(db), nil
	default:
		return nil, fmt.Errorf("chronicle: unsupported grove driver %q", driverName)
	}
}

// buildHashChain validates TamperEvidence, resolves a key provider from
// config when one was not supplied programmatically, and constructs the
// *hash.Chain both the store and Chronicle will use.
//
// Validation happens here, at Register time, rather than the first Record or
// Append, so a misconfigured deployment refuses to start instead of writing
// digests an operator believes are keyed.
func (e *Extension) buildHashChain() (*hash.Chain, error) {
	if err := e.config.TamperEvidence.Validate(); err != nil {
		// Validate only inspects TamperEvidence.Keys, so it cannot see a
		// keys.Provider supplied directly via WithKeyProvider -- the
		// documented way to satisfy KeyConfig.Provider == "" (see its doc
		// comment). Swallow exactly that false positive; every other error
		// Validate returns (an unknown digest, a file provider with no path)
		// still applies regardless of e.keyProvider.
		suppliedDirectly := e.keyProvider != nil &&
			e.config.TamperEvidence.Keys.Provider == "" &&
			e.config.TamperEvidence.Keys.Path == ""
		if !errors.Is(err, ErrKeyProviderRequired) || !suppliedDirectly {
			return nil, err
		}
	}

	// Gated on Digest == "hmac" too: without it, a plain (or unset) deployment
	// that still has a stale tamper_evidence.keys.provider: file block left
	// over from an earlier config would fail startup trying to read a keyset
	// nothing is ever going to use.
	if e.keyProvider == nil && e.config.TamperEvidence.Digest == "hmac" && e.config.TamperEvidence.Keys.Provider == "file" {
		p, err := keys.NewFileProvider(e.config.TamperEvidence.Keys.Path)
		if err != nil {
			return nil, err
		}
		e.keyProvider = p
	}

	scheme := hash.SchemePlain
	if e.config.TamperEvidence.Digest == "hmac" {
		scheme = hash.SchemeHMAC
	}

	chain, err := hash.NewChain(scheme, e.keyProvider)
	if err != nil {
		return nil, fmt.Errorf("chronicle: %w", err)
	}
	return chain, nil
}

// buildCheckpointSigner resolves a keys.Provider for checkpoint signing --
// from config or [WithKeyProvider], mirroring buildHashChain -- and returns
// a ready Ed25519Signer, or an error if this deployment has no working way
// to sign a checkpoint. Callers must only invoke this when Checkpoints.Enabled
// is true.
//
// The same e.keyProvider WithKeyProvider sets for tamper_evidence doubles as
// the checkpoint signing key source: keys.Provider is parameterised by Use,
// so a single provider (a keyset file or a KMS-backed implementation) can
// vend both the hmac digest key and the ed25519 checkpoint key without the
// deployment naming two separate sources.
//
// Three failure modes reach here that CheckpointConfig.Validate and the
// original construction could not catch on their own, all found in review:
//
//  1. checkpoints.signer.provider naming something this extension does not
//     implement -- "kms", "vault", a typo, a capitalised "File" -- used to
//     pass Validate (it only special-cased "file" and rejected empty), leave
//     provider nil below, and reach checkpoint.NewEd25519Signer(nil).
//     Nothing panicked until the scheduler's first tick called Sign on it,
//     inside its own goroutine, taking the process down. Validate now
//     rejects any Signer.Provider it does not implement, and the nil check
//     below is a second, construction-time backstop -- mirroring
//     hash.NewChain's own explicit nil check for SchemeHMAC -- so a future
//     gap in Validate fails Register instead of reaching Sign.
//  2. A provider that resolves cleanly but cannot vend a checkpoint-sig key:
//     e.g. one supplied via WithKeyProvider that only holds tamper
//     evidence's hmac key. Register used to succeed and every tick then
//     failed silently forever -- checkpoints.enabled: true recording
//     nothing is exactly the gap the store-support probe in
//     buildCheckpointer exists to close, reached through a different door.
//     The active key is now resolved once, here, and construction fails if
//     it is missing or the wrong size; the key itself is then discarded,
//     the same way hash.NewChain's check discards its resolved key --
//     Ed25519Signer re-resolves per checkpoint so rotation takes effect
//     without a restart.
//  3. An inherited e.keyProvider silently outranking an explicit
//     checkpoints.signer.path: tamper_evidence.keys.provider: file and
//     checkpoints.signer.provider: file naming two different keyset files
//     used to open only the first, because buildHashChain runs first and
//     leaves e.keyProvider already non-nil by the time this runs, regardless
//     of whether WithKeyProvider was ever called. An explicit
//     Signer.Provider: "file" now always opens Signer.Path, ahead of
//     whatever e.keyProvider already holds.
func (e *Extension) buildCheckpointSigner() (checkpoint.Signer, error) {
	if err := e.config.Checkpoints.Validate(e.keyProvider != nil); err != nil {
		return nil, err
	}

	var provider keys.Provider
	switch {
	case e.config.Checkpoints.Signer.Provider == "file":
		// Explicit config always wins over an inherited provider: naming
		// checkpoints.signer.path is a deliberate choice of keyset, and
		// silently using whatever tamper_evidence left in e.keyProvider
		// instead is not debuggable from outside.
		p, err := keys.NewFileProvider(e.config.Checkpoints.Signer.Path)
		if err != nil {
			return nil, err
		}
		provider = p
	case e.keyProvider != nil:
		provider = e.keyProvider
	}
	if provider == nil {
		return nil, ErrCheckpointSignerRequired
	}

	key, keyID, err := provider.Current(context.Background(), keys.UseCheckpointSig)
	if err != nil {
		return nil, fmt.Errorf(
			"chronicle: checkpoints.enabled is true but no active %s key could be resolved: %w",
			keys.UseCheckpointSig, err)
	}
	if len(key) != keys.Ed25519KeySize {
		return nil, fmt.Errorf(
			"chronicle: checkpoints signing key %q is %d bytes, want %d (a %s key)",
			keyID, len(key), keys.Ed25519KeySize, keys.UseCheckpointSig)
	}

	return checkpoint.NewEd25519Signer(provider), nil
}

// buildCheckpointer validates checkpoints.* against whatever signing key
// material is available, probes s for checkpoint support, and constructs the
// Checkpointer, the store, and the signer that go with it. All three come
// back nil when Checkpoints.Enabled is false, which is what leaves
// handler.Dependencies' CheckpointStore, Checkpointer and CheckpointSigner
// nil for a deployment that never turned checkpoints on -- the routes then
// report 503 rather than mounting a write path with nothing behind it, the
// verify route and the dashboard behave exactly as they did before
// checkpoints existed, and Start never launches runCheckpointScheduler.
//
// The signer is returned rather than rebuilt by each reader because the read
// side has to check what the write side actually signed. Rebuilding it from
// the digest's key provider is the bug this return value exists to prevent.
//
// The probe matters because store/redis (deliberately: it is a read-through
// cache, the wrong home for a root of trust) returns checkpoint.ErrUnsupported
// from every checkpoint method. Running with checkpoints.enabled: true
// against such a backend would otherwise start clean and record nothing --
// exactly the silent gap signed checkpoints exist to close. s already
// satisfies checkpoint.Store (store.Store embeds it), so no type assertion is
// needed to make the call; LatestCheckpoint against a zero stream ID is a
// cheap, side-effect-free way to ask a real backend "have you heard of
// checkpoints at all" without needing any checkpoint to already exist.
func (e *Extension) buildCheckpointer(s store.Store) (*checkpoint.Checkpointer, checkpoint.Store, checkpoint.Signer, error) {
	if !e.config.Checkpoints.Enabled {
		return nil, nil, nil, nil
	}

	signer, err := e.buildCheckpointSigner()
	if err != nil {
		return nil, nil, nil, err
	}

	if _, probeErr := s.LatestCheckpoint(context.Background(), id.Nil); probeErr != nil && errors.Is(probeErr, checkpoint.ErrUnsupported) {
		return nil, nil, nil, fmt.Errorf("%w (store type %T)", ErrCheckpointsUnsupportedByStore, s)
	}

	return checkpoint.NewCheckpointer(s, signer, e.Logger()), s, signer, nil
}

// checkpointStore returns the store the dashboard should read checkpoints
// from, or nil when this deployment takes none.
//
// It is derived from e.checkpointSigner rather than kept as a fourth field:
// buildCheckpointer only ever returns the store alongside a signer, so the
// two are set and cleared together, and a deployment with no signer must not
// hand the dashboard a store whose rows nothing can authenticate.
func (e *Extension) checkpointStore() checkpoint.Store {
	if e.checkpointSigner == nil || e.store == nil {
		return nil
	}
	return e.store
}
