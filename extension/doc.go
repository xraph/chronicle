// Package extension provides a Forge-compatible extension for Chronicle.
//
// # Overview
//
// Extension wraps the entire Chronicle stack — [chronicle.Chronicle],
// [compliance.Engine], [retention.Enforcer], and [handler.API] — as a single
// [forge.Extension] that can be registered into any Forge application with one
// call.
//
// # Lifecycle
//
//  1. [New](opts...) — create the extension (no I/O yet)
//  2. [Extension.Register](fapp) — called by Forge during startup; builds the
//     Chronicle instance, wires all sub-components, registers HTTP routes into
//     the Forge router (unless disabled), and provides [chronicle.Emitter] in
//     the DI container
//  3. [Extension.Start](ctx) — run store migrations (unless disabled) and launch
//     the background retention scheduler
//  4. [Extension.Stop](ctx) — cancel the retention scheduler context
//  5. [Extension.Health](ctx) — delegates to store.Ping for readiness probes
//
// # Store Requirement
//
// The extension requires a [store.Store] (the composite interface, not
// [chronicle.Storer]). Provide it via [WithStore]:
//
//	ext := extension.New(extension.WithStore(myStore))
//
// Internally, [Register] calls [store.NewAdapter] to bridge [store.Store] into
// [chronicle.Storer] before constructing [chronicle.New].
//
// # DI Pattern
//
// After [Register], other Forge extensions receive the [chronicle.Emitter]
// interface through Vessel (the Forge DI container):
//
//	vessel.Invoke(app.Container(), func(emitter chronicle.Emitter) {
//	    // emit audit events without importing Chronicle internals
//	    emitter.Info(ctx, "login", "session", id).Category("auth").Record()
//	})
//
// Or access the emitter directly:
//
//	emitter := ext.Emitter()
//
// # Accessors
//
//   - [Extension.Chronicle]         — the underlying [chronicle.Chronicle] instance
//   - [Extension.Emitter]           — [chronicle.Emitter] for DI injection
//   - [Extension.ComplianceEngine]  — the [compliance.Engine]
//   - [Extension.RetentionEnforcer] — the [retention.Enforcer]
//   - [Extension.API]               — the [handler.API] (21 HTTP endpoints)
//   - [Extension.Handler]           — http.Handler for standalone use outside Forge
//
// # Options
//
//   - [WithStore](s)               — required; the composite store backend
//   - [WithBatchSize](n)           — event batch size (default 100)
//   - [WithFlushInterval](d)       — batch flush interval (default 1s)
//   - [WithCryptoErasure](enabled) — enable GDPR AES-256-GCM crypto-erasure
//   - [WithRetentionInterval](d)   — how often retention policies are enforced
//     (default 24h; set to 0 to disable)
//   - [WithArchiveSink](s)         — sink.Sink used for archival during retention
//   - [WithLogger](l)              — *slog.Logger (default: slog.Default())
//   - [WithDisableRoutes](true)    — skip HTTP route registration
//   - [WithDisableMigrate](true)   — skip automatic schema migration on Start
package extension
