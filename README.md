# Chronicle — Composable Immutable Audit Trail for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/xraph/chronicle.svg)](https://pkg.go.dev/github.com/xraph/chronicle)
[![Go Version](https://img.shields.io/badge/go-1.25+-blue)](https://go.dev)

Chronicle is a production-grade audit trail library that records every event into a SHA-256 hash chain, making tampering cryptographically detectable. It is designed for multi-tenant SaaS applications that need SOC2, HIPAA, or GDPR compliance out of the box.

## Features

- **Hash chain integrity** — Every event is linked by SHA-256 hashes. Tampering breaks the chain.
- **GDPR crypto-erasure** — Per-subject AES-256-GCM encryption. Delete the key, the data becomes irrecoverable, but the hash chain stays intact.
- **Multi-tenant scoping** — Events are automatically scoped to app + tenant from context. Cross-tenant queries are impossible.
- **Compliance reports** — Generate SOC2 Type II, HIPAA, EU AI Act, and custom reports. Export to JSON, CSV, Markdown, or HTML.
- **Pluggable stores** — Postgres (pgx), Grove ORM, SQLite, Redis (cache layer), and in-memory (testing).
- **Pluggable sinks** — Fire-and-forget event outputs (stdout, file, S3, custom). Sinks never block the pipeline.
- **Plugin system** — BeforeRecord enrichment, AfterRecord notification, SinkProvider, AlertHandler, and more.
- **Retention policies** — Automatic archival and purge with configurable schedules.
- **Admin HTTP API** — 21 endpoints for events, verification, erasure, retention, compliance, and stats.
- **Forge integration** — Drop-in extension for the Forge framework with DI-injected Emitter.
- **Type-safe IDs** — TypeID-based identifiers (`audit_01h2x...`, `stream_01h2x...`).

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/xraph/chronicle"
    "github.com/xraph/chronicle/audit"
    "github.com/xraph/chronicle/scope"
    "github.com/xraph/chronicle/store"
    "github.com/xraph/chronicle/store/memory"
)

func main() {
    ctx := context.Background()
    ctx = scope.WithAppID(ctx, "myapp")
    ctx = scope.WithTenantID(ctx, "tenant-1")

    mem := memory.New()
    adapter := store.NewAdapter(mem)

    c, err := chronicle.New(chronicle.WithStore(adapter))
    if err != nil {
        log.Fatal(err)
    }

    // Record an event.
    err = c.Info(ctx, "login", "session", "sess-001").
        Category("auth").
        UserID("user-42").
        Meta("provider", "okta").
        Record()
    if err != nil {
        log.Fatal(err)
    }

    // Query events.
    result, err := c.Query(ctx, &audit.Query{Limit: 10, Order: "desc"})
    if err != nil {
        log.Fatal(err)
    }
    for _, ev := range result.Events {
        fmt.Printf("[%s] %s %s/%s\n", ev.Severity, ev.Action, ev.Resource, ev.ResourceID)
    }
}
```

## Installation

```bash
go get github.com/xraph/chronicle
```

## Architecture

```
Context (AppID, TenantID, UserID, IP)
    |
    v
EventBuilder  -->  Chronicle.Record()
                       |
                  1. Apply scope from context
                  2. Assign ID + timestamp
                  3. Validate required fields
                  4. Resolve or create stream (app+tenant)
                  5. Compute SHA-256 hash chain
                  6. Store.Append
                  7. Update stream head
                       |
                  Plugins (BeforeRecord / AfterRecord)
                       |
                  Sinks (stdout, file, S3, ...)
```

**Package Index:**

| Package | Import Path | Purpose |
|---------|-------------|---------|
| chronicle | `github.com/xraph/chronicle` | Root engine, EventBuilder, Emitter, Storer |
| audit | `.../audit` | Event type, query types, Store interface |
| stream | `.../stream` | Hash chain stream per app+tenant |
| hash | `.../hash` | SHA-256 chain computation |
| verify | `.../verify` | Chain integrity verification |
| store | `.../store` | Composite Store interface, Adapter |
| crypto | `.../crypto` | AES-256-GCM for GDPR erasure |
| erasure | `.../erasure` | GDPR subject erasure service |
| compliance | `.../compliance` | Report generation and export |
| retention | `.../retention` | Policy-based archival and purge |
| sink | `.../sink` | Fire-and-forget output targets |
| plugin | `.../plugin` | Extensibility hooks |
| batcher | `.../batcher` | Batched event writing |
| scope | `.../scope` | Context-based tenant isolation |
| id | `.../id` | TypeID-based entity identifiers |
| handler | `.../handler` | Admin REST endpoints (21 routes) |
| extension | `.../extension` | Forge framework extension |

## Store Backends

| Backend | Package | Use Case |
|---------|---------|----------|
| **PostgreSQL** (pgx) | `store/postgres` | Production — direct pgx driver |
| **Grove ORM** | `store/grovestore` | Production — Grove ORM |
| **SQLite** | `store/sqlite` | Single-node / embedded |
| **Redis** | `store/redis` | Cache layer (read-through) |
| **Memory** | `store/memory` | Testing and examples |

All backends implement the composite `store.Store` interface and are wrapped with `store.NewAdapter()` to satisfy `chronicle.Storer`.

## Compliance Reports

Generate compliance reports from your audit data:

```go
engine := compliance.NewEngine(auditStore, verifyStore, reportStore, logger)

// SOC2 Type II
report, _ := engine.SOC2(ctx, &compliance.SOC2Input{
    Period:      compliance.DateRange{From: from, To: to},
    AppID:       "myapp",
    GeneratedBy: "admin",
})

// HIPAA
report, _ := engine.HIPAA(ctx, &compliance.HIPAAInput{...})

// EU AI Act
report, _ := engine.EUAIAct(ctx, &compliance.EUAIActInput{...})

// Custom
report, _ := engine.Custom(ctx, &compliance.CustomInput{...})

// Export
engine.Export(ctx, report, compliance.FormatMarkdown, os.Stdout)
```

Supported formats: `json`, `csv`, `markdown`, `html`.

## GDPR Crypto-Erasure

Chronicle supports GDPR Article 17 (right to erasure) through crypto-erasure:

1. Each data subject's events are associated with a per-subject encryption key.
2. On erasure request, the key is destroyed — making encrypted data irrecoverable.
3. Events are marked as erased in the store.
4. The hash chain remains structurally valid (hashes are computed over event metadata, not encrypted payloads).

```go
keyStore := crypto.NewInMemoryKeyStore()
service := erasure.NewService(store, keyStore)

result, _ := service.Erase(ctx, &erasure.Input{
    SubjectID:   "user-alice",
    Reason:      "GDPR Article 17",
    RequestedBy: "dpo@company.com",
}, appID, tenantID)
// result.KeyDestroyed == true
// result.EventsAffected == 3
```

## Plugin System

Plugins implement any subset of hook interfaces. The registry discovers capabilities at registration time for O(1) dispatch:

```go
type MyPlugin struct{}

func (p *MyPlugin) Name() string { return "my-plugin" }

// Enrich events before they are stored.
func (p *MyPlugin) OnBeforeRecord(ctx context.Context, event *audit.Event) error {
    event.Metadata["enriched"] = true
    return nil
}

// React after events are stored.
func (p *MyPlugin) OnAfterRecord(ctx context.Context, event *audit.Event) error {
    fmt.Println("Event recorded:", event.ID)
    return nil
}

registry := plugin.NewRegistry(logger)
registry.Register(&MyPlugin{})
```

| Interface | When |
|-----------|------|
| `OnInit` | Chronicle starts |
| `OnShutdown` | Chronicle stops |
| `BeforeRecord` | Before event is persisted (enrichment, filtering) |
| `AfterRecord` | After event is persisted (notifications, alerts) |
| `SinkProvider` | Provides a custom Sink |
| `Exporter` | Provides a custom export format |
| `AlertHandler` | Fires when events match alert rules |

## Admin API

The handler package provides 21 REST endpoints mounted under `/chronicle/`:

**Events:** `GET /events`, `GET /events/{id}`, `GET /events/user/{user_id}`, `POST /events/aggregate`

**Verification:** `POST /verify`

**Erasure:** `POST /erasures`, `GET /erasures`, `GET /erasures/{id}`

**Retention:** `GET /retention`, `POST /retention`, `DELETE /retention/{id}`, `POST /retention/enforce`, `GET /retention/archives`

**Reports:** `GET /reports`, `POST /reports/soc2`, `POST /reports/hipaa`, `POST /reports/euaiact`, `POST /reports/custom`, `GET /reports/{id}`, `GET /reports/{id}/export/{format}`

**Stats:** `GET /stats`

## Forge Integration

Chronicle ships as a Forge extension with full lifecycle management:

```go
ext := extension.New(
    extension.WithBatchSize(100),
    extension.WithCryptoErasure(true),
    extension.WithRetentionInterval(24 * time.Hour),
)

ext.Init(ctx, store)  // runs migrations, wires components
ext.Start(ctx)        // starts background retention scheduler
defer ext.Stop(ctx)

// DI: other extensions receive the Emitter interface
emitter := ext.Emitter()
emitter.Info(ctx, "login", "session", "sess-1").Category("auth").Record()

// Mount admin API
mux.Handle("/", ext.Routes())
```

## Configuration

```go
c, _ := chronicle.New(
    chronicle.WithStore(adapter),             // required: backing store
    chronicle.WithLogger(logger),             // slog.Logger (default: slog.Default)
    chronicle.WithBatchSize(100),             // max events before flush
    chronicle.WithFlushInterval(time.Second), // max time between flushes
    chronicle.WithCryptoErasure(true),        // enable GDPR crypto-erasure
)
```

| Option | Default |
|--------|---------|
| BatchSize | 100 |
| FlushInterval | 1s |
| ShutdownTimeout | 30s |
| CryptoErasure | false |
| RetentionCheckInterval | 24h |

## Examples

See the [`_examples/`](./_examples/) directory:

| Example | Description |
|---------|-------------|
| [`basic`](./_examples/basic/) | Record, query, and verify events |
| [`plugins`](./_examples/plugins/) | Custom plugins with enrichment and sinks |
| [`compliance`](./_examples/compliance/) | SOC2 and HIPAA report generation |
| [`gdpr`](./_examples/gdpr/) | Crypto-erasure with key destruction |
| [`hash-chain`](./_examples/hash-chain/) | Hash chain structure and verification |
| [`forge`](./_examples/forge/) | Forge extension lifecycle |

```bash
go run ./_examples/basic/
```

## License

Part of the Forge ecosystem.
