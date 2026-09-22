# Chronicle — Composable Immutable Audit Trail for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/xraph/chronicle.svg)](https://pkg.go.dev/github.com/xraph/chronicle)
[![Go Version](https://img.shields.io/badge/go-1.25+-blue)](https://go.dev)

Chronicle is a production-grade audit trail library that records every event into a SHA-256 hash chain. Key that chain with HMAC and it cannot be recomputed without material your database never holds. It is designed for multi-tenant SaaS applications that need SOC2, HIPAA, or GDPR compliance out of the box.

## Features

- **Hash chain integrity** — Every event is linked by SHA-256 hashes, optionally keyed with HMAC. Read [Tamper evidence](#tamper-evidence) for what each mode detects, and what neither one does.
- **GDPR crypto-erasure** — Per-subject AES-256-GCM encryption of the personal payload. Destroy the key and it is irrecoverable, while the operational record and the hash chain stay intact and verifiable.
- **Multi-tenant scoping** — Events are automatically scoped to app + tenant from context. Cross-tenant queries are impossible.
- **Compliance reports** — Generate SOC2 Type II, HIPAA, EU AI Act, and custom reports. Export to JSON, CSV, Markdown, or HTML.
- **Pluggable stores** — Postgres (pgx), Grove ORM, SQLite, Redis (cache layer), and in-memory (testing).
- **Pluggable sinks** — Fire-and-forget event outputs (stdout, file, S3, custom). Sinks never block the pipeline.
- **Plugin system** — BeforeRecord enrichment, AfterRecord notification, SinkProvider, AlertHandler, and more.
- **Retention policies** — Automatic archival and purge with configurable schedules.
- **Admin HTTP API** — 21 endpoints for events, verification, erasure, retention, compliance, and stats, guarded per operation class (read / write / admin).
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
    extension.WithCryptoErasure(false),  // see note below: not implemented yet
    extension.WithRetentionInterval(24 * time.Hour),

    // Required: the admin API can purge audit history.
    extension.WithAuth("jwt",
        []string{"chronicle:read"},   // observe events, reports, policies
        []string{"chronicle:write"},  // save policies, generate reports
        []string{"chronicle:admin"},  // enforce retention, delete policies, erase
    ),
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

### API authentication

The admin API exposes operations that permanently destroy audit data:
`POST /v1/retention/enforce` purges events, `DELETE /v1/retention/:id` disables
retention, and `POST /v1/erasures` cannot be undone. Chronicle's per-request
scope check keeps tenants out of each other's data, but it does not gate these
operations, so the extension refuses to start until you decide who may call them.

Pick one:

```yaml
chronicle:
  auth:
    provider: jwt                      # a registered forge auth provider
    read_scopes:  [chronicle:read]
    write_scopes: [chronicle:write]
    admin_scopes: [chronicle:admin]
```

```yaml
chronicle:
  auth:
    allow_unauthenticated: true        # something upstream already authenticates
```

```yaml
chronicle:
  disable_routes: true                 # do not mount the API at all
```

Routes are graded by blast radius. `read` observes; `write` creates records that
destroy nothing (saving a policy, generating a report); `admin` covers the
irreversible operations. A token that can read events cannot purge them.

Note that forge's `WithAuth` route options only annotate the OpenAPI spec — they
are not enforced at request time in forge v1.9.5. Chronicle enforces with the
auth registry's middleware and uses those options for documentation only.

### Dashboard

The Forge dashboard pages are read-only by default. Chronicle cannot authenticate
the dashboard route (Forge's dashboard extension owns it), so creating and
deleting retention policies, running enforcement, and generating reports are
disabled until you assert that the route is already protected:

```yaml
chronicle:
  dashboard_mutations: true
```

Dashboard reads are always tenant-scoped, and dashboard enforcement only runs the
viewing tenant's own policies.

## Configuration

```go
c, _ := chronicle.New(
    chronicle.WithStore(adapter),             // required: backing store
    chronicle.WithLogger(logger),             // slog.Logger (default: slog.Default)
    chronicle.WithBatchSize(100),             // max events before flush
    chronicle.WithFlushInterval(time.Second), // max time between flushes
    chronicle.WithCryptoErasure(false),       // see note below
)
```

### Tamper evidence

The default digest is an unkeyed SHA-256. It catches corruption and accidental
edits. It does not catch tampering by anyone who can write to your database,
because the algorithm ships in this repository, so rewriting an event and
recomputing every digest after it is about twenty lines of work.
`TestPlainChainDoesNotDetectARewrite` in `tamper_test.go` asserts that directly,
so the limit is pinned by a test rather than left to inference.

Keying the digest changes who can do that:

```yaml
chronicle:
  tamper_evidence:
    digest: hmac                    # plain (default) | hmac
    keys:
      provider: file
      path: /etc/chronicle/hmac.json
```

Or programmatically:

```go
c, _ := chronicle.New(
    chronicle.WithStore(adapter),
    chronicle.WithDigestScheme(hash.SchemeHMAC),
    chronicle.WithKeyProvider(kp),
)
```

Set `digest: hmac` without a key source and Chronicle refuses to start. You
configured a keyed chain, so writing unkeyed digests while you believed
otherwise is the worse failure. A keyset that parses but has no active `hmac`
key in it, because the `use` is misspelled or the only entry is `"active":
false`, is caught at startup as well. Otherwise the process boots green and then
fails on every event you record.

The keyset is a JSON file holding every key you have used, with one marked
active per use. Rotating means adding a key and moving the active flag. Retired
keys stay, because events written under them still have to verify, and
`Provider.ByID` is what resolves them.

Rotating is not enough when a key leaks. Whoever holds it can rewrite every
event, label each row with that key's ID, recompute, and get a clean report,
because the digests genuinely check out. Set `"revoked": true` on the entry and
`ByID` refuses to resolve it at all, so verification errors instead of passing.
Leave the material in the file when you do, so a row naming that key is reported
as revoked, not as an ID nobody recognises. It cuts both ways. Events you signed
honestly with that key stop verifying too, because nobody can tell them apart
from the forged ones. That stretch of the log no longer proves anything, and
saying so beats a green tick that does not mean what it looks like.

**What keying buys you.** An event's digest can no longer be produced from the
stored row alone. Each event records the scheme that wrote it and each stream
records the scheme it is pinned to from which sequence, so an event claiming a
weaker scheme than its stream promises is reported as tampering rather than
read as history.

Turn `hmac` on for a database that already holds events and the pin moves on its
own. The first time you record into a stream, Chronicle advances that stream to
the keyed scheme from the next sequence, and writes the pin before the event.
Everything below the new boundary keeps verifying under the scheme it was
written with. Chronicle only ever moves a pin up. Point a plain-configured
process at a stream already pinned to `hmac` and it refuses to record, because a
pin that drops on its own looks exactly like an attacker lowering it.

**What it does not buy you.** Someone who can write to your database can still
rewrite every event to the unkeyed scheme and rewrite the stream's pin to
match. Verification accepts that, because both halves of the evidence live in
the same database and whoever controls it controls both.
`TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints` pins that limit
too. Closing it needs a signature held somewhere Chronicle cannot reach.
Signed checkpoints, covered below, are the first half of that, and they exist
now. On their own they only get you so far: a local checkpoint still lives in
the same database as the events, so an attacker with that same write access
can delete it too. External anchoring is what reaches the rest, and that part
isn't built yet.

So read keying as narrowing who can carry the attack out, not ending it. It
defends against someone who can write `chronicle_events` but not
`chronicle_streams`, and who holds no key your provider has ever known. Both
halves have to hold. Reach the stream row too and the pin moves with the events,
which is the case above. Get hold of a key and every digest recomputes cleanly,
which is what revoking it is for.

#### Checkpoints

Turn checkpointing on and Chronicle periodically signs a statement about
where a stream's chain stood. That statement is what makes a later rewrite of
anything before it provable, even when the events and the stream's pin get
rewritten together.

```yaml
chronicle:
  checkpoints:
    enabled: true
    every_events: 1000       # checkpoint once a stream gains this many events
    every_interval: 1h       # or at least this often, whichever comes first
    signer:
      provider: file
      path: /etc/chronicle/checkpoint-signer.json
```

Leave `signer.provider` empty and Chronicle takes the signing key from
whatever `keys.Provider` you already passed to `WithKeyProvider` in code, as
long as it resolves `UseCheckpointSig`. Give it neither and checkpointing
refuses to start rather than silently signing nothing.

`every_interval` matters more than `every_events` looks like it should. The
gap between two checkpoints is exactly how long an attacker can rewrite
without a signature standing in the way, so a quiet stream that never hits
the event count still needs the interval to bound that window.

Sign a checkpoint over a range and rewriting any event inside it stops
passing verification, but only once the range you verify actually reaches
the checkpoint's `ToSeq`. The checkpoint already asserted, under a key
nobody but the signer holds, what the chain hashed to at that point, and
recomputing the row after it's been changed can't reproduce that hash.
Verify a narrower range that stops short of `ToSeq` and that comparison
never runs at all: `HashChecked` stays false, and a relinked rewrite inside
the part you skipped passes clean. `TestRewriteAfterACheckpointIsProvable`
pins the ordinary case, where the range does reach it.

Checkpoints chain to each other too, each one carrying the digest of the one
before it. Delete one from the middle of a run and the next checkpoint can no
longer show a clean line back to the one before the gap, which is how a
missing checkpoint gets caught. `TestDeletingAMiddleCheckpointIsDetected`
pins that.

The range checks don't reach past the head you claim, and the reason is more
specific than "a checkpoint can be deleted too." Verification asks the
checkpoint store for what falls inside the range you're checking, and the top
of that range comes from the head you claim. A checkpoint whose starting
sequence sits past that head gets excluded before its signature or its hash
is looked at, on every backend. Rewrite the stream's own head to hide a
truncated tail and every checkpoint covering the removed events drops out of
that comparison, whether its row survives or not.

One check runs outside the range, and it catches exactly that. Chronicle
reads the stream's latest checkpoint directly, confirms its signature still
verifies, and compares its `to_seq` against the head you claimed. A
checkpoint asserting the chain once reached sequence 15, against a claimed
head of 10, fails the verification: `checkpoint_head_ok` comes back false,
and `checkpoint_head_checked` tells you the comparison ran rather than
leaving you to guess. It runs before the range is resolved at all, so
deleting every event and zeroing the head doesn't get past it either.
`TestTruncationIsDetectedWhileTheCheckpointSurvives` pins the truncation and
`TestTotalWipeIsCaughtByTheLatestCheckpoint` pins the wipe.

Retention won't trip it. Purging works from the front of a stream and never
lowers the head, so a checkpoint ending past the head you claim means events
left the tail.

Deleting every checkpoint a stream has is milder. Nothing gets tampered
with, so `Valid` stays true. But no span of the coverage ladder can claim
`LevelSigned` anymore, because nothing survived to have signed it.
`TestDeletingEveryCheckpointDropsCoverageNotValidity` pins that too.

What still gets through is deleting the covering checkpoint along with the
events it covers. The newest surviving checkpoint then ends exactly where the
rewritten head says it should, the comparison agrees, and it's right to,
given what's left to compare against.

You don't have to delete the row to get that, either. Blanking or corrupting
its `signature` column does the same job for less work. The head comparison
only lets a checkpoint contradict you if its signature still verifies, so a
corrupted one drops straight out of it, and the row already sits past the
rewritten head, which keeps it out of the range checks too. Nothing reports a
signature failure, because nothing fetched the row to find one. `Valid` comes
back true either way.

Closing this needs a signature held somewhere write access to Chronicle's own
database can't reach. External anchoring, publishing a checkpoint or just its
hash somewhere an attacker with a SQL shell can't also edit, is what does it,
and it's the next piece of work.
`TestTruncationBeyondADeletedCheckpointIsNotDetected` pins the deletion half.

### Crypto-erasure

Enabling it requires a key store, because the key store's durability decides
whether sealed events can ever be read again:

```go
c, _ := chronicle.New(
    chronicle.WithStore(adapter),
    chronicle.WithCryptoErasure(true),
    chronicle.WithSealer(crypto.NewSealer(keyStore)),
)
```

Under the Forge extension, `extension.WithKeyStore(...)` supplies it and the
store is wrapped automatically so reads come back decrypted.

**What is encrypted:** `Metadata`, `Reason` and `IP`, keyed per subject, for any
event carrying a `SubjectID`.

**What is not, and why:** `SubjectID` stays readable because it is the lookup key
used to find a subject's events in order to erase them and to prove afterwards
that they were erased. `UserID` stays readable because it identifies the *actor*
rather than the data subject, and `ByUser` depends on it. `Action`, `Resource`,
`Category`, `Outcome`, `Severity`, `ResourceID` and the timestamps stay readable
because they are the operational record that must outlive an erasure, and queries
and compliance reports group on them.

So an erasure destroys what was recorded *about* a subject, not the fact that an
event involving them occurred. Read the guarantee as exactly that.

**Why the chain survives:** the digest is computed over the encrypted bytes, not
the plaintext. Destroying a key therefore changes nothing the verifier reads. Had
the hash covered plaintext, every erased event would have reported as tampered.
The corollary is that verification paths (`EventRange`, `VerifyEvent`) read the
stored form while display paths (`Get`, `Query`, `ByUser`) return decrypted
copies. Retention archives the sealed bytes, so cold storage never holds
plaintext an erasure was meant to destroy.

Once a key is gone, sealed fields read back as `[ERASED]`, metadata is dropped,
and the event reports `Erased: true`.

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
