<p align="center">
  <img src="assets/readme-banner.svg" alt="Chronicle, a tamper-evident audit logging library for Go with a SHA-256 hash chain, GDPR erasure and compliance reports" width="100%">
</p>

# Chronicle: tamper-evident audit logging for Go

Chronicle is an audit trail library for Go. Every event you record lands in a SHA-256 hash chain scoped to an app and tenant, and you can key that chain with HMAC, sign checkpoints over it, crypto-erase a data subject for GDPR, run retention policies and generate SOC 2, HIPAA and EU AI Act reports from it. It's built for multi-tenant SaaS backends, runs inside your own process against your own database, and plugs into [Forge](https://github.com/xraph/forge) as an extension when you want config, DI and an admin API wired for you.

[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/) [![CI](https://github.com/xraph/chronicle/actions/workflows/ci.yml/badge.svg)](https://github.com/xraph/chronicle/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/xraph/chronicle.svg)](https://pkg.go.dev/github.com/xraph/chronicle) [![GitHub Stars](https://img.shields.io/github/stars/xraph/chronicle?style=flat)](https://github.com/xraph/chronicle/stargazers)

[Documentation](https://www.xraph.com/docs/chronicle) · [Quick start](#quick-start) · [Features](#why-chronicle) · [Stores](#storage-backends) · [Tamper evidence](#tamper-evidence) · [GDPR erasure](#gdpr-crypto-erasure) · [Forge](#use-it-with-forge) · [FAQ](#faq)

## Quick start

You need [Go 1.26 or later](https://go.dev/dl/).

```bash
go get github.com/xraph/chronicle@latest
```

Save this as `main.go`. It records two events into an in-memory store and then verifies the chain:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

func main() {
	ctx := context.Background()
	ctx = scope.WithAppID(ctx, "billing")
	ctx = scope.WithTenantID(ctx, "acme")
	ctx = scope.WithUserID(ctx, "user-42")

	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(memory.New())))
	if err != nil {
		log.Fatal(err)
	}

	err = c.Info(ctx, "invoice.paid", "invoice", "inv-1001").
		Category("billing").
		Meta("amount_cents", 4999).
		Record()
	if err != nil {
		log.Fatal(err)
	}

	err = c.Critical(ctx, "role.granted", "role", "admin").
		Category("access").
		Reason("granted by support ticket 812").
		Record()
	if err != nil {
		log.Fatal(err)
	}

	report, err := c.VerifyChain(ctx, &verify.Input{AppID: "billing", TenantID: "acme"})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("valid=%v verified=%d tampered=%v\n", report.Valid, report.Verified, report.Tampered)
}
```

Run it:

```bash
go mod tidy
go run .
# valid=true verified=2 tampered=[]
```

You put the app, tenant and user on the context once, usually in middleware, and every event you record from that request picks them up. `Info`, `Warning` and `Critical` set the severity, and the builder takes `Category`, `Reason`, `Outcome`, `SubjectID`, `Meta` and the request fields (`IP`, `UserAgent`, `RequestID`, `SessionID`) before `Record` writes it. You read events back with `c.Query`, `c.Aggregate` or `c.ByUser`.

Swap `memory.New()` for a real backend from the [table below](#storage-backends) and you have a persistent audit log.

## Why Chronicle?

An audit log that anyone with database access can quietly edit is a log you can't show an auditor. Chronicle links each event to the one before it, so when you verify, a deleted or edited row shows up, and on top of that chain you get the pieces your compliance work keeps asking for.

| You need | Chronicle gives you |
| --- | --- |
| Evidence nobody edited the log | A per-stream SHA-256 hash chain, optional HMAC keying, and ed25519-signed checkpoints, checked by `VerifyChain` |
| Tenant isolation | Streams scoped to app and tenant from the context, with queries filtered the same way |
| GDPR right to erasure | Per-subject AES-256-GCM sealing. Destroy the key and the personal payload is gone while the chain still verifies |
| Retention | Per-category retention policies that archive to a sink and purge, recorded so verification can tell a purge from a deletion |
| Compliance reports | SOC 2 Type II, HIPAA, EU AI Act and custom reports, exported as JSON, CSV, Markdown or HTML |
| An admin API | Event, verification, checkpoint, erasure, retention, report and stats routes, guarded per operation class |
| Your existing database | PostgreSQL, SQLite, MongoDB and Redis through [Grove](https://github.com/xraph/grove), plus an in-memory store for tests |
| Readable IDs | TypeID identifiers such as `audit_01h2x...` |

## Storage backends

Every backend implements the composite `store.Store` interface. Wrap one with `store.NewAdapter` to pass it to `chronicle.New`.

| Backend | Package | Constructor | Notes |
| --- | --- | --- | --- |
| In-memory | `store/memory` | `memory.New()` | Tests and examples |
| SQLite | `store/sqlite` | `sqlite.New(db *grove.DB, opts...)` | Single node or embedded |
| PostgreSQL | `store/postgres` | `postgres.New(db *grove.DB, opts...)` | Production, through Grove's pgdriver |
| MongoDB | `store/mongo` | `mongo.New(db *grove.DB)` | Production, through Grove's mongodriver |
| Redis | `store/redis` | `redis.New(kvStore *kv.Store, opts...)` | Through Grove KV. Doesn't support checkpoints |

`store/sealedstore` wraps any of them so reads come back decrypted when crypto-erasure is on. The [stores docs](https://www.xraph.com/docs/chronicle/stores/postgres) cover schema and migration for each one.

## Tamper evidence

The default digest is plain SHA-256 (scheme `chronicle/v4`). It catches corruption and accidental edits. It will not stop someone who can write to your database, because the algorithm is public and recomputing every digest after a rewritten row takes a few lines of code. `TestPlainChainDoesNotDetectARewrite` in `tamper_test.go` pins that limit so you don't have to take it on trust.

If you key the chain, nobody can produce a digest from the stored row alone:

```go
c, err := chronicle.New(
	chronicle.WithStore(adapter),
	chronicle.WithDigestScheme(hash.SchemeHMACV5),
	chronicle.WithKeyProvider(kp), // for example keys.NewFileProvider("/etc/chronicle/keys.json")
)
```

Ask for HMAC without a key provider and `New` returns `ErrHMACKeyUnavailable`. That refusal at startup is deliberate: writing unkeyed digests while you believe they are keyed would be the worse failure.

Each event records the scheme that wrote it, and each stream records the scheme it is pinned to and from which sequence. If you turn HMAC on for a database that already holds events, the pin moves forward from the next sequence you record, and your older events keep verifying under the scheme they were written with. A pin only moves up. Point a plain-configured process at a stream already pinned to HMAC and it refuses to record. An older Chronicle process doesn't know `chronicle/v5`, so when you change schemes, stop every instance and then start them. During a rolling restart the old and new processes would drag the pin back and forth.

| Scheme | Digest | Status |
| --- | --- | --- |
| `chronicle/v1`, `chronicle/v2` | SHA-256 | Verify only |
| `chronicle/v3` | HMAC-SHA256 | Verify only |
| `chronicle/v4` | SHA-256, length-prefixed fields | Written by default |
| `chronicle/v5` | HMAC-SHA256, length-prefixed fields | Written when you choose HMAC |

v2 and v3 joined fields with a bare `|`, so content could slide across a separator without changing the hashed bytes. Chronicle will not write them any more, and `TestDelimiterJoinedContentCollides` in `hash/` keeps the collision on record.

Keying narrows who can rewrite your log. Someone who can write both the events table and the streams table can still downgrade a whole stream and its pin together. Signed checkpoints close most of that gap. Turn them on and Chronicle periodically signs where each stream's chain stood, chains each checkpoint to the one before, and on verification compares the latest checkpoint against the head you claim, which catches a truncated tail or a wiped stream. If an attacker deletes a checkpoint together with the events it covers, verification still passes, because all of the evidence lives in the same database you are protecting. Anchoring checkpoints somewhere outside that database is not built yet.

The [verification docs](https://www.xraph.com/docs/chronicle/subsystems/verification) walk through each check and the test that pins it.

## GDPR crypto-erasure

To use it, turn on crypto-erasure and give Chronicle a key store:

```go
keyStore := crypto.NewInMemoryKeyStore() // tests only: losing the key store erases everyone

c, err := chronicle.New(
	chronicle.WithStore(adapter),
	chronicle.WithCryptoErasure(true),
	chronicle.WithSealer(crypto.NewSealer(keyStore)),
)
```

For every event with a `SubjectID`, the `Metadata`, `Reason` and `IP` fields are encrypted under a key that belongs to that subject in one app and tenant. The same subject in two tenants gets two keys. The digest covers the encrypted bytes, so destroying a key changes nothing the verifier reads, and the chain keeps verifying.

To erase a subject, call the erasure service with the subject and the scope:

```go
svc := erasure.NewService(chronicleStore, keyStore)

result, err := svc.Erase(ctx, &erasure.Input{
	SubjectID:   "user-alice",
	Reason:      "GDPR Article 17 request",
	RequestedBy: "dpo@example.com",
}, "billing", "acme")
// result.KeyDestroyed, result.EventsAffected
```

After that, the sealed fields you read back say `[ERASED]`, metadata is dropped and the event reports `Erased: true`. `SubjectID`, `UserID`, the action, resource, category, outcome, severity and timestamps stay readable on purpose: they are the operational record, and reports group on them. An erasure destroys what was recorded about a person, not the fact that something involving them happened. The [GDPR erasure guide](https://www.xraph.com/docs/chronicle/guides/gdpr-erasure) has the rest.

## Compliance reports and retention

`compliance.NewEngine(auditStore, verifyStore, reportStore, logger)` builds reports with `SOC2`, `HIPAA`, `EUAIAct` and `Custom`, and `Export` writes one as `compliance.FormatJSON`, `FormatCSV`, `FormatMarkdown` or `FormatHTML`. Reports carry the chain verification result for their period.

Retention lives in `retention/`. A policy names a category, a duration and whether to archive. When it runs, the enforcer first writes a retention record into the chain, then archives the expired events through a `sink.Sink` if the policy asks for that (`sink.NewFileSink`, `sink.NewS3Sink` and `sink.NewStdoutSink` are built in), and then purges them. Verification reads those records, so a purged range shows up as retained and not as a gap.

## Use it with Forge

The `extension` package turns Chronicle into a [Forge extension](https://github.com/xraph/forge#extensions). It reads `extensions.chronicle` from your config (falling back to a top-level `chronicle` key), builds the store, mounts the admin API under `/chronicle`, runs the retention and checkpoint schedulers, and registers `chronicle.Emitter` in the container so other extensions can record events with `vessel.Inject[chronicle.Emitter]`.

```bash
go get github.com/xraph/chronicle@latest github.com/xraph/grove/extension@latest
```

```go
import (
	chronicle "github.com/xraph/chronicle/extension"
	grove "github.com/xraph/grove/extension"
)

app := forge.NewApp(forge.AppConfig{
	Name: "billing-api",
	Extensions: []forge.Extension{
		grove.New(),     // extensions.grove: driver and dsn
		chronicle.New(), // extensions.chronicle: auth, tamper evidence, checkpoints
	},
})
```

List Grove first. Chronicle looks up the container's `*grove.DB` during `Register` and picks the PostgreSQL, SQLite or MongoDB store to match its driver. You can also name a database with `grove_database`, point at a Grove KV store with `grove_kv` for Redis, or skip discovery and pass `chronicle.WithStore(memory.New())`.

The admin API can purge history, so the extension won't start until you decide who may call it. Configure an auth provider, allow unauthenticated access explicitly, or turn the routes off. Requests also need an app scope on the context (Forge's scope, or `scope.WithAppID` from your own middleware), or they get a 401.

## Configuration

```yaml
extensions:
  grove:
    driver: postgres
    dsn: postgres://app:secret@localhost:5432/app?sslmode=disable

  chronicle:
    base_path: /chronicle
    retention_interval: 24h        # 0 turns the retention scheduler off
    enable_crypto_erasure: false   # true also needs WithKeyStore
    auth:
      provider: jwt                # a forge auth provider; or allow_unauthenticated: true
      read_scopes: [chronicle:read]
      write_scopes: [chronicle:write]
      admin_scopes: [chronicle:admin]
    tamper_evidence:
      digest: hmac                 # plain (default) or hmac
      keys:
        provider: file
        path: /etc/chronicle/keys.json
    checkpoints:
      enabled: true
      every_events: 1000
      every_interval: 1h
      signer:
        provider: file
        path: /etc/chronicle/checkpoint-signer.json
```

Read scopes cover listing and verifying. Write scopes cover saving a retention policy and generating a report. Admin scopes cover the irreversible operations: enforcing retention, deleting a policy and requesting an erasure.

| Key | Option | Default |
| --- | --- | --- |
| `disable_routes` | `WithDisableRoutes()` | `false` |
| `disable_migrate` | `WithDisableMigrate()` | `false` |
| `base_path` | `WithBasePath(path)` | `/chronicle` |
| `retention_interval` | `WithRetentionInterval(d)` | `24h` |
| `enable_crypto_erasure` | `WithCryptoErasure(true)` plus `WithKeyStore(ks)` | `false` |
| `grove_database` | `WithGroveDatabase(name)` | default `*grove.DB` |
| `grove_kv` | `WithGroveKV(name)` | unset |
| `auth.*` | `WithAuth(provider, read, write, admin)` or `WithUnauthenticatedAPI()` | none, so startup fails while routes are on |
| `tamper_evidence.digest` | `WithDigestScheme("hmac")` plus `WithKeyProvider(p)` | `plain` |
| `checkpoints.*` | `WithCheckpoints(cfg)` | off |
| `dashboard.app_id`, `dashboard.tenant_id` | none | unset |

`WithStore`, `WithArchiveSink`, `WithConfig` and `WithRequireConfig` round out the options. `batch_size` and `flush_interval` still load, but `Record` writes each event synchronously, so they don't change how events are stored. The dashboard keys name the app a Forge dashboard session falls back to when its claims carry none; [MIGRATION.md](MIGRATION.md) covers the move from the old server-rendered dashboard pages.

## Documentation

| Topic | Where |
| --- | --- |
| Getting started | [Getting started](https://www.xraph.com/docs/chronicle/getting-started), [architecture](https://www.xraph.com/docs/chronicle/architecture) |
| Recording and scoping | [Recording](https://www.xraph.com/docs/chronicle/subsystems/recording), [multi-tenancy](https://www.xraph.com/docs/chronicle/concepts/multi-tenancy), [configuration](https://www.xraph.com/docs/chronicle/concepts/configuration) |
| Integrity | [Verification](https://www.xraph.com/docs/chronicle/subsystems/verification) |
| Compliance work | [Erasure](https://www.xraph.com/docs/chronicle/subsystems/erasure), [retention](https://www.xraph.com/docs/chronicle/subsystems/retention), [compliance reports](https://www.xraph.com/docs/chronicle/subsystems/compliance) |
| Storage | [PostgreSQL](https://www.xraph.com/docs/chronicle/stores/postgres), [SQLite](https://www.xraph.com/docs/chronicle/stores/sqlite), [MongoDB](https://www.xraph.com/docs/chronicle/stores/mongo), [Redis](https://www.xraph.com/docs/chronicle/stores/redis), [memory](https://www.xraph.com/docs/chronicle/stores/memory), [custom store](https://www.xraph.com/docs/chronicle/guides/custom-store) |
| Forge | [Forge extension guide](https://www.xraph.com/docs/chronicle/guides/forge-extension), [admin API](https://www.xraph.com/docs/chronicle/subsystems/admin-api), [HTTP API reference](https://www.xraph.com/docs/chronicle/api-reference/http-api) |

The Go API is on [pkg.go.dev](https://pkg.go.dev/github.com/xraph/chronicle).

## Examples

| Example | What it shows |
| --- | --- |
| [basic](_examples/basic/) | Recording, querying and verifying events |
| [hash-chain](_examples/hash-chain/) | How the chain links events, and what verification reports |
| [gdpr](_examples/gdpr/) | Crypto-erasure and key destruction |
| [compliance](_examples/compliance/) | SOC 2 and HIPAA reports |
| [plugins](_examples/plugins/) | The `plugin` hook registry and a custom sink |
| [forge](_examples/forge/) | Registering the extension against a Forge app |

Run one from the repository root with `GOWORK=off go run ./_examples/basic`.

## FAQ

### How do I make an audit log tamper-evident in Go?

Record events through Chronicle and verify with `VerifyChain`. For protection against someone with database write access, switch the digest to HMAC with a key the database never holds, and turn on signed checkpoints.

### Does Chronicle support GDPR right to erasure?

Yes, through crypto-erasure. Each subject's personal fields are encrypted under their own key, and erasing the subject destroys the key. The hash chain still verifies afterwards because the digest covers the ciphertext.

### Which databases can Chronicle store audit events in?

PostgreSQL, SQLite and MongoDB through Grove, Redis through Grove KV, and an in-memory store for tests. You can write your own by implementing `store.Store`.

### Can I use Chronicle without Forge?

Yes. The root package, the stores and the subsystems are plain Go. The `extension` package is only there if you run a Forge app.

### Does Chronicle write events in batches?

No. `Record` writes each event synchronously, because linking an event needs the previous event's hash. The `batcher` package exists for callers that drive batching themselves.

## Contributing

Issues and focused pull requests are welcome on [GitHub](https://github.com/xraph/chronicle/issues).

```bash
git clone https://github.com/xraph/chronicle.git
cd chronicle
GOWORK=off go test ./...
GOWORK=off go vet ./...
golangci-lint run ./...
```

The Postgres, MongoDB and Redis tests skip unless you set `CHRONICLE_TEST_POSTGRES_DSN`, `CHRONICLE_TEST_MONGO_URI` or `CHRONICLE_TEST_REDIS_DSN`, so a green run without them says nothing about those backends. Point them at throwaway containers on non-default ports. [AGENTS.md](AGENTS.md) has the container commands, the lint rules that bite and the release steps. Commits follow [Conventional Commits](https://www.conventionalcommits.org/).

## License

See the [Chronicle repository](https://github.com/xraph/chronicle) for license terms.

Chronicle is part of the [Forge](https://github.com/xraph/forge) forgery stack, built by [Rex Raphael](https://github.com/juicycleff) and [contributors](https://github.com/xraph/chronicle/graphs/contributors).
