# Chronicle

Chronicle is an audit trail library for Go. You record events and each one lands in a SHA-256 hash chain (HMAC-keyed if you give it a key), scoped to an app and tenant, with GDPR crypto-erasure, retention, signed checkpoints and compliance reports built on that chain. It ships as a plain library plus a Forge extension, so there's no daemon to run.

Module path: `github.com/xraph/chronicle`. There's one `go.mod`, at the root. `_examples/` is part of that module, but Go skips directories whose names start with an underscore, so `./...` never builds or tests anything in there.

## Commands

```sh
GOWORK=off go test ./...                  # memory and sqlite backends always run
GOWORK=off go test -race -count=1 ./...   # what release.yml runs
GOWORK=off go vet ./...
golangci-lint run ./...                   # v2, configured by .golangci.yml
gofmt -s -w . && goimports -w -local github.com/xraph/chronicle .
```

If you prefer make, the Makefile wraps these as `make test` (`go test -v ./...`), `make test-race`, `make vet`, `make lint`, `make lint-fix`, `make fmt`, `make check` (fmt, vet, lint) and `make coverage`. Skip `make build`, `make run`, `make install`, `make dev` and `make all`. They point at `./cmd/chronicle`, and there is no such directory.

CI lives in `.github/workflows/ci.yml`, which calls the shared `xraph/workflows` `go-ci.yml@v1`. That workflow runs `make test`, a race-enabled coverage pass, golangci-lint at whatever version it pins, `gofmt -l .`, `make vet`, gosec and govulncheck, plus a tidiness check that runs `go mod tidy` and fails if `go.mod` or `go.sum` changed. Gosec and govulncheck findings fail the build. `ci.yml` adds two jobs of its own: Format, which runs `goimports -l -local github.com/xraph/chronicle .`, and Docs, which runs `pnpm install --frozen-lockfile`, `pnpm types:check`, `pnpm lint` and `pnpm build` inside `docs/`.

## Tests that need a database

Postgres, MongoDB and Redis tests read a DSN from the environment:

| Variable | Read by |
|---|---|
| `CHRONICLE_TEST_POSTGRES_DSN` | `store/postgres`, `store`, `extension`, root package |
| `CHRONICLE_TEST_MONGO_URI` | `store/mongo`, root package |
| `CHRONICLE_TEST_MONGO_DSN` | `store/scope_behaviour_test.go` only |
| `CHRONICLE_TEST_REDIS_DSN` | `store/redis`, `store`, root package |

Leave a variable unset and those tests quietly call `t.Skip`. A plain `go test ./...` goes green with every live backend skipped, and you'll only notice if you run with `-v` and read the SKIP lines. CI sets none of these variables, so a green CI run tells you nothing about Postgres, Mongo or Redis. Set one and you've asked for that backend by name: from then on, every dial, ping or migrate failure is a `t.Fatalf`.

Most helpers refuse a default port. `internal/pgtest`, `store/postgres/live_test.go`, `store/mongo/live_test.go` and the root package's backend loop fail the test on a DSN containing `:5432`, `:27017` or (in that loop) `:6379`, and `internal/redistest` refuses any Redis database that holds a key outside the `chronicle:` prefix. A few helpers don't check at all, including `store/postgres/store_test.go` and both `purge_scope_test.go` files, so treat the guard as a backstop and never point these variables at a database you care about. Nothing in the repo starts testcontainers. You run throwaway containers yourself, on other ports:

```sh
docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=test postgres
docker run -d --rm -p 57017:27017 mongo
docker run -d --rm -p 56379:6379 redis
export CHRONICLE_TEST_POSTGRES_DSN='postgres://postgres:test@localhost:55432/postgres?sslmode=disable'
export CHRONICLE_TEST_MONGO_URI='mongodb://localhost:57017' CHRONICLE_TEST_MONGO_DSN='mongodb://localhost:57017'
export CHRONICLE_TEST_REDIS_DSN='redis://localhost:56379/0'
```

Postgres tests each get a random schema (`internal/pgtest`), the `store/mongo` tests a uniquely named database, and Redis tests their own key prefix (`internal/redistest`), so packages running in parallel stay out of each other's way. SQLite needs no setup. Its tests open a file under `t.TempDir()`, because grove pools connections and every pooled connection to `:memory:` would get its own empty database.

## Layout

| Path | What lives there |
|---|---|
| root (`package chronicle`) | `Chronicle`, `New` and its options, sentinel errors, `Storer`, `Emitter`, retention records and backfill |
| `audit/`, `stream/`, `verify/`, `erasure/`, `retention/`, `checkpoint/` | One subsystem each: its entities plus its own `Store` interface |
| `store/` | `store.Store`, the composite that embeds every subsystem store plus `Migrate`, `Ping`, `Close` |
| `store/memory`, `store/sqlite`, `store/postgres`, `store/mongo`, `store/redis` | The five backends. `store/sealedstore` decrypts sealed events on the way out |
| `hash/`, `keys/`, `crypto/` | Chain digests (plain and HMAC), key material for keyed digests and signed checkpoints, AES-256-GCM sealing for crypto-erasure |
| `acceptance/` | Recoverable ingestion contracts. `internal/acceptancetest` is the shared suite each backend runs |
| `compliance/` | SOC2, HIPAA, EU AI Act and custom reports, plus export |
| `sink/`, `plugin/`, `batcher/` | Event outputs (stdout, file, S3, archive), plugin hooks (`BeforeRecord`, `AfterRecord`, `SinkProvider` and the rest), batched writes |
| `scope/` | Pulls app, tenant, user, IP and request ID out of the context |
| `handler/` | The admin HTTP API on `forge.Router` |
| `extension/` | The Forge extension. `extension/contract` wires the dashboard contract (`manifest.yaml`) |
| `id/` | TypeID identifiers |
| `docs/` | Fumadocs site (Next.js, pnpm). `make docs` serves it |
| `plans/`, `specs/`, `docs/architecture/` | Design notes |

## Conventions

Errors are sentinels in `errors.go`, built with `errors.New` and prefixed `chronicle: `. You wrap with `fmt.Errorf("chronicle: what failed: %w", err)` and match with `errors.Is`. Subpackages keep their own (`acceptance.ErrConflict`, for one). A backend that misses a row returns the matching sentinel, never the driver error: `groveError` in `store/postgres/store.go` checks `grove.ErrNoRows` and `sql.ErrNoRows` with `errors.Is` and swaps in, say, `chronicle.ErrEventNotFound`. With `errorlint` and `errname` on, you can't compare errors with `==`, and every sentinel name starts with `Err`.

IDs come from `id/`. There's one `ID` struct over a TypeID (UUIDv7, `prefix_suffix`) and a `Prefix` constant per entity: `audit`, `stream`, `erasure`, `report`, `retpol`, `archive`, `plugin`, `ckpt`. Use `id.NewAuditID()`, `id.ParseAuditID(s)` and their siblings. If you add an entity type, give it a prefix and its own `New` and `Parse` pair.

A new store method goes into the subsystem's `Store` interface first, then into all five backends. Miss one and the compile-time assertions at the top of that backend's `store.go` (`_ audit.Store = (*Store)(nil)` and so on) break the build. Migrations are a grove `migrate.NewGroup("chronicle")` in the postgres, sqlite and mongo `migrations.go`, versioned by timestamp. `Migrate` re-runs every migration's DDL on each call, so whatever DDL you add has to be idempotent (`IF NOT EXISTS` and friends). Redis key format changes go in `store/redis/migrate.go`.

Options are functional. At the root it's `type Option func(*Chronicle) error`, which lets an option reject bad input and makes `New` return that error. The extension uses `func(*Extension)`. Backends use `func(*Store)` (`WithHasher`, `WithKeyPrefix`).

The Forge extension is `extension.New(opts...)`, embedding `*forge.BaseExtension`. `Register` loads config from `extensions.chronicle` (falling back to the legacy `chronicle` key), merges it with programmatic options, resolves `*grove.DB` from the container with `vessel.Inject` (or `vessel.InjectNamed` under `WithGroveDatabase`), picks the matching store, and publishes `chronicle.Emitter` with `vessel.Provide`. Herald and authsome pull it back out with `vessel.Inject[chronicle.Emitter]`, so if you change that interface you break both of them. `Start` launches the retention and checkpoint schedulers as goroutines, and `var _ forge.Extension = (*Extension)(nil)` guards the interface.

Logging uses `github.com/xraph/go-utils/log`. A component takes a `log.Logger` through `WithLogger` and falls back to `log.NewNoopLogger()`. Messages start with the package name (`"chronicle: checkpoint taken"`, `"retention: policy enforced"`) and carry typed fields like `log.String("stream_id", ...)`. Inside the extension, use `e.Logger()` with `forge.F`.

Tracing and metrics go through `internal/telemetry`. Start spans with `telemetry.Start` (tracer `github.com/xraph/chronicle`, kind internal), name them "verb object" with no IDs, and mark failures with `telemetry.Fail`, which records the error's class and never its message. Background runs in the extension start a root span with `trace.WithNewRoot()`, because Start's ctx carries forge's boot span. Metrics take a go-utils `metrics.Metrics` through a `WithMetrics` option (root, `retention`, `checkpoint`), registered up front in `internal/telemetry/metrics.go`, never `otel.Meter`. No span attribute or metric label may carry a user, subject, IP, payload, key or error text, and labels never carry IDs. `internal/telemetrytest` has the span recorder, a fake sink and `Leaks`, and `docs/content/docs/subsystems/observability.mdx` lists every span and metric, so update it when you add one.

Tests use the standard `testing` package with `t.Helper()` and `t.Fatalf`. Testify isn't in `go.mod`, and new tests shouldn't pull it in.

### Lint rules that bite

- `govet` runs with `enable-all` (minus `fieldalignment`), which turns on `shadow`, so an inner `err :=` that shadows an outer `err` fails. You can't dodge it with `if err = f(); err != nil` either, because the `diagnostic` gocritic tag brings in `sloppyReassign`. Give the inner error its own name (`rbErr`, `getErr`), the way the code already does.
- `errcheck` has `check-blank` and `check-type-assertions` on. Assign an error to `_` and it's flagged, unless the call is a `Close` or one of the `Rollback` methods listed under `exclude-functions`. Type assertions need the two-value form.
- `.golangci.yml` excludes gosec G104, G304 and G401, but CI's standalone gosec job excludes only G115. If you read a file from a variable path, you still need a `// #nosec G304` comment with the reason after it, like `keys/file.go` and `sink/file.go` have.
- `goimports` puts `github.com/xraph/chronicle/...` imports in their own group, last.
- `revive` checks receiver names, lowercase error strings and unused parameters (name them `_`). `nolintlint` reports a `//nolint` that suppresses nothing.
- `_test.go` files are exempt from gosec, errcheck and gocritic. `_examples/` is exempt from errcheck and gosec.

## Dependencies

Chronicle depends on grove (`grove`, `drivers/mongodriver`, `drivers/pgdriver`, `drivers/sqlitedriver`, `kv`, `kv/drivers/redisdriver`), forge and `forge/extensions/auth`, plus `go-utils` and `vessel`. Herald, dispatch, `trove/extension` and authsome consume it. Versions live in `go.mod`, nowhere else.

Grove and forge tag every submodule with the same version. When you bump one line from either, bump all of that repo's lines to the same tag:

```sh
GOWORK=off go get github.com/xraph/grove@vX.Y.Z github.com/xraph/grove/drivers/pgdriver@vX.Y.Z  # and every other grove line
GOWORK=off go get github.com/xraph/forge@vA.B.C github.com/xraph/forge/extensions/auth@vA.B.C
./updatemod.sh   # go mod tidy in every directory with a go.mod
GOWORK=off go test ./...
```

Keep `GOWORK=off` on your Go commands so a `go.work` somewhere above the checkout can't change what resolves. CI has none. Never commit a `go.work`, and never commit a `replace` pointing at a sibling checkout: it builds on your machine and breaks for everyone who runs `go get`. Run `./updatemod.sh` before you push, since CI fails on an untidy `go.mod` or `go.sum`.

## Releasing

You cut a release by dispatching the workflow. Never push a tag by hand.

```sh
gh run list --workflow ci.yml --branch main --limit 1   # wait for green
gh workflow run release.yml --ref main -f tag=vX.Y.Z
```

`release.yml` tags the dispatched commit and pushes the tag first, then runs `go mod download`, `go build ./...` and `go test -race -count=1 ./...`, and only then creates the GitHub release with notes from `git log` since the previous tag. If that build or test step fails, you're left with a pushed tag and no release, and the module proxy may already have recorded the tag, so fix forward with the next patch version.

Release chronicle only after the grove and forge versions it needs are tagged and pinned here. Once it's out, the consumers (herald, dispatch, `trove/extension`, authsome) re-pin to it.

Commits follow conventional style: `feat:`, `fix(store):`, `chore(deps):`, `test(extension):`.

## Branch rules

The `main` ruleset blocks deletion and force-push, nothing else. You can push to `main` directly. It has no required checks and no signed-commit rule.
