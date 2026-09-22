# Pluggable tamper evidence

Status: approved, not yet implemented
Date: 2026-09-22

Chronicle records every event into a SHA-256 hash chain. That chain is unkeyed,
so anyone who can write to the database can rewrite an event, recompute every
digest after it, update the stream head, and verification still reports a clean
chain. The algorithm ships in this repository. Recomputing a chain is about
twenty lines.

That is fine against accidental corruption and useless against an insider, which
matters because the question a SOC 2 auditor actually asks is not whether you
can
detect tampering but whether you can detect tampering by someone holding the
same
access your application already has.

This spec adds two independent controls that you turn on per deployment, plus
the migration and verification machinery that makes switching them on safe.

## Turning it on

```yaml
chronicle:
  tamper_evidence:
    digest: hmac                    # plain (default) | hmac
    keys:
      provider: file
      path: /etc/chronicle/hmac.json
    checkpoints:
      enabled: true
      every_events: 10000
      every_interval: 1h
      signer:
        provider: file
        path: /etc/chronicle/checkpoint-ed25519.pem
      fail_closed: false
      max_unanchored_events: 50000
      max_unanchored_age: 6h
      publishers:
        - type: s3
          bucket: acme-audit-anchors
          prefix: chronicle
        - type: file
          dir: /var/lib/chronicle/anchors
```

Programmatically:

```go
c, err := chronicle.New(
    chronicle.WithStore(adapter),
    chronicle.WithDigestScheme(hash.SchemeHMAC),
    chronicle.WithKeyProvider(kp),
    chronicle.WithCheckpointer(cpr),
)
```

Set `digest: hmac` without a key provider and `New` returns
`ErrHMACKeyUnavailable`. It will not start. That is the same posture as
`ErrCryptoErasureUnavailable` today, for the same reason: if you configured a
keyed chain and got an unkeyed one, you'd carry on believing a guarantee you
don't have.

## Two axes, not three

The three mechanisms do not sit at the same level.

HMAC changes how one event's digest is computed. A checkpoint is a signed
statement about a range of events. Anchoring is a place to put a checkpoint. You
cannot anchor without something to anchor, so anchoring is a destination
rather than a peer.

So there are two axes. Pick a digest mode, then decide whether you checkpoint
and where those checkpoints go. A deployment can run any combination, including
checkpoints over a plain chain, which is a reasonable choice and is covered
below.

### Axis one: the digest

`hash.Chain` stops being an empty struct and carries a scheme and a key
provider.

```go
type Scheme string

const (
    SchemeLegacy Scheme = "chronicle/v1" // what ComputeLegacy reproduces
    SchemePlain  Scheme = "chronicle/v2" // today's unkeyed SHA-256
    SchemeHMAC   Scheme = "chronicle/v3" // HMAC-SHA256 over identical content
)
```

`SchemeHMAC` hashes the same content string `Compute` builds today, through
`hmac.New(sha256.New, key)` instead of `sha256.Sum256`. The field coverage does
not change, so the reasoning already written into that
function still holds.

`Compute` returns a key ID now, because a digest is only reproducible if you
know which key generation made it:

```go
func (c *Chain) Compute(prevHash string, event *audit.Event) (digest, keyID string, err error)
```

That breaks the exported signature. `store/postgres/audit.go` calls it and
changes with it. Adding a parallel method would leave two ways to compute a
digest, which is worse.

### Axis two: checkpoints and anchors

New package, same shape as every other subsystem here. Its own entity, its own
`Store` interface, embedded into the `store.Store` composite.

```go
type Signer interface {
    Sign(ctx context.Context, payload []byte) (sig []byte, keyID, alg string, err error)
    Verify(ctx context.Context, payload, sig []byte, keyID string) error
}

type Publisher interface {
    Name() string
    Publish(ctx context.Context, cp *Checkpoint) (ref string, err error)
    Fetch(ctx context.Context, ref string) (*Checkpoint, error)
}
```

`Publisher` is the anchor. Shipped: `checkpoint/publisher/file` and
`checkpoint/publisher/s3`. The S3 one takes a narrow writer interface the way
`sink.S3Writer` already does, so no AWS SDK lands in `go.mod`. A transparency
log is a documented `Publisher` shape, not shipped code.

`Fetch` is not optional. Read why under "Anchors get fetched" below.

### Keys

Keys get their own package. Extending `crypto.KeyStore` would be the obvious
move and it is the wrong one, because the two lifecycles are opposites. Erasure
keys are per subject and exist to be
destroyed. HMAC and signing keys are per deployment and exist to be retained
and rotated. Conflate them and someone exercises their right to erasure and you
can no longer verify a five-year-old event.

```go
type Use string

const (
    UseHMAC          Use = "hmac"            // symmetric, for SchemeHMAC digests
    UseCheckpointSig Use = "checkpoint-sig"  // ed25519, for signing checkpoints
)

type Provider interface {
    Current(ctx context.Context, use Use) (key []byte, keyID string, err error)
    ByID(ctx context.Context, keyID string) (key []byte, err error)
}
```

One interface covers both uses, and the two YAML blocks (`keys:` and
`checkpoints.signer:`) each configure a provider for one of them. They are kept
separate in config because the material differs: one is a 32-byte symmetric key
and the other is an ed25519 keypair, and a deployment will usually want them in
different KMS keys or different files. `ByID` does not take a `Use`, so key IDs
have to be unique across both.

`Current` writes, `ByID` verifies old artifacts. That pair is what makes
rotation work, and it's what `crypto.KeyStore` lacks: it returns the subject ID
as the key ID, so a subject can never have two generations.

Ships with `keys.FileProvider`, reading a JSON keyset with an active key ID and
retained prior keys. Rotating is adding a key and moving the active pointer. A
KMS-backed provider is an adapter you write, and the interface is small enough
that it's short.

Dependency graph, no cycles:

```
keys  <--  hash  <--  chronicle
  ^                       ^
  +--  checkpoint  -------+
            ^
      publisher/{file,s3}
```

## Data model

Two columns on `chronicle_events`:

```sql
ALTER TABLE chronicle_events
    ADD COLUMN IF NOT EXISTS hash_scheme TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS hash_key_id TEXT NOT NULL DEFAULT '';
```

Non-volatile defaults, so Postgres 11+ treats this as metadata and skips the
table rewrite. That matters on the one table that reaches hundreds of millions
of rows.

Two on `chronicle_streams`:

```sql
ALTER TABLE chronicle_streams
    ADD COLUMN IF NOT EXISTS scheme       TEXT   NOT NULL DEFAULT 'chronicle/v2',
    ADD COLUMN IF NOT EXISTS scheme_since BIGINT NOT NULL DEFAULT 0;
```

### Why both

Neither column alone is enough, and the security comes from having both.

Per-event scheme alone is forgeable, since an attacker who rewrites
`hash_scheme`
to `chronicle/v2` and recomputes the unkeyed digest has done nothing the
verifier
will object to, and the verifier then obligingly checks that event under the
weaker scheme for them.

Per-stream pin alone is forgeable too. One row update downgrades the whole
stream.

Together they cross-check. The stream says everything from sequence 84,301
onward is HMAC. An event at 90,000 claiming `chronicle/v2` is not an old event,
it is a downgrade attempt, and the verifier reports it as tampering. Downgrading
then requires forging the keyed digest, which is the
thing the key is for.

### The window that can't be closed

Streams that already exist get `scheme_since = 0`, and everything below it keeps
today's try-v2-then-v1 resolution.

We cannot retroactively work out where the legacy scheme ended, because nothing
recorded it. So this freezes the ambiguity instead of closing it. The moment you
enable HMAC, `scheme_since` is set to `head_seq + 1` and resolution is strict
from there. The tolerant window stops growing, permanently, and verification
output states
its bounds.

Say that plainly in the docs, including the sequence number the window closes
at, so anyone reading a verification report knows which half of the stream it
applies to.

### Checkpoints

```sql
CREATE TABLE chronicle_checkpoints (
    id              TEXT PRIMARY KEY,
    stream_id       TEXT NOT NULL REFERENCES chronicle_streams(id),
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    from_seq        BIGINT NOT NULL,
    to_seq          BIGINT NOT NULL,
    from_hash       TEXT NOT NULL,
    to_hash         TEXT NOT NULL,
    event_count     BIGINT NOT NULL,
    prev_checkpoint TEXT NOT NULL DEFAULT '',
    algorithm       TEXT NOT NULL,
    sign_key_id     TEXT NOT NULL,
    signature       BYTEA NOT NULL,
    signed_payload  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(stream_id, to_seq)
);
```

`signed_payload` stores the exact bytes that were signed, and you should never
re-derive them from the columns at verification time. Signing systems break when
someone
adjusts canonicalisation and silently invalidates every historical signature,
and a few hundred bytes per checkpoint buys you out of that conversation
forever.

`prev_checkpoint` holds the SHA-256 of the preceding checkpoint's
`signed_payload`, not of its row or its signature, so the link survives a
re-signing under a rotated key. It chains checkpoints to each other. With the
continuity rule
that `from_seq` equals the previous `to_seq + 1`, deleting a checkpoint from the
middle becomes detectable locally. Deleting the newest one isn't, and that's
exactly the job anchoring does, so checkpoints cover gaps in the middle and
anchors cover truncation at the end.

### Anchors

```sql
CREATE TABLE chronicle_anchors (
    id            TEXT PRIMARY KEY,
    checkpoint_id TEXT NOT NULL REFERENCES chronicle_checkpoints(id),
    publisher     TEXT NOT NULL,
    ref           TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL,
    error         TEXT NOT NULL DEFAULT '',
    attempts      INT  NOT NULL DEFAULT 0,
    published_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(checkpoint_id, publisher)
);

CREATE INDEX ON chronicle_anchors (status) WHERE status <> 'published';
```

Own table, not a JSONB column, because an anchor has a lifecycle that a blob
handles badly: attempted, failed, retried, and eventually published. That
partial index is the queue
that drains when S3 comes back, and without it "we alerted and carried on"
leaves a permanent evidence gap.

One migration per backend, numbered 006. Postgres and SQLite both take plain
`ADD COLUMN`. Note that `store/sqlite/migrations.go` rebuilds
`chronicle_retention_policies` and carries a warning about its copy list. These
columns go on `chronicle_events` and `chronicle_streams`, which are never
rebuilt, so that trap doesn't apply.

## Verification

### Valid stops being the whole answer

Today `Valid` means the hashes link. That question has a graded answer now,
because assurance varies inside a single stream. A chain migrated last month is
unkeyed below `scheme_since` and keyed above it, anchored up to the last
published checkpoint and only signed above that. One boolean flattens all of it
into a green tick, and that flattening is what makes an auditor stop trusting
the tool.

The four levels are an ordered ladder, and a range reports the highest level it
satisfies. A stream running HMAC with signed and fetched anchors reports
`anchored`, not three separate levels. Each level implies the ones below it,
so `signed` on an unkeyed chain and `signed` on an HMAC chain are distinguished
by `Note` rather than by a separate level.

```go
type Level string // unkeyed < keyed < signed < anchored

type Coverage struct {
    FromSeq, ToSeq uint64
    Level          Level
    Note           string
}
```

`Report` gains `Coverage []Coverage`, `Checkpoints []CheckpointResult`,
`HeadMatch bool`, `HeadSeq uint64`, and `Downgrades []uint64`. `Valid` stays and
keeps its current meaning, so nothing you already call changes behaviour under
you.

### Verify the whole chain by default

`Input.FromSeq = 0` means genesis and `ToSeq = 0` means head. The verifier
asserts the last verified hash equals `chronicle_streams.head_hash`.
`handler/verify.go` currently requires `to_seq > 0`, and that inverts. Bounded
ranges still work, and come back with `Partial: true`.

This closes a real hole. Right now the first event in a range vouches for its
own `PrevHash` and nothing compares the tail to the stream head, so deleting the
newest 500 events passes verification on any range you ask about.

### What a checkpoint proves

For each checkpoint covering the range: verify the signature under its
`sign_key_id`, verify continuity against `prev_checkpoint` and `from_seq`, then
verify the event now sitting at `to_seq` still hashes to the recorded `to_hash`.

The third check is the one that does the work. A signed checkpoint says the
chain hash at sequence N was H, and the signature makes that statement
unforgeable without the signing key, so an event at N that hashes to something
else today is proof the chain was rewritten after the checkpoint was taken.

This works under the plain unkeyed scheme, which is why checkpointing on its own
is a coherent choice for a deployment that does not want HMAC on the write path.

### Anchors get fetched

If anchor status only lives in `chronicle_anchors`, then "anchored" is a claim
in the same database the attacker already owns, and deleting the row is trivial.
So `Publisher` carries `Fetch`, and verification with `verify_anchors: true`
pulls the checkpoint back from S3 or the log and compares it to the local row.

Only a fetched and matched anchor reports `Level: anchored`. A local row with no
fetch reports `signed`, with a note saying so. A `Publisher` without `Fetch`
would let you report a range as anchored on the strength of a row the attacker
could have written.

### API

- `POST /v1/verify` drops the `to_seq` requirement, gains `verify_anchors`, returns coverage
- `GET /v1/checkpoints` and `GET /v1/checkpoints/:id`, read guard
- `POST /v1/checkpoints` to force one, write guard, since it destroys nothing
- `GET /v1/anchors?status=failed`, read guard, the drain queue

### Compliance reports

`compliance.buildSection` never calls the verifier, so a SOC 2 report over a
tampered log renders clean. Each report gains a verification block covering the
reporting period: sequences verified, coverage levels, gaps.

Without it a report only summarises whatever the log currently says, which is
the thing under question when someone asks whether the log was edited.

Signing the report itself is a natural follow-on once `Signer` exists. It's out
of scope here on purpose.

## Failure behaviour

Event writes never block on checkpointing or anchoring by default. A publish
failure writes the anchor row as `failed` with the error and an attempt count,
fires through the existing `plugin.AlertHandler`, and retries with backoff on
later ticks. The affected range reports as `signed` rather than `anchored`, so
the gap shows up in the artifact an auditor reads instead of a log line nobody
opens.

### What fail_closed actually means

The naive reading is nonsense, because anchoring runs hourly while writes happen
thousands of times a second, so a literal "block writes until anchored" would
stall every event on an operation that has not run yet and is not due for
another
fifty minutes.

It's a lag bound:

```
if events_since_last_anchored_checkpoint > max_unanchored_events
   OR age_of_oldest_failed_anchor > max_unanchored_age:
       Record returns ErrUnanchoredLagExceeded
```

`Record` reads a cached counter, so the hot path pays an atomic load and not a
query. If you have a hard regulatory anchoring requirement you get real
enforcement. Everyone else leaves it off and takes the alert.

### Cadence, and what it costs

Per stream, whichever of `every_events` and `every_interval` comes first. The
interval matters more than it looks, because the window between checkpoints is
the attacker's free-rewrite window, and a quiet stream that never reaches 10,000
events would otherwise sit unprotected indefinitely.

The cost is one signature and one publish per stream per window. Ed25519 signs
in tens of microseconds so that part is free. Five thousand tenant streams on an
hourly interval is five thousand S3 PUTs an hour, which is not free. Raise
`every_interval` for low-traffic tenants.

A roll-up anchor covering many streams in one object fixes this properly, but it
needs a Merkle tree for per-stream inclusion proofs. Not building one until
somebody actually hits the volume. This paragraph exists so the escape hatch is
on record.

### Concurrency

The `Checkpointer` has the shape that already produced a bug here: a background
ticker plus an HTTP handler mutating shared state, which is how
`batcher.Flush` and `S3Sink.Flush` ended up duplicating every buffered event and
panicking on a slice bound.

So do not rely on lock discipline. `UNIQUE(stream_id, to_seq)` makes a duplicate
checkpoint impossible at the database, and the concurrent case fails cleanly on
insert.

The checkpointer takes its own per-stream lock rather than reusing
`Chronicle.lockStream`. Sharing that mutex would make checkpointing block event
writes, and that lock is already the per-tenant throughput ceiling.
Checkpointing reads the head at time T and signs that. Concurrent appends land
in the next window.

## Backends

`checkpoint.Store` gets implemented for memory, postgres, sqlite and mongo.

Redis does not get it. The README positions Redis as a read-through cache layer,
and a cache is the wrong home for a root of trust. It returns
`ErrCheckpointsUnsupported`.

The important half of that is what the extension does about it. If
`checkpoints.enabled` is true and the backend can't store them, the extension
refuses to start. Running silently without checkpoints is the exact failure this
feature exists to prevent.

`sealedstore` needs no new code, because it embeds `store.Store` and therefore
forwards an embedded `checkpoint.Store` automatically, and forwarding unchanged
happens to be correct here for exactly the reason its own doc comment already
gives about `EventRange`: checkpoint verification recomputes digests over the
stored bytes and has to see sealed fields, so decrypting on that path would make
every sealed event in a checkpointed range report as tampered.

Since nothing in `sealedstore` states that dependency, someone adding an
override later would break verification without seeing why, so it gets a
compile-time assertion and a test that pins the behaviour.

## Testing

The centrepiece is an adversarial suite that plays the attacker. Write N events,
rewrite one row, recompute the whole downstream chain the way someone with a SQL
shell would, and assert what each configuration catches.

| Configuration | Expected |
|---|---|
| plain, no checkpoints | verification passes |
| HMAC | fails, event reported tampered |
| plain plus checkpoints | fails at the checkpoint boundary |
| tail truncated | `HeadMatch: false` |
| anchor row deleted, `verify_anchors` | fetch mismatch detected |
| event downgraded above `scheme_since` | reported in `Downgrades` |

That first row is the one worth having most. A test asserting the unkeyed chain
fails to detect a rewrite is honest documentation of what the default gives you,
and it stops anyone reading "immutable audit trail" as a stronger claim than the
code makes. It's also what you hand an auditor who asks how you know the control
works.

Then: key rotation, where you write, rotate, write again, and verify both halves
resolve through `ByID`. Publisher round-trip, `Publish` then `Fetch`. A
concurrency test under `-race` proving two racing checkpointers produce exactly
one checkpoint.

Tests come first, per the normal workflow. The adversarial suite is written and
failing for the right reason before any of this is built.

### One piece of scope to watch

A shared conformance suite is genuinely needed, because "the chain verifies the
same on every backend" is a claim across four implementations and there is no
shared suite to make it. Only memory and sqlite have store tests at all today.

Scope it to a `storetest` package exercising the new checkpoint surface across
all four. Backfilling coverage of the existing store surface is separate work.
Otherwise this spec quietly turns into a testing project.

## Scope

Closes: the unkeyed chain, range verification that never anchors to genesis or
head, the unbounded legacy-scheme fallback, and rotation for the new keys
package. Adds the verification block to compliance reports.

Does not touch: the concurrent-flush bug in `batcher` and `sink/s3`, erasure
reporting success when the key was not destroyed, unscoped `Chronicle.ByUser`,
tenant scope failing open on a missing tenant ID, database-level immutability,
unaudited destructive operations, legal hold, or any of the performance work.

Several of those are smaller and more urgent than this. The erasure one
especially.
