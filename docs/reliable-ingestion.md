# Recoverable audit ingestion

Use `Chronicle.RecordOnce` when a durable publisher must retry an unknown
outcome. PostgreSQL atomically commits the event, stream creation, scheme pin,
head advancement, and acceptance receipt. The memory backend has the same
serialization rules for development, but loses everything on process exit.
SQLite, MongoDB, Redis, and custom stores without `acceptance.Store` return
`acceptance.ErrUnsupported`.

`Record` keeps its existing API. It does not provide idempotent acceptance.

```go
request := acceptance.Request{
    Producer:          "dispatch",
    Installation:      installationID,
    SourceKey:         deliveryID,
    SourceFingerprint: envelopeFingerprint,
    OrgID:             trustedOrgID,
    Event: &audit.Event{
        AppID:     trustedAppID,
        TenantID:  trustedTenantID,
        Timestamp: originalEventTime,
        Action:    "run.completed",
        Resource:  "run",
        Category:  "workflow",
    },
}
expected, err := acceptance.Fingerprint(request)
if err != nil {
    return err
}
receipt, err := engine.RecordOnce(ctx, request)
if err != nil {
    return err
}
if receipt.Fingerprint != expected {
    return errors.New("audit receipt does not match the request")
}
```

Your host must authenticate the producer and installation and authorize the
explicit app, organization, and tenant. This library does not derive that trust
from strings or overwrite them with context scope. The source identity is
`(Producer, Installation, SourceKey)`, encoded without delimiter ambiguity.
Scope is an immutable binding, not another uniqueness dimension. Reusing that
identity with changed scope, content, or source fingerprint returns a generic
conflict and no receipt. Two installations can reuse the same source key.

The source fingerprint describes your publisher's envelope. Chronicle computes
its own versioned semantic fingerprint over the source identity, source
fingerprint, organization, and normalized audit event. These are different
hashes. Before acknowledging an outbox delivery, compare the expected semantic
fingerprint and the returned producer, installation, source key, source
fingerprint, app, organization, and tenant. Check that event/stream identities,
sequence and chain hash are present. Enforce your required `HashScheme` and key
provenance separately. A receipt comparison is not a cryptographic signature.

## Stable content

You must supply the original nonzero timestamp on every attempt. Chronicle
normalizes it to UTC and preserves all nanoseconds; it never substitutes the
retry time or truncates to PostgreSQL's microsecond precision. The existing
`timestamp_sub_us` column restores the nanoseconds after a database read.
The semantic fingerprint and stored chain hash both use that same instant.

The v1 semantic encoding uses Go's sorted JSON object keys. Equivalent JSON
number spellings, such as `1`, `1.00`, and `1e0`, normalize to the same exact
fixed-point decimal. No float64 conversion occurs during acceptance. Already
rounded float64 input cannot recover lost digits: use `json.Number` when your
publisher decodes JSON. Duplicate keys in embedded raw JSON, nonfinite values,
invalid JSON, nesting beyond 64 levels, and out-of-range numeric exponents are
rejected. Metadata input is limited to 1 MiB, scope/source fields to 512 bytes,
decimal expansion to 4096 places, and expanded numbers to 1 MiB in total.
The normalized request is limited to 2 MiB. Missing and empty metadata are equivalent.

Supply valid UTF-8 without embedded NUL in every event text field and metadata
string or object key. Invalid text returns `acceptance.ErrInvalid` before any
receipt lookup, stream/event write, or sealing key access. A real replacement
character (U+FFFD) is valid. Raw JSON and `MarshalJSON` output must also contain
valid UTF-8 and paired Unicode surrogate escapes; an escaped NUL is rejected
because PostgreSQL jsonb cannot store it.

Metadata supports plain JSON values and custom `MarshalJSON` representations.
Each JSON marshaler runs once during normalization, and its output is validated
before decoding. Types that only implement `encoding.TextMarshaler`, and map
keys implementing that interface, are rejected. Supply plain strings or implement
`MarshalJSON` for values, and convert map keys to strings yourself. This reliable
API deliberately supports fewer input types than `encoding/json`; `Record`
keeps its existing encoding behavior. Custom JSON encoders own their output,
including any deliberate transformations of their private input data.

Chronicle copies nested metadata before acceptance. It neither allocates chain
fields on your event nor seals your caller-owned payload. Event ID, stream ID,
sequence, hash provenance, and the backend-assigned `ExactMetadata` marker are
excluded from the semantic fingerprint. Inputs already marked encrypted or
erased are rejected.

Reliable events set `ExactMetadata`, whose presence is covered by the v4/v5
chain digest through an additional framed encoding marker. Unmarked historical
events keep their original hash bytes. PostgreSQL records that choice in
`lossless_metadata`, and reads those rows using `json.Number`. Legacy rows
retain their historical float/int decoding so existing chain hashes still
verify. Crypto-erasure seals the normalized metadata, then the chain hashes the
stored ciphertext. Decryption uses exact numeric decoding for reliable events.
Archives preserve the event's marker and exact numeric representation.

## Retry, retention, and protection

Receipt lookup runs under the backend's uniqueness lock before stream setup,
hashing, sealing, or subject-key resolution. That includes a losing concurrent
first request. A retry returns the original receipt even after payload erasure,
purge, key-service failure, or a change to the current stream's scheme. It does
not restore personal content or recreate an erased key.

Acceptance tombstones have no expiry and no foreign key to the event. Payload
retention is independent. The migration refuses automatic rollback of the
receipt table. Removing tombstones safely requires a coordinated retirement
protocol for every producer that might retry. The receipt retains source
identities, scope, fingerprints, and chain coordinates; choose opaque source
keys because that evidence intentionally outlives payload deletion.

New PostgreSQL acceptance uses one transaction. A failed new attempt may have
called your external key service before the database rolls back. Key services
are not part of that SQL transaction. A replay or concurrent loser never makes
that call. If commit acknowledgement is lost, retry the identical request.

The root engine passes its configured hasher into the storage critical section.
There is no default-unkeyed replacement on the reliable path. `store.NewAdapter`
and `sealedstore.Store` forward acceptance explicitly; the sealed wrapper uses
its own sealer. `VerifyEvent` and `VerifyChain` on the configured engine verify
the stored representation, including after erasure. A new engine that requires
HMAC must still satisfy its normal startup key checks; receipt recovery with
unavailable keys is proven for an already initialized engine.

`HashScheme` and `HashKeyID` report the digest actually committed. An unkeyed
chain does not protect against a database writer who can rewrite it. A keyed
receipt does not establish a signed checkpoint or external anchor. The existing
checkpoint scheduler runs independently and can cover newly accepted events
later. Neither root `Record` nor `RecordOnce` currently dispatches per-event
plugin hooks, sinks, or counters. Receipt recovery creates no event or such
side effect.

## Deployment and rollback boundary

Apply migration `20261009000001` before starting reliable publishers. All writers
and readers sharing this stream must run a build containing this API, exact
metadata decoding, and monotonic stream-head updates. Use the published commit
pin recorded with your deployment, not only the migration version.

Tests cover mixed `Record` and `RecordOnce` writers on this version. They do not
qualify old binaries. An old writer can still rewind a head with its unchecked
update, and an old reader or decrypter can round a reliable event's numbers and
fail verification. Do not roll back to those binaries after enabling reliable
records. Retain tombstones and the metadata column during recovery.

The module pins toolchain Go 1.26.9. Your consuming executable must pin its own
patched compiler; a dependency's toolchain directive does not select the host's
compiler. Process kills, database promotion, backup restore, external anchoring,
and fleet rollout remain separate deployment qualification exercises.
