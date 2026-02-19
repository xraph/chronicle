// Package audit defines the core audit event types, query types, and the
// event store interface for Chronicle.
//
// # Event
//
// [Event] is the central type in Chronicle. It is an append-only record of
// something that happened in your system. Events are immutable once written —
// there is no Update or Delete path for individual events.
//
// Event fields are organised into seven groups:
//
//   - Identity: ID (TypeID with "audit_" prefix), Timestamp, Sequence (monotonically
//     increasing per stream)
//   - Hash chain: Hash (SHA-256 of this event), PrevHash (hash of predecessor),
//     StreamID (the chain this event belongs to)
//   - Scope: AppID (required), TenantID, UserID, IP — automatically applied
//     from the context by chronicle.Record
//   - Action: Action (verb, e.g. "login"), Resource (noun, e.g. "session"),
//     Category (logical group, e.g. "auth")
//   - Details: ResourceID, Metadata (arbitrary key-value pairs), Outcome,
//     Severity, Reason
//   - GDPR: SubjectID (data subject for crypto-erasure), EncryptionKeyID
//   - Erasure state: Erased, ErasedAt, ErasureID — set by the erasure engine,
//     never by the caller
//
// # Severity
//
// Three severity constants are defined:
//
//   - [SeverityInfo]     — routine operational events
//   - [SeverityWarning]  — anomalies that may need attention
//   - [SeverityCritical] — security events or failures requiring immediate review
//
// # Outcome
//
// Three outcome constants are defined:
//
//   - [OutcomeSuccess] — the action completed successfully
//   - [OutcomeFailure] — the action failed due to an error
//   - [OutcomeDenied]  — the action was rejected (authorisation / policy)
//
// # Queries
//
// [Query] accepts filters for time range, severity, outcome, category, user,
// resource, and pagination (Limit, Offset, Order). [QueryResult] carries the
// matching [Event] slice and a Total count.
//
// [AggregateQuery] groups events by a chosen field and returns counts via
// [AggregateResult]. [CountQuery] returns a scalar count without fetching events.
//
// [TimeRange] is a simple From/To pair used by [Store.ByUser].
//
// # Store
//
// [Store] is the event persistence interface. It is append-only by design:
//
//   - [Store.Append] — persist a single event
//   - [Store.AppendBatch] — persist multiple events atomically
//   - [Store.Get] — retrieve one event by ID
//   - [Store.Query] — filtered, paginated event listing
//   - [Store.Aggregate] — grouped counts for analytics
//   - [Store.ByUser] — events for a specific user within a time range
//   - [Store.Count] — scalar count without fetching events
//   - [Store.LastSequence] — highest sequence number in a stream (for hash chain init)
//   - [Store.LastHash] — hash of the most recent event in a stream
//
// All backends (Postgres, Bun, SQLite, Memory) implement this interface and are
// combined into the composite [store.Store] interface alongside the other
// sub-interfaces.
package audit
