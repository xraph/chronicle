// Package stream defines the hash chain stream entity and store interface.
//
// # What is a Stream?
//
// A Stream is the head pointer of an independent SHA-256 hash chain. Every
// app+tenant combination has exactly one stream. All audit events recorded
// within that scope are appended to the same chain in monotonically increasing
// sequence order.
//
// [Stream] fields:
//
//   - ID       — TypeID with "stream_" prefix, globally unique
//   - AppID    — the application this stream belongs to
//   - TenantID — the tenant within the application (empty for single-tenant apps)
//   - HeadHash — SHA-256 hash of the most recently appended event
//   - HeadSeq  — sequence number of the most recently appended event
//
// # Hash Chain Mechanics
//
// When an event is appended, Chronicle:
//
//  1. Reads HeadHash and HeadSeq from the stream.
//  2. Sets the event's PrevHash = HeadHash and Sequence = HeadSeq + 1.
//  3. Computes the event's Hash over: prevHash|timestamp|action|resource|
//     category|resourceID|outcome|severity|metadata_json (sorted keys).
//  4. Persists the event.
//  5. Updates the stream: HeadHash = event.Hash, HeadSeq = event.Sequence.
//
// For the very first event in a stream, PrevHash is an empty string.
// Any modification of a past event changes its hash, breaking every subsequent
// hash in the chain — making tampering cryptographically detectable.
//
// # Multi-Tenant Isolation
//
// Each app+tenant pair has its own independent chain. This means:
//
//   - Cross-tenant queries are structurally impossible (no shared sequence space).
//   - Compliance reports, verification, and retention are always scoped.
//   - The [Store.GetStreamByScope] method retrieves or creates the stream for a
//     given (appID, tenantID) pair.
//
// # Import Cycle Note
//
// The root chronicle package cannot import stream (that would create a cycle).
// Instead, chronicle defines its own [chronicle.StreamInfo] type mirroring the
// fields that the record pipeline needs (ID, AppID, TenantID, HeadHash, HeadSeq).
// [store.NewAdapter] translates between [Stream] and [chronicle.StreamInfo] so
// both sides remain decoupled.
//
// # Store
//
// [Store] manages stream lifecycle:
//
//   - [Store.CreateStream]      — initialise a new stream for an app+tenant scope
//   - [Store.GetStream]         — retrieve by stream ID
//   - [Store.GetStreamByScope]  — retrieve by (appID, tenantID)
//   - [Store.ListStreams]        — paginated listing of all streams
//   - [Store.UpdateStreamHead]  — atomically advance HeadHash and HeadSeq after append
package stream
