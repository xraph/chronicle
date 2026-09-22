// Package verify provides hash chain verification for Chronicle audit streams.
//
// # What Verification Does
//
// Chronicle records events in a SHA-256 hash chain: every event's Hash field
// is computed over its own content plus the previous event's Hash. Verification
// re-derives each hash from scratch and compares it against the stored value,
// making two classes of tampering detectable:
//
//   - Gaps     — sequence numbers are missing, indicating events were deleted
//   - Tampered — a stored hash does not match the recomputed value, indicating
//     the event's content was modified after recording
//
// A chain that passes verification has Valid = true, Gaps = nil, and
// Tampered = nil.
//
// Erased events (GDPR crypto-erasure) do not break the chain: hashes are
// computed over event metadata (action, resource, timestamp, etc.), not the
// encrypted payload, so key destruction does not invalidate any hash.
//
// # Types
//
// [Input] defines the verification request:
//
//   - StreamID  — the stream to verify
//   - FromSeq   — first sequence number to check (0 = genesis)
//   - ToSeq     — last sequence number to check (0 = the stream head)
//   - AppID     — required for scope enforcement
//   - TenantID  — required for scope enforcement
//   - HeadSeq, HeadHash — the stream's recorded head, so a truncated tail is
//     detectable rather than silently verifying whatever range is asked for
//
// [Report] is returned by the verifier:
//
//   - Valid      — true if the full range has no gaps, no tampered hashes,
//     no downgrades, and (when checked) the tail matches the recorded head
//   - Verified   — count of events successfully checked
//   - Gaps       — sequence numbers that are absent from the store
//   - Tampered   — sequence numbers whose stored hash differs from recomputed
//   - FirstEvent — sequence of the first checked event
//   - LastEvent  — sequence of the last checked event
//   - Partial    — true when the caller bounded the range rather than
//     verifying genesis to head
//   - HeadMatch  — whether the verified tail's hash equals the recorded head
//   - Coverage   — the assurance [Level] over each span of the verified range
//
// # Store
//
// [Store] provides the data access needed for verification:
//
//   - [Store.EventRange] — fetch events between two sequence numbers
//   - [Store.Gaps]       — detect missing sequence numbers in a range
//
// The composite [store.Store] embeds this interface, so any Chronicle backend
// satisfies it automatically.
//
// # Usage
//
// Verification is typically triggered via the Admin HTTP API
// (POST /chronicle/verify) or directly through [chronicle.Chronicle.VerifyChain]:
//
//	report, err := c.VerifyChain(ctx, &verify.Input{
//	    StreamID:  streamID,
//	    AppID:     "myapp",
//	    TenantID:  "tenant-1",
//	})
//	if !report.Valid {
//	    log.Printf("chain broken: gaps=%v tampered=%v", report.Gaps, report.Tampered)
//	}
package verify
