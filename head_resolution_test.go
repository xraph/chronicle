package chronicle_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/verify"
)

// TestVerifyChainDoesNotAnchorAgainstAnotherScopesStream proves that
// VerifyChain's automatic head resolution only fires when the resolved
// stream -- looked up by the Input's AppID/TenantID -- is actually the
// stream being verified. Without that guard, a StreamID that does not
// belong to the supplied scope (a caller error, or what an Input reused
// across a loop of different streams looks like on its second iteration)
// would get anchored against an unrelated stream's head: an intact chain
// silently condemned as tampered because some other stream's head didn't
// match its tail.
//
// It also proves the caller's *Input is never mutated: whatever VerifyChain
// resolves internally must not leak back into the value the caller holds.
func TestVerifyChainDoesNotAnchorAgainstAnotherScopesStream(t *testing.T) {
	c := newTestChronicle(t)
	ctx := context.Background()

	var streamAID chronicle.ID
	for i := range 3 {
		event := &audit.Event{
			Action: "action", Resource: "resource", Category: "cat",
			AppID: "scope-a", TenantID: "tenant-a",
		}
		if err := c.Record(ctx, event); err != nil {
			t.Fatalf("Record scope-a event %d: %v", i, err)
		}
		if i == 0 {
			streamAID = event.StreamID
		}
	}

	// A second, unrelated stream with its own, different head.
	for i := range 5 {
		event := &audit.Event{
			Action: "action", Resource: "resource", Category: "cat",
			AppID: "scope-b", TenantID: "tenant-b",
		}
		if err := c.Record(ctx, event); err != nil {
			t.Fatalf("Record scope-b event %d: %v", i, err)
		}
	}

	// Ask for stream A's events but supply scope B's AppID/TenantID -- a
	// caller error, or what a reused Input looks like on its second stream.
	input := &verify.Input{
		StreamID: streamAID,
		AppID:    "scope-b",
		TenantID: "tenant-b",
		FromSeq:  1,
		ToSeq:    3,
	}
	report, err := c.VerifyChain(ctx, input)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("stream A's intact chain reported invalid when resolved against scope B: "+
			"gaps=%v tampered=%v head_match=%v head_seq=%d",
			report.Gaps, report.Tampered, report.HeadMatch, report.HeadSeq)
	}
	if report.HeadSeq != 0 {
		t.Errorf("HeadSeq = %d, want 0: scope B's head must not be attributed to stream A "+
			"just because scope B was supplied", report.HeadSeq)
	}
	if report.HeadChecked {
		t.Error("HeadChecked is true even though the resolved stream did not match the verified StreamID")
	}

	// The caller's Input must come back exactly as supplied.
	if input.HeadSeq != 0 || input.HeadHash != "" || input.Pin != (hash.Pin{}) {
		t.Errorf("caller's Input was mutated: HeadSeq=%d HeadHash=%q Pin=%+v",
			input.HeadSeq, input.HeadHash, input.Pin)
	}
}

// TestVerifyChainKeepsACallerSuppliedHeadHash proves the HeadSeq/HeadHash
// pair fills atomically: a caller who already supplied a HeadHash -- sourced
// out of band, from a checkpoint or an external notary -- must not have it
// silently replaced just because it left HeadSeq at its zero value.
func TestVerifyChainKeepsACallerSuppliedHeadHash(t *testing.T) {
	c := newTestChronicle(t)
	ctx := context.Background()

	var streamID chronicle.ID
	for i := range 3 {
		event := &audit.Event{
			Action: "action", Resource: "resource", Category: "cat",
			AppID: "scope-hh", TenantID: "tenant-hh",
		}
		if err := c.Record(ctx, event); err != nil {
			t.Fatalf("Record event %d: %v", i, err)
		}
		if i == 0 {
			streamID = event.StreamID
		}
	}

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID,
		AppID:    "scope-hh", TenantID: "tenant-hh",
		HeadHash: "external-notary-hash",
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.HeadSeq != 0 {
		t.Errorf("HeadSeq = %d, want 0: a caller-supplied HeadHash must not trigger the "+
			"store's HeadSeq filling in alongside it, which would silently replace the "+
			"caller's own HeadHash with the store's", report.HeadSeq)
	}
}

// TestVerifyChainResolvesTheStreamIDFromScope covers the call every doc page
// shows: scope in, nothing else. getting-started, the verification subsystem
// page, the full example and the GDPR erasure guide all write it exactly
// this way.
//
// It used to report a healthy stream as ruined. The fill resolved the stream
// and copied its head, its hash and its pin, but never its ID, so the range
// query ran against a nil stream and came back empty. The head that had just
// been filled in then made the report specific: Valid false, Verified 0, and
// every sequence in the stream named as a gap. Before head resolution
// existed it was obvious nonsense (Gaps:[0]); afterwards it was a confident
// accusation.
func TestVerifyChainResolvesTheStreamIDFromScope(t *testing.T) {
	c := newTestChronicle(t)
	ctx := context.Background()

	for i := range 5 {
		event := &audit.Event{
			Action: "action", Resource: "resource", Category: "cat",
			AppID: "scope-fill", TenantID: "tenant-fill",
		}
		if err := c.Record(ctx, event); err != nil {
			t.Fatalf("Record event %d: %v", i, err)
		}
	}

	report, err := c.VerifyChain(ctx, &verify.Input{
		AppID:    "scope-fill",
		TenantID: "tenant-fill",
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("a healthy five-event stream verified as invalid: gaps=%v tampered=%v verified=%d "+
			"head_match=%v", report.Gaps, report.Tampered, report.Verified, report.HeadMatch)
	}
	if report.Verified != 5 {
		t.Errorf("Verified = %d, want 5: the range query ran against the wrong stream", report.Verified)
	}
	if len(report.Gaps) != 0 {
		t.Errorf("Gaps = %v, want none: these events are all present", report.Gaps)
	}
	if !report.HeadChecked || !report.HeadMatch {
		t.Errorf("HeadChecked=%v HeadMatch=%v, want both true on an intact chain verified to its head",
			report.HeadChecked, report.HeadMatch)
	}
}

// TestVerifyChainResolvesTheStreamIDWithHeadAndPinSupplied is the same fill
// through the one door that stays shut if the resolve only triggers on a
// missing head or pin. A caller that supplies both and no StreamID has
// nothing to query events by either, so the resolve has to run for it too.
func TestVerifyChainResolvesTheStreamIDWithHeadAndPinSupplied(t *testing.T) {
	c := newTestChronicle(t)
	ctx := context.Background()

	var last *audit.Event
	for i := range 3 {
		event := &audit.Event{
			Action: "action", Resource: "resource", Category: "cat",
			AppID: "scope-both", TenantID: "tenant-both",
		}
		if err := c.Record(ctx, event); err != nil {
			t.Fatalf("Record event %d: %v", i, err)
		}
		last = event
	}

	report, err := c.VerifyChain(ctx, &verify.Input{
		AppID: "scope-both", TenantID: "tenant-both",
		HeadSeq: last.Sequence, HeadHash: last.Hash,
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid || report.Verified != 3 {
		t.Fatalf("report = %+v, want a valid three-event verification", report)
	}
}
