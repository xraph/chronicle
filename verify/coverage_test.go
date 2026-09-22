package verify_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// Truncating the newest events is invisible unless the tail is compared to the
// stream head. Before this, deleting the last 500 events passed on every range.
func TestVerifyChainDetectsTruncationAgainstTheHead(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5) // helper below

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID,
		HeadSeq:  10,                  // the stream says 10
		HeadHash: "hash-that-is-gone", // and this is its head
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.HeadMatch {
		t.Error("HeadMatch is true although the tail stops five events short of the head")
	}
	if report.Valid {
		t.Error("a truncated chain reported Valid")
	}
}

func TestVerifyChainMatchesAnIntactHead(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID,
		HeadSeq:  5,
		HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.HeadMatch {
		t.Error("HeadMatch is false on an intact chain")
	}
	if report.Partial {
		t.Error("a genesis-to-head verification should not be Partial")
	}
	if !report.HeadChecked {
		t.Error("HeadChecked is false even though a full-range head comparison ran")
	}
}

// An explicitly bounded range is legitimate, but it must say it did not cover
// the whole chain rather than implying it did.
func TestBoundedRangeReportsPartial(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 2, ToSeq: 4,
		HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Partial {
		t.Error("a bounded range did not report Partial")
	}
	if report.HeadMatch {
		t.Error("a range stopping short of the head must not claim HeadMatch")
	}
	if report.HeadChecked {
		t.Error("HeadChecked is true although Partial skipped the head comparison entirely")
	}
}

func TestCoverageReportsKeyedForAnHMACPin(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if len(report.Coverage) == 0 {
		t.Fatal("Coverage is empty")
	}
	if report.Coverage[0].Level != verify.LevelUnkeyed {
		t.Errorf("Level = %q, want %q for a plain pin", report.Coverage[0].Level, verify.LevelUnkeyed)
	}
}

func TestLevelsAreOrdered(t *testing.T) {
	ordered := []verify.Level{
		verify.LevelUnkeyed, verify.LevelKeyed, verify.LevelSigned, verify.LevelAnchored,
	}
	for i := 1; i < len(ordered); i++ {
		if verify.LevelRank(ordered[i]) <= verify.LevelRank(ordered[i-1]) {
			t.Errorf("%q does not rank above %q", ordered[i], ordered[i-1])
		}
	}
}

// TestEmptyResolvedRangeIsNotValid pins the fix for a hole the original
// early return left open: a resolved range that comes up empty against a
// stream that claims a real, non-zero head must fail, not vacuously pass.
// This is reachable two ways -- a FromSeq beyond every event the stream has
// ever held (as this test builds directly), or Chronicle.VerifyChain
// defaulting ToSeq to an unresolved HeadSeq of 0 -- and before this fix both
// reported {valid: true, verified: 0}, silently clean where the pre-Task-5
// code had (by accident, via a spurious Gaps(0,0) -> [0]) at least been
// loudly wrong.
func TestEmptyResolvedRangeIsNotValid(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()

	// The store has nothing in the requested range -- what from_seq=100
	// against a 5-event stream produces -- but the stream itself claims a
	// real, non-zero head.
	v := verify.NewVerifier(fakeStore{})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID,
		FromSeq:  100,
		HeadSeq:  5,
		HeadHash: "the-real-head-hash",
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Error("an empty resolved range against a stream that claims a head reported Valid")
	}
	if report.Verified != 0 {
		t.Errorf("Verified = %d, want 0 (nothing in the resolved range)", report.Verified)
	}
	if !report.HeadChecked {
		t.Error("HeadChecked is false even though the empty range was judged against a known head")
	}
}

// TestEmptyResolvedRangeOfATrulyEmptyStreamIsValid is
// TestEmptyResolvedRangeIsNotValid's counterpart: a stream that claims no
// head at all (HeadSeq == 0, which is indistinguishable in Input from "the
// caller never told me") must still verify vacuously true. A freshly created,
// genuinely empty stream is not evidence of tampering.
func TestEmptyResolvedRangeOfATrulyEmptyStreamIsValid(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()

	v := verify.NewVerifier(fakeStore{})
	report, err := v.VerifyChain(ctx, &verify.Input{StreamID: streamID})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Error("a stream with no claimed head reported invalid on an empty range")
	}
	if report.HeadChecked {
		t.Error("HeadChecked is true even though no head was ever claimed")
	}
}

// TestBoundedRangeWithoutHeadReportsPartial pins the fix for a range bounded
// only on its upper end -- ToSeq set explicitly, HeadSeq left unknown. The
// original Partial formula could not see this: fromSeq stayed 1 (not > 1),
// and the HeadSeq > 0 term never applied because HeadSeq was exactly the
// unknown value the formula needed in order to detect the bound. An explicit
// ToSeq is a bound regardless of whether this verifier can prove "here" was
// really the head.
func TestBoundedRangeWithoutHeadReportsPartial(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 10)

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, ToSeq: 7,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Partial {
		t.Error("an explicit ToSeq with no known head did not report Partial")
	}
}

// TestNoHeadSuppliedLeavesHeadCheckedFalse proves a caller that never
// supplies a head gets an honest signal that the tail was not compared,
// rather than a HeadMatch whose zero value is indistinguishable from
// "checked and mismatched."
func TestNoHeadSuppliedLeavesHeadCheckedFalse(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: 5,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.HeadChecked {
		t.Error("HeadChecked is true even though no head was supplied")
	}
	if !report.Valid {
		t.Error("a chain with no head to compare against should still verify its own linkage")
	}
}

// buildChain builds n audit events genuinely linked into a hash chain, computed
// with a zero-value (plain, unkeyed) hash.Chain over the previous hash, with
// PrevHash set accordingly. This is what makes VerifyChain's linkage
// assertions actually exercised rather than bypassed by a fake chain.
//
// fakeStore (used above) is declared in downgrade_test.go, in this same
// verify_test package; it is reused here rather than redeclared.
func buildChain(t *testing.T, streamID id.ID, n int) []*audit.Event {
	t.Helper()

	ctx := context.Background()
	var chain hash.Chain

	events := make([]*audit.Event, 0, n)
	prevHash := ""
	for i := 1; i <= n; i++ {
		event := &audit.Event{
			ID:        id.NewAuditID(),
			StreamID:  streamID,
			Sequence:  uint64(i),
			Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			AppID:     "app1",
			TenantID:  "tenant1",
			Action:    "login",
			Resource:  "session",
			Category:  "auth",
			Outcome:   audit.OutcomeSuccess,
			Severity:  audit.SeverityInfo,
			PrevHash:  prevHash,
		}

		digest, _, err := chain.Compute(ctx, prevHash, event)
		if err != nil {
			t.Fatalf("Compute event %d: %v", i, err)
		}
		event.Hash = digest
		event.HashScheme = string(chain.Scheme())

		events = append(events, event)
		prevHash = digest
	}
	return events
}
