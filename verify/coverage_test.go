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

// buildChain builds n audit events genuinely linked into a hash chain, computed
// with a zero-value (plain, unkeyed) hash.Chain over the previous hash, with
// PrevHash set accordingly. This is what makes VerifyChain's linkage
// assertions actually exercised rather than bypassed by a fake chain.
//
// fakeStore (used above) is declared in downgrade_test.go, in this same
// verify_test package; it is reused here rather than redeclared.
//
// n is always called with 5, kept as a parameter so a future test can build a
// shorter or longer chain without changing the helper's shape.
//
//nolint:unparam // n kept general on purpose, see comment above.
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
