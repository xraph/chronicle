package verify_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// TestTotalWipeIsCaughtByTheLatestCheckpoint is the case the range-bounded
// checkpoint checks structurally cannot reach.
//
// Delete every event, zero the stream's head, and there is no range left to
// ask about: verification resolves an empty range and used to return Valid
// true, Verified 0, Coverage [] while LatestCheckpoint in the same store
// still answered ToSeq 5. A clean bill of health with the disproving
// evidence one method call away.
func TestTotalWipeIsCaughtByTheLatestCheckpoint(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)
	cps, signer := checkpointOver(t, streamID, events)

	// Every event gone and the head row zeroed, which is what the attacker
	// leaves behind.
	v := verify.NewVerifierWithCheckpoints(fakeStore{}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{StreamID: streamID})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatalf("a wiped stream whose checkpoint still asserts five events reported Valid: %+v", report)
	}
	if !report.CheckpointHeadChecked {
		t.Fatalf("the latest checkpoint was never compared against the claimed head: %+v", report)
	}
	if report.CheckpointHeadOK {
		t.Errorf("CheckpointHeadOK is true while a checkpoint asserts ToSeq 5 against a claimed head "+
			"of 0: %+v", report)
	}
}

// TestBoundedSubRangeDoesNotTripTheHeadComparison pins the direction this
// check must never be wrong in. The comparison is against the head the
// caller claims, never against the resolved end of the range, so asking
// about sequences 1 to 5 of a fifteen-event stream is an ordinary bounded
// question and not a truncation.
func TestBoundedSubRangeDoesNotTripTheHeadComparison(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 15)
	cps, signer := checkpointsOverThree(t, streamID, events)

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events[:5]}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: 5, HeadSeq: 15, HeadHash: events[14].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("a bounded sub-range of an intact chain reported invalid: %+v", report)
	}
	if !report.CheckpointHeadChecked || !report.CheckpointHeadOK {
		t.Errorf("checked=%v ok=%v, want a clean comparison: the latest checkpoint ends at 15 and the "+
			"caller claims 15", report.CheckpointHeadChecked, report.CheckpointHeadOK)
	}
}

// TestABoundedRangeWithNoClaimedHeadDoesNotTripTheComparison is the
// _examples input shape: a StreamID, a FromSeq, a ToSeq, no scope and no
// head. All five VerifyChain calls across _examples/basic, _examples/gdpr,
// _examples/forge and _examples/hash-chain are written exactly this way, and
// Input.HeadSeq documents HeadSeq 0 as "the caller does not hold the stream
// row" rather than as a claim that the chain ends at zero.
//
// Comparing a checkpoint against that zero condemned every such call on any
// stream that had ever been checkpointed: latest.ToSeq <= 0 is false for all
// of them, so an intact chain came back Valid false, CheckpointHeadOK false.
// A false tamper verdict from an audit tool, which is the same harm the rest
// of this branch exists to remove.
func TestABoundedRangeWithNoClaimedHeadDoesNotTripTheComparison(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 15)
	cps, signer := checkpointsOverThree(t, streamID, events)

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events[2:7]}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{StreamID: streamID, FromSeq: 3, ToSeq: 7})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("an untouched, checkpointed chain verified as invalid through the call shape every "+
			"example uses: %+v", report)
	}
	if report.CheckpointHeadChecked {
		t.Errorf("the head comparison ran against a caller that claimed no head; there is nothing "+
			"there for a checkpoint to contradict: %+v", report)
	}
}

// TestNoCheckpointLeavesTheHeadComparisonUnchecked pins "no opinion". A
// stream nothing has checkpointed yet must verify exactly as it did before
// checkpoints existed, and the report has to say the comparison did not run
// rather than leaving a false CheckpointHeadOK to be read as a failure.
func TestNoCheckpointLeavesTheHeadComparisonUnchecked(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	v := verify.NewVerifierWithCheckpoints(
		fakeStore{events: events}, nil, &fakeCheckpointStore{}, newTestSigner(t))
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("an intact chain with no checkpoints reported invalid: %+v", report)
	}
	if report.CheckpointHeadChecked {
		t.Errorf("CheckpointHeadChecked is true with no checkpoint to compare against: %+v", report)
	}
	if !report.CheckpointsChecked {
		t.Errorf("CheckpointsChecked is false even though a checkpoint store was consulted and came "+
			"back empty; an auditor cannot tell those two apart without it: %+v", report)
	}
}

// TestUnsupportedCheckpointStoreIsNoOpinion covers the backend that
// implements the interface and refuses every call (store/redis). It must
// read as "nothing was checked here", not as a verification failure and not
// as "checked and clean".
func TestUnsupportedCheckpointStoreIsNoOpinion(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	v := verify.NewVerifierWithCheckpoints(
		fakeStore{events: events}, nil, unsupportedCheckpointStore{}, newTestSigner(t))
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("a store that cannot hold checkpoints made verification fail: %+v", report)
	}
	if report.CheckpointHeadChecked || report.CheckpointsChecked {
		t.Errorf("head_checked=%v checkpoints_checked=%v, want both false: this backend answers "+
			"nothing", report.CheckpointHeadChecked, report.CheckpointsChecked)
	}
}

// TestAForgedLatestCheckpointCannotCondemnAHealthyChain is why the head
// comparison verifies the signature before it trusts the number.
//
// A row inserted by whoever can write chronicle_checkpoints proves nothing
// about where the chain stood. If an unverifiable one could contradict the
// claimed head, that same attacker could fail every verification of a
// healthy log forever by inserting a single checkpoint claiming ToSeq
// 500. A forged checkpoint inside the verified range is still reported, as
// the signature failure it is.
func TestAForgedLatestCheckpointCannotCondemnAHealthyChain(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)
	cps, signer := checkpointOver(t, streamID, events)

	forged := *cps.list[0]
	forged.ID = id.NewCheckpointID()
	forged.FromSeq, forged.ToSeq = 100, 500
	cps.list = append(cps.list, &forged)

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.CheckpointHeadChecked {
		t.Errorf("a checkpoint whose payload does not match its own fields was treated as proof of "+
			"where the chain stood: %+v", report)
	}
	if !report.Valid {
		t.Fatalf("planting one unsigned checkpoint row made an untouched chain verify as tampered: "+
			"%+v", report)
	}
}

// unsupportedCheckpointStore is store/redis's posture: it satisfies the
// interface and refuses every call, because a read-through cache is the
// wrong home for a root of trust.
type unsupportedCheckpointStore struct{}

func (unsupportedCheckpointStore) AppendCheckpoint(context.Context, *checkpoint.Checkpoint) error {
	return checkpoint.ErrUnsupported
}

func (unsupportedCheckpointStore) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

func (unsupportedCheckpointStore) CheckpointsInRange(
	context.Context, id.ID, uint64, uint64,
) ([]*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

func (unsupportedCheckpointStore) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

func (unsupportedCheckpointStore) ListCheckpoints(
	context.Context, id.ID, checkpoint.ListOpts,
) ([]*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// Compile-time check.
var _ checkpoint.Store = unsupportedCheckpointStore{}
