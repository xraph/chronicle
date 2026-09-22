package verify_test

import (
	"context"
	"crypto/ed25519"
	"sort"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// The whole point: a signed checkpoint says the chain hash at N was H. If the
// event now at N hashes to something else, the rewrite happened after the
// checkpoint and the signature proves it.
func TestRewriteAfterACheckpointIsDetected(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	cps, signer := checkpointOver(t, streamID, events) // helper below

	// The attacker rewrites the chain and relinks it perfectly.
	rewritten := buildChainWithActor(t, streamID, 5, "attacker-was-not-here")

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: rewritten}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: rewritten[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatal("a rewrite of checkpointed events reported Valid")
	}
	if len(report.Checkpoints) != 1 || report.Checkpoints[0].HashMatch {
		t.Error("the covering checkpoint did not report a ToHash mismatch")
	}
}

func TestIntactCheckpointedChainReportsSigned(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)
	cps, signer := checkpointOver(t, streamID, events)

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("an intact checkpointed chain reported invalid: %+v", report)
	}
	if len(report.Coverage) == 0 || report.Coverage[len(report.Coverage)-1].Level != verify.LevelSigned {
		t.Errorf("coverage = %+v, want the checkpointed span at %q", report.Coverage, verify.LevelSigned)
	}
	if !report.Checkpoints[0].SignatureValid || !report.Checkpoints[0].HashMatch {
		t.Error("an untampered checkpoint did not verify")
	}
}

func TestForgedCheckpointSignatureIsRejected(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)
	cps, signer := checkpointOver(t, streamID, events)

	// The attacker rewrites what the checkpoint asserts but cannot re-sign it.
	cps.list[0].ToHash = "forged"
	cps.list[0].SignedPayload = checkpoint.CanonicalPayload(cps.list[0])

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatal("a checkpoint whose payload was edited after signing reported Valid")
	}
	if report.Checkpoints[0].SignatureValid {
		t.Error("SignatureValid is true for an edited payload")
	}
}

// Continuity: deleting a checkpoint from the middle leaves a hole the next
// one's PrevCheckpoint no longer matches.
func TestDeletedMiddleCheckpointBreaksContinuity(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 15)
	cps, signer := checkpointsOverThree(t, streamID, events) // 1-5, 6-10, 11-15

	// Delete the middle one.
	cps.list = []*checkpoint.Checkpoint{cps.list[0], cps.list[2]}

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 15, HeadHash: events[14].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatal("a stream missing a middle checkpoint reported Valid")
	}
	var sawBreak bool
	for _, r := range report.Checkpoints {
		if !r.ContinuityOK {
			sawBreak = true
		}
	}
	if !sawBreak {
		t.Error("no checkpoint reported a continuity break")
	}
}

// TestUntrackedFieldEditIsCaughtBySignedPayloadComparison proves the
// recompute-vs-stored comparison in verifyCheckpoints is load-bearing on its
// own, not merely redundant with signer.Verify. TestForgedCheckpointSignatureIsRejected
// regenerates SignedPayload after mutating the row, so that test's mismatch
// is always caught downstream by the signature check, whichever branch runs
// first. Here the attacker edits EventCount -- a field CanonicalPayload
// covers but that neither HashMatch nor ContinuityOK ever look at -- and
// leaves SignedPayload and Signature untouched. The signature still verifies
// against the (untouched, genuinely signed) stored payload, so only the
// comparison between that stored payload and what the row's current fields
// recompute to can catch the edit.
func TestUntrackedFieldEditIsCaughtBySignedPayloadComparison(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)
	cps, signer := checkpointOver(t, streamID, events)

	// SignedPayload and Signature are left exactly as signed; only the row's
	// own EventCount now lies about what CanonicalPayload would render.
	cps.list[0].EventCount = 99

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatal("a checkpoint whose EventCount was edited without updating SignedPayload reported Valid")
	}
	if report.Checkpoints[0].SignatureValid {
		t.Error("SignatureValid is true although the stored payload no longer matches the row's own fields")
	}
}

// TestBoundedSubRangeInsideAValidCheckpointDoesNotReportTampering guards
// against a false positive on a healthy chain: CheckpointsInRange overlaps
// rather than contains, so verifying a narrow sub-range can surface a
// checkpoint whose own ToSeq sits outside the fetched events, and whose
// immediate predecessor was never fetched either (there was no reason to,
// nothing in [fromSeq,toSeq] needed it). Neither of those is evidence the
// chain was rewritten; they are just outside what this particular
// verification call looked at.
//
// This is the review's Finding 2, reproduced with the exact shape it
// described: a healthy 15-event, 3-checkpoint (1-5, 6-10, 11-15) stream,
// asked only about sequence 12. Because fakeStore ignores its from/to
// arguments and always returns whatever events slice it was built with (a
// known, pre-existing simplification -- see coverage_test.go's buildChain
// doc), this test constructs fakeStore with only event 12 in it, which is
// exactly what a real store's EventRange(streamID, 12, 12) would return.
func TestBoundedSubRangeInsideAValidCheckpointDoesNotReportTampering(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 15)
	cps, signer := checkpointsOverThree(t, streamID, events) // 1-5, 6-10, 11-15

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: []*audit.Event{events[11]}}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 12, ToSeq: 12, HeadSeq: 15,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("a bounded sub-range inside a healthy checkpointed chain reported invalid: %+v", report)
	}
	if len(report.Checkpoints) != 1 {
		t.Fatalf("got %d checkpoint results, want the one (11-15) overlapping seq 12", len(report.Checkpoints))
	}
	if report.Checkpoints[0].HashChecked {
		t.Error("HashChecked is true although to_seq (15) was never fetched for this sub-range verification")
	}
	if report.Checkpoints[0].ContinuityChecked {
		t.Error("ContinuityChecked is true although this checkpoint's predecessor was never fetched")
	}
}

// TestCheckpointDoesNotUpgradeCoverageBelowTheSchemesPin is the review's
// Finding 3 test. Events 1-3 predate the stream's HMAC pin at seq 4 and are
// plain, unkeyed digests; events 4-5 are genuinely HMAC-keyed. A single
// checkpoint signs over the whole range. Coverage for 1-3 must stay at
// unkeyed even though the checkpoint's signature is genuine and its ToHash
// matches: the checkpoint only proves nothing changed after it was taken, not
// that the unkeyed digests underneath were ever tamper-evident to begin with.
// Only 4-5, which rest on a real key the store does not hold, may be raised
// to signed.
func TestCheckpointDoesNotUpgradeCoverageBelowTheSchemesPin(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()

	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"}
	hmacChain, err := hash.NewChain(hash.SchemeHMAC, provider)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	var plainChain hash.Chain

	events := make([]*audit.Event, 0, 5)
	prevHash := ""
	for i := 1; i <= 5; i++ {
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

		var (
			digest, keyID string
			scheme        hash.Scheme
		)
		if i < 4 {
			digest, keyID, err = plainChain.Compute(ctx, prevHash, event)
			scheme = plainChain.Scheme()
		} else {
			digest, keyID, err = hmacChain.Compute(ctx, prevHash, event)
			scheme = hmacChain.Scheme()
		}
		if err != nil {
			t.Fatalf("Compute event %d: %v", i, err)
		}
		event.Hash = digest
		event.HashScheme = string(scheme)
		event.HashKeyID = keyID

		events = append(events, event)
		prevHash = digest
	}

	cps, signer := checkpointOver(t, streamID, events)

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events}, hmacChain, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
		Pin: hash.Pin{Scheme: hash.SchemeHMAC, Since: 4},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("report unexpectedly invalid: %+v", report)
	}
	if len(report.Coverage) != 2 {
		t.Fatalf("coverage = %+v, want two spans (below and at/above the pin)", report.Coverage)
	}
	below, above := report.Coverage[0], report.Coverage[1]
	if below.FromSeq != 1 || below.ToSeq != 3 || below.Level != verify.LevelUnkeyed {
		t.Errorf("below-pin span = %+v, want 1-3 at %q", below, verify.LevelUnkeyed)
	}
	if above.FromSeq != 4 || above.ToSeq != 5 || above.Level != verify.LevelSigned {
		t.Errorf("at/above-pin span = %+v, want 4-5 at %q", above, verify.LevelSigned)
	}
}

// buildChainWithActor is buildChain with an attacker-controlled UserID on
// every event, so it produces a chain that relinks perfectly (each event's
// PrevHash genuinely matches the previous event's Hash) but hashes
// differently at every sequence than the original chain, because UserID is
// part of what Chain.Compute covers. That is what "the attacker rewrites the
// chain and relinks it perfectly" means in practice: a self-consistent chain
// with different content.
func buildChainWithActor(t *testing.T, streamID id.ID, n int, actor string) []*audit.Event {
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
			UserID:    actor,
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

// fakeCheckpointStore is a minimal, mutable checkpoint.Store backed by a
// slice the test can edit directly (cps.list[0].ToHash = "forged", deleting
// an entry, and so on), which is the point: these tests simulate an attacker
// with write access to the checkpoint table, not just the event table.
type fakeCheckpointStore struct {
	list []*checkpoint.Checkpoint
}

func (f *fakeCheckpointStore) AppendCheckpoint(_ context.Context, cp *checkpoint.Checkpoint) error {
	f.list = append(f.list, cp)
	return nil
}

func (f *fakeCheckpointStore) LatestCheckpoint(_ context.Context, streamID id.ID) (*checkpoint.Checkpoint, error) {
	var latest *checkpoint.Checkpoint
	for _, cp := range f.list {
		if cp.StreamID.String() != streamID.String() {
			continue
		}
		if latest == nil || cp.ToSeq > latest.ToSeq {
			latest = cp
		}
	}
	if latest == nil {
		return nil, checkpoint.ErrNotFound
	}
	return latest, nil
}

// CheckpointsInRange returns every checkpoint whose range overlaps
// [fromSeq, toSeq], ascending by ToSeq, mirroring the real stores' contract.
func (f *fakeCheckpointStore) CheckpointsInRange(
	_ context.Context, streamID id.ID, fromSeq, toSeq uint64,
) ([]*checkpoint.Checkpoint, error) {
	var result []*checkpoint.Checkpoint
	for _, cp := range f.list {
		if cp.StreamID.String() != streamID.String() {
			continue
		}
		if cp.FromSeq > toSeq || cp.ToSeq < fromSeq {
			continue
		}
		result = append(result, cp)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ToSeq < result[j].ToSeq })
	return result, nil
}

func (f *fakeCheckpointStore) GetCheckpoint(_ context.Context, checkpointID id.ID) (*checkpoint.Checkpoint, error) {
	for _, cp := range f.list {
		if cp.ID.String() == checkpointID.String() {
			return cp, nil
		}
	}
	return nil, checkpoint.ErrNotFound
}

func (f *fakeCheckpointStore) ListCheckpoints(
	_ context.Context, streamID id.ID, _ checkpoint.ListOpts,
) ([]*checkpoint.Checkpoint, error) {
	var result []*checkpoint.Checkpoint
	for _, cp := range f.list {
		if cp.StreamID.String() == streamID.String() {
			result = append(result, cp)
		}
	}
	return result, nil
}

// signCheckpoint renders and signs cp's canonical payload, the way
// Checkpointer.CheckpointStream does: render, sign, then store the exact
// bytes that were signed.
func signCheckpoint(t *testing.T, signer checkpoint.Signer, cp *checkpoint.Checkpoint) {
	t.Helper()
	cp.SignedPayload = checkpoint.CanonicalPayload(cp)
	sig, keyID, alg, err := signer.Sign(context.Background(), []byte(cp.SignedPayload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cp.Signature, cp.SignKeyID, cp.Algorithm = sig, keyID, alg
}

// newTestSigner builds an ed25519 signer over a fresh key, backed by the
// stubProvider declared in downgrade_test.go (same package).
func newTestSigner(t *testing.T) checkpoint.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return checkpoint.NewEd25519Signer(stubProvider{key: priv, activeID: "cp-1"})
}

// checkpointOver signs a single checkpoint covering the whole of events
// (sequence 1 through len(events)), the way a stream's first checkpoint
// would look.
func checkpointOver(
	t *testing.T, streamID id.ID, events []*audit.Event,
) (*fakeCheckpointStore, checkpoint.Signer) {
	t.Helper()

	signer := newTestSigner(t)
	cp := &checkpoint.Checkpoint{
		ID:         id.NewCheckpointID(),
		StreamID:   streamID,
		AppID:      "app1",
		TenantID:   "tenant1",
		FromSeq:    1,
		ToSeq:      uint64(len(events)),
		FromHash:   "",
		ToHash:     events[len(events)-1].Hash,
		EventCount: int64(len(events)),
		CreatedAt:  time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
	}
	signCheckpoint(t, signer, cp)

	return &fakeCheckpointStore{list: []*checkpoint.Checkpoint{cp}}, signer
}

// checkpointsOverThree signs three checkpoints over a 15-event chain,
// covering 1-5, 6-10 and 11-15, properly chained (each PrevCheckpoint is the
// digest of the one before it), all under the same signing key.
func checkpointsOverThree(
	t *testing.T, streamID id.ID, events []*audit.Event,
) (*fakeCheckpointStore, checkpoint.Signer) {
	t.Helper()

	signer := newTestSigner(t)

	bounds := [][2]uint64{{1, 5}, {6, 10}, {11, 15}}
	list := make([]*checkpoint.Checkpoint, 0, len(bounds))
	var prev *checkpoint.Checkpoint
	for i, b := range bounds {
		from, to := b[0], b[1]
		cp := &checkpoint.Checkpoint{
			ID:         id.NewCheckpointID(),
			StreamID:   streamID,
			AppID:      "app1",
			TenantID:   "tenant1",
			FromSeq:    from,
			ToSeq:      to,
			ToHash:     events[to-1].Hash,
			EventCount: int64(to - from + 1),
			CreatedAt:  time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Hour),
		}
		if prev != nil {
			cp.FromHash = prev.ToHash
			cp.PrevCheckpoint = checkpoint.Digest(prev.SignedPayload)
		}
		signCheckpoint(t, signer, cp)
		list = append(list, cp)
		prev = cp
	}

	return &fakeCheckpointStore{list: list}, signer
}
