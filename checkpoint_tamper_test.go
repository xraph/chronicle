package chronicle_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/verify"
)

// TestRewriteAfterACheckpointIsProvable is the checkpoint-era counterpart to
// TestHMACChainDetectsARewrite: this time nothing about the digest scheme
// catches the rewrite. The chain is unkeyed (hash.SchemePlainV4), the same
// scheme TestPlainChainDoesNotDetectARewrite proves recomputes cleanly for an
// attacker who relinks what they change. What catches it here is a signed
// checkpoint taken before the attack: it already asserted, under a signature
// the attacker cannot forge, what sequence 5 hashed to. Recomputing the
// chain after the rewrite still succeeds -- the digests are internally
// consistent -- but the checkpoint's own ToHash no longer matches, and that
// mismatch is what flips the report.
func TestRewriteAfterACheckpointIsProvable(t *testing.T) {
	ctx := context.Background()
	c, events, streamID := seedChain(t, hash.SchemePlainV4, nil)

	signer := newCheckpointSigner(t)
	cps := &mutableCheckpointStore{}
	checkpointer := checkpoint.NewCheckpointer(cps, signer, nil)
	takeCheckpoint(t, c, checkpointer, events)

	// The attacker rewrites event 3 (index 2) and relinks everything after
	// it, exactly as TestPlainChainDoesNotDetectARewrite's attacker does. On
	// its own, against an unkeyed chain, this leaves nothing to catch: every
	// digest still recomputes from what is now on disk. The checkpoint taken
	// above is the only thing in this test that was not itself rewritten.
	rewriteAndRelink(t, events, 2, "attacker-was-not-here")
	persist(t, c, events)

	v := verify.NewVerifierWithCheckpoints(c.Store(), &hash.Chain{}, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemePlainV4, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatalf("a rewrite of checkpointed events reported Valid: %+v", report)
	}

	if len(report.Checkpoints) != 1 {
		t.Fatalf("got %d checkpoint results, want exactly the one covering this range: %+v",
			len(report.Checkpoints), report.Checkpoints)
	}
	result := report.Checkpoints[0]
	// HashChecked distinguishes "we looked and it matched" from "we never
	// looked": read HashMatch's zero value as a failure only once HashChecked
	// says the comparison actually ran, or this assertion would pass just as
	// happily against a verifier that skipped the checkpoint entirely.
	if !result.HashChecked {
		t.Fatalf("checkpoint result never actually re-checked ToHash (HashChecked false); "+
			"the HashMatch assertion below would pass vacuously: %+v", result)
	}
	if result.HashMatch {
		t.Errorf("checkpoint reported HashMatch true after the range it covers was rewritten: %+v", result)
	}
}

// TestDeletingAMiddleCheckpointIsDetected removes the middle one of three
// checkpoints and shows the gap it leaves is itself evidence: the checkpoint
// after it can no longer verify a continuous chain of PrevCheckpoint digests
// back to the one before it, because the link in between is gone.
func TestDeletingAMiddleCheckpointIsDetected(t *testing.T) {
	ctx := context.Background()
	c, events, streamID := seedChain(t, hash.SchemePlainV4, nil)

	signer := newCheckpointSigner(t)
	cps := &mutableCheckpointStore{}
	checkpointer := checkpoint.NewCheckpointer(cps, signer, nil)

	// Three checkpoints, one every five events: 1-5, 6-10, 11-15. Each is
	// taken only after the events it covers exist, the way a production
	// scheduler calling CheckpointStream on a cadence would.
	cp1 := takeCheckpoint(t, c, checkpointer, events)
	recordFiveMore(t, c, events)
	cp2 := takeCheckpoint(t, c, checkpointer, events)
	recordFiveMore(t, c, events)
	cp3 := takeCheckpoint(t, c, checkpointer, events)

	if cp1.FromSeq != 1 || cp1.ToSeq != 5 || cp2.FromSeq != 6 || cp2.ToSeq != 10 || cp3.FromSeq != 11 || cp3.ToSeq != 15 {
		t.Fatalf("unexpected checkpoint bounds: cp1=%+v cp2=%+v cp3=%+v", cp1, cp2, cp3)
	}

	// The attacker's DELETE FROM chronicle_checkpoints WHERE to_seq = 10 --
	// removing the one in the middle, leaving the first and the last.
	cps.deleteToSeq(cp2.ToSeq)

	v := verify.NewVerifierWithCheckpoints(c.Store(), &hash.Chain{}, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: 15,
		Pin: hash.Pin{Scheme: hash.SchemePlainV4, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatalf("a stream missing its middle checkpoint reported Valid: %+v", report)
	}

	// ContinuityChecked has to be true here, not just ContinuityOK false: a
	// checkpoint whose predecessor was simply never fetched also reports
	// ContinuityOK false at its zero value, without ever having evaluated
	// anything. Only a *checked* break is the deletion actually being caught.
	var sawCheckedBreak bool
	for _, r := range report.Checkpoints {
		if r.ContinuityChecked && !r.ContinuityOK {
			sawCheckedBreak = true
		}
	}
	if !sawCheckedBreak {
		t.Fatalf("no checkpoint reported a *checked* continuity break (ContinuityChecked true, "+
			"ContinuityOK false); report.Checkpoints=%+v", report.Checkpoints)
	}
}

// truncatedChain is the state the two truncation tests below share: a
// fifteen-event chain with three checkpoints over it, its tail deleted, and
// its head row rewritten to hide that.
type truncatedChain struct {
	verifier *verify.Verifier
	streamID id.ID

	// claimedHeadSeq/Hash are the head the attacker left in the stream row.
	claimedHeadSeq  uint64
	claimedHeadHash string

	// honestHeadSeq/Hash are the head as it stood before the attack, which
	// is what an external anchor would have preserved.
	honestHeadSeq  uint64
	honestHeadHash string
}

// verifyAt runs a full genesis-to-head verification against the head given.
func (tc truncatedChain) verifyAt(t *testing.T, headSeq uint64, headHash string) *verify.Report {
	t.Helper()

	report, err := tc.verifier.VerifyChain(context.Background(), &verify.Input{
		StreamID: tc.streamID, FromSeq: 1, HeadSeq: headSeq, HeadHash: headHash,
		Pin: hash.Pin{Scheme: hash.SchemePlainV4, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Partial {
		t.Fatalf("this was meant to be a full genesis-to-head check, not a bounded one, or the result "+
			"below would mean something different: %+v", report)
	}
	return report
}

// truncateTailBeyondTheLastCheckpoint builds a fifteen-event chain with
// checkpoints over 1-5, 6-10 and 11-15, then deletes every event after ten
// and rewrites the stream's head so the truncation reads as a stream that
// simply never grew past ten.
//
// deleteCheckpoint decides whether the checkpoint covering the deleted range
// goes with them, and that is the entire difference between a truncation
// Chronicle can prove and one it still cannot. Neither variant is caught by
// anything inside the verified range: verification only asks the checkpoint
// store for what overlaps [fromSeq, toSeq], and toSeq comes from the head
// the attacker just rewrote, so a checkpoint covering 11-15 is excluded
// before its signature is looked at either way.
func truncateTailBeyondTheLastCheckpoint(t *testing.T, deleteCheckpoint bool) truncatedChain {
	t.Helper()
	ctx := context.Background()

	c, events, streamID := seedChain(t, hash.SchemePlainV4, nil)

	signer := newCheckpointSigner(t)
	cps := &mutableCheckpointStore{}
	checkpointer := checkpoint.NewCheckpointer(cps, signer, nil)

	takeCheckpoint(t, c, checkpointer, events) // 1-5
	recordFiveMore(t, c, events)
	takeCheckpoint(t, c, checkpointer, events) // 6-10
	recordFiveMore(t, c, events)
	latest := takeCheckpoint(t, c, checkpointer, events) // 11-15

	all, err := c.Store().EventRange(ctx, streamID, 1, 15)
	if err != nil {
		t.Fatalf("EventRange: %v", err)
	}
	if len(all) != 15 {
		t.Fatalf("got %d events, want 15", len(all))
	}

	if deleteCheckpoint {
		cps.deleteToSeq(latest.ToSeq)
	}
	purger, ok := c.Store().(eventPurger)
	if !ok {
		t.Fatalf("store %T cannot purge events for a truncation", c.Store())
	}
	truncated := make([]id.ID, 0, len(all)-10)
	for _, e := range all[10:] {
		truncated = append(truncated, e.ID)
	}
	if _, purgeErr := purger.PurgeEvents(ctx, truncated); purgeErr != nil {
		t.Fatalf("PurgeEvents: %v", purgeErr)
	}
	if headErr := c.Store().UpdateStreamHead(ctx, streamID, all[9].Hash, all[9].Sequence); headErr != nil {
		t.Fatalf("UpdateStreamHead: %v", headErr)
	}

	// The stream head row is no safeguard, because the same attacker who
	// rewrites events rewrites it too. Read it back through the same
	// streamReader path TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints
	// uses rather than trusting UpdateStreamHead's nil error.
	reader, ok := c.Store().(streamReader)
	if !ok {
		t.Fatalf("store %T cannot read the stream row directly", c.Store())
	}
	st, err := reader.GetStream(ctx, streamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if st.HeadSeq != 10 || st.HeadHash != all[9].Hash {
		t.Fatalf("stream head row = (seq %d, hash %q), want (10, %q): the rewrite did not take, "+
			"so this test would not be exercising the attack it claims to", st.HeadSeq, st.HeadHash, all[9].Hash)
	}

	return truncatedChain{
		verifier:        verify.NewVerifierWithCheckpoints(c.Store(), &hash.Chain{}, cps, signer),
		streamID:        streamID,
		claimedHeadSeq:  all[9].Sequence,
		claimedHeadHash: all[9].Hash,
		honestHeadSeq:   all[14].Sequence,
		honestHeadHash:  all[14].Hash,
	}
}

// TestTruncationIsDetectedWhileTheCheckpointSurvives is the closable half of
// what used to be one flat "not detected" test.
//
// Nothing inside the range the attacker left behind looks wrong: sequences 1
// to 10 are all present, every digest recomputes, the chain links, and the
// head row agrees with the tail. The checkpoint covering 11-15 is never
// fetched either, because it starts past the claimed head. What catches the
// truncation is the stream's latest checkpoint, read directly rather than by
// range: it asserts, under a signature, that this chain once reached
// sequence 15, and the caller is claiming 10.
func TestTruncationIsDetectedWhileTheCheckpointSurvives(t *testing.T) {
	tc := truncateTailBeyondTheLastCheckpoint(t, false)

	report := tc.verifyAt(t, tc.claimedHeadSeq, tc.claimedHeadHash)
	if report.Valid {
		t.Fatalf("a truncated tail with its covering checkpoint still in the table verified as Valid: %+v", report)
	}
	if !report.CheckpointHeadChecked {
		t.Fatalf("the latest checkpoint was never compared against the claimed head, so the verdict "+
			"rests on something else: %+v", report)
	}
	if report.CheckpointHeadOK {
		t.Errorf("CheckpointHeadOK is true while a checkpoint asserts the chain reached 15 and the "+
			"caller claims 10: %+v", report)
	}

	// Everything else has to look clean, or this test would pass for a
	// reason that has nothing to do with the checkpoint.
	if len(report.Gaps) != 0 || len(report.Tampered) != 0 || len(report.Downgrades) != 0 {
		t.Errorf("the surviving range itself reported problems (gaps=%v tampered=%v downgrades=%v); "+
			"the truncation is meant to be invisible inside it", report.Gaps, report.Tampered, report.Downgrades)
	}
	if !report.HeadChecked || !report.HeadMatch {
		t.Errorf("head anchoring flagged the truncation (checked=%v match=%v); the attacker moved the "+
			"head row precisely so it would not", report.HeadChecked, report.HeadMatch)
	}
}

// TestTruncationBeyondADeletedCheckpointIsNotDetected names the boundary a
// local checkpoint still cannot cover.
//
// Delete the covering checkpoint along with the events and there is nothing
// left to compare the claimed head against: the newest surviving checkpoint
// ends at ten, which is exactly what the rewritten head row says. The
// comparison runs, agrees, and is right to, given what it can see.
//
// TestDeletingAMiddleCheckpointIsDetected shows deleting one checkpoint out
// of several IS caught, by the continuity chain the survivors still carry.
// That relies on a checkpoint on either side of the hole falling inside the
// verified range, and there is no checkpoint after the last one by
// definition.
//
// Closing this needs a signature held somewhere write access to Chronicle's
// own database cannot reach. External anchoring is what does that, and it is
// the next piece of work.
func TestTruncationBeyondADeletedCheckpointIsNotDetected(t *testing.T) {
	tc := truncateTailBeyondTheLastCheckpoint(t, true)

	report := tc.verifyAt(t, tc.claimedHeadSeq, tc.claimedHeadHash)
	if !report.Valid {
		t.Fatalf("truncation past a deleted checkpoint was reported invalid; if that is now genuinely "+
			"detected, update this test, the companion note on "+
			"TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints, and the README -- this test "+
			"exists to document a real, still-open gap, not to pin a broken fixture. Full report: %+v", report)
	}
	if report.CheckpointHeadChecked && !report.CheckpointHeadOK {
		t.Fatalf("the head comparison reported a break while the checkpoint that could prove one was "+
			"deleted: %+v", report)
	}

	// Proof this documents a real limit rather than a fixture that would
	// report Valid true regardless: verified against the head an external
	// anchor would have preserved, the same chain, the same checkpoints and
	// the same verifier catch the truncation immediately.
	honest := tc.verifyAt(t, tc.honestHeadSeq, tc.honestHeadHash)
	if honest.Valid {
		t.Fatalf("expected the truncation to be caught once verified against the head an external "+
			"anchor would have preserved, but it still reported Valid: %+v", honest)
	}
}

// TestDeletingEveryCheckpointDropsCoverageNotValidity wipes the checkpoint
// table clean while leaving every event untouched. Nothing was rewritten, so
// the chain still verifies: Valid stays true. What changes is what the
// report can claim about it -- with no checkpoint left to have signed
// anything, no span of the coverage ladder can stand on LevelSigned, and
// there is nothing left to report per-checkpoint either. This is the
// honest, non-alarming half of the story: losing checkpoints degrades
// assurance, it does not manufacture a false positive.
func TestDeletingEveryCheckpointDropsCoverageNotValidity(t *testing.T) {
	ctx := context.Background()
	c, events, streamID := seedChain(t, hash.SchemePlainV4, nil)

	signer := newCheckpointSigner(t)
	cps := &mutableCheckpointStore{}
	checkpointer := checkpoint.NewCheckpointer(cps, signer, nil)
	takeCheckpoint(t, c, checkpointer, events) // 1-5, genuine, nothing tampered

	v := verify.NewVerifierWithCheckpoints(c.Store(), &hash.Chain{}, cps, signer)
	input := &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemePlainV4, Since: 1},
	}

	// Before touching anything: prove the checkpoint taken above is actually
	// doing something, or deleting it below would not be a real mutation.
	// Without this, a no-op AppendCheckpoint or a signer that silently never
	// verifies would still leave every assertion after deleteAll passing --
	// there would be no LevelSigned span to lose either way.
	before, err := v.VerifyChain(ctx, input)
	if err != nil {
		t.Fatalf("VerifyChain (before deleting): %v", err)
	}
	var sawSigned bool
	for _, cov := range before.Coverage {
		if cov.Level == verify.LevelSigned {
			sawSigned = true
		}
	}
	if !sawSigned {
		t.Fatalf("expected LevelSigned coverage before any checkpoint was deleted, so that deleting "+
			"them below is a real change rather than starting from nothing: %+v", before)
	}

	// The attacker's DELETE FROM chronicle_checkpoints with no WHERE clause.
	cps.deleteAll()

	report, err := v.VerifyChain(ctx, input)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("a stream with no event tampered, only a wiped checkpoint table, reported invalid; "+
			"deleting evidence of assurance is not the same thing as introducing tampering, and this "+
			"report should not conflate the two. Full report: %+v", report)
	}
	for _, cov := range report.Coverage {
		if cov.Level == verify.LevelSigned || cov.Level == verify.LevelAnchored {
			t.Fatalf("coverage still claims %q after every checkpoint was deleted, with nothing left "+
				"to have asserted it: %+v", cov.Level, report.Coverage)
		}
	}
	if len(report.Checkpoints) != 0 {
		t.Errorf("report.Checkpoints = %+v, want none: there is nothing left to report on", report.Checkpoints)
	}
}

// mutableCheckpointStore is a checkpoint.Store backed by a slice this suite
// can edit directly: remove one entry, remove all of them. checkpoint.Store
// itself offers no such method by design -- see its doc: "There is no update
// and no delete: a checkpoint that could be revised would assert nothing" --
// so simulating an attacker with a SQL shell against chronicle_checkpoints
// needs a store built for exactly that, the same role persist's
// PurgeEvents-then-AppendBatch plays for events.
//
// It matches store/memory's behaviour for the methods verification actually
// uses: AppendCheckpoint's duplicate-ToSeq-or-FromSeq rejection and
// CheckpointsInRange's overlap-and-exclude filter, which is what
// verifyCheckpoints (and this suite's proof, in
// TestTruncationBeyondADeletedCheckpointIsNotDetected, that a checkpoint
// outside the claimed range is never even asked about) both depend on. It is not a full replica: it does not clone on read the way
// store/memory does, and GetCheckpoint and ListCheckpoints are simplified
// stubs, with ListCheckpoints ignoring ListOpts and not sorting newest-first.
// Neither of those two is called anywhere in this file or by verify.Verifier,
// so the gap is harmless here.
type mutableCheckpointStore struct {
	mu   sync.Mutex
	list []*checkpoint.Checkpoint
}

func (s *mutableCheckpointStore) AppendCheckpoint(_ context.Context, cp *checkpoint.Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Both halves of store/memory's duplicate check, to_seq and from_seq.
	for _, existing := range s.list {
		if existing.StreamID.String() != cp.StreamID.String() {
			continue
		}
		if existing.ToSeq == cp.ToSeq || existing.FromSeq == cp.FromSeq {
			return checkpoint.ErrExists
		}
	}
	s.list = append(s.list, cp)
	return nil
}

func (s *mutableCheckpointStore) LatestCheckpoint(_ context.Context, streamID id.ID) (*checkpoint.Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idStr := streamID.String()
	var latest *checkpoint.Checkpoint
	for _, cp := range s.list {
		if cp.StreamID.String() != idStr {
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

func (s *mutableCheckpointStore) CheckpointsInRange(
	_ context.Context, streamID id.ID, fromSeq, toSeq uint64,
) ([]*checkpoint.Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idStr := streamID.String()
	var result []*checkpoint.Checkpoint
	for _, cp := range s.list {
		if cp.StreamID.String() != idStr {
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

func (s *mutableCheckpointStore) GetCheckpoint(_ context.Context, checkpointID id.ID) (*checkpoint.Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idStr := checkpointID.String()
	for _, cp := range s.list {
		if cp.ID.String() == idStr {
			return cp, nil
		}
	}
	return nil, checkpoint.ErrNotFound
}

func (s *mutableCheckpointStore) ListCheckpoints(
	_ context.Context, streamID id.ID, _ checkpoint.ListOpts,
) ([]*checkpoint.Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idStr := streamID.String()
	var result []*checkpoint.Checkpoint
	for _, cp := range s.list {
		if cp.StreamID.String() == idStr {
			result = append(result, cp)
		}
	}
	return result, nil
}

// deleteToSeq removes the checkpoint whose ToSeq matches, simulating an
// attacker's DELETE FROM chronicle_checkpoints WHERE to_seq = ?.
func (s *mutableCheckpointStore) deleteToSeq(toSeq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, cp := range s.list {
		if cp.ToSeq == toSeq {
			s.list = append(s.list[:i], s.list[i+1:]...)
			return
		}
	}
}

// deleteAll removes every checkpoint, simulating a DELETE with no WHERE
// clause at all.
func (s *mutableCheckpointStore) deleteAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = nil
}

// Compile-time check.
var _ checkpoint.Store = (*mutableCheckpointStore)(nil)

// newCheckpointSigner builds an ed25519 signer over a fresh key, using the
// stubProvider declared in chronicle_test.go the same way seedChain's HMAC
// tests do. stubProvider.Current ignores the keys.Use it is asked for and
// simply returns whatever key it holds, so handing it a freshly generated
// ed25519 private key under its own activeID is enough to make it a valid
// checkpoint signer, independent of whatever digest scheme the chain itself
// uses.
func newCheckpointSigner(t *testing.T) checkpoint.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return checkpoint.NewEd25519Signer(stubProvider{key: priv, activeID: "checkpoint-1"})
}

// takeCheckpoint signs a checkpoint over whatever the stream has accrued
// since the previous one (or since sequence 1, for the first), the way a
// production scheduler calling CheckpointStream on a cadence would: read the
// stream's current head, sign, store. The scope it reads that head under
// comes off events[0] rather than a literal, the same device
// TestRotatedKeyStillVerifiesOldEvents uses to avoid hardcoding seedChain's
// app/tenant strings a second time.
func takeCheckpoint(
	t *testing.T, c *chronicle.Chronicle, checkpointer *checkpoint.Checkpointer, events []*audit.Event,
) *checkpoint.Checkpoint {
	t.Helper()
	ctx := context.Background()

	info, err := c.Store().GetStreamByScope(ctx, events[0].AppID, events[0].TenantID)
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	cp, err := checkpointer.CheckpointStream(ctx, checkpoint.StreamHead{
		ID: info.ID, AppID: info.AppID, TenantID: info.TenantID,
		HeadSeq: info.HeadSeq, HeadHash: info.HeadHash,
	})
	if err != nil {
		t.Fatalf("CheckpointStream: %v", err)
	}
	return cp
}

// recordFiveMore appends five more events to the stream seedChain built,
// through the same Info(...).Record() path -- not persist's raw-write
// bypass -- under the scope events[0] already carries. It exists so
// TestDeletingAMiddleCheckpointIsDetected and the two truncation tests can
// grow a chain to fifteen events, three checkpoints' worth, past seedChain's
// fixed five.
func recordFiveMore(t *testing.T, c *chronicle.Chronicle, events []*audit.Event) {
	t.Helper()
	ctx := context.Background()
	recCtx := scope.WithTenantID(scope.WithAppID(ctx, events[0].AppID), events[0].TenantID)

	for i := 1; i <= 5; i++ {
		err := c.Info(recCtx, "login", "session", fmt.Sprintf("session-more-%d", i)).
			Category("auth").
			UserID(fmt.Sprintf("user-more-%d", i)).
			Record()
		if err != nil {
			t.Fatalf("Record extra event %d: %v", i, err)
		}
	}
}
