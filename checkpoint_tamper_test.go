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
// catches the rewrite. The chain is unkeyed (hash.SchemePlain), the same
// scheme TestPlainChainDoesNotDetectARewrite proves recomputes cleanly for an
// attacker who relinks what they change. What catches it here is a signed
// checkpoint taken before the attack: it already asserted, under a signature
// the attacker cannot forge, what sequence 5 hashed to. Recomputing the
// chain after the rewrite still succeeds -- the digests are internally
// consistent -- but the checkpoint's own ToHash no longer matches, and that
// mismatch is what flips the report.
func TestRewriteAfterACheckpointIsProvable(t *testing.T) {
	ctx := context.Background()
	c, events, streamID := seedChain(t, hash.SchemePlain, nil)

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
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
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
	c, events, streamID := seedChain(t, hash.SchemePlain, nil)

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
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
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

// TestTruncationBeyondTheLastCheckpointIsNotDetected names the boundary a
// local checkpoint cannot cover.
//
// What actually defeats detection is not that the checkpoint gets deleted.
// verifyCheckpoints (verify/verifier.go) only ever asks the checkpoint store
// for CheckpointsInRange(fromSeq, toSeq), where toSeq resolves from the head
// the caller claims. Every backend's CheckpointsInRange excludes a checkpoint
// whose FromSeq exceeds that toSeq -- see the identical `cp.FromSeq > toSeq`
// guard in store/memory and store/sqlite -- so once an attacker rewrites the
// stream's head down to hide a truncated tail, a checkpoint covering the
// truncated range is never fetched, whether its row still exists or was
// deleted along with everything else. The two subtests below prove that
// directly: deleting the covering checkpoint and leaving it untouched in the
// checkpoint table produce the identical non-result, which is the evidence
// that the row's survival was never the deciding factor. (An earlier version
// of this test and this comment attributed the gap to the deletion; a review
// caught that the deletion at the time was not load-bearing. It is kept only
// as one of the two variants now, not as the cause.)
//
// TestDeletingAMiddleCheckpointIsDetected shows deleting one checkpoint out
// of several IS caught, by the continuity chain the survivors still carry.
// That relies on a checkpoint on either side of the hole both falling inside
// the verified range. There is no checkpoint after the last one, by
// definition, so nothing past a rewritten head can ever supply that
// continuity check, checkpoint present or not.
//
// This also names a real, closable half of the gap rather than one flat
// "not detected": a check that compared LatestCheckpoint's ToSeq against the
// claimed head would catch the checkpoint-survives variant today, with a
// store method every backend already implements. Nothing in VerifyChain runs
// that comparison yet. The checkpoint-deleted variant needs more even than
// that: comparing against a checkpoint only helps while the checkpoint row is
// still there to compare against, so closing that half needs a signature
// held somewhere write access to Chronicle's own database cannot reach.
// External anchoring is what closes it, and it is still the next piece of
// work.
func TestTruncationBeyondTheLastCheckpointIsNotDetected(t *testing.T) {
	for _, tc := range []struct {
		name             string
		deleteCheckpoint bool
	}{
		{name: "checkpoint deleted", deleteCheckpoint: true},
		{name: "checkpoint survives", deleteCheckpoint: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c, events, streamID := seedChain(t, hash.SchemePlain, nil)

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
			// What an external anchor would have preserved: the head as it
			// stood before the attack. Used below to show the same verifier
			// call catches the truncation once it is not also trusting the
			// tampered row for the answer to "how far should this chain go".
			honestHeadSeq, honestHeadHash := all[14].Sequence, all[14].Hash

			// The attack: delete every event after the checkpoint before the
			// newest one, and fix up the stream's own head so the truncation
			// reads as the stream simply never having grown past ten.
			// Whether the newest checkpoint's own row also gets deleted is
			// the thing this subtest pair varies: either way it covers
			// 11-15, past the rewritten head, so CheckpointsInRange(1, 10)
			// never returns it regardless.
			if tc.deleteCheckpoint {
				cps.deleteToSeq(latest.ToSeq)
			}
			purger, ok := c.Store().(eventPurger)
			if !ok {
				t.Fatalf("persist: store %T cannot purge events for a truncation", c.Store())
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

			// The doc comment above calls the stream head row "no safeguard"
			// because the same attacker who rewrites events can rewrite it
			// too. Prove that by reading it back through the same
			// streamReader path TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints
			// uses, rather than only asserting UpdateStreamHead returned no
			// error.
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

			v := verify.NewVerifierWithCheckpoints(c.Store(), &hash.Chain{}, cps, signer)
			report, err := v.VerifyChain(ctx, &verify.Input{
				StreamID: streamID, FromSeq: 1, HeadSeq: all[9].Sequence, HeadHash: all[9].Hash,
				Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
			})
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			if report.Partial {
				t.Fatalf("this was meant to be a full genesis-to-head check, not a bounded one, or the "+
					"non-detection below would be unsurprising for the wrong reason: %+v", report)
			}
			if !report.Valid {
				t.Fatalf("truncation past the last surviving checkpoint (%s) was reported invalid; if "+
					"that is now genuinely detected, update this test, the companion note on "+
					"TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints, and the README -- this "+
					"test exists to document a real, still-open gap, not to pin a broken fixture. Full "+
					"report: %+v", tc.name, report)
			}

			// Proof this documents a real limit rather than a fixture that
			// would report Valid true regardless of what happened: verified
			// against the head an external anchor would have preserved, the
			// honest one, not the one now sitting in the tampered stream
			// row, the same chain, same checkpoints, same verifier call
			// catches the truncation immediately, in both subtests alike.
			honest := verify.NewVerifierWithCheckpoints(c.Store(), &hash.Chain{}, cps, signer)
			honestReport, err := honest.VerifyChain(ctx, &verify.Input{
				StreamID: streamID, FromSeq: 1, HeadSeq: honestHeadSeq, HeadHash: honestHeadHash,
				Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
			})
			if err != nil {
				t.Fatalf("VerifyChain (honest head): %v", err)
			}
			if honestReport.Valid {
				t.Fatalf("expected the truncation to be caught once verified against the head an "+
					"external anchor would have preserved, but it still reported Valid: %+v", honestReport)
			}
		})
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
	c, events, streamID := seedChain(t, hash.SchemePlain, nil)

	signer := newCheckpointSigner(t)
	cps := &mutableCheckpointStore{}
	checkpointer := checkpoint.NewCheckpointer(cps, signer, nil)
	takeCheckpoint(t, c, checkpointer, events) // 1-5, genuine, nothing tampered

	v := verify.NewVerifierWithCheckpoints(c.Store(), &hash.Chain{}, cps, signer)
	input := &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
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
// uses: AppendCheckpoint's duplicate-ToSeq rejection and CheckpointsInRange's
// overlap-and-exclude filter, which is what verifyCheckpoints (and this
// suite's proof, in TestTruncationBeyondTheLastCheckpointIsNotDetected, that
// a checkpoint outside the claimed range is never even asked about) both
// depend on. It is not a full replica: it does not clone on read the way
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

	for _, existing := range s.list {
		if existing.StreamID.String() == cp.StreamID.String() && existing.ToSeq == cp.ToSeq {
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
// TestDeletingAMiddleCheckpointIsDetected and
// TestTruncationBeyondTheLastCheckpointIsNotDetected can grow a chain to
// fifteen events, three checkpoints' worth, past seedChain's fixed five.
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
