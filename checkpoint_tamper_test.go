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
// TestDeletingAMiddleCheckpointIsDetected shows that deleting one checkpoint
// out of several is caught by the continuity chain the survivors still
// carry. That relies on a checkpoint on either side of the hole. There is no
// checkpoint after the last one, by definition, so deleting the newest
// checkpoint and every event after the one before it leaves nothing later to
// notice the hole: no continuity link points past where the chain now ends,
// and no signed ToHash exists for a sequence that no longer exists to
// compare against. The stream's own head row is not a safeguard here either,
// because it is exactly as reachable to the same attacker as the events and
// the checkpoints -- rewriting it to match the truncated tail is the same
// database write as the other two.
//
// This is deliberate, not a bug: local checkpoints, like the stream's pin in
// TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints, live in the
// same database as the events they attest to. Closing this needs a signature
// held somewhere that write access does not reach -- external anchoring,
// still the next piece of work.
func TestTruncationBeyondTheLastCheckpointIsNotDetected(t *testing.T) {
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
	// What an external anchor would have preserved: the head as it stood
	// before the attack. The mutation proof below uses this to show the same
	// verifier call catches the truncation once it is not also trusting the
	// tampered row for the answer to "how far should this chain go".
	honestHeadSeq, honestHeadHash := all[14].Sequence, all[14].Hash

	// The attack: delete the newest checkpoint, delete every event it
	// covered, and fix up the stream's own head so the truncation reads as
	// the stream simply never having grown past ten. All three writes land
	// in the same database an attacker with write access already reaches.
	cps.deleteToSeq(latest.ToSeq)
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
		t.Fatalf("truncation past the last surviving checkpoint was reported invalid; if that is now "+
			"genuinely detected, update this test, the companion note on "+
			"TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints, and the README -- this test "+
			"exists to document a real, still-open gap, not to pin a broken fixture. Full report: %+v", report)
	}

	// Proof this documents a real limit rather than a fixture that would
	// report Valid true regardless of what happened: verified against the
	// head an external anchor would have preserved -- the honest one, not
	// the one now sitting in the tampered stream row -- the same chain, same
	// checkpoints, same verifier call catches the truncation immediately.
	honest := verify.NewVerifierWithCheckpoints(c.Store(), &hash.Chain{}, cps, signer)
	honestReport, err := honest.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, HeadSeq: honestHeadSeq, HeadHash: honestHeadHash,
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain (honest head): %v", err)
	}
	if honestReport.Valid {
		t.Fatalf("expected the truncation to be caught once verified against the head an external "+
			"anchor would have preserved, but it still reported Valid: %+v", honestReport)
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

	// The attacker's DELETE FROM chronicle_checkpoints with no WHERE clause.
	cps.deleteAll()

	v := verify.NewVerifierWithCheckpoints(c.Store(), &hash.Chain{}, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
	})
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
// PurgeEvents-then-AppendBatch plays for events. Its AppendCheckpoint,
// LatestCheckpoint, CheckpointsInRange, GetCheckpoint and ListCheckpoints
// mirror store/memory's real implementations field for field, so a
// checkpoint taken through checkpoint.Checkpointer behaves here exactly as
// it would against a production backend, right up until a test reaches in
// and deletes something.
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
