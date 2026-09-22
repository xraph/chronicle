package verify

import (
	"context"
	"errors"
	"fmt"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
)

// Verifier provides hash chain verification services.
type Verifier struct {
	store Store
	chain *hash.Chain

	// checkpoints and signer are optional. Without them verification behaves
	// exactly as it did before checkpoints existed and coverage tops out at
	// keyed.
	checkpoints checkpoint.Store
	signer      checkpoint.Signer
}

// NewVerifier creates a new Verifier with the given store.
//
// It verifies under a zero-value, unkeyed chain, so it cannot recompute an
// HMAC digest. Callers that have a keyed chain in hand should use
// NewVerifierWithChain instead.
func NewVerifier(store Store) *Verifier {
	return &Verifier{
		store: store,
		chain: &hash.Chain{},
	}
}

// NewVerifierWithChain creates a Verifier that verifies under a specific chain.
//
// A keyed chain needs its key provider to recompute a digest, so a verifier
// built with NewVerifier (which uses a plain chain) cannot check HMAC events.
func NewVerifierWithChain(store Store, chain *hash.Chain) *Verifier {
	return &Verifier{store: store, chain: chain}
}

// NewVerifierWithCheckpoints creates a Verifier that also checks signed
// checkpoints covering the range.
//
// Both cps and signer may be nil, in which case verification behaves exactly
// as it did before checkpoints existed, and coverage tops out at keyed.
func NewVerifierWithCheckpoints(store Store, chain *hash.Chain, cps checkpoint.Store, signer checkpoint.Signer) *Verifier {
	v := NewVerifierWithChain(store, chain)
	v.checkpoints, v.signer = cps, signer
	return v
}

// VerifyChain verifies the integrity of a hash chain for a stream within a sequence range.
// It checks that each event's hash correctly links to the previous event's hash.
func (v *Verifier) VerifyChain(ctx context.Context, input *Input) (*Report, error) {
	report := &Report{
		Valid: true,
	}

	// FromSeq 0 means genesis and ToSeq 0 means the stream head, so the default
	// is to verify the whole chain. A caller that wants less says so, and gets
	// Partial set.
	fromSeq := input.FromSeq
	if fromSeq == 0 {
		fromSeq = 1
	}
	toSeq := input.ToSeq
	if toSeq == 0 {
		toSeq = input.HeadSeq
	}
	// A range is Partial when the caller bounded either end: FromSeq above
	// genesis, or ToSeq below a known head. ToSeq alone is also a bound even
	// when the head is unknown -- an explicit ToSeq says "stop here"
	// regardless of whether this verifier can prove "here" was the head, and
	// treating an unprovable upper bound as full coverage would be the wrong
	// direction to be wrong in.
	report.Partial = fromSeq > 1 ||
		(input.HeadSeq > 0 && toSeq < input.HeadSeq) ||
		(input.ToSeq > 0 && input.HeadSeq == 0)
	report.HeadSeq = input.HeadSeq

	// Detect gaps in the sequence range.
	gaps, err := v.store.Gaps(ctx, input.StreamID, fromSeq, toSeq)
	if err != nil {
		return nil, err
	}
	if len(gaps) > 0 {
		report.Valid = false
		report.Gaps = gaps
	}

	// Get the events in the range.
	events, err := v.store.EventRange(ctx, input.StreamID, fromSeq, toSeq)
	if err != nil {
		return nil, err
	}

	if len(events) == 0 {
		// An empty resolved range against a stream that claims a head (a
		// non-zero HeadSeq) is a failure, not a trivially valid pass: either
		// the request asked for a range past the head (from_seq beyond what
		// the stream has ever held), or every sequence in range is missing,
		// which Gaps above would already have caught -- so the only way to
		// land here with a known head is a range that could never have
		// covered it. A stream with no claimed head (HeadSeq == 0) is
		// different: that is what a genuinely empty, freshly created stream
		// reports, and verifying it vacuously true is correct.
		if input.HeadSeq > 0 {
			report.Valid = false
			report.HeadChecked = true
		}
		return report, nil
	}

	report.FirstEvent = events[0].Sequence
	report.LastEvent = events[len(events)-1].Sequence

	// Verify each event's hash.
	for i, event := range events {
		var expectedPrevHash string
		if i == 0 {
			// First event in range — use its declared PrevHash.
			expectedPrevHash = event.PrevHash
		} else {
			expectedPrevHash = events[i-1].Hash
		}

		// Recompute the hash and cross-check the event's claimed scheme against
		// the stream's pin, so a downgrade is reported as evidence rather than
		// being collapsed into an ordinary tamper.
		res, err := v.chain.VerifyWithPin(ctx, expectedPrevHash, event, input.Pin)
		if err != nil {
			return nil, fmt.Errorf("verify event %d: %w", event.Sequence, err)
		}
		if res.Downgrade {
			report.Valid = false
			report.Downgrades = append(report.Downgrades, event.Sequence)
		}
		if res.Tolerant {
			report.Tolerant = append(report.Tolerant, event.Sequence)
		}
		if !res.OK {
			report.Valid = false
			if !containsSeq(report.Tampered, event.Sequence) {
				report.Tampered = append(report.Tampered, event.Sequence)
			}
		}

		// Check chain linkage (except first event).
		if i > 0 && event.PrevHash != events[i-1].Hash {
			report.Valid = false
			if !containsSeq(report.Tampered, event.Sequence) {
				report.Tampered = append(report.Tampered, event.Sequence)
			}
		}

		report.Verified++
	}

	// Anchor the tail. A chain whose last verified hash is not the stream's
	// head has had events removed from the end, which no amount of internal
	// linkage can reveal.
	if input.HeadHash != "" && !report.Partial {
		report.HeadChecked = true
		last := events[len(events)-1]
		report.HeadMatch = last.Hash == input.HeadHash && last.Sequence == input.HeadSeq
		if !report.HeadMatch {
			report.Valid = false
		}
	}

	report.Coverage = gradeCoverage(input, fromSeq, toSeq)

	// A checkpoint is a signed assertion about where the chain stood. Three
	// things have to hold: the signature is genuine, the events still hash to
	// what it recorded, and it follows its predecessor without a gap.
	if v.checkpoints != nil && v.signer != nil {
		results, covered, err := v.verifyCheckpoints(ctx, input, fromSeq, toSeq, events)
		if err != nil {
			return nil, err
		}
		report.Checkpoints = results
		for _, r := range results {
			// SignatureValid is always determinate: the tamper check and the
			// signer call between them always resolve one way or the other,
			// so a false here is always a genuine failure. HashMatch and
			// ContinuityOK are different -- CheckpointsInRange's overlap
			// contract can hand back a checkpoint whose ToSeq or predecessor
			// this verification never fetched, in which case those fields
			// sit at their false zero value without ever having been
			// checked. Only flip Valid for those two when *Checked says the
			// check actually ran; otherwise a narrow sub-range verification
			// would report tampering on a chain nothing is wrong with.
			if !r.SignatureValid {
				report.Valid = false
			}
			if r.HashChecked && !r.HashMatch {
				report.Valid = false
			}
			if r.ContinuityChecked && !r.ContinuityOK {
				report.Valid = false
			}
		}
		report.Coverage = upgradeCoverage(report.Coverage, covered, input.Pin.Since)
	}

	return report, nil
}

// verifyCheckpoints checks every checkpoint covering [fromSeq, toSeq] against
// the events already fetched for this verification.
//
// CheckpointsInRange overlaps rather than contains, so a checkpoint returned
// here may extend beyond the requested range (verifying 150-160 can surface
// the checkpoint covering 101-200: that is the assertion those events fall
// under), and its immediate predecessor may not have been fetched at all
// (nothing in [fromSeq,toSeq] needed it). Neither is evidence of tampering on
// its own. When a checkpoint's ToSeq lands outside the fetched events, its
// hash cannot be re-confirmed from what this call already has in hand, so
// HashMatch stays at its false zero value and HashChecked stays false rather
// than silently assuming a match; the same goes for ContinuityOK and
// ContinuityChecked when no fetched predecessor exists to compare against.
// A checkpoint left unconfirmed this way also does not contribute to the
// returned covered spans, so a caller verifying an inner sub-range does not
// get LevelSigned for a boundary it never actually checked -- but nor does
// VerifyChain flip Valid false for it; see the *Checked-gated loop in
// VerifyChain that consumes these results.
//
// ErrUnsupported from the store (a backend, such as redis, that implements
// the interface but refuses every call) is treated the same as "no
// checkpoints here" rather than a hard failure: a store that cannot hold
// checkpoints is exactly the case NewVerifierWithCheckpoints's "keep working
// when it does not have them" contract exists for.
func (v *Verifier) verifyCheckpoints(
	ctx context.Context, input *Input, fromSeq, toSeq uint64, events []*audit.Event,
) ([]CheckpointResult, []Coverage, error) {
	cps, err := v.checkpoints.CheckpointsInRange(ctx, input.StreamID, fromSeq, toSeq)
	if err != nil {
		if errors.Is(err, checkpoint.ErrUnsupported) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("verify: checkpoints in range: %w", err)
	}
	if len(cps) == 0 {
		return nil, nil, nil
	}

	bySeq := make(map[uint64]*audit.Event, len(events))
	for _, e := range events {
		bySeq[e.Sequence] = e
	}

	results := make([]CheckpointResult, 0, len(cps))
	var covered []Coverage
	var prev *checkpoint.Checkpoint

	for _, cp := range cps {
		res := CheckpointResult{ID: cp.ID.String(), FromSeq: cp.FromSeq, ToSeq: cp.ToSeq}

		// The tamper check that costs nothing and the signer cannot make for
		// us: if the stored payload does not match what the row's own fields
		// recompute to, the row was edited after signing. Fail without even
		// asking the signer, and never sign or verify against the
		// recomputation itself -- only the stored bytes were ever signed.
		if checkpoint.CanonicalPayload(cp) != cp.SignedPayload {
			res.Note = "stored payload does not match its own fields; the row was edited after signing"
		} else if verr := v.signer.Verify(ctx, []byte(cp.SignedPayload), cp.Signature, cp.SignKeyID); verr == nil {
			res.SignatureValid = true
		} else {
			res.Note = fmt.Sprintf("signature does not verify: %v", verr)
		}

		if event, ok := bySeq[cp.ToSeq]; ok {
			res.HashChecked = true
			res.HashMatch = event.Hash == cp.ToHash
			if !res.HashMatch && res.Note == "" {
				res.Note = "chain hash at to_seq no longer matches what the checkpoint recorded"
			}
		} else if res.Note == "" {
			res.Note = "to_seq falls outside the verified range; hash not re-checked"
		}

		switch {
		case cp.FromSeq == 1 && cp.PrevCheckpoint == "":
			// A stream's first checkpoint has nothing to chain to.
			res.ContinuityChecked = true
			res.ContinuityOK = true
		case prev != nil:
			// The immediate predecessor was also fetched by this
			// verification, so continuity can actually be evaluated.
			res.ContinuityChecked = true
			res.ContinuityOK = cp.FromSeq == prev.ToSeq+1 && cp.PrevCheckpoint == checkpoint.Digest(prev.SignedPayload)
			if !res.ContinuityOK && res.Note == "" {
				res.Note = "does not continue from the previous checkpoint without a gap"
			}
		default:
			// Neither this checkpoint's own first-checkpoint case nor a
			// fetched predecessor to compare against: CheckpointsInRange's
			// overlap contract can return a checkpoint without also
			// returning the one immediately before it (nothing in the
			// requested range needed it). Continuity is simply unknown here,
			// not broken -- ContinuityChecked stays false and Valid must not
			// be flipped for it.
			if res.Note == "" {
				res.Note = "predecessor checkpoint not in the verified range; continuity not checked"
			}
		}

		results = append(results, res)

		if res.SignatureValid && res.HashMatch && res.ContinuityOK {
			from, to := cp.FromSeq, cp.ToSeq
			if from < fromSeq {
				from = fromSeq
			}
			if to > toSeq {
				to = toSeq
			}
			if from <= to {
				covered = append(covered, Coverage{FromSeq: from, ToSeq: to, Level: LevelSigned})
			}
		}

		prev = cp
	}

	return results, covered, nil
}

// upgradeCoverage raises the portion of each existing span that a fully-valid
// checkpoint covers to LevelSigned, splitting a span where a checkpoint
// covers only part of it.
//
// pinSince is input.Pin.Since, the same boundary gradeCoverage used to decide
// which spans predate the stream's scheme pin. A span entirely below it is
// left alone regardless of checkpoint coverage: a signature over an unkeyed
// digest only proves that digest was not changed after the checkpoint was
// taken. It says nothing about whether the digest was ever tamper-evident to
// begin with, so it cannot lift a pre-migration span to the same assurance a
// keyed span gets. Reading pinSince directly, rather than pattern-matching
// gradeCoverage's Note text, keeps the two functions correct as a pair
// without coupling them through prose that a later wording change could
// silently break.
func upgradeCoverage(existing, covered []Coverage, pinSince uint64) []Coverage {
	if len(covered) == 0 {
		return existing
	}

	out := make([]Coverage, 0, len(existing))
	for _, span := range existing {
		out = append(out, upgradeSpan(span, covered, pinSince)...)
	}
	return out
}

// upgradeSpan splits one coverage span against the checkpoint-covered ranges,
// in ascending order, raising the overlapping portion(s) to LevelSigned.
//
// gradeCoverage only ever produces a span that sits entirely below pinSince
// or entirely at/above it, never a mix, so checking the span's own ToSeq
// against pinSince is enough to tell which one this is.
func upgradeSpan(span Coverage, covered []Coverage, pinSince uint64) []Coverage {
	if span.ToSeq < pinSince {
		return []Coverage{span}
	}

	var result []Coverage
	cursor := span.FromSeq

	for _, cov := range covered {
		lo, hi := cov.FromSeq, cov.ToSeq
		if hi < cursor || lo > span.ToSeq {
			continue // no overlap with the remaining, unprocessed part of span
		}
		if lo < cursor {
			lo = cursor
		}
		if hi > span.ToSeq {
			hi = span.ToSeq
		}

		if cursor < lo {
			result = append(result, Coverage{FromSeq: cursor, ToSeq: lo - 1, Level: span.Level, Note: span.Note})
		}
		result = append(result, Coverage{FromSeq: lo, ToSeq: hi, Level: LevelSigned})
		cursor = hi + 1
	}

	if cursor <= span.ToSeq {
		result = append(result, Coverage{FromSeq: cursor, ToSeq: span.ToSeq, Level: span.Level, Note: span.Note})
	}

	if len(result) == 0 {
		return []Coverage{span}
	}
	return result
}

func containsSeq(s []uint64, v uint64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
