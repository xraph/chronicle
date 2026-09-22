package verify

import (
	"context"
	"fmt"

	"github.com/xraph/chronicle/hash"
)

// Verifier provides hash chain verification services.
type Verifier struct {
	store Store
	chain *hash.Chain
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
	report.Partial = fromSeq > 1 || (input.HeadSeq > 0 && toSeq < input.HeadSeq)
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
		last := events[len(events)-1]
		report.HeadMatch = last.Hash == input.HeadHash && last.Sequence == input.HeadSeq
		if !report.HeadMatch {
			report.Valid = false
		}
	}

	report.Coverage = gradeCoverage(input, fromSeq, toSeq)

	return report, nil
}

func containsSeq(s []uint64, v uint64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
