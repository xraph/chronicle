package verify

import (
	"context"

	"github.com/xraph/chronicle/hash"
)

// Verifier provides hash chain verification services.
type Verifier struct {
	store Store
	chain *hash.Chain
}

// NewVerifier creates a new Verifier with the given store.
func NewVerifier(store Store) *Verifier {
	return &Verifier{
		store: store,
		chain: &hash.Chain{},
	}
}

// VerifyChain verifies the integrity of a hash chain for a stream within a sequence range.
// It checks that each event's hash correctly links to the previous event's hash.
func (v *Verifier) VerifyChain(ctx context.Context, input *Input) (*Report, error) {
	report := &Report{
		Valid: true,
	}

	// Detect gaps in the sequence range.
	gaps, err := v.store.Gaps(ctx, input.StreamID, input.FromSeq, input.ToSeq)
	if err != nil {
		return nil, err
	}
	if len(gaps) > 0 {
		report.Valid = false
		report.Gaps = gaps
	}

	// Get the events in the range.
	events, err := v.store.EventRange(ctx, input.StreamID, input.FromSeq, input.ToSeq)
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

		// Recompute the hash. Verify accepts the legacy scheme too, so events
		// written before the hash coverage was extended are not all reported as
		// tampered after an upgrade.
		if !v.chain.Verify(expectedPrevHash, event) {
			report.Valid = false
			report.Tampered = append(report.Tampered, event.Sequence)
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
