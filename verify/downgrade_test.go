package verify_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/verify"
)

// stubProvider is a keys.Provider backed by a fixed key. It mirrors the one
// in hash/scheme_test.go; that copy lives in package hash_test and is not
// importable from here.
type stubProvider struct {
	key      []byte
	activeID string
}

func (s stubProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return s.key, s.activeID, nil
}

func (s stubProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != s.activeID {
		return nil, keys.ErrKeyNotFound
	}
	return s.key, nil
}

// fakeStore returns a fixed range of events.
type fakeStore struct{ events []*audit.Event }

func (f fakeStore) EventRange(_ context.Context, _ id.ID, _, _ uint64) ([]*audit.Event, error) {
	return f.events, nil
}
func (f fakeStore) Gaps(_ context.Context, _ id.ID, _, _ uint64) ([]uint64, error) {
	return nil, nil
}

func TestVerifyChainReportsDowngrade(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"} // mirror hash/scheme_test.go
	chain, err := hash.NewChain(hash.SchemeHMAC, provider)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	event := &audit.Event{
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Sequence:  10, Action: "login", Resource: "session", Category: "auth",
		Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
	}

	// The attacker recomputes under the weaker scheme and relabels the row.
	var plain hash.Chain
	digest, _, err := plain.Compute(ctx, "", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme = digest, string(hash.SchemePlain)

	v := verify.NewVerifierWithChain(fakeStore{events: []*audit.Event{event}}, chain)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: id.NewStreamID(),
		FromSeq:  1, ToSeq: 20,
		Pin: hash.Pin{Scheme: hash.SchemeHMAC, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if report.Valid {
		t.Error("a downgraded chain reported Valid")
	}
	if len(report.Downgrades) != 1 || report.Downgrades[0] != 10 {
		t.Errorf("Downgrades = %v, want [10]", report.Downgrades)
	}
}

// TestVerifyChainTolerantResolutionDoesNotInvalidate proves that a tolerant
// resolution alone — a pre-migration event with no recorded scheme, below the
// stream's pin — is noted but does not flip Valid to false the way a
// downgrade or a genuine tamper does.
func TestVerifyChainTolerantResolutionDoesNotInvalidate(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"}
	chain, err := hash.NewChain(hash.SchemeHMAC, provider)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	event := &audit.Event{
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Sequence:  5, Action: "login", Resource: "session", Category: "auth",
		Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
	}

	// A pre-migration row: computed under the plain scheme, no HashScheme
	// recorded, sitting below the pin's Since.
	var plain hash.Chain
	digest, _, err := plain.Compute(ctx, "", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme = digest, ""

	v := verify.NewVerifierWithChain(fakeStore{events: []*audit.Event{event}}, chain)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: id.NewStreamID(),
		FromSeq:  1, ToSeq: 20,
		Pin: hash.Pin{Scheme: hash.SchemeHMAC, Since: 100},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if !report.Valid {
		t.Error("a tolerant-only resolution flipped Valid to false")
	}
	if len(report.Tolerant) != 1 || report.Tolerant[0] != 5 {
		t.Errorf("Tolerant = %v, want [5]", report.Tolerant)
	}
	if len(report.Downgrades) != 0 {
		t.Errorf("Downgrades = %v, want none", report.Downgrades)
	}
}
