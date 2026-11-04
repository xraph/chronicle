package backendtest_test

import (
	"context"
	"sort"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/verify"
)

// The helpers below are copies of ones the root package's tests still use
// (pin_advance_test.go, retention_chain_test.go, retention_backfill_test.go and
// tamper_test.go). The tests here live in their own module so the root never
// depends on a database driver, so they can't share those files.

// rotatingProvider is a keys.Provider over a fixed set of keys: Current
// resolves the active one and ByID resolves any of them.
type rotatingProvider struct {
	keys     map[string][]byte
	activeID string
}

func (p *rotatingProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	key, ok := p.keys[p.activeID]
	if !ok {
		return nil, "", keys.ErrNoActiveKey
	}
	return key, p.activeID, nil
}

func (p *rotatingProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, keys.ErrKeyNotFound
	}
	return key, nil
}

var _ keys.Provider = (*rotatingProvider)(nil)

func hmacProvider() *rotatingProvider {
	return &rotatingProvider{
		keys:     map[string][]byte{"k1": []byte("0123456789abcdef0123456789abcdef")},
		activeID: "k1",
	}
}

// openPinChronicle builds a Chronicle over an already-existing store, the way
// a restart under a new configuration does.
func openPinChronicle(t *testing.T, s chronicle.Storer, scheme hash.Scheme, provider keys.Provider) *chronicle.Chronicle {
	t.Helper()

	opts := []chronicle.Option{
		chronicle.WithStore(s),
		chronicle.WithDigestScheme(scheme),
	}
	if provider != nil {
		opts = append(opts, chronicle.WithKeyProvider(provider))
	}

	c, err := chronicle.New(opts...)
	if err != nil {
		t.Fatalf("New (%s): %v", scheme, err)
	}
	return c
}

// retainedSeqs flattens a report's retained ranges into sorted sequences.
func retainedSeqs(r *verify.Report) []uint64 {
	var out []uint64
	for _, rr := range r.Retained {
		for s := rr.FromSeq; s <= rr.ToSeq; s++ {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sameSeqs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func recoveredSeqs(r *chronicle.BackfillReport) []uint64 {
	out := make([]uint64, 0, len(r.Recovered))
	for _, rec := range r.Recovered {
		out = append(out, rec.Seq)
	}
	return out
}
