package chronicle_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
)

// chronicle_test.go has no shared store helper; it builds one inline at each
// call site. Match that rather than introducing one.

// Accepting the flag without a provider is how a deployment ends up believing
// its chain is keyed while writing plain digests.
func TestNewRefusesHMACWithoutKeyProvider(t *testing.T) {
	_, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(memory.New())),
		chronicle.WithDigestScheme(hash.SchemeHMACV5),
	)
	if !errors.Is(err, chronicle.ErrHMACKeyUnavailable) {
		t.Fatalf("New error = %v, want ErrHMACKeyUnavailable", err)
	}
}

func TestNewAcceptsHMACWithKeyProvider(t *testing.T) {
	key := make([]byte, 32)
	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(memory.New())),
		chronicle.WithDigestScheme(hash.SchemeHMACV5),
		chronicle.WithKeyProvider(stubProvider{key: key, activeID: "hmac-1"}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("New returned a nil Chronicle")
	}
}

func TestDefaultSchemeIsPlain(t *testing.T) {
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(memory.New())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("New returned a nil Chronicle")
	}
}

// A retired scheme has to be reported as retired, whether or not a key
// provider happens to be present.
//
// The keyed-scheme guard runs before hash.NewChain, so without the writability
// check it fired first on chronicle/v3 and sent the operator off to configure a
// key provider. They would add one, restart, and only then be told the scheme
// itself is gone. Two restarts to learn one fact.
func TestNewNamesTheReplacementForARetiredScheme(t *testing.T) {
	for _, tc := range []struct {
		scheme      hash.Scheme
		replacement hash.Scheme
	}{
		{hash.SchemePlain, hash.SchemePlainV4},
		{hash.SchemeHMAC, hash.SchemeHMACV5},
		{hash.SchemeLegacy, ""},
	} {
		_, err := chronicle.New(
			chronicle.WithStore(store.NewAdapter(memory.New())),
			chronicle.WithDigestScheme(tc.scheme),
		)
		if err == nil {
			t.Errorf("New(%s) succeeded; the scheme is verify-only", tc.scheme)
			continue
		}
		if errors.Is(err, chronicle.ErrHMACKeyUnavailable) {
			t.Errorf("New(%s) reported a missing key provider; the scheme is retired, "+
				"and adding a provider would not help", tc.scheme)
		}
		if tc.replacement != "" && !strings.Contains(err.Error(), string(tc.replacement)) {
			t.Errorf("New(%s) error %q does not name %s", tc.scheme, err, tc.replacement)
		}
	}
}
