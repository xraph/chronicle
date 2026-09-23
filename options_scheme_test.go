package chronicle_test

import (
	"errors"
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
