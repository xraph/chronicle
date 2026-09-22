package hash_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/keys"
)

// writeKeyset writes a keyset JSON file and returns its path.
func writeKeyset(t *testing.T, entries []map[string]any) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "keys.json")
	data, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatalf("marshal keyset: %v", err)
	}
	if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
		t.Fatalf("write keyset: %v", writeErr)
	}
	return path
}

func keyMaterial() string {
	return base64.StdEncoding.EncodeToString(make([]byte, keys.HMACKeySize))
}

// TestNewChainRefusesAKeysetWithNoActiveHMACKey is the regression test for a
// green boot followed by total write failure.
//
// The keyset here is structurally perfect: one key, right length, valid base64.
// It is simply not active. NewFileProvider has nothing to object to, and before
// this check NewChain had nothing to object to either, so the process started
// clean and then failed on every single Record. Startup is where this belongs.
func TestNewChainRefusesAKeysetWithNoActiveHMACKey(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-1", "use": "hmac", "active": false, "material": keyMaterial()},
	})

	provider, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider rejected a structurally valid keyset: %v", err)
	}

	_, err = hash.NewChain(hash.SchemeHMAC, provider)
	if err == nil {
		t.Fatal("NewChain accepted a provider with no active hmac key; every Record would fail at runtime")
	}
	if !errors.Is(err, keys.ErrNoActiveKey) {
		t.Fatalf("NewChain error = %v, want it to wrap keys.ErrNoActiveKey", err)
	}
}

// A misspelled use is the same failure wearing a different hat: the key is
// active, it just is not active for hmac.
func TestNewChainRefusesAMisspelledUse(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-1", "use": "hmca", "active": true, "material": keyMaterial()},
	})

	provider, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	if _, err := hash.NewChain(hash.SchemeHMAC, provider); err == nil {
		t.Fatal("NewChain accepted a keyset whose only key is filed under the wrong use")
	}
}

// The happy path still has to work, or the check above is just a new way to
// break startup.
func TestNewChainAcceptsAUsableKeyset(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-1", "use": "hmac", "active": true, "material": keyMaterial()},
		{"id": "hmac-0", "use": "hmac", "active": false, "material": keyMaterial()},
	})

	provider, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	chain, err := hash.NewChain(hash.SchemeHMAC, provider)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	if chain.Scheme() != hash.SchemeHMAC {
		t.Errorf("Scheme = %s, want %s", chain.Scheme(), hash.SchemeHMAC)
	}
}

// emptyKeyProvider resolves an active key ID with no material behind it, which
// a KMS-backed provider can do when a secret exists but is unset.
type emptyKeyProvider struct{}

func (emptyKeyProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return nil, "hmac-1", nil
}

func (emptyKeyProvider) ByID(_ context.Context, _ string) ([]byte, error) { return nil, nil }

// HMAC over a zero-length key is well defined and completely pointless: the
// digest is reproducible by anyone who knows the algorithm, which is the exact
// property the keyed scheme exists to remove.
func TestNewChainRefusesAnEmptyKey(t *testing.T) {
	if _, err := hash.NewChain(hash.SchemeHMAC, emptyKeyProvider{}); err == nil {
		t.Fatal("NewChain accepted an empty hmac key")
	}
}

// The plain scheme must not consult the provider at all: a deployment running
// unkeyed digests with a stale keys block in its config has nothing to resolve
// and no reason to fail.
func TestNewChainPlainIgnoresTheProvider(t *testing.T) {
	if _, err := hash.NewChain(hash.SchemePlain, emptyKeyProvider{}); err != nil {
		t.Fatalf("NewChain(plain): %v", err)
	}
	if _, err := hash.NewChain("", nil); err != nil {
		t.Fatalf("NewChain(default): %v", err)
	}
}
