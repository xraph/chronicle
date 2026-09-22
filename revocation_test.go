package chronicle_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/verify"
)

// keysetFileProvider writes a keyset to a temp file and loads it.
func keysetFileProvider(t *testing.T, entries []map[string]any) *keys.FileProvider {
	t.Helper()

	path := filepath.Join(t.TempDir(), "keys.json")
	data, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatalf("marshal keyset: %v", err)
	}
	if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
		t.Fatalf("write keyset: %v", writeErr)
	}

	p, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}
	return p
}

// forgeWithLeakedKey is the attack this file exists for: rewrite every event
// and re-sign the whole chain with a key the attacker holds, labelling each row
// with that key's ID.
//
// It reproduces hash.Chain's content layout rather than calling Compute,
// because Compute signs with whatever key the provider currently says is
// active, and the attacker is by definition not using that one.
func forgeWithLeakedKey(t *testing.T, events []*audit.Event, key []byte, keyID, newUserID string) {
	t.Helper()
	ctx := context.Background()

	// A chain built directly on a provider that still hands out the leaked key
	// is exactly what the attacker has: the algorithm ships in this repo, and
	// the key is the only thing that was ever secret.
	forger, err := hash.NewChain(hash.SchemeHMAC, fixedKeyProvider{key: key, id: keyID})
	if err != nil {
		t.Fatalf("build forging chain: %v", err)
	}

	events[0].UserID = newUserID
	for i := range events {
		if i > 0 {
			events[i].PrevHash = events[i-1].Hash
		}
		digest, resolvedID, computeErr := forger.Compute(ctx, events[i].PrevHash, events[i])
		if computeErr != nil {
			t.Fatalf("forge event %d: %v", i, computeErr)
		}
		events[i].Hash = digest
		events[i].HashScheme = string(hash.SchemeHMAC)
		events[i].HashKeyID = resolvedID
	}
}

// fixedKeyProvider always resolves the one key it was built with, under the one
// ID. It stands in for an attacker's copy of a leaked keyset.
type fixedKeyProvider struct {
	key []byte
	id  string
}

func (p fixedKeyProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return p.key, p.id, nil
}

func (p fixedKeyProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != p.id {
		return nil, keys.ErrKeyNotFound
	}
	return p.key, nil
}

// TestRetiringALeakedKeyDoesNotStopIt is the honest statement of what rotation
// alone buys you, committed deliberately the way
// TestPlainChainDoesNotDetectARewrite is.
//
// Rotation moves new writes onto a new key. It does nothing about the old one,
// because ByID still resolves it, which is the property that keeps genuinely
// old events verifying. So whoever holds the retired key can rewrite the whole
// chain, label every row with that key's ID, and get a clean report. Revocation
// is the remedy; see the test below.
func TestRetiringALeakedKeyDoesNotStopIt(t *testing.T) {
	ctx := context.Background()

	leaked := make([]byte, 32)
	leaked[0] = 1
	fresh := make([]byte, 32)
	fresh[0] = 2

	// Era 1: hmac-leaked is the active signing key.
	writing := keysetFileProvider(t, []map[string]any{
		{"id": "hmac-leaked", "use": "hmac", "active": true, "material": b64Key(leaked)},
	})
	c, events, streamID := seedChain(t, hash.SchemeHMAC, writing)

	forgeWithLeakedKey(t, events, leaked, "hmac-leaked", "attacker-was-here")
	persist(t, c, events)

	// Era 2: rotated away from the leaked key, but only retired, not revoked.
	verifier := reopenWithProvider(t, c, keysetFileProvider(t, []map[string]any{
		{"id": "hmac-fresh", "use": "hmac", "active": true, "material": b64Key(fresh)},
		{"id": "hmac-leaked", "use": "hmac", "active": false, "material": b64Key(leaked)},
	}))

	report, err := verifier.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemeHMAC, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("a rewrite signed with a merely retired key was detected: "+
			"gaps=%v tampered=%v downgrades=%v. If retirement now revokes, that is a real "+
			"change in the product's guarantee and this test failing is how you find out",
			report.Gaps, report.Tampered, report.Downgrades)
	}
}

// TestRevokingALeakedKeyStopsIt is the fix.
//
// Same forged chain, same rotation, one difference: the leaked key is marked
// revoked in the keyset. Verification now refuses to resolve it at all, so the
// report is an error rather than a green tick. Erroring is the right outcome,
// not a silent false: nothing can distinguish a row the attacker signed from
// one the deployment signed before the compromise, so the honest answer is that
// this segment no longer proves anything.
func TestRevokingALeakedKeyStopsIt(t *testing.T) {
	ctx := context.Background()

	leaked := make([]byte, 32)
	leaked[0] = 1
	fresh := make([]byte, 32)
	fresh[0] = 2

	writing := keysetFileProvider(t, []map[string]any{
		{"id": "hmac-leaked", "use": "hmac", "active": true, "material": b64Key(leaked)},
	})
	c, events, streamID := seedChain(t, hash.SchemeHMAC, writing)

	forgeWithLeakedKey(t, events, leaked, "hmac-leaked", "attacker-was-here")
	persist(t, c, events)

	verifier := reopenWithProvider(t, c, keysetFileProvider(t, []map[string]any{
		{"id": "hmac-fresh", "use": "hmac", "active": true, "material": b64Key(fresh)},
		{"id": "hmac-leaked", "use": "hmac", "active": false, "revoked": true, "material": b64Key(leaked)},
	}))

	report, err := verifier.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemeHMAC, Since: 1},
	})
	if err == nil {
		t.Fatalf("VerifyChain accepted a chain signed with a revoked key: valid=%v tampered=%v downgrades=%v",
			report.Valid, report.Tampered, report.Downgrades)
	}
	if !errors.Is(err, keys.ErrKeyRevoked) {
		t.Fatalf("VerifyChain error = %v, want it to wrap keys.ErrKeyRevoked", err)
	}
}

// reopenWithProvider builds a second Chronicle over the same store under a
// different key provider, which is what a restart after rotation looks like.
func reopenWithProvider(t *testing.T, c *chronicle.Chronicle, provider keys.Provider) *chronicle.Chronicle {
	t.Helper()

	reopened, err := chronicle.New(
		chronicle.WithStore(c.Store()),
		chronicle.WithDigestScheme(hash.SchemeHMAC),
		chronicle.WithKeyProvider(provider),
	)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	return reopened
}

func b64Key(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
