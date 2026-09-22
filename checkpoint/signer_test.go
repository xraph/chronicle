package checkpoint_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
)

// stubProvider serves one ed25519 private key.
type stubProvider struct {
	key      ed25519.PrivateKey
	activeID string
	revoked  bool
}

func (s stubProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return s.key, s.activeID, nil
}

func (s stubProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != s.activeID {
		return nil, keys.ErrKeyNotFound
	}
	if s.revoked {
		return nil, keys.ErrKeyRevoked
	}
	return s.key, nil
}

// newSigner always receives revoked=false; TestVerifyRejectsARevokedKey builds
// its own revoked provider directly instead of going through this helper.
//
//nolint:unparam // revoked kept for symmetry with the stubProvider it configures.
func newSigner(t *testing.T, revoked bool) (*checkpoint.Ed25519Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return checkpoint.NewEd25519Signer(stubProvider{key: priv, activeID: "cp-1", revoked: revoked}), priv
}

func newCheckpoint() *checkpoint.Checkpoint {
	return &checkpoint.Checkpoint{
		ID:             id.NewCheckpointID(),
		StreamID:       id.NewStreamID(),
		AppID:          "app",
		TenantID:       "tenant",
		FromSeq:        1,
		ToSeq:          100,
		FromHash:       "aaaa",
		ToHash:         "bbbb",
		EventCount:     100,
		PrevCheckpoint: "",
		CreatedAt:      time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC),
	}
}

func TestCanonicalPayloadIsDeterministic(t *testing.T) {
	cp := newCheckpoint()
	//nolint:staticcheck // SA4000: two calls on the same *cp is the point, not a copy-paste bug.
	if checkpoint.CanonicalPayload(cp) != checkpoint.CanonicalPayload(cp) {
		t.Error("canonical payload is not deterministic")
	}
}

// Every field the checkpoint asserts must be covered, or an attacker edits the
// uncovered one and the signature still verifies.
func TestCanonicalPayloadCoversEveryAssertedField(t *testing.T) {
	base := checkpoint.CanonicalPayload(newCheckpoint())

	mutations := map[string]func(*checkpoint.Checkpoint){
		"StreamID":       func(c *checkpoint.Checkpoint) { c.StreamID = id.NewStreamID() },
		"AppID":          func(c *checkpoint.Checkpoint) { c.AppID = "other" },
		"TenantID":       func(c *checkpoint.Checkpoint) { c.TenantID = "other" },
		"FromSeq":        func(c *checkpoint.Checkpoint) { c.FromSeq = 2 },
		"ToSeq":          func(c *checkpoint.Checkpoint) { c.ToSeq = 101 },
		"FromHash":       func(c *checkpoint.Checkpoint) { c.FromHash = "cccc" },
		"ToHash":         func(c *checkpoint.Checkpoint) { c.ToHash = "cccc" },
		"EventCount":     func(c *checkpoint.Checkpoint) { c.EventCount = 99 },
		"PrevCheckpoint": func(c *checkpoint.Checkpoint) { c.PrevCheckpoint = "dddd" },
		"CreatedAt":      func(c *checkpoint.Checkpoint) { c.CreatedAt = c.CreatedAt.Add(time.Second) },
	}

	for name, mutate := range mutations {
		cp := newCheckpoint()
		mutate(cp)
		if checkpoint.CanonicalPayload(cp) == base {
			t.Errorf("%s is not covered by the canonical payload", name)
		}
	}
}

// A bare "|" join lets a separator inside a free-text field masquerade as a
// field boundary: AppID="a", TenantID="b|c" and AppID="a|b", TenantID="c"
// render identically unless each field's end is fixed independently of its
// content. AppID and TenantID are free text arriving from caller scope, so
// this is the reachable case, not a theoretical one.
func TestCanonicalPayloadIsUnambiguousAcrossFieldBoundaries(t *testing.T) {
	a := newCheckpoint()
	a.AppID = "a"
	a.TenantID = "b|c"

	b := newCheckpoint()
	b.StreamID = a.StreamID // isolate the boundary shift to AppID/TenantID
	b.AppID = "a|b"
	b.TenantID = "c"

	pa := checkpoint.CanonicalPayload(a)
	pb := checkpoint.CanonicalPayload(b)
	if pa == pb {
		t.Fatalf("AppID/TenantID pairs differing only in where the \"|\" falls "+
			"canonicalized to the same payload: %q", pa)
	}
}

func TestSignThenVerifyRoundTrips(t *testing.T) {
	ctx := context.Background()
	signer, _ := newSigner(t, false)
	cp := newCheckpoint()

	payload := checkpoint.CanonicalPayload(cp)
	sig, keyID, alg, err := signer.Sign(ctx, []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if keyID != "cp-1" {
		t.Errorf("keyID = %q, want cp-1", keyID)
	}
	if alg != checkpoint.AlgorithmEd25519 {
		t.Errorf("alg = %q, want %q", alg, checkpoint.AlgorithmEd25519)
	}

	if err := signer.Verify(ctx, []byte(payload), sig, keyID); err != nil {
		t.Errorf("Verify on a freshly signed payload: %v", err)
	}
}

// The point of signing: altering what was asserted invalidates the signature.
func TestVerifyRejectsAnAlteredPayload(t *testing.T) {
	ctx := context.Background()
	signer, _ := newSigner(t, false)
	cp := newCheckpoint()

	sig, keyID, _, err := signer.Sign(ctx, []byte(checkpoint.CanonicalPayload(cp)))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cp.ToHash = "tampered"
	if err := signer.Verify(ctx, []byte(checkpoint.CanonicalPayload(cp)), sig, keyID); err == nil {
		t.Fatal("Verify accepted a payload altered after signing")
	}
}

func TestVerifyRejectsAnUnknownKeyID(t *testing.T) {
	ctx := context.Background()
	signer, _ := newSigner(t, false)
	payload := []byte(checkpoint.CanonicalPayload(newCheckpoint()))

	sig, _, _, err := signer.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.Verify(ctx, payload, sig, "cp-does-not-exist"); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("Verify error = %v, want ErrKeyNotFound", err)
	}
}

// Revoking the signing key must invalidate every checkpoint it signed, the same
// way revoking an hmac key invalidates the events it digested.
func TestVerifyRejectsARevokedKey(t *testing.T) {
	ctx := context.Background()
	live, priv := newSigner(t, false)
	payload := []byte(checkpoint.CanonicalPayload(newCheckpoint()))
	sig, keyID, _, err := live.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	revoked := checkpoint.NewEd25519Signer(stubProvider{key: priv, activeID: keyID, revoked: true})
	if err := revoked.Verify(ctx, payload, sig, keyID); !errors.Is(err, keys.ErrKeyRevoked) {
		t.Errorf("Verify error = %v, want ErrKeyRevoked", err)
	}
}

// A third party must be able to check a signature without the private key.
func TestPublicKeyIsDerivableForThirdPartyVerification(t *testing.T) {
	ctx := context.Background()
	signer, priv := newSigner(t, false)

	pub, err := signer.PublicKey(ctx, "cp-1")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	payload := []byte(checkpoint.CanonicalPayload(newCheckpoint()))
	sig, _, _, err := signer.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		t.Error("stdlib ed25519.Verify rejected a signature the exported public key should validate")
	}
	if !ed25519.PublicKey(pub).Equal(priv.Public()) {
		t.Error("exported public key does not match the signing key")
	}
}

func TestSignerRejectsWrongSizedKeyMaterial(t *testing.T) {
	ctx := context.Background()
	signer := checkpoint.NewEd25519Signer(stubProvider{key: make([]byte, 7), activeID: "cp-1"})
	if _, _, _, err := signer.Sign(ctx, []byte("x")); err == nil {
		t.Fatal("Sign accepted 7-byte key material for ed25519")
	}
}

func TestDigestIsHexSHA256(t *testing.T) {
	d := checkpoint.Digest("payload")
	if len(d) != 64 {
		t.Errorf("digest length = %d, want 64", len(d))
	}
	if strings.ToLower(d) != d {
		t.Error("digest should be lowercase hex")
	}
	if checkpoint.Digest("payload") != d {
		t.Error("digest is not deterministic")
	}
}
