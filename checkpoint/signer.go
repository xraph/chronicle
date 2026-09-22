package checkpoint

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/xraph/chronicle/keys"
)

// AlgorithmEd25519 names the signature algorithm recorded on a checkpoint.
const AlgorithmEd25519 = "ed25519"

// Signer signs and verifies checkpoint payloads.
type Signer interface {
	// Sign returns the signature, the ID of the key used, and the algorithm.
	Sign(ctx context.Context, payload []byte) (sig []byte, keyID, alg string, err error)

	// Verify checks a signature against the key that made it.
	Verify(ctx context.Context, payload, sig []byte, keyID string) error

	// PublicKey returns the public half of a signing key, so an auditor can
	// check a checkpoint without holding anything secret.
	PublicKey(ctx context.Context, keyID string) ([]byte, error)
}

// Ed25519Signer signs checkpoints with an ed25519 key from a keys.Provider.
//
// Verification resolves the key through the provider by ID, so revoking a
// signing key invalidates every checkpoint it signed. That is deliberate and
// matches how revoking an hmac key invalidates the events it digested.
type Ed25519Signer struct {
	keys keys.Provider
}

// NewEd25519Signer creates a signer backed by the given provider.
func NewEd25519Signer(provider keys.Provider) *Ed25519Signer {
	return &Ed25519Signer{keys: provider}
}

// Sign signs payload with the provider's active checkpoint key.
func (s *Ed25519Signer) Sign(ctx context.Context, payload []byte) (sig []byte, keyID, alg string, err error) {
	material, keyID, err := s.keys.Current(ctx, keys.UseCheckpointSig)
	if err != nil {
		return nil, "", "", fmt.Errorf("checkpoint: resolve signing key: %w", err)
	}
	if len(material) != ed25519.PrivateKeySize {
		return nil, "", "", fmt.Errorf(
			"checkpoint: signing key %q is %d bytes, want %d",
			keyID, len(material), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(ed25519.PrivateKey(material), payload), keyID, AlgorithmEd25519, nil
}

// Verify checks sig against payload under the key named by keyID.
func (s *Ed25519Signer) Verify(ctx context.Context, payload, sig []byte, keyID string) error {
	pub, err := s.PublicKey(ctx, keyID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("checkpoint: signature does not verify under key %q", keyID)
	}
	return nil
}

// PublicKey derives the public half of a stored signing key.
func (s *Ed25519Signer) PublicKey(ctx context.Context, keyID string) ([]byte, error) {
	material, err := s.keys.ByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: resolve signing key %q: %w", keyID, err)
	}
	if len(material) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"checkpoint: signing key %q is %d bytes, want %d",
			keyID, len(material), ed25519.PrivateKeySize)
	}
	pub, ok := ed25519.PrivateKey(material).Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("checkpoint: signing key %q does not yield an ed25519 public key", keyID)
	}
	return pub, nil
}

// Compile-time check.
var _ Signer = (*Ed25519Signer)(nil)
