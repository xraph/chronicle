package keys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// FileProvider reads a keyset from a JSON file at construction time.
//
// The file holds every key the deployment has used, with exactly one marked
// active per use. Rotating is adding a key and moving the active flag; the
// retired entry stays so its events keep verifying.
//
//	{
//	  "keys": [
//	    {"id": "hmac-2026-09", "use": "hmac", "active": true,  "material": "<base64>"},
//	    {"id": "hmac-2026-03", "use": "hmac", "active": false, "material": "<base64>"},
//	    {"id": "hmac-2025-11", "use": "hmac", "active": false, "revoked": true, "material": "<base64>"}
//	  ]
//	}
//
// The third entry is a revoked key, and it is not the same thing as the second.
// See the package doc: retiring stops new writes, revoking invalidates
// everything the key ever signed. Keep the material in the file when you revoke
// rather than deleting the entry, so an artifact naming that key is reported as
// revoked rather than as an unknown key ID.
//
// It is read once and held in memory. Rotating requires a restart, which is a
// deliberate limit: reloading under a running chain would let a digest be
// written under a key that verification later cannot find.
type FileProvider struct {
	byID     map[string][]byte
	revoked  map[string]bool
	activeID map[Use]string
}

type keysetFile struct {
	Keys []keysetEntry `json:"keys"`
}

type keysetEntry struct {
	ID       string `json:"id"`
	Use      Use    `json:"use"`
	Active   bool   `json:"active"`
	Revoked  bool   `json:"revoked"`
	Material string `json:"material"`
}

// NewFileProvider loads and validates a keyset file.
//
// Validation happens here rather than at first use so a malformed keyset stops
// the process at startup instead of at the first audit event.
func NewFileProvider(path string) (*FileProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keys: read keyset %q: %w", path, err)
	}

	var file keysetFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("keys: parse keyset %q: %w", path, err)
	}
	if len(file.Keys) == 0 {
		return nil, fmt.Errorf("keys: keyset %q contains no keys", path)
	}

	p := &FileProvider{
		byID:     make(map[string][]byte, len(file.Keys)),
		revoked:  make(map[string]bool),
		activeID: make(map[Use]string),
	}

	for _, entry := range file.Keys {
		if entry.ID == "" {
			return nil, fmt.Errorf("keys: keyset %q has a key with no id", path)
		}
		if _, dup := p.byID[entry.ID]; dup {
			return nil, fmt.Errorf("keys: keyset %q repeats key id %q", path, entry.ID)
		}

		material, decErr := base64.StdEncoding.DecodeString(entry.Material)
		if decErr != nil {
			return nil, fmt.Errorf("keys: key %q material is not base64: %w", entry.ID, decErr)
		}
		if entry.Use == UseHMAC && len(material) != HMACKeySize {
			return nil, fmt.Errorf(
				"keys: key %q is %d bytes; a %s key must be %d",
				entry.ID, len(material), UseHMAC, HMACKeySize)
		}
		if entry.Use == UseCheckpointSig && len(material) != Ed25519KeySize {
			return nil, fmt.Errorf(
				"keys: key %q is %d bytes; a %s key must be %d",
				entry.ID, len(material), UseCheckpointSig, Ed25519KeySize)
		}

		if entry.Active && entry.Revoked {
			return nil, fmt.Errorf(
				"keys: key %q in keyset %q is marked both active and revoked; "+
					"a revoked key must not sign anything new", entry.ID, path)
		}

		p.byID[entry.ID] = material
		if entry.Revoked {
			p.revoked[entry.ID] = true
		}

		if entry.Active {
			if existing, ok := p.activeID[entry.Use]; ok {
				return nil, fmt.Errorf(
					"keys: keyset %q marks both %q and %q active for use %q",
					path, existing, entry.ID, entry.Use)
			}
			p.activeID[entry.Use] = entry.ID
		}
	}

	return p, nil
}

// Current returns the active key for a use.
func (p *FileProvider) Current(_ context.Context, use Use) (key []byte, keyID string, err error) {
	keyID, ok := p.activeID[use]
	if !ok {
		return nil, "", fmt.Errorf("%w: %s", ErrNoActiveKey, use)
	}
	return p.byID[keyID], keyID, nil
}

// ByID returns a key by ID, whether or not it is still active.
//
// Retired keys resolve, because that is what makes rotation work. Revoked keys
// do not: they are refused with ErrKeyRevoked, so an artifact naming a leaked
// key fails verification instead of passing it.
func (p *FileProvider) ByID(_ context.Context, keyID string) (key []byte, err error) {
	key, ok := p.byID[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	if p.revoked[keyID] {
		return nil, fmt.Errorf("%w: %s", ErrKeyRevoked, keyID)
	}
	return key, nil
}

// Compile-time check.
var _ Provider = (*FileProvider)(nil)
