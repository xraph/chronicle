package keys_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xraph/chronicle/keys"
)

// writeKeyset writes a keyset file and returns its path.
func writeKeyset(t *testing.T, entries []map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.json")
	data, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatalf("marshal keyset: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write keyset: %v", err)
	}
	return path
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestFileProviderCurrentReturnsActiveKey(t *testing.T) {
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i)
	}
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-2026-09", "use": "hmac", "active": true, "material": b64(material)},
	})

	p, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	key, keyID, err := p.Current(context.Background(), keys.UseHMAC)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if keyID != "hmac-2026-09" {
		t.Errorf("keyID = %q, want %q", keyID, "hmac-2026-09")
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

// Rotation is the whole reason ByID exists: a retired key must still resolve so
// events written under it stay verifiable.
func TestFileProviderByIDResolvesRetiredKey(t *testing.T) {
	old, cur := make([]byte, 32), make([]byte, 32)
	old[0], cur[0] = 1, 2
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-old", "use": "hmac", "active": false, "material": b64(old)},
		{"id": "hmac-new", "use": "hmac", "active": true, "material": b64(cur)},
	})

	p, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	_, keyID, err := p.Current(context.Background(), keys.UseHMAC)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if keyID != "hmac-new" {
		t.Errorf("active keyID = %q, want hmac-new", keyID)
	}

	got, err := p.ByID(context.Background(), "hmac-old")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got[0] != 1 {
		t.Errorf("ByID returned the wrong key material")
	}
}

func TestFileProviderUnknownKeyID(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-1", "use": "hmac", "active": true, "material": b64(make([]byte, 32))},
	})
	p, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	if _, err := p.ByID(context.Background(), "nope"); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("ByID error = %v, want ErrKeyNotFound", err)
	}
}

func TestFileProviderNoActiveKeyForUse(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-1", "use": "hmac", "active": false, "material": b64(make([]byte, 32))},
	})
	p, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	if _, _, err := p.Current(context.Background(), keys.UseHMAC); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Errorf("Current error = %v, want ErrNoActiveKey", err)
	}
}

// A short HMAC key silently weakens every digest, so it is rejected at load
// time rather than at the first write.
func TestFileProviderRejectsShortHMACKey(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-1", "use": "hmac", "active": true, "material": b64(make([]byte, 16))},
	})
	if _, err := keys.NewFileProvider(path); err == nil {
		t.Fatal("NewFileProvider accepted a 16-byte HMAC key, want an error")
	}
}

func TestFileProviderRejectsTwoActiveKeysForOneUse(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "a", "use": "hmac", "active": true, "material": b64(make([]byte, 32))},
		{"id": "b", "use": "hmac", "active": true, "material": b64(make([]byte, 32))},
	})
	if _, err := keys.NewFileProvider(path); err == nil {
		t.Fatal("NewFileProvider accepted two active hmac keys, want an error")
	}
}

func TestFileProviderRejectsDuplicateKeyID(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "dup", "use": "hmac", "active": true, "material": b64(make([]byte, 32))},
		{"id": "dup", "use": "checkpoint-sig", "active": true, "material": b64(make([]byte, 32))},
	})
	if _, err := keys.NewFileProvider(path); err == nil {
		t.Fatal("NewFileProvider accepted a duplicate key ID across uses, want an error")
	}
}
