package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/crypto"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc := crypto.NewEncryptor()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("sensitive user data that needs protection")

	ciphertext, err := enc.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	enc := crypto.NewEncryptor()

	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1 // different key

	ciphertext, err := enc.Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = enc.Decrypt(key2, ciphertext)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestEncryptDifferentNonces(t *testing.T) {
	enc := crypto.NewEncryptor()

	key := make([]byte, 32)
	plaintext := []byte("same data")

	c1, err := enc.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}

	c2, err := enc.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	// Same plaintext+key should produce different ciphertext due to random nonce.
	if bytes.Equal(c1, c2) {
		t.Error("encrypting same data twice should produce different ciphertext")
	}
}

func TestKeyStoreGetOrCreate(t *testing.T) {
	ks := crypto.NewInMemoryKeyStore()

	key1, keyID1, err := ks.GetOrCreate("subject-1")
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
	if keyID1 != "subject-1" {
		t.Errorf("keyID = %q, want %q", keyID1, "subject-1")
	}

	// Second call should return same key.
	key2, _, err := ks.GetOrCreate("subject-1")
	if err != nil {
		t.Fatalf("GetOrCreate second: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("GetOrCreate should return same key for same subject")
	}
}

func TestKeyStoreGet(t *testing.T) {
	ks := crypto.NewInMemoryKeyStore()

	_, err := ks.Get("nonexistent")
	if !errors.Is(err, chronicle.ErrErasureKeyNotFound) {
		t.Errorf("expected ErrErasureKeyNotFound, got: %v", err)
	}

	key, _, err := ks.GetOrCreate("subject-1")
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}

	got, err := ks.Get("subject-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("Get should return the same key as GetOrCreate")
	}
}

func TestKeyStoreDelete(t *testing.T) {
	ks := crypto.NewInMemoryKeyStore()

	_, _, err := ks.GetOrCreate("subject-1")
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}

	err = ks.Delete("subject-1")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = ks.Get("subject-1")
	if !errors.Is(err, chronicle.ErrErasureKeyNotFound) {
		t.Errorf("expected ErrErasureKeyNotFound after delete, got: %v", err)
	}
}

func TestErasureMakesDataIrrecoverable(t *testing.T) {
	enc := crypto.NewEncryptor()
	ks := crypto.NewInMemoryKeyStore()

	// Encrypt data.
	key, _, err := ks.GetOrCreate("user-42")
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}

	ciphertext, err := enc.Encrypt(key, []byte("user PII data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Verify we can decrypt before erasure.
	_, err = enc.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt before erasure: %v", err)
	}

	// Erase: delete key.
	err = ks.Delete("user-42")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Try to get key after erasure.
	_, err = ks.Get("user-42")
	if !errors.Is(err, chronicle.ErrErasureKeyNotFound) {
		t.Errorf("expected ErrErasureKeyNotFound, got: %v", err)
	}
}
