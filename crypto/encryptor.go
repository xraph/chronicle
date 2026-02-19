// Package crypto provides AES-256-GCM encryption for GDPR crypto-erasure.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Encryptor provides AES-256-GCM envelope encryption.
type Encryptor struct{}

// NewEncryptor creates a new Encryptor.
func NewEncryptor() *Encryptor {
	return &Encryptor{}
}

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
// The key must be 32 bytes (256 bits).
// Returns nonce + ciphertext (nonce is prepended).
func (e *Encryptor) Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext (nonce + encrypted data) using AES-256-GCM.
// The key must be 32 bytes (256 bits).
func (e *Encryptor) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("crypto: ciphertext too short")
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, encrypted, nil)
}
