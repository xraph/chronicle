package crypto

import (
	"crypto/rand"
	"sync"

	"github.com/xraph/chronicle"
)

// KeyStore manages per-subject encryption keys.
type KeyStore interface {
	// GetOrCreate returns the key for a subject, creating one if it doesn't exist.
	GetOrCreate(subjectID string) ([]byte, string, error)

	// Get returns the key for a subject. Returns ErrErasureKeyNotFound if not found.
	Get(subjectID string) ([]byte, error)

	// Delete destroys the key for a subject, making encrypted data irrecoverable.
	Delete(subjectID string) error
}

// InMemoryKeyStore is an in-memory key store for testing.
type InMemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte // subjectID → 32-byte AES key
}

// NewInMemoryKeyStore creates a new InMemoryKeyStore.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		keys: make(map[string][]byte),
	}
}

func (ks *InMemoryKeyStore) GetOrCreate(subjectID string) (retKey []byte, retKeyID string, retErr error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if existing, ok := ks.keys[subjectID]; ok {
		return existing, subjectID, nil
	}

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return nil, "", err
	}
	ks.keys[subjectID] = newKey
	return newKey, subjectID, nil
}

func (ks *InMemoryKeyStore) Get(subjectID string) ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	key, ok := ks.keys[subjectID]
	if !ok {
		return nil, chronicle.ErrErasureKeyNotFound
	}
	return key, nil
}

func (ks *InMemoryKeyStore) Delete(subjectID string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	delete(ks.keys, subjectID)
	return nil
}
