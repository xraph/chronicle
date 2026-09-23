package crypto

import (
	"crypto/rand"
	"sync"

	"github.com/xraph/chronicle"
)

// KeyStore holds the encryption keys crypto-erasure destroys.
//
// Every method takes an opaque key ID. [Sealer] builds it with [ScopedKeyID],
// so each (app, tenant, subject) gets its own key and erasing a subject in one
// scope cannot touch another. Implementations must store and compare the ID as
// given, byte for byte, and must not parse it or assume it is a subject ID.
//
// Events sealed before keys were scoped used the bare subject ID as the key ID.
// Those keys live in the same store under that name, and [Sealer.Open] still
// asks for them by it, so an existing durable key store keeps working across
// the upgrade without moving a single key. See the erasure package for what
// erasing such a key does when more than one scope depends on it.
//
// The ID space is shared between the two forms. That is safe because a scoped
// ID always starts with "ck1|" followed by a length, and nothing new is ever
// sealed under a legacy ID.
type KeyStore interface {
	// GetOrCreate returns the key stored under keyID, creating one if none
	// exists. The returned ID is informational: Sealer records keyID itself,
	// because keyID is what a later Get has to ask for.
	GetOrCreate(keyID string) ([]byte, string, error)

	// Get returns the key stored under keyID, or ErrErasureKeyNotFound.
	Get(keyID string) ([]byte, error)

	// Delete destroys the key stored under keyID, making everything sealed
	// with it irrecoverable. Deleting a key that does not exist is not an error.
	Delete(keyID string) error
}

// InMemoryKeyStore is an in-memory key store for testing.
type InMemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte // key ID to 32-byte AES key
}

// NewInMemoryKeyStore creates a new InMemoryKeyStore.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		keys: make(map[string][]byte),
	}
}

func (ks *InMemoryKeyStore) GetOrCreate(keyID string) (retKey []byte, retKeyID string, retErr error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if existing, ok := ks.keys[keyID]; ok {
		return existing, keyID, nil
	}

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return nil, "", err
	}
	ks.keys[keyID] = newKey
	return newKey, keyID, nil
}

func (ks *InMemoryKeyStore) Get(keyID string) ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	key, ok := ks.keys[keyID]
	if !ok {
		return nil, chronicle.ErrErasureKeyNotFound
	}
	return key, nil
}

func (ks *InMemoryKeyStore) Delete(keyID string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	delete(ks.keys, keyID)
	return nil
}
