package crypto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
)

// sealPrefix marks a field value as ciphertext produced by [Sealer.Seal].
//
// The version segment lets the encoding change later without misreading old
// rows, and the prefix makes double-sealing detectable.
const sealPrefix = "enc:v1:"

// sealedMetadataKey holds the ciphertext of a sealed metadata map. The map
// itself stays a map so the column type does not change.
const sealedMetadataKey = "__chronicle_sealed"

// ErasedMarker replaces a sealed value whose key has been destroyed.
const ErasedMarker = "[ERASED]"

// ErrAlreadySealed is returned when sealing an event that already carries
// ciphertext, which would make the original unrecoverable behind two layers.
var ErrAlreadySealed = errors.New("crypto: event is already sealed")

// Sealer encrypts and decrypts the personal payload of an audit event using a
// per-subject key, which is what makes crypto-erasure work: destroy the key and
// the payload is unrecoverable while the event's shape and hash chain survive.
//
// Sealed fields are Metadata, Reason and IP. Deliberately left in plaintext:
//
//   - SubjectID, because it is the lookup key used to find a subject's events in
//     order to erase them, and to prove afterwards that they were erased.
//   - UserID, because it identifies the actor rather than the data subject, and
//     because the per-user index and ByUser lookups depend on it.
//   - Action, Resource, Category, Outcome, Severity, ResourceID and the
//     timestamps, because they are the operational record that must outlive an
//     erasure, and queries and compliance reports group on them.
//
// So an erasure destroys what was recorded about a subject, not the fact that an
// event involving them occurred. That is the intended posture for an audit log,
// and callers should not read more into it than that.
type Sealer struct {
	keys      KeyStore
	encryptor *Encryptor
}

// NewSealer creates a Sealer backed by the given key store.
func NewSealer(keys KeyStore) *Sealer {
	return &Sealer{keys: keys, encryptor: NewEncryptor()}
}

// Seal encrypts the event's personal payload in place and records which key was
// used.
//
// It is a no-op for an event with no SubjectID: there is no subject to key the
// encryption to, and a key that is never destroyed protects nothing.
//
// Callers must Seal before computing the event's hash. Hashing the plaintext
// would make the chain unverifiable the moment a key is destroyed, because the
// original bytes needed to recompute the digest would be gone.
func (s *Sealer) Seal(event *audit.Event) error {
	if event.SubjectID == "" {
		return nil
	}
	if IsSealed(event) {
		return ErrAlreadySealed
	}

	key, keyID, err := s.keys.GetOrCreate(event.SubjectID)
	if err != nil {
		return fmt.Errorf("crypto: resolve key for subject %q: %w", event.SubjectID, err)
	}

	if event.Reason != "" {
		event.Reason, err = s.sealString(key, event.Reason)
		if err != nil {
			return fmt.Errorf("crypto: seal reason: %w", err)
		}
	}

	if event.IP != "" {
		event.IP, err = s.sealString(key, event.IP)
		if err != nil {
			return fmt.Errorf("crypto: seal ip: %w", err)
		}
	}

	if len(event.Metadata) > 0 {
		plaintext, marshalErr := json.Marshal(event.Metadata)
		if marshalErr != nil {
			return fmt.Errorf("crypto: marshal metadata: %w", marshalErr)
		}

		sealed, sealErr := s.sealBytes(key, plaintext)
		if sealErr != nil {
			return fmt.Errorf("crypto: seal metadata: %w", sealErr)
		}
		event.Metadata = map[string]any{sealedMetadataKey: sealed}
	}

	event.EncryptionKeyID = keyID
	return nil
}

// Open decrypts a sealed event in place.
//
// When the subject's key has been destroyed, the sealed fields are replaced with
// [ErasedMarker] and the event is flagged Erased, rather than returning an error:
// a destroyed key is the expected end state of an erasure, not a failure, and the
// remaining record still has to be readable.
//
// Open must not be used on events destined for hash verification. The stored
// bytes are what the digest covers, so a verifier has to see the sealed form.
func (s *Sealer) Open(event *audit.Event) error {
	if event.EncryptionKeyID == "" {
		return nil
	}

	// KeyStore is keyed by subject: erasure destroys a subject's key, so that is
	// what a lookup has to ask for. EncryptionKeyID records only that the event
	// was sealed, and with which key generation.
	subject := event.SubjectID
	if subject == "" {
		subject = event.EncryptionKeyID
	}

	key, err := s.keys.Get(subject)
	if err != nil {
		if errors.Is(err, chronicle.ErrErasureKeyNotFound) {
			markErased(event)
			return nil
		}
		return fmt.Errorf("crypto: resolve key for subject %q: %w", subject, err)
	}

	if isSealedString(event.Reason) {
		event.Reason, err = s.openString(key, event.Reason)
		if err != nil {
			return fmt.Errorf("crypto: open reason: %w", err)
		}
	}

	if isSealedString(event.IP) {
		event.IP, err = s.openString(key, event.IP)
		if err != nil {
			return fmt.Errorf("crypto: open ip: %w", err)
		}
	}

	if sealed, ok := sealedMetadata(event.Metadata); ok {
		plaintext, openErr := s.openBytes(key, sealed)
		if openErr != nil {
			return fmt.Errorf("crypto: open metadata: %w", openErr)
		}

		var metadata map[string]any
		if unmarshalErr := json.Unmarshal(plaintext, &metadata); unmarshalErr != nil {
			return fmt.Errorf("crypto: unmarshal metadata: %w", unmarshalErr)
		}
		event.Metadata = metadata
	}

	return nil
}

// OpenAll decrypts each event in place, stopping at the first hard failure.
func (s *Sealer) OpenAll(events []*audit.Event) error {
	for _, event := range events {
		if event == nil {
			continue
		}
		if err := s.Open(event); err != nil {
			return err
		}
	}
	return nil
}

// IsSealed reports whether any of the event's payload fields hold ciphertext.
func IsSealed(event *audit.Event) bool {
	if isSealedString(event.Reason) || isSealedString(event.IP) {
		return true
	}
	_, ok := sealedMetadata(event.Metadata)
	return ok
}

func (s *Sealer) sealString(key []byte, plaintext string) (string, error) {
	return s.sealBytes(key, []byte(plaintext))
}

func (s *Sealer) sealBytes(key, plaintext []byte) (string, error) {
	ciphertext, err := s.encryptor.Encrypt(key, plaintext)
	if err != nil {
		return "", err
	}
	return sealPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *Sealer) openString(key []byte, sealed string) (string, error) {
	plaintext, err := s.openBytes(key, sealed)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (s *Sealer) openBytes(key []byte, sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, sealPrefix))
	if err != nil {
		return nil, fmt.Errorf("decode sealed value: %w", err)
	}
	return s.encryptor.Decrypt(key, raw)
}

// markErased replaces every sealed field with the erased marker.
func markErased(event *audit.Event) {
	if isSealedString(event.Reason) {
		event.Reason = ErasedMarker
	}
	if isSealedString(event.IP) {
		event.IP = ErasedMarker
	}
	if _, ok := sealedMetadata(event.Metadata); ok {
		event.Metadata = nil
	}
	event.Erased = true
}

func isSealedString(v string) bool {
	return strings.HasPrefix(v, sealPrefix)
}

// sealedMetadata returns the ciphertext of a sealed metadata map, if it is one.
func sealedMetadata(m map[string]any) (string, bool) {
	if len(m) != 1 {
		return "", false
	}
	v, ok := m[sealedMetadataKey]
	if !ok {
		return "", false
	}
	sealed, ok := v.(string)
	if !ok || !isSealedString(sealed) {
		return "", false
	}
	return sealed, true
}
