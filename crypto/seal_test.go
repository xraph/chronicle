package crypto_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
)

func sealableEvent() *audit.Event {
	return &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  id.NewStreamID(),
		Sequence:  1,
		AppID:     "app-1",
		TenantID:  "tenant-1",
		UserID:    "operator@corp",
		IP:        "203.0.113.10",
		Action:    "export",
		Resource:  "user",
		Category:  "data",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Reason:    "subject access request",
		SubjectID: "subject-9",
		Metadata:  map[string]any{"email": "alice@example.com", "rows": float64(42)},
		Timestamp: time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC),
	}
}

func TestSealHidesPersonalPayload(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())
	event := sealableEvent()

	if err := sealer.Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if strings.Contains(event.Reason, "subject access request") {
		t.Errorf("Reason still holds plaintext: %q", event.Reason)
	}
	if strings.Contains(event.IP, "203.0.113.10") {
		t.Errorf("IP still holds plaintext: %q", event.IP)
	}
	if v, ok := event.Metadata["email"]; ok {
		t.Errorf("Metadata still holds plaintext email: %v", v)
	}
	if event.EncryptionKeyID == "" {
		t.Error("EncryptionKeyID should record which key sealed the event")
	}

	// The operational record must survive so the log stays useful.
	if event.Action != "export" || event.Category != "data" {
		t.Error("Seal must not touch the operational fields")
	}
	if event.SubjectID != "subject-9" {
		t.Error("SubjectID must stay readable; it is the erasure lookup key")
	}
	if event.UserID != "operator@corp" {
		t.Error("UserID identifies the actor and must stay queryable")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())
	original := sealableEvent()

	event := sealableEvent()
	event.ID = original.ID

	if err := sealer.Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := sealer.Open(event); err != nil {
		t.Fatalf("Open: %v", err)
	}

	if event.Reason != original.Reason {
		t.Errorf("Reason = %q, want %q", event.Reason, original.Reason)
	}
	if event.IP != original.IP {
		t.Errorf("IP = %q, want %q", event.IP, original.IP)
	}
	if event.Metadata["email"] != original.Metadata["email"] {
		t.Errorf("Metadata email = %v, want %v", event.Metadata["email"], original.Metadata["email"])
	}
	if event.Metadata["rows"] != original.Metadata["rows"] {
		t.Errorf("Metadata rows = %v, want %v", event.Metadata["rows"], original.Metadata["rows"])
	}
}

// TestDestroyingKeyMakesPayloadIrrecoverable is the guarantee the README makes.
func TestDestroyingKeyMakesPayloadIrrecoverable(t *testing.T) {
	keys := crypto.NewInMemoryKeyStore()
	sealer := crypto.NewSealer(keys)

	event := sealableEvent()
	if err := sealer.Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if err := keys.Delete(event.SubjectID); err != nil {
		t.Fatalf("Delete key: %v", err)
	}

	if err := sealer.Open(event); err != nil {
		t.Fatalf("Open after key destruction should not fail: %v", err)
	}

	if event.Reason != crypto.ErasedMarker {
		t.Errorf("Reason = %q, want %q", event.Reason, crypto.ErasedMarker)
	}
	if event.IP != crypto.ErasedMarker {
		t.Errorf("IP = %q, want %q", event.IP, crypto.ErasedMarker)
	}
	if event.Metadata != nil {
		t.Errorf("Metadata should be gone, got %v", event.Metadata)
	}
	if !event.Erased {
		t.Error("an event whose key is destroyed should report Erased")
	}

	// The operational record survives, which is the point of crypto-erasure.
	if event.Action != "export" || event.SubjectID != "subject-9" {
		t.Error("the operational record must outlive the erasure")
	}
}

// TestChainStillVerifiesAfterKeyDestruction is the constraint that dictates the
// whole design: the hash covers the *sealed* bytes, so destroying a key must not
// make a healthy chain report tampering. Hashing plaintext would have made every
// erased event look forged.
func TestChainStillVerifiesAfterKeyDestruction(t *testing.T) {
	keys := crypto.NewInMemoryKeyStore()
	sealer := crypto.NewSealer(keys)
	chain := &hash.Chain{}

	event := sealableEvent()
	if err := sealer.Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Hash is computed after sealing, exactly as Chronicle.Record does.
	event.Hash = chain.Compute("prev", event)

	if err := keys.Delete(event.SubjectID); err != nil {
		t.Fatalf("Delete key: %v", err)
	}

	// A verifier reads the stored form, which is unchanged by key destruction.
	if !chain.Verify("prev", event) {
		t.Fatal("chain verification failed after key destruction; " +
			"the digest must cover the sealed bytes, not the plaintext")
	}
}

// TestOpenedEventDoesNotVerify documents why reads and verification must not
// share a representation: an opened event no longer matches its stored digest.
func TestOpenedEventDoesNotVerify(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())
	chain := &hash.Chain{}

	event := sealableEvent()
	if err := sealer.Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	event.Hash = chain.Compute("prev", event)

	if err := sealer.Open(event); err != nil {
		t.Fatalf("Open: %v", err)
	}

	if chain.Verify("prev", event) {
		t.Fatal("an opened event should not match its stored digest; " +
			"if it did, the digest would be covering plaintext")
	}
}

func TestSealIsNoOpWithoutSubject(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())

	event := sealableEvent()
	event.SubjectID = ""
	before := *event

	if err := sealer.Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if event.Reason != before.Reason || event.IP != before.IP {
		t.Error("an event with no subject has no key to erase, so it must be left alone")
	}
	if event.EncryptionKeyID != "" {
		t.Error("EncryptionKeyID should stay empty for an unsealed event")
	}
}

func TestSealRejectsDoubleSealing(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())
	event := sealableEvent()

	if err := sealer.Seal(event); err != nil {
		t.Fatalf("first Seal: %v", err)
	}

	err := sealer.Seal(event)
	if err == nil {
		t.Fatal("sealing twice would bury the plaintext behind two keys")
	}
	if !errors.Is(err, crypto.ErrAlreadySealed) {
		t.Fatalf("error = %v, want ErrAlreadySealed", err)
	}
}

func TestOpenIsNoOpForUnsealedEvent(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())

	event := sealableEvent()
	before := *event

	if err := sealer.Open(event); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if event.Reason != before.Reason || event.IP != before.IP {
		t.Error("Open must leave an unsealed event untouched")
	}
}

func TestSealedValuesDifferPerEventEvenForSameSubject(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())

	first := sealableEvent()
	second := sealableEvent()

	if err := sealer.Seal(first); err != nil {
		t.Fatalf("Seal first: %v", err)
	}
	if err := sealer.Seal(second); err != nil {
		t.Fatalf("Seal second: %v", err)
	}

	// AES-GCM uses a fresh nonce per encryption, so identical plaintext must not
	// produce identical ciphertext; otherwise equal values would be linkable.
	if first.Reason == second.Reason {
		t.Error("identical plaintext produced identical ciphertext")
	}
}

func TestOpenAllStopsAtFirstFailure(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())

	good := sealableEvent()
	if err := sealer.Seal(good); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	corrupt := sealableEvent()
	if err := sealer.Seal(corrupt); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	corrupt.Reason = "enc:v1:not-valid-base64!!"

	if err := sealer.OpenAll([]*audit.Event{good, corrupt}); err == nil {
		t.Fatal("OpenAll should surface a corrupt sealed value")
	}
}

func TestIsSealedDetectsCiphertext(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())

	event := sealableEvent()
	if crypto.IsSealed(event) {
		t.Error("a fresh event should not report sealed")
	}

	if err := sealer.Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !crypto.IsSealed(event) {
		t.Error("a sealed event should report sealed")
	}
}
