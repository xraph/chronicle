package hash_test

import (
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
)

func TestComputeDeterministic(t *testing.T) {
	c := &hash.Chain{}
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	event := &audit.Event{
		Timestamp:  ts,
		Action:     "create",
		Resource:   "user",
		Category:   "auth",
		ResourceID: "usr-123",
		Outcome:    audit.OutcomeSuccess,
		Severity:   audit.SeverityInfo,
		Metadata:   map[string]any{"key": "value"},
	}

	h1 := c.Compute("", event)
	h2 := c.Compute("", event)

	if h1 != h2 {
		t.Errorf("hashes should be deterministic: %q != %q", h1, h2)
	}

	// SHA-256 hex is 64 characters.
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64", len(h1))
	}
}

func TestComputeChainLinkage(t *testing.T) {
	c := &hash.Chain{}
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	event1 := &audit.Event{
		Timestamp: ts,
		Action:    "create",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
	}
	hash1 := c.Compute("", event1)

	event2 := &audit.Event{
		Timestamp: ts.Add(time.Second),
		Action:    "update",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
	}
	hash2 := c.Compute(hash1, event2)

	event3 := &audit.Event{
		Timestamp: ts.Add(2 * time.Second),
		Action:    "delete",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
	}
	hash3 := c.Compute(hash2, event3)

	// All hashes must be different.
	if hash1 == hash2 {
		t.Error("hash1 should differ from hash2")
	}
	if hash2 == hash3 {
		t.Error("hash2 should differ from hash3")
	}

	// Hash 3 depends on hash 2 (and transitively on hash 1).
	hash3Alt := c.Compute("tampered", event3)
	if hash3 == hash3Alt {
		t.Error("hash3 should differ when prevHash changes")
	}
}

func TestComputeDifferentPrevHash(t *testing.T) {
	c := &hash.Chain{}
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	event := &audit.Event{
		Timestamp: ts,
		Action:    "create",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
	}

	h1 := c.Compute("abc", event)
	h2 := c.Compute("def", event)

	if h1 == h2 {
		t.Error("different prevHash should produce different hashes")
	}
}

func TestComputeEmptyMetadata(t *testing.T) {
	c := &hash.Chain{}
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	event1 := &audit.Event{
		Timestamp: ts,
		Action:    "create",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Metadata:  nil,
	}

	event2 := &audit.Event{
		Timestamp: ts,
		Action:    "create",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Metadata:  map[string]any{},
	}

	// nil and empty metadata should produce the same hash.
	h1 := c.Compute("", event1)
	h2 := c.Compute("", event2)

	if h1 != h2 {
		t.Errorf("nil and empty metadata should produce the same hash: %q != %q", h1, h2)
	}
}

func TestComputeMetadataKeyOrder(t *testing.T) {
	c := &hash.Chain{}
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	// Two events with same metadata in different insertion order.
	event1 := &audit.Event{
		Timestamp: ts,
		Action:    "create",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Metadata:  map[string]any{"b": 2, "a": 1, "c": 3},
	}

	event2 := &audit.Event{
		Timestamp: ts,
		Action:    "create",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Metadata:  map[string]any{"c": 3, "a": 1, "b": 2},
	}

	h1 := c.Compute("", event1)
	h2 := c.Compute("", event2)

	if h1 != h2 {
		t.Errorf("metadata key order should not affect hash: %q != %q", h1, h2)
	}
}

// ──────────────────────────────────────────────────
// Field coverage
// ──────────────────────────────────────────────────

// baseEvent returns a fully populated event for coverage tests.
func baseEvent() *audit.Event {
	return &audit.Event{
		StreamID:   id.NewStreamID(),
		Sequence:   7,
		AppID:      "app-1",
		TenantID:   "tenant-1",
		UserID:     "alice@corp",
		IP:         "203.0.113.10",
		Action:     "create",
		Resource:   "user",
		Category:   "auth",
		ResourceID: "usr-123",
		Outcome:    audit.OutcomeSuccess,
		Severity:   audit.SeverityInfo,
		Reason:     "operator request",
		SubjectID:  "subject-9",
		Metadata:   map[string]any{"key": "value"},
		Timestamp:  time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
	}
}

// TestComputeCoversEveryAttributableField pins that the tamper-evidence hash
// covers the fields most worth falsifying: who acted, from where, and under
// which tenant. Leaving any of them out lets an attacker rewrite that column
// and still have the chain verify as valid.
func TestComputeCoversEveryAttributableField(t *testing.T) {
	c := &hash.Chain{}

	mutations := map[string]func(e *audit.Event){
		"UserID":     func(e *audit.Event) { e.UserID = "innocent@corp" },
		"IP":         func(e *audit.Event) { e.IP = "10.0.0.1" },
		"AppID":      func(e *audit.Event) { e.AppID = "app-2" },
		"TenantID":   func(e *audit.Event) { e.TenantID = "tenant-2" },
		"Reason":     func(e *audit.Event) { e.Reason = "" },
		"SubjectID":  func(e *audit.Event) { e.SubjectID = "subject-other" },
		"Sequence":   func(e *audit.Event) { e.Sequence = 99 },
		"Action":     func(e *audit.Event) { e.Action = "delete" },
		"Resource":   func(e *audit.Event) { e.Resource = "admin" },
		"Category":   func(e *audit.Event) { e.Category = "system" },
		"ResourceID": func(e *audit.Event) { e.ResourceID = "usr-999" },
		"Outcome":    func(e *audit.Event) { e.Outcome = audit.OutcomeFailure },
		"Severity":   func(e *audit.Event) { e.Severity = audit.SeverityCritical },
		"Timestamp":  func(e *audit.Event) { e.Timestamp = e.Timestamp.Add(time.Hour) },
		"Metadata":   func(e *audit.Event) { e.Metadata = map[string]any{"key": "other"} },
	}

	original := c.Compute("prev", baseEvent())

	for field, mutate := range mutations {
		t.Run(field, func(t *testing.T) {
			tampered := baseEvent()
			mutate(tampered)

			if got := c.Compute("prev", tampered); got == original {
				t.Fatalf("rewriting %s did not change the hash, so tampering with it is undetectable", field)
			}
		})
	}
}

// TestVerifyAcceptsCurrentHash is the happy path for Verify.
func TestVerifyAcceptsCurrentHash(t *testing.T) {
	c := &hash.Chain{}
	event := baseEvent()
	event.Hash = c.Compute("prev", event)

	if !c.Verify("prev", event) {
		t.Fatal("Verify rejected a hash it had just computed")
	}
}

// TestVerifyRejectsTamperedActor is the attack the extended coverage prevents.
func TestVerifyRejectsTamperedActor(t *testing.T) {
	c := &hash.Chain{}
	event := baseEvent()
	event.Hash = c.Compute("prev", event)

	event.UserID = "innocent@corp"
	event.IP = "10.0.0.1"
	event.Reason = ""

	if c.Verify("prev", event) {
		t.Fatal("Verify accepted an event whose actor, IP and reason were rewritten")
	}
}

// TestVerifyAcceptsLegacyHash pins backward compatibility: events written before
// the coverage was extended must still verify, otherwise upgrading would report
// every historical event as tampered.
func TestVerifyAcceptsLegacyHash(t *testing.T) {
	c := &hash.Chain{}
	event := baseEvent()
	event.Hash = hash.ComputeLegacy("prev", event)

	if !c.Verify("prev", event) {
		t.Fatal("Verify rejected a legacy hash, which would flag all historical events as tampered")
	}
}

// TestLegacyAndCurrentHashesDiffer confirms the two schemes are distinguishable,
// which is what keeps the legacy fallback from weakening current events: a
// current-scheme event that is tampered cannot pass as a legacy one.
func TestLegacyAndCurrentHashesDiffer(t *testing.T) {
	c := &hash.Chain{}
	event := baseEvent()

	if c.Compute("prev", event) == hash.ComputeLegacy("prev", event) {
		t.Fatal("current and legacy hashes must differ")
	}
}

// TestVerifyRejectsTamperedActorOnLegacyEventUnderCurrentScheme documents the
// limit of the fallback: a legacy event's actor is not covered by its own hash,
// so tampering with it stays undetectable for pre-existing rows. New rows are
// protected because their stored hash is a current-scheme digest.
func TestLegacyFallbackDoesNotWeakenCurrentEvents(t *testing.T) {
	c := &hash.Chain{}
	event := baseEvent()
	event.Hash = c.Compute("prev", event) // current scheme

	event.UserID = "innocent@corp"

	// The tampered event must match neither scheme.
	if c.Compute("prev", event) == event.Hash {
		t.Fatal("current recompute matched after tampering")
	}
	if hash.ComputeLegacy("prev", event) == event.Hash {
		t.Fatal("legacy recompute matched a current-scheme hash, which would let tampering slip through")
	}
}
