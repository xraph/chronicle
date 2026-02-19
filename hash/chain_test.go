package hash_test

import (
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
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
