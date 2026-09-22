package memory

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

func TestEventSchemeFieldsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := New()

	eventID := id.NewAuditID()
	if err := s.Append(ctx, &audit.Event{
		ID:         eventID,
		Timestamp:  time.Now().UTC(),
		Sequence:   1,
		Hash:       "abc",
		AppID:      "app",
		Action:     "login",
		Resource:   "session",
		Category:   "auth",
		Outcome:    audit.OutcomeSuccess,
		Severity:   audit.SeverityInfo,
		HashScheme: "chronicle/v3",
		HashKeyID:  "hmac-1",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := s.Get(ctx, eventID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HashScheme != "chronicle/v3" {
		t.Errorf("HashScheme = %q, want chronicle/v3", got.HashScheme)
	}
	if got.HashKeyID != "hmac-1" {
		t.Errorf("HashKeyID = %q, want hmac-1", got.HashKeyID)
	}
}

// Backends speak stream.Stream. chronicle.StreamInfo is the adapter's language;
// see store/adapter_test.go for that side.
func TestStreamSchemePinRoundTrips(t *testing.T) {
	ctx := context.Background()
	s := New()

	st := &stream.Stream{
		ID:          id.NewStreamID(),
		AppID:       "app",
		TenantID:    "tenant",
		Scheme:      "chronicle/v3",
		SchemeSince: 84301,
	}
	if err := s.CreateStream(ctx, st); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	got, err := s.GetStreamByScope(ctx, "app", "tenant")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	if got.Scheme != "chronicle/v3" {
		t.Errorf("Scheme = %q, want chronicle/v3", got.Scheme)
	}
	if got.SchemeSince != 84301 {
		t.Errorf("SchemeSince = %d, want 84301", got.SchemeSince)
	}
}

// TestUpdateStreamSchemeMovesThePin covers the write path that turning a
// stronger digest on depends on. Without it the pin written at creation is the
// only pin a stream ever has, and every stream that predates the change keeps
// advertising the weaker scheme while keyed events land in it.
func TestUpdateStreamSchemeMovesThePin(t *testing.T) {
	ctx := context.Background()
	s := New()

	st := &stream.Stream{
		ID:          id.NewStreamID(),
		AppID:       "app",
		TenantID:    "tenant",
		Scheme:      "chronicle/v2",
		SchemeSince: 1,
	}
	if err := s.CreateStream(ctx, st); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	if err := s.UpdateStreamScheme(ctx, st.ID, "chronicle/v3", 42); err != nil {
		t.Fatalf("UpdateStreamScheme: %v", err)
	}

	got, err := s.GetStream(ctx, st.ID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.Scheme != "chronicle/v3" || got.SchemeSince != 42 {
		t.Errorf("pin = %s from %d, want chronicle/v3 from 42", got.Scheme, got.SchemeSince)
	}

	if err := s.UpdateStreamScheme(ctx, id.NewStreamID(), "chronicle/v3", 1); err == nil {
		t.Error("UpdateStreamScheme on an unknown stream returned nil; a silent no-op would hide a lost pin")
	}
}
