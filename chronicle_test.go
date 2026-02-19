package chronicle_test

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

func newTestChronicle(t *testing.T) *chronicle.Chronicle {
	t.Helper()
	s := store.NewAdapter(memory.New())
	c, err := chronicle.New(chronicle.WithStore(s))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestRecordValidation(t *testing.T) {
	c := newTestChronicle(t)

	tests := []struct {
		name    string
		event   *audit.Event
		wantErr bool
	}{
		{
			name: "valid event",
			event: &audit.Event{
				Action:   "create",
				Resource: "user",
				Category: "auth",
			},
			wantErr: false,
		},
		{
			name: "missing action",
			event: &audit.Event{
				Resource: "user",
				Category: "auth",
			},
			wantErr: true,
		},
		{
			name: "missing resource",
			event: &audit.Event{
				Action:   "create",
				Category: "auth",
			},
			wantErr: true,
		},
		{
			name: "missing category",
			event: &audit.Event{
				Action:   "create",
				Resource: "user",
			},
			wantErr: true,
		},
		{
			name:    "all missing",
			event:   &audit.Event{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.Record(context.Background(), tt.event)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, chronicle.ErrInvalidQuery) {
				t.Errorf("expected ErrInvalidQuery, got: %v", err)
			}
		})
	}
}

func TestRecordAssignsIDAndTimestamp(t *testing.T) {
	c := newTestChronicle(t)

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err := c.Record(context.Background(), event)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if event.ID.String() == "" {
		t.Error("expected ID to be assigned")
	}
	if event.Timestamp.IsZero() {
		t.Error("expected Timestamp to be assigned")
	}
}

func TestRecordAssignsHashChain(t *testing.T) {
	c := newTestChronicle(t)

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err := c.Record(context.Background(), event)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if event.Hash == "" {
		t.Error("expected Hash to be assigned")
	}
	if event.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1 (genesis)", event.Sequence)
	}
	if event.PrevHash != "" {
		t.Errorf("PrevHash = %q, want empty for genesis", event.PrevHash)
	}
	if event.StreamID.String() == "" {
		t.Error("expected StreamID to be assigned")
	}
}

func TestRecordChainLinkage(t *testing.T) {
	c := newTestChronicle(t)

	event1 := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenant1",
	}
	err := c.Record(context.Background(), event1)
	if err != nil {
		t.Fatalf("Record event1: %v", err)
	}

	event2 := &audit.Event{
		Action:   "update",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenant1",
	}
	err = c.Record(context.Background(), event2)
	if err != nil {
		t.Fatalf("Record event2: %v", err)
	}

	event3 := &audit.Event{
		Action:   "delete",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenant1",
	}
	err = c.Record(context.Background(), event3)
	if err != nil {
		t.Fatalf("Record event3: %v", err)
	}

	// Chain linkage: event2.PrevHash == event1.Hash, event3.PrevHash == event2.Hash.
	if event2.PrevHash != event1.Hash {
		t.Errorf("event2.PrevHash = %q, want event1.Hash = %q", event2.PrevHash, event1.Hash)
	}
	if event3.PrevHash != event2.Hash {
		t.Errorf("event3.PrevHash = %q, want event2.Hash = %q", event3.PrevHash, event2.Hash)
	}

	// All in same stream.
	if event1.StreamID != event2.StreamID || event2.StreamID != event3.StreamID {
		t.Error("all events should be in the same stream")
	}

	// Sequence increments.
	if event1.Sequence != 1 || event2.Sequence != 2 || event3.Sequence != 3 {
		t.Errorf("sequences = %d, %d, %d, want 1, 2, 3", event1.Sequence, event2.Sequence, event3.Sequence)
	}

	// All hashes unique.
	if event1.Hash == event2.Hash || event2.Hash == event3.Hash {
		t.Error("all hashes should be unique")
	}
}

func TestRecordDifferentStreamsPerTenant(t *testing.T) {
	c := newTestChronicle(t)

	event1 := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenantA",
	}
	err := c.Record(context.Background(), event1)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	event2 := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenantB",
	}
	err = c.Record(context.Background(), event2)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Different tenants get different streams.
	if event1.StreamID == event2.StreamID {
		t.Error("different tenants should have different streams")
	}

	// Both are genesis events.
	if event1.Sequence != 1 || event2.Sequence != 1 {
		t.Errorf("both should be sequence 1, got %d and %d", event1.Sequence, event2.Sequence)
	}
}

func TestVerifyEvent(t *testing.T) {
	c := newTestChronicle(t)

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err := c.Record(context.Background(), event)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	valid, err := c.VerifyEvent(context.Background(), event.ID)
	if err != nil {
		t.Fatalf("VerifyEvent: %v", err)
	}
	if !valid {
		t.Error("event should be valid")
	}
}

func TestVerifyChain(t *testing.T) {
	c := newTestChronicle(t)
	ctx := context.Background()

	// Record 10 events in a chain.
	var streamID chronicle.StreamInfo
	for i := range 10 {
		event := &audit.Event{
			Action:   "action",
			Resource: "resource",
			Category: "cat",
			AppID:    "app1",
			TenantID: "tenant1",
		}
		err := c.Record(ctx, event)
		if err != nil {
			t.Fatalf("Record event %d: %v", i, err)
		}
		if i == 0 {
			streamID = chronicle.StreamInfo{ID: event.StreamID}
		}
	}

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID.ID,
		FromSeq:  1,
		ToSeq:    10,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if !report.Valid {
		t.Errorf("chain should be valid, gaps=%v, tampered=%v", report.Gaps, report.Tampered)
	}
	if report.Verified != 10 {
		t.Errorf("Verified = %d, want 10", report.Verified)
	}
	if report.FirstEvent != 1 {
		t.Errorf("FirstEvent = %d, want 1", report.FirstEvent)
	}
	if report.LastEvent != 10 {
		t.Errorf("LastEvent = %d, want 10", report.LastEvent)
	}
}

func TestRecordAppliesScope(t *testing.T) {
	c := newTestChronicle(t)

	ctx := scope.WithInfo(context.Background(), scope.Info{
		AppID:    "app1",
		TenantID: "tenant1",
		UserID:   "user1",
		IP:       "10.0.0.1",
	})

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err := c.Record(ctx, event)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if event.AppID != "app1" {
		t.Errorf("AppID = %q, want %q", event.AppID, "app1")
	}
	if event.TenantID != "tenant1" {
		t.Errorf("TenantID = %q, want %q", event.TenantID, "tenant1")
	}
	if event.UserID != "user1" {
		t.Errorf("UserID = %q, want %q", event.UserID, "user1")
	}
	if event.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want %q", event.IP, "10.0.0.1")
	}
}

func TestRecordNoStore(t *testing.T) {
	c, err := chronicle.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err = c.Record(context.Background(), event)
	if !errors.Is(err, chronicle.ErrNoStore) {
		t.Errorf("expected ErrNoStore, got: %v", err)
	}
}

func TestBuilderProducesEvent(t *testing.T) {
	c := newTestChronicle(t)

	b := c.Info(context.Background(), "login", "session", "sess-123").
		Category("auth").
		Reason("user authenticated").
		Meta("method", "oauth").
		SubjectID("user-42").
		Outcome(audit.OutcomeSuccess).
		TenantID("t1").
		UserID("u1").
		AppID("a1")

	event := b.Event()

	if event.Action != "login" {
		t.Errorf("Action = %q, want %q", event.Action, "login")
	}
	if event.Resource != "session" {
		t.Errorf("Resource = %q, want %q", event.Resource, "session")
	}
	if event.ResourceID != "sess-123" {
		t.Errorf("ResourceID = %q, want %q", event.ResourceID, "sess-123")
	}
	if event.Severity != audit.SeverityInfo {
		t.Errorf("Severity = %q, want %q", event.Severity, audit.SeverityInfo)
	}
	if event.Category != "auth" {
		t.Errorf("Category = %q, want %q", event.Category, "auth")
	}
	if event.Reason != "user authenticated" {
		t.Errorf("Reason = %q, want %q", event.Reason, "user authenticated")
	}
	if event.Metadata["method"] != "oauth" {
		t.Errorf("Metadata[method] = %v, want %q", event.Metadata["method"], "oauth")
	}
	if event.SubjectID != "user-42" {
		t.Errorf("SubjectID = %q, want %q", event.SubjectID, "user-42")
	}
	if event.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", event.Outcome, audit.OutcomeSuccess)
	}
	if event.TenantID != "t1" {
		t.Errorf("TenantID = %q, want %q", event.TenantID, "t1")
	}
}

func TestBuilderRecord(t *testing.T) {
	c := newTestChronicle(t)

	err := c.Warning(context.Background(), "delete", "document", "doc-1").
		Category("documents").
		Reason("user deleted document").
		Record()

	if err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func TestBuilderSeverityLevels(t *testing.T) {
	c := newTestChronicle(t)

	tests := []struct {
		name     string
		builder  *chronicle.EventBuilder
		severity string
	}{
		{"info", c.Info(context.Background(), "a", "r", "id"), audit.SeverityInfo},
		{"warning", c.Warning(context.Background(), "a", "r", "id"), audit.SeverityWarning},
		{"critical", c.Critical(context.Background(), "a", "r", "id"), audit.SeverityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := tt.builder.Event()
			if event.Severity != tt.severity {
				t.Errorf("Severity = %q, want %q", event.Severity, tt.severity)
			}
		})
	}
}

func TestQueryAppliesScope(t *testing.T) {
	c := newTestChronicle(t)

	ctx := scope.WithInfo(context.Background(), scope.Info{
		AppID:    "app1",
		TenantID: "tenant1",
	})

	// Record an event for tenant1.
	err := c.Record(ctx, &audit.Event{
		Action:   "read",
		Resource: "doc",
		Category: "docs",
		AppID:    "app1",
		TenantID: "tenant1",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Record an event for tenant2.
	err = c.Record(context.Background(), &audit.Event{
		Action:   "read",
		Resource: "doc",
		Category: "docs",
		AppID:    "app1",
		TenantID: "tenant2",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Query as tenant1 — should only see tenant1 events.
	q := &audit.Query{}
	result, err := c.Query(ctx, q)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("Total = %d, want 1 (tenant isolation)", result.Total)
	}
}
