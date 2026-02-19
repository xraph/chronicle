package retention_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
)

// mockSink captures events written for verification.
type mockSink struct {
	name    string
	events  []*audit.Event
	flushed bool
}

func (s *mockSink) Name() string { return s.name }
func (s *mockSink) Write(_ context.Context, events []*audit.Event) error {
	s.events = append(s.events, events...)
	return nil
}
func (s *mockSink) Flush(_ context.Context) error { s.flushed = true; return nil }
func (s *mockSink) Close() error                  { return nil }

func setupEnforcerTest(t *testing.T) (store.Store, *mockSink) {
	t.Helper()
	s := memory.New()
	sink := &mockSink{name: "test-archive"}
	return s, sink
}

func seedEvents(t *testing.T, s store.Store, category string, count int, age time.Duration) []*audit.Event {
	t.Helper()
	ctx := context.Background()

	events := make([]*audit.Event, count)
	for i := range count {
		e := &audit.Event{
			ID:        id.NewAuditID(),
			StreamID:  id.NewStreamID(),
			Sequence:  uint64(i + 1),
			Hash:      "hash",
			AppID:     "app1",
			Action:    "test.action",
			Resource:  "test.resource",
			Category:  category,
			Outcome:   audit.OutcomeSuccess,
			Severity:  audit.SeverityInfo,
			Timestamp: time.Now().Add(-age),
		}
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("seed event: %v", err)
		}
		events[i] = e
	}
	return events
}

func TestEnforceWithArchive(t *testing.T) {
	s, sink := setupEnforcerTest(t)
	ctx := context.Background()

	// Seed old events.
	oldEvents := seedEvents(t, s, "auth", 5, 48*time.Hour)

	// Seed recent events (should not be affected).
	recentEvents := seedEvents(t, s, "auth", 3, 1*time.Hour)

	// Create policy: retain auth events for 24 hours, archive before purge.
	policy := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: 24 * time.Hour,
		Archive:  true,
		AppID:    "app1",
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	if err := s.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	enforcer := retention.NewEnforcer(s, sink, nil)
	result, err := enforcer.Enforce(ctx)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}

	// Verify old events were archived.
	if result.Archived != int64(len(oldEvents)) {
		t.Errorf("archived = %d, want %d", result.Archived, len(oldEvents))
	}

	// Verify old events were purged.
	if result.Purged != int64(len(oldEvents)) {
		t.Errorf("purged = %d, want %d", result.Purged, len(oldEvents))
	}

	// Verify sink received the events.
	if len(sink.events) != len(oldEvents) {
		t.Errorf("sink events = %d, want %d", len(sink.events), len(oldEvents))
	}
	if !sink.flushed {
		t.Error("sink was not flushed")
	}

	// Verify recent events still exist.
	for _, e := range recentEvents {
		got, getErr := s.Get(ctx, e.ID)
		if getErr != nil {
			t.Errorf("recent event %s should still exist: %v", e.ID, getErr)
			continue
		}
		if got.ID != e.ID {
			t.Errorf("got event ID = %s, want %s", got.ID, e.ID)
		}
	}

	// Verify archive was recorded.
	archives, err := s.ListArchives(ctx, retention.ListOpts{Limit: 10})
	if err != nil {
		t.Fatalf("list archives: %v", err)
	}
	if len(archives) != 1 {
		t.Fatalf("archives = %d, want 1", len(archives))
	}
	if archives[0].Category != "auth" {
		t.Errorf("archive category = %s, want auth", archives[0].Category)
	}
	if archives[0].EventCount != int64(len(oldEvents)) {
		t.Errorf("archive event count = %d, want %d", archives[0].EventCount, len(oldEvents))
	}
	if archives[0].SinkName != "test-archive" {
		t.Errorf("archive sink name = %s, want test-archive", archives[0].SinkName)
	}
}

func TestEnforceWithoutArchive(t *testing.T) {
	s, sink := setupEnforcerTest(t)
	ctx := context.Background()

	// Seed old events.
	oldEvents := seedEvents(t, s, "system", 4, 72*time.Hour)

	// Create policy: purge system events after 24h, no archive.
	policy := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "system",
		Duration: 24 * time.Hour,
		Archive:  false,
		AppID:    "app1",
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	if err := s.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	enforcer := retention.NewEnforcer(s, sink, nil)
	result, err := enforcer.Enforce(ctx)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}

	// Should not archive since policy.Archive is false.
	if result.Archived != 0 {
		t.Errorf("archived = %d, want 0", result.Archived)
	}

	// Should still purge.
	if result.Purged != int64(len(oldEvents)) {
		t.Errorf("purged = %d, want %d", result.Purged, len(oldEvents))
	}

	// Sink should not have received events.
	if len(sink.events) != 0 {
		t.Errorf("sink events = %d, want 0", len(sink.events))
	}
}

func TestEnforceNoPolicies(t *testing.T) {
	s, sink := setupEnforcerTest(t)
	ctx := context.Background()

	enforcer := retention.NewEnforcer(s, sink, nil)
	result, err := enforcer.Enforce(ctx)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}

	if result.Archived != 0 || result.Purged != 0 || result.Retained != 0 {
		t.Errorf("expected zero result, got %+v", result)
	}
}

func TestEnforceNoMatchingEvents(t *testing.T) {
	s, sink := setupEnforcerTest(t)
	ctx := context.Background()

	// Seed recent events only.
	seedEvents(t, s, "auth", 3, 1*time.Hour)

	// Policy targets events older than 48h.
	policy := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: 48 * time.Hour,
		Archive:  true,
		AppID:    "app1",
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	if err := s.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	enforcer := retention.NewEnforcer(s, sink, nil)
	result, err := enforcer.Enforce(ctx)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}

	if result.Archived != 0 || result.Purged != 0 {
		t.Errorf("expected no action, got archived=%d purged=%d", result.Archived, result.Purged)
	}
}
