package retention_test

import (
	"context"
	"errors"
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
	return seedEventsForApp(t, s, "app1", "", category, count, age)
}

func seedEventsForApp(
	t *testing.T, s store.Store, appID, tenantID, category string, count int, age time.Duration,
) []*audit.Event {
	t.Helper()
	ctx := context.Background()

	events := make([]*audit.Event, count)
	for i := range count {
		e := &audit.Event{
			ID:        id.NewAuditID(),
			StreamID:  id.NewStreamID(),
			Sequence:  uint64(i + 1),
			Hash:      "hash",
			AppID:     appID,
			TenantID:  tenantID,
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

// TestEnforceDoesNotPurgeOtherApps is the cross-tenant destruction path: app2
// registers a one-hour policy on a category app1 also uses, and enforcement
// must leave app1's events alone.
func TestEnforceDoesNotPurgeOtherApps(t *testing.T) {
	s, sink := setupEnforcerTest(t)
	ctx := context.Background()

	victimEvents := seedEventsForApp(t, s, "app1", "", "auth", 4, 48*time.Hour)
	attackerEvents := seedEventsForApp(t, s, "app2", "", "auth", 2, 48*time.Hour)

	policy := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: 1 * time.Hour,
		AppID:    "app2",
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

	if result.Purged != int64(len(attackerEvents)) {
		t.Errorf("purged = %d, want %d (only app2's own events)", result.Purged, len(attackerEvents))
	}

	for _, e := range victimEvents {
		if _, getErr := s.Get(ctx, e.ID); getErr != nil {
			t.Errorf("app1 event %s was purged by app2's policy: %v", e.ID, getErr)
		}
	}
}

// TestEnforceIsolatesTenantsWithinAnApp covers the tenant dimension.
func TestEnforceIsolatesTenantsWithinAnApp(t *testing.T) {
	s, sink := setupEnforcerTest(t)
	ctx := context.Background()

	tenantA := seedEventsForApp(t, s, "app1", "tenant-a", "auth", 3, 48*time.Hour)
	tenantB := seedEventsForApp(t, s, "app1", "tenant-b", "auth", 2, 48*time.Hour)

	policy := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: 1 * time.Hour,
		AppID:    "app1",
		TenantID: "tenant-b",
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

	if result.Purged != int64(len(tenantB)) {
		t.Errorf("purged = %d, want %d", result.Purged, len(tenantB))
	}
	for _, e := range tenantA {
		if _, getErr := s.Get(ctx, e.ID); getErr != nil {
			t.Errorf("tenant-a event %s purged by tenant-b's policy: %v", e.ID, getErr)
		}
	}
}

// TestEnforceForAppOnlyRunsThatApp pins that the HTTP enforce endpoint can run
// one caller's policies without touching anyone else's.
func TestEnforceForAppOnlyRunsThatApp(t *testing.T) {
	s, sink := setupEnforcerTest(t)
	ctx := context.Background()

	app1Events := seedEventsForApp(t, s, "app1", "", "auth", 3, 48*time.Hour)
	app2Events := seedEventsForApp(t, s, "app2", "", "auth", 2, 48*time.Hour)

	for _, appID := range []string{"app1", "app2"} {
		p := &retention.Policy{
			ID:       id.NewPolicyID(),
			Category: "auth",
			Duration: 1 * time.Hour,
			AppID:    appID,
		}
		p.CreatedAt = time.Now()
		p.UpdatedAt = time.Now()
		if err := s.SavePolicy(ctx, p); err != nil {
			t.Fatalf("save policy for %s: %v", appID, err)
		}
	}

	enforcer := retention.NewEnforcer(s, sink, nil)
	result, err := enforcer.EnforceScope(ctx, retention.Scope{AppID: "app2"})
	if err != nil {
		t.Fatalf("EnforceScope: %v", err)
	}

	if result.Purged != int64(len(app2Events)) {
		t.Errorf("purged = %d, want %d", result.Purged, len(app2Events))
	}
	for _, e := range app1Events {
		if _, getErr := s.Get(ctx, e.ID); getErr != nil {
			t.Errorf("app1 event %s purged by an app2-scoped enforce: %v", e.ID, getErr)
		}
	}
}

// TestEnforceDoesNotPurgeWhenArchiveFails pins that a failed archive write
// aborts the purge, so events are never lost without a copy.
func TestEnforceDoesNotPurgeWhenArchiveFails(t *testing.T) {
	s := memory.New()
	ctx := context.Background()

	events := seedEventsForApp(t, s, "app1", "", "auth", 3, 48*time.Hour)

	policy := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: 1 * time.Hour,
		Archive:  true,
		AppID:    "app1",
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	if err := s.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}

	enforcer := retention.NewEnforcer(s, &failingSink{}, nil)
	if _, err := enforcer.Enforce(ctx); err == nil {
		t.Fatal("Enforce should surface the archive failure")
	}

	for _, e := range events {
		if _, getErr := s.Get(ctx, e.ID); getErr != nil {
			t.Errorf("event %s purged despite the archive write failing: %v", e.ID, getErr)
		}
	}
}

// failingSink fails every write, standing in for an unreachable archive target.
type failingSink struct{}

func (s *failingSink) Name() string { return "failing" }
func (s *failingSink) Write(_ context.Context, _ []*audit.Event) error {
	return errArchiveUnavailable
}
func (s *failingSink) Flush(_ context.Context) error { return nil }
func (s *failingSink) Close() error                  { return nil }

var errArchiveUnavailable = errors.New("archive target unavailable")

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
