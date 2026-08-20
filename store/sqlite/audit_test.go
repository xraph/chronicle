package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate" // registers the sqlite migrate executor

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// newTestStore opens a migrated SQLite store backed by a temp file. A file is
// used rather than :memory: because grove pools connections and each pooled
// connection would otherwise get its own empty in-memory database.
func newTestStore(t *testing.T) *Store {
	t.Helper()

	dsn := filepath.Join(t.TempDir(), "chronicle_test.db")

	sdb := sqlitedriver.New()
	if err := sdb.Open(context.Background(), dsn); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := New(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// seedStream creates a stream row so events can satisfy the FK.
func seedStream(t *testing.T, s *Store, appID, tenantID string) id.ID {
	t.Helper()

	st := &stream.Stream{
		ID:       id.NewStreamID(),
		AppID:    appID,
		TenantID: tenantID,
	}
	if err := s.CreateStream(context.Background(), st); err != nil {
		t.Fatalf("create stream: %v", err)
	}
	return st.ID
}

func testEvent(streamID id.ID, appID, tenantID, userID, category string, ts time.Time) *audit.Event {
	return &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  streamID,
		Hash:      "hash-" + category + "-" + userID + "-" + ts.Format(time.RFC3339Nano),
		AppID:     appID,
		TenantID:  tenantID,
		UserID:    userID,
		Action:    "test.action",
		Resource:  "test",
		Category:  category,
		Outcome:   "success",
		Severity:  "info",
		Timestamp: ts,
	}
}

// TestAggregateRejectsInjectedGroupBy pins the SQL injection fix: an
// attacker-supplied group_by must be rejected before any SQL is executed.
func TestAggregateRejectsInjectedGroupBy(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamID := seedStream(t, s, "app-1", "")
	if err := s.Append(ctx, testEvent(streamID, "app-1", "", "u1", "auth", time.Now().UTC())); err != nil {
		t.Fatalf("append: %v", err)
	}

	injections := []string{
		"category, (SELECT COUNT(*) FROM chronicle_streams)",
		"category; DROP TABLE chronicle_events",
		"1",
		"*",
		"user_id",
		"category)--",
	}

	for _, payload := range injections {
		t.Run(payload, func(t *testing.T) {
			_, err := s.Aggregate(ctx, &audit.AggregateQuery{GroupBy: []string{payload}})
			if err == nil {
				t.Fatalf("Aggregate accepted injected group_by %q", payload)
			}
			if !strings.Contains(err.Error(), "unsupported group_by field") {
				t.Fatalf("expected whitelist rejection for %q, got: %v", payload, err)
			}
		})
	}

	// The events table must still be intact after the DROP attempt.
	if _, err := s.Count(ctx, &audit.CountQuery{}); err != nil {
		t.Fatalf("events table damaged after injection attempts: %v", err)
	}
}

func TestAggregateGroupsByWhitelistedFields(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamID := seedStream(t, s, "app-1", "")
	now := time.Now().UTC()
	for _, category := range []string{"auth", "auth", "data"} {
		if err := s.Append(ctx, testEvent(streamID, "app-1", "", "u1", category, now)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	result, err := s.Aggregate(ctx, &audit.AggregateQuery{GroupBy: []string{"category"}})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if result.Total != 3 {
		t.Fatalf("expected total 3, got %d", result.Total)
	}
	if len(result.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(result.Groups))
	}
	if result.Groups[0].Category != "auth" || result.Groups[0].Count != 2 {
		t.Fatalf("expected auth=2 first, got %+v", result.Groups[0])
	}
}

// TestQueryReturnsEvents pins the scalar-scan fix. Before the fix the count
// query passed a *int64 to grove's model scanner, which rejects it.
func TestQueryReturnsEvents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamID := seedStream(t, s, "app-1", "")
	now := time.Now().UTC()
	for i := range 3 {
		ev := testEvent(streamID, "app-1", "", "u1", "auth", now.Add(time.Duration(i)*time.Second))
		if err := s.Append(ctx, ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	result, err := s.Query(ctx, &audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if result.Total != 3 {
		t.Fatalf("expected total 3, got %d", result.Total)
	}
	if len(result.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(result.Events))
	}
	if result.HasMore {
		t.Fatal("expected HasMore false")
	}
}

func TestQueryPaginationReportsHasMore(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamID := seedStream(t, s, "app-1", "")
	now := time.Now().UTC()
	for i := range 5 {
		ev := testEvent(streamID, "app-1", "", "u1", "auth", now.Add(time.Duration(i)*time.Second))
		if err := s.Append(ctx, ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	result, err := s.Query(ctx, &audit.Query{Limit: 2})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if result.Total != 5 {
		t.Fatalf("expected total 5, got %d", result.Total)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(result.Events))
	}
	if !result.HasMore {
		t.Fatal("expected HasMore true")
	}
}

func TestCountReturnsScalar(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamID := seedStream(t, s, "app-1", "")
	now := time.Now().UTC()
	if err := s.Append(ctx, testEvent(streamID, "app-1", "", "u1", "auth", now)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Append(ctx, testEvent(streamID, "app-1", "", "u1", "data", now)); err != nil {
		t.Fatalf("append: %v", err)
	}

	total, err := s.Count(ctx, &audit.CountQuery{})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected 2, got %d", total)
	}

	scoped, err := s.Count(ctx, &audit.CountQuery{Category: "auth"})
	if err != nil {
		t.Fatalf("Count(category): %v", err)
	}
	if scoped != 1 {
		t.Fatalf("expected 1 auth event, got %d", scoped)
	}
}

func TestLastSequenceAndLastHash(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamID := seedStream(t, s, "app-1", "")

	seq, err := s.LastSequence(ctx, streamID)
	if err != nil {
		t.Fatalf("LastSequence on empty stream: %v", err)
	}
	if seq != 0 {
		t.Fatalf("expected 0 on empty stream, got %d", seq)
	}

	now := time.Now().UTC()
	for i := range 3 {
		ev := testEvent(streamID, "app-1", "", "u1", "auth", now.Add(time.Duration(i)*time.Second))
		if appendErr := s.Append(ctx, ev); appendErr != nil {
			t.Fatalf("append: %v", appendErr)
		}
	}

	seq, err = s.LastSequence(ctx, streamID)
	if err != nil {
		t.Fatalf("LastSequence: %v", err)
	}
	if seq != 3 {
		t.Fatalf("expected sequence 3, got %d", seq)
	}

	hash, err := s.LastHash(ctx, streamID)
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if hash == "" {
		t.Fatal("expected a non-empty head hash")
	}
}

// TestByUserWithEmptyTimeRange pins the zero-time bug: an unset TimeRange must
// mean "no bound", not "bounded by year 1".
func TestByUserWithEmptyTimeRange(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamID := seedStream(t, s, "app-1", "")
	now := time.Now().UTC()
	if err := s.Append(ctx, testEvent(streamID, "app-1", "", "alice", "auth", now)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Append(ctx, testEvent(streamID, "app-1", "", "bob", "auth", now)); err != nil {
		t.Fatalf("append: %v", err)
	}

	result, err := s.ByUser(ctx, "alice", audit.TimeRange{})
	if err != nil {
		t.Fatalf("ByUser: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event for alice with an empty TimeRange, got %d", len(result.Events))
	}
	if result.Events[0].UserID != "alice" {
		t.Fatalf("expected alice, got %q", result.Events[0].UserID)
	}
}

// TestByUserAppliesScope pins that a per-user lookup cannot cross tenants.
func TestByUserAppliesScope(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamA := seedStream(t, s, "app-a", "")
	streamB := seedStream(t, s, "app-b", "")
	now := time.Now().UTC()

	if err := s.Append(ctx, testEvent(streamA, "app-a", "", "alice", "auth", now)); err != nil {
		t.Fatalf("append app-a: %v", err)
	}
	if err := s.Append(ctx, testEvent(streamB, "app-b", "", "alice", "auth", now)); err != nil {
		t.Fatalf("append app-b: %v", err)
	}

	result, err := s.ByUser(ctx, "alice", audit.TimeRange{AppID: "app-a"})
	if err != nil {
		t.Fatalf("ByUser: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event scoped to app-a, got %d", len(result.Events))
	}
	if result.Events[0].AppID != "app-a" {
		t.Fatalf("leaked event from %q", result.Events[0].AppID)
	}
}

func TestByUserAppliesLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamID := seedStream(t, s, "app-1", "")
	now := time.Now().UTC()
	for i := range 5 {
		ev := testEvent(streamID, "app-1", "", "alice", "auth", now.Add(time.Duration(i)*time.Second))
		if err := s.Append(ctx, ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	result, err := s.ByUser(ctx, "alice", audit.TimeRange{Limit: 2})
	if err != nil {
		t.Fatalf("ByUser: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected the limit to bound results to 2, got %d", len(result.Events))
	}
}

func TestByUserRespectsTimeRange(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamID := seedStream(t, s, "app-1", "")
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)

	if err := s.Append(ctx, testEvent(streamID, "app-1", "", "alice", "auth", old)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Append(ctx, testEvent(streamID, "app-1", "", "alice", "auth", now)); err != nil {
		t.Fatalf("append: %v", err)
	}

	result, err := s.ByUser(ctx, "alice", audit.TimeRange{After: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("ByUser: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 recent event, got %d", len(result.Events))
	}
}

// TestConcurrentAppendKeepsChainLinked pins the store-level re-link. Append
// re-derives the sequence and prev_hash inside its transaction, so concurrent
// appends produce a single unbroken chain even when the callers all started from
// the same stale head — which is what happens with several replicas on one DB.
func TestConcurrentAppendKeepsChainLinked(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	streamID := seedStream(t, s, "app-1", "")

	const writers = 6
	var wg sync.WaitGroup
	errs := make(chan error, writers)

	now := time.Now().UTC()
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ev := testEvent(streamID, "app-1", "", fmt.Sprintf("u%d", w), "auth", now)
			// Every writer chains off the empty head, as separate replicas would.
			ev.PrevHash = ""
			if err := s.Append(ctx, ev); err != nil {
				errs <- err
			}
		}(w)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Append: %v", err)
	}

	events, err := s.EventRange(ctx, streamID, 1, writers)
	if err != nil {
		t.Fatalf("EventRange: %v", err)
	}
	if len(events) != writers {
		t.Fatalf("got %d events, want %d", len(events), writers)
	}

	// Sequences must be 1..writers with no duplicates, and each event's PrevHash
	// must equal its predecessor's Hash.
	for i, ev := range events {
		if ev.Sequence != uint64(i+1) {
			t.Fatalf("event %d has sequence %d, want %d", i, ev.Sequence, i+1)
		}
		if i == 0 {
			continue
		}
		if ev.PrevHash != events[i-1].Hash {
			t.Fatalf("chain broken at sequence %d: prev_hash %q != predecessor hash %q",
				ev.Sequence, ev.PrevHash, events[i-1].Hash)
		}
	}

	// And the head must point at the last event.
	headHash, err := s.LastHash(ctx, streamID)
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if headHash != events[len(events)-1].Hash {
		t.Fatalf("head hash %q does not match the last event %q", headHash, events[len(events)-1].Hash)
	}
}

// TestSealedFieldsSurviveSQLiteRoundTrip pins that ciphertext survives the TEXT
// columns and the JSON metadata encoding intact.
//
// The memory store keeps Go values, so it cannot catch an encoding problem. Here
// the sealed values actually pass through SQL types and back.
func TestSealedFieldsSurviveSQLiteRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	streamID := seedStream(t, s, "app-1", "")

	keys := crypto.NewInMemoryKeyStore()
	sealer := crypto.NewSealer(keys)
	chain := &hash.Chain{}

	ev := testEvent(streamID, "app-1", "", "operator", "data", time.Now().UTC())
	ev.SubjectID = "subject-1"
	ev.Reason = "subject access request"
	ev.IP = "203.0.113.9"
	ev.Metadata = map[string]any{"email": "alice@example.com", "rows": float64(7)}

	if err := sealer.Seal(ev); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealedReason, sealedIP := ev.Reason, ev.IP

	if err := s.Append(ctx, ev); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Append re-derives the hash under its lock; capture what was stored.
	storedHash, storedPrev := ev.Hash, ev.PrevHash

	got, err := s.Get(ctx, ev.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Reason != sealedReason {
		t.Fatalf("sealed Reason did not survive the round trip:\n got %q\nwant %q",
			got.Reason, sealedReason)
	}
	if got.IP != sealedIP {
		t.Fatalf("sealed IP did not survive the round trip:\n got %q\nwant %q", got.IP, sealedIP)
	}
	if !crypto.IsSealed(got) {
		t.Fatal("the event read back should still be sealed")
	}

	// The digest must still match what SQLite returned.
	got.Hash, got.PrevHash = storedHash, storedPrev
	if !chain.Verify(storedPrev, got) {
		t.Fatal("stored digest does not match the event read back from SQLite")
	}

	// Opening it yields the original values.
	if openErr := sealer.Open(got); openErr != nil {
		t.Fatalf("Open: %v", openErr)
	}
	if got.Reason != "subject access request" {
		t.Fatalf("Reason = %q, want the original plaintext", got.Reason)
	}
	if got.Metadata["email"] != "alice@example.com" {
		t.Fatalf("Metadata email = %v, want the original plaintext", got.Metadata["email"])
	}
	if got.Metadata["rows"] != float64(7) {
		t.Fatalf("Metadata rows = %v, want 7", got.Metadata["rows"])
	}

	// After key destruction the digest still verifies.
	if delErr := keys.Delete("subject-1"); delErr != nil {
		t.Fatalf("Delete key: %v", delErr)
	}
	reread, err := s.Get(ctx, ev.ID)
	if err != nil {
		t.Fatalf("Get after erasure: %v", err)
	}
	if !chain.Verify(storedPrev, reread) {
		t.Fatal("digest must still verify after the key is destroyed")
	}
}

// TestByUserIsolatesTenantsWithinAnApp covers the tenant half of the scope. The
// other tests all use an empty tenant, so without this the tenant filter on the
// sqlite backend was never exercised.
func TestByUserIsolatesTenantsWithinAnApp(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	streamA := seedStream(t, s, "app-1", "tenant-a")
	streamB := seedStream(t, s, "app-1", "tenant-b")
	now := time.Now().UTC()

	if err := s.Append(ctx, testEvent(streamA, "app-1", "tenant-a", "alice", "auth", now)); err != nil {
		t.Fatalf("append tenant-a: %v", err)
	}
	if err := s.Append(ctx, testEvent(streamB, "app-1", "tenant-b", "alice", "auth", now)); err != nil {
		t.Fatalf("append tenant-b: %v", err)
	}

	result, err := s.ByUser(ctx, "alice", audit.TimeRange{AppID: "app-1", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("ByUser: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event scoped to tenant-a, got %d", len(result.Events))
	}
	if result.Events[0].TenantID != "tenant-a" {
		t.Fatalf("leaked event from tenant %q", result.Events[0].TenantID)
	}
}
