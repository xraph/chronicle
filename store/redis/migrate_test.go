package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/stream"
)

// legacyKey is how the pre-v2 code joined scope parts into a key.
func legacyKey(prefix string, parts ...string) string {
	return prefix + strings.Join(parts, ":")
}

// seedLegacyStream writes a stream the way CreateStream did before v2 keys:
// the entity, the all-streams index, and a bare-joined scope pointer.
func seedLegacyStream(ctx context.Context, t *testing.T, s *Store, sc retention.Scope) id.ID {
	t.Helper()
	st := &stream.Stream{ID: id.NewStreamID(), AppID: sc.AppID, TenantID: sc.TenantID}
	st.CreatedAt = time.Now().UTC()
	m := toStreamModel(st)
	if err := s.setEntity(ctx, entityKey(prefixStream, m.ID), m); err != nil {
		t.Fatalf("seed stream: %v", err)
	}
	pipe := s.rdb.Pipeline()
	pipe.ZAdd(ctx, zStreamAll, goredis.Z{Score: scoreFromTime(m.CreatedAt), Member: m.ID})
	pipe.Set(ctx, legacyKey(legacyStreamScope, sc.AppID, sc.TenantID), m.ID, 0)
	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatalf("seed stream indexes: %v", err)
	}
	return st.ID
}

// seedLegacyEvent writes an event into streamID the way storeEvent did before
// v2 keys. The event's own scope may differ from the stream's, which is what a
// collision left behind.
func seedLegacyEvent(ctx context.Context, t *testing.T, s *Store, streamID id.ID, seq uint64, sc retention.Scope) {
	t.Helper()
	evt := &audit.Event{
		ID: id.NewAuditID(), StreamID: streamID, Sequence: seq, Hash: "seed",
		Timestamp: time.Now().UTC(), AppID: sc.AppID, TenantID: sc.TenantID,
		Action: "test.seed", Resource: "doc", Category: "test",
		Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
	}
	m := toEventModel(evt)
	if err := s.setEntity(ctx, entityKey(prefixEvent, m.ID), m); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	score := scoreFromTime(m.Timestamp)
	pipe := s.rdb.Pipeline()
	pipe.ZAdd(ctx, zEventAll, goredis.Z{Score: score, Member: m.ID})
	pipe.ZAdd(ctx, zEventStream+m.StreamID, goredis.Z{Score: float64(m.Sequence), Member: m.ID})
	pipe.ZAdd(ctx, legacyKey(legacyEventScope, sc.AppID, sc.TenantID), goredis.Z{Score: score, Member: m.ID})
	pipe.ZAdd(ctx, zEventApp+m.AppID, goredis.Z{Score: score, Member: m.ID})
	pipe.ZAdd(ctx, zEventCategory+m.Category, goredis.Z{Score: score, Member: m.ID})
	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatalf("seed event indexes: %v", err)
	}
}

// seedLegacyPolicy writes a policy the way SavePolicy did before v2 keys.
func seedLegacyPolicy(ctx context.Context, t *testing.T, s *Store, sc retention.Scope, category string) id.ID {
	t.Helper()
	p := &retention.Policy{
		ID: id.NewPolicyID(), Category: category, Duration: time.Hour,
		AppID: sc.AppID, TenantID: sc.TenantID,
	}
	p.CreatedAt = time.Now().UTC()
	m := toPolicyModel(p)
	if err := s.setEntity(ctx, entityKey(prefixPolicy, m.ID), m); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	pipe := s.rdb.Pipeline()
	pipe.ZAdd(ctx, zPolicyAll, goredis.Z{Score: scoreFromTime(m.CreatedAt), Member: m.ID})
	pipe.Set(ctx, legacyKey(legacyPolicyScope, sc.AppID, sc.TenantID, category), m.ID, 0)
	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatalf("seed policy indexes: %v", err)
	}
	return p.ID
}

// countKeys returns how many keys match a SCAN pattern.
func countKeys(ctx context.Context, t *testing.T, rdb goredis.UniversalClient, pattern string) int {
	t.Helper()
	n := 0
	iter := rdb.Scan(ctx, 0, pattern, 1000).Iterator()
	for iter.Next(ctx) {
		n++
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("scan %q: %v", pattern, err)
	}
	return n
}

func mustStreamByScope(ctx context.Context, t *testing.T, s *Store, sc retention.Scope) id.ID {
	t.Helper()
	st, err := s.GetStreamByScope(ctx, sc.AppID, sc.TenantID)
	if err != nil {
		t.Fatalf("GetStreamByScope(%q, %q): %v", sc.AppID, sc.TenantID, err)
	}
	return st.ID
}

func mustCount(ctx context.Context, t *testing.T, s *Store, sc retention.Scope) int64 {
	t.Helper()
	n, err := s.Count(ctx, &audit.CountQuery{AppID: sc.AppID, TenantID: sc.TenantID})
	if err != nil {
		t.Fatalf("Count(%q, %q): %v", sc.AppID, sc.TenantID, err)
	}
	return n
}

// Before Migrate, the v2 stream index is empty. Reporting a miss would make
// Chronicle.resolveStream start a second chain for every existing tenant, so
// the lookup has to fail loudly instead.
func TestGetStreamByScopeRefusesBeforeMigrate(t *testing.T) {
	s, _ := openTestStore(t, false)
	ctx := context.Background()

	sc := retention.Scope{AppID: "app-" + runSuffix(t), TenantID: "t1"}
	seedLegacyStream(ctx, t, s, sc)

	_, err := s.GetStreamByScope(ctx, sc.AppID, sc.TenantID)
	if !errors.Is(err, ErrScopeKeysNotMigrated) {
		t.Fatalf("GetStreamByScope before Migrate: err = %v, want ErrScopeKeysNotMigrated", err)
	}
	if errors.Is(err, chronicle.ErrStreamNotFound) {
		t.Fatalf("GetStreamByScope before Migrate reported not-found, which would fork the tenant's chain")
	}
}

func TestMigrateMovesLegacyScopeKeys(t *testing.T) {
	s, rdb := openTestStore(t, false)
	ctx := context.Background()

	sc := retention.Scope{AppID: "app-" + runSuffix(t), TenantID: "t1"}
	streamID := seedLegacyStream(ctx, t, s, sc)
	seedLegacyEvent(ctx, t, s, streamID, 1, sc)
	seedLegacyEvent(ctx, t, s, streamID, 2, sc)
	policyID := seedLegacyPolicy(ctx, t, s, sc, "auth")

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if got := mustStreamByScope(ctx, t, s, sc); got.String() != streamID.String() {
		t.Errorf("stream for %q/%q = %s after Migrate, want the existing %s", sc.AppID, sc.TenantID, got, streamID)
	}
	if got := mustCount(ctx, t, s, sc); got != 2 {
		t.Errorf("Count after Migrate = %d, want 2", got)
	}
	res, err := s.Query(ctx, &audit.Query{AppID: sc.AppID, TenantID: sc.TenantID})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Events) != 2 {
		t.Errorf("Query after Migrate returned %d events, want 2", len(res.Events))
	}

	// The policy index moved too: saving a replacement for the same scope and
	// category finds the old policy through the v2 key and removes it.
	replacement := &retention.Policy{
		ID: id.NewPolicyID(), Category: "auth", Duration: 2 * time.Hour,
		AppID: sc.AppID, TenantID: sc.TenantID,
	}
	if err := s.SavePolicy(ctx, replacement); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}
	if _, err := s.GetPolicy(ctx, policyID); !errors.Is(err, chronicle.ErrPolicyNotFound) {
		t.Errorf("old policy after replacement: err = %v, want ErrPolicyNotFound (the v2 index missed it)", err)
	}

	for _, prefix := range []string{legacyStreamScope, legacyEventScope, legacyPolicyScope} {
		if n := countKeys(ctx, t, rdb, prefix+"*"); n != 0 {
			t.Errorf("%d keys left under legacy prefix %q", n, prefix)
		}
	}
	if n := countKeys(ctx, t, rdb, scopeKeyFormatMarker); n != 1 {
		t.Errorf("format marker not set after Migrate")
	}

	// Running it again, as every extension start does, is a no-op.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if got := mustCount(ctx, t, s, sc); got != 2 {
		t.Errorf("Count after second Migrate = %d, want 2", got)
	}
}

// The old CreateStream overwrote the scope pointer, so a colliding scope that
// created its own stream took the pointer away from the first scope's stream.
// Migrate has to give each stream back to its own scope.
func TestMigrateRestoresOverwrittenStreamPointer(t *testing.T) {
	s, _ := openTestStore(t, false)
	ctx := context.Background()

	first, second := collidingScopes(t)
	firstStream := seedLegacyStream(ctx, t, s, first)
	secondStream := seedLegacyStream(ctx, t, s, second) // overwrites the shared legacy pointer

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if got := mustStreamByScope(ctx, t, s, first); got.String() != firstStream.String() {
		t.Errorf("first scope's stream = %s, want %s", got, firstStream)
	}
	if got := mustStreamByScope(ctx, t, s, second); got.String() != secondStream.String() {
		t.Errorf("second scope's stream = %s, want %s", got, secondStream)
	}
}

// Two streams for one scope (two processes creating it at once) leave the old
// pointer on whichever wrote last, and that is the one the scope's events went
// into. Migrate keeps that one and leaves the older duplicate unindexed.
func TestMigrateKeepsLivePointerOverOlderDuplicate(t *testing.T) {
	s, _ := openTestStore(t, false)
	ctx := context.Background()

	sc := retention.Scope{AppID: "app-" + runSuffix(t), TenantID: "t1"}
	seedLegacyStream(ctx, t, s, sc)
	live := seedLegacyStream(ctx, t, s, sc) // newer, and the pointer's final value

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if got := mustStreamByScope(ctx, t, s, sc); got.String() != live.String() {
		t.Errorf("stream for %q/%q = %s, want the live %s", sc.AppID, sc.TenantID, got, live)
	}
}

// A deployment where the collision already happened has two tenants' events
// in one chain. Migrate cannot split that chain: every event's hash covers its
// predecessor, so moving one out breaks verification for all that follow. It
// migrates what it can, names the merged stream, and returns ErrScopeCollision.
func TestMigrateReportsMergedChain(t *testing.T) {
	s, rdb := openTestStore(t, false)
	ctx := context.Background()

	first, second := collidingScopes(t)
	shared := seedLegacyStream(ctx, t, s, first)
	seedLegacyEvent(ctx, t, s, shared, 1, first)
	seedLegacyEvent(ctx, t, s, shared, 2, second) // the second scope found the first one's stream

	err := s.Migrate(ctx)
	if !errors.Is(err, ErrScopeCollision) {
		t.Fatalf("Migrate over a merged chain: err = %v, want ErrScopeCollision", err)
	}
	if !strings.Contains(err.Error(), shared.String()) {
		t.Errorf("Migrate error does not name the merged stream %s: %v", shared, err)
	}

	isMember, err := rdb.SIsMember(ctx, scopeCollisionsKey, shared.String()).Result()
	if err != nil {
		t.Fatalf("SISMEMBER %s: %v", scopeCollisionsKey, err)
	}
	if !isMember {
		t.Errorf("merged stream %s not recorded in %s", shared, scopeCollisionsKey)
	}

	// The stream stays with the scope that created it. The other scope has no
	// stream of its own, so its next event starts a fresh chain.
	if got := mustStreamByScope(ctx, t, s, first); got.String() != shared.String() {
		t.Errorf("first scope's stream = %s, want %s", got, shared)
	}
	if _, err := s.GetStreamByScope(ctx, second.AppID, second.TenantID); !errors.Is(err, chronicle.ErrStreamNotFound) {
		t.Errorf("second scope after Migrate: err = %v, want ErrStreamNotFound", err)
	}

	// Each event is indexed under the scope it carries, not the stream it sits in.
	if got := mustCount(ctx, t, s, first); got != 1 {
		t.Errorf("Count(first) = %d, want 1", got)
	}
	if got := mustCount(ctx, t, s, second); got != 1 {
		t.Errorf("Count(second) = %d, want 1", got)
	}

	// The migration itself finished, so the next start is not blocked by it.
	if err := s.Migrate(ctx); err != nil {
		t.Errorf("second Migrate: %v", err)
	}
}
