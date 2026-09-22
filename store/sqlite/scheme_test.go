package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// TestMigrationPinsExistingStreamsAboveTheirHead exercises the actual upgrade
// scenario migration 006 is for: a stream that was already at head_seq 5 when
// the migration ran, from before scheme/scheme_since existed at all.
//
// newTestStore (used by the other test below) runs every migration in one
// shot against an empty database, so there is never a pre-existing row for
// 006's "UPDATE ... WHERE scheme_since = 0" backfill to touch. That path
// needs a database that genuinely predates 006. This test builds one by
// running migrations 000-005, inserting a stream the way pre-006 code would
// have (no scheme columns exist yet), and only then running 006, so the
// backfill clause has a real pre-existing row to act on.
func TestMigrationPinsExistingStreamsAboveTheirHead(t *testing.T) {
	ctx := context.Background()

	dsn := filepath.Join(t.TempDir(), "chronicle_backfill_test.db")
	sdb := sqlitedriver.New()
	if err := sdb.Open(ctx, dsn); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	executor, err := migrate.NewExecutorFor(sdb)
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}

	all := Migrations.Migrations()
	if len(all) == 0 {
		t.Fatal("no migrations registered")
	}
	last := all[len(all)-1]
	if last.Name != "record_hash_scheme" {
		t.Fatalf("expected the newest migration to be record_hash_scheme, got %q; update this test's split point", last.Name)
	}

	for _, m := range all[:len(all)-1] {
		if upErr := m.Up(ctx, executor); upErr != nil {
			t.Fatalf("migration %s: %v", m.Name, upErr)
		}
	}

	// Seed a stream the way pre-006 code would have: head_seq 5, no scheme
	// columns because they don't exist on this schema yet.
	streamID := id.NewStreamID()
	if _, seedErr := executor.Exec(ctx,
		`INSERT INTO chronicle_streams (id, app_id, tenant_id, head_hash, head_seq, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		streamID.String(), "app", "t", "somehash", 5,
		"2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z",
	); seedErr != nil {
		t.Fatalf("seed pre-migration stream: %v", seedErr)
	}

	if upErr := last.Up(ctx, executor); upErr != nil {
		t.Fatalf("migration %s: %v", last.Name, upErr)
	}

	s := New(db)
	got, err := s.GetStreamByScope(ctx, "app", "t")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	if got.Scheme != "chronicle/v2" {
		t.Errorf("Scheme = %q, want chronicle/v2 (the column default backfilling a pre-existing row)", got.Scheme)
	}
	if got.SchemeSince != 6 {
		t.Errorf("SchemeSince = %d, want 6 (head_seq 5 + 1); a pre-existing row must land in the tolerant window, not at 0", got.SchemeSince)
	}
}

func TestEventSchemeColumnsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	st := &stream.Stream{ID: id.NewStreamID(), AppID: "app", Scheme: "chronicle/v3", SchemeSince: 1}
	if err := s.CreateStream(ctx, st); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	eventID := id.NewAuditID()
	if err := s.Append(ctx, &audit.Event{
		ID: eventID, StreamID: st.ID, Timestamp: time.Now().UTC(),
		AppID: "app", Action: "login", Resource: "session", Category: "auth",
		Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
		HashScheme: "chronicle/v3", HashKeyID: "hmac-1",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := s.Get(ctx, eventID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Append derives HashScheme/HashKeyID from the store's own hasher rather
	// than trusting the event's claim (hash/chain.go's VerifyWithPin doc:
	// trusting a caller-supplied scheme would let an attacker relabel a
	// downgraded event and recompute under the weaker algorithm). The
	// package-level hasher here is a zero-value plain chain, so "chronicle/v3"
	// and "hmac-1" above are overwritten and never reach the database; what
	// this test actually proves is that whatever Append does write comes back
	// unchanged through the new columns.
	wantScheme, wantKeyID := string(hasher.Scheme()), ""
	if got.HashScheme != wantScheme || got.HashKeyID != wantKeyID {
		t.Errorf("scheme columns = (%q, %q), want (%q, %q)", got.HashScheme, got.HashKeyID, wantScheme, wantKeyID)
	}
}
