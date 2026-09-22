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
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/stream"
)

// stubProvider is a Provider backed by a fixed key, mirroring the one in
// hash/scheme_test.go and chronicle_test.go.
type stubProvider struct {
	key      []byte
	activeID string
}

func (s stubProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return s.key, s.activeID, nil
}

func (s stubProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != s.activeID {
		return nil, keys.ErrKeyNotFound
	}
	return s.key, nil
}

// newHMACTestStore is newTestStore, but the store re-links under an HMAC
// chain instead of the default plain one, so tests can prove Append picks up
// the configured scheme rather than a hardcoded one.
func newHMACTestStore(t *testing.T) *Store {
	t.Helper()

	dsn := filepath.Join(t.TempDir(), "chronicle_hmac_test.db")

	sdb := sqlitedriver.New()
	if err := sdb.Open(context.Background(), dsn); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	h, err := hash.NewChain(hash.SchemeHMAC, stubProvider{key: make([]byte, 32), activeID: "hmac-1"})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	s := New(db, WithHasher(h))
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// backfillFixture runs migrations 000-005 against a fresh database, seeds a
// stream at headSeq the way pre-006 code would have (no scheme columns exist
// yet), optionally raw-inserts events at eventSeqs for that stream, and only
// then runs migration 006, so its backfill clause has a real pre-existing row
// (and, when eventSeqs is set, events head_seq does not account for) to act
// on. It returns the resulting stream.
//
// newTestStore (used by TestEventSchemeColumnsRoundTrip below) runs every
// migration in one shot against an empty database, which is fine for that
// test but cannot exercise this path: there is never a pre-existing row for
// 006's backfill UPDATE to touch, since nothing was written before it ran.
func backfillFixture(t *testing.T, headSeq int, eventSeqs []int) *stream.Stream {
	t.Helper()
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

	streamID := id.NewStreamID()
	if _, seedErr := executor.Exec(ctx,
		`INSERT INTO chronicle_streams (id, app_id, tenant_id, head_hash, head_seq, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		streamID.String(), "app", "t", "somehash", headSeq,
		"2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z",
	); seedErr != nil {
		t.Fatalf("seed pre-migration stream: %v", seedErr)
	}

	// Simulates a crash between an event insert and the head update (see
	// store/sqlite/audit.go's appendOnce: the head is written in the same
	// transaction as the event specifically to close that window, which
	// implies it was open before). These events exist but head_seq does not
	// know about them yet.
	for _, seq := range eventSeqs {
		if _, seedErr := executor.Exec(ctx,
			`INSERT INTO chronicle_events (id, stream_id, sequence, hash, app_id, action, resource, category, timestamp)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id.NewAuditID().String(), streamID.String(), seq, "h", "app", "login", "session", "auth",
			"2024-01-01T00:00:00Z",
		); seedErr != nil {
			t.Fatalf("seed pre-migration event %d: %v", seq, seedErr)
		}
	}

	if upErr := last.Up(ctx, executor); upErr != nil {
		t.Fatalf("migration %s: %v", last.Name, upErr)
	}

	s := New(db)
	got, err := s.GetStreamByScope(ctx, "app", "t")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	return got
}

// TestMigrationPinsExistingStreamsAboveTheirHead exercises the actual upgrade
// scenario migration 006 is for.
func TestMigrationPinsExistingStreamsAboveTheirHead(t *testing.T) {
	t.Run("no events beyond head_seq, pins from head_seq", func(t *testing.T) {
		got := backfillFixture(t, 5, nil)
		if got.Scheme != "chronicle/v2" {
			t.Errorf("Scheme = %q, want chronicle/v2 (the column default backfilling a pre-existing row)", got.Scheme)
		}
		if got.SchemeSince != 6 {
			t.Errorf("SchemeSince = %d, want 6 (head_seq 5 + 1); a pre-existing row must land in the tolerant window, not at 0", got.SchemeSince)
		}
	})

	t.Run("head_seq lags MAX(sequence), pins from the true max", func(t *testing.T) {
		// head_seq is 5 but events exist up to sequence 10. Pinning from
		// head_seq alone would put events 9 and 10 at or above scheme_since
		// with no recorded scheme, which hash/chain.go's VerifyWithPin reads
		// as a permanent downgrade rather than as pre-migration history.
		got := backfillFixture(t, 5, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
		if got.SchemeSince != 11 {
			t.Errorf("SchemeSince = %d, want 11 (MAX(sequence) 10 + 1, not head_seq 5 + 1)", got.SchemeSince)
		}
	})
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
	// downgraded event and recompute under the weaker algorithm), so
	// "chronicle/v3" and "hmac-1" above are overwritten and never reach the
	// database. store/sqlite/store.go hardcodes the package-level hasher to a
	// zero-value Chain, which is SchemePlain with no key provider; asserting
	// the literal here (rather than re-deriving it from hasher.Scheme(), the
	// same call the code under test makes) pins that behavior instead of
	// mirroring it. What this test actually proves is that whatever Append
	// does write comes back unchanged through the new columns.
	wantScheme, wantKeyID := string(hash.SchemePlain), ""
	if got.HashScheme != wantScheme || got.HashKeyID != wantKeyID {
		t.Errorf("scheme columns = (%q, %q), want (%q, %q)", got.HashScheme, got.HashKeyID, wantScheme, wantKeyID)
	}
}

// TestEventModelCarriesHashKeyID closes the coverage gap TestEventSchemeColumnsRoundTrip
// leaves: that test can only observe whatever Append's hasher happens to
// write, which is always an empty key ID until a later task makes the hasher
// configurable, so it cannot tell a correctly wired hash_key_id column apart
// from one silently dropped by fromEvent/toEvent. This test seeds hash_key_id
// with a raw INSERT, bypassing Append entirely, and reads it back through
// s.Get (toEvent), proving the column and its grove tag round-trip a
// non-empty key ID without needing any change to production code.
func TestEventModelCarriesHashKeyID(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	st := &stream.Stream{ID: id.NewStreamID(), AppID: "app"}
	if err := s.CreateStream(ctx, st); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	executor, err := migrate.NewExecutorFor(s.sdb)
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}

	eventID := id.NewAuditID()
	if _, seedErr := executor.Exec(ctx,
		`INSERT INTO chronicle_events
		    (id, stream_id, sequence, hash, app_id, action, resource, category, timestamp, hash_scheme, hash_key_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		eventID.String(), st.ID.String(), 1, "h", "app", "login", "session", "auth",
		"2024-01-01T00:00:00Z", string(hash.SchemeHMAC), "hmac-key-7",
	); seedErr != nil {
		t.Fatalf("seed event: %v", seedErr)
	}

	got, err := s.Get(ctx, eventID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HashKeyID != "hmac-key-7" {
		t.Errorf("HashKeyID = %q, want hmac-key-7", got.HashKeyID)
	}
	if got.HashScheme != string(hash.SchemeHMAC) {
		t.Errorf("HashScheme = %q, want %q", got.HashScheme, hash.SchemeHMAC)
	}
}

// Append re-derives the sequence and prev_hash under a row lock, and therefore
// recomputes the digest. If it recomputes under a plain chain while Chronicle
// is configured for HMAC, every event silently reverts to an unkeyed digest.
func TestAppendRecomputesUnderTheConfiguredScheme(t *testing.T) {
	ctx := context.Background()
	s := newHMACTestStore(t) // wraps newTestStore with an HMAC chain; see step 3

	st := &stream.Stream{ID: id.NewStreamID(), AppID: "app", Scheme: "chronicle/v3", SchemeSince: 1}
	if err := s.CreateStream(ctx, st); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	eventID := id.NewAuditID()
	if err := s.Append(ctx, &audit.Event{
		ID: eventID, StreamID: st.ID, Timestamp: time.Now().UTC(),
		AppID: "app", Action: "login", Resource: "session", Category: "auth",
		Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := s.Get(ctx, eventID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HashScheme != "chronicle/v3" {
		t.Errorf("HashScheme = %q, want chronicle/v3; Append reverted to an unkeyed digest", got.HashScheme)
	}
	if got.HashKeyID == "" {
		t.Error("HashKeyID is empty; the key used for the digest was not recorded")
	}
}
