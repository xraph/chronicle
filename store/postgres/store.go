package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/grove/drivers/pgdriver/pgmigrate"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// Store implements the Chronicle store interface using grove ORM.
type Store struct {
	db     *grove.DB
	pg     *pgdriver.PgDB
	hasher *hash.Chain
}

// Compile-time interface checks.
var (
	_ store.Store            = (*Store)(nil)
	_ audit.Store            = (*Store)(nil)
	_ stream.Store           = (*Store)(nil)
	_ verify.Store           = (*Store)(nil)
	_ erasure.Store          = (*Store)(nil)
	_ retention.Store        = (*Store)(nil)
	_ compliance.ReportStore = (*Store)(nil)
	_ checkpoint.Store       = (*Store)(nil)
)

// Option configures a Store constructed by New.
type Option func(*Store)

// WithHasher sets the chain the store re-links with.
//
// Append re-derives the sequence and prev_hash while holding the stream's row
// lock, which means it must also recompute the digest. That recomputation has
// to use the same scheme Chronicle was configured with; a store left on the
// default plain chain would quietly downgrade every event it re-linked.
func WithHasher(h *hash.Chain) Option {
	return func(s *Store) { s.hasher = h }
}

// SetHasher replaces the chain the store re-links with after construction.
//
// This exists for a store built directly (e.g. passed to
// extension.WithStore) rather than through New with WithHasher: it lets a
// caller who already holds the Store give it the chain later, which is what
// lets that path be brought up to the configured digest scheme instead of
// silently staying on the default plain one.
func (s *Store) SetHasher(h *hash.Chain) { s.hasher = h }

// New creates a new grove ORM store with the given database connection.
//
// Without WithHasher, Append re-links under a zero-value hash.Chain, which is
// SchemePlainV4 with no key provider: unkeyed, but with the unambiguous content
// encoding, so a default-configured store is not writing forgeable digests.
func New(db *grove.DB, opts ...Option) *Store {
	s := &Store{
		db:     db,
		pg:     pgdriver.Unwrap(db),
		hasher: &hash.Chain{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Migrate applies the Chronicle migrations this database hasn't had yet.
//
// grove records each one in grove_migrations as it lands, so on a current
// schema this runs no DDL at all. It used to run every ALTER TABLE on each
// call, and ALTER TABLE waits for an exclusive lock on the table even when the
// column is already there, so a process starting up could deadlock with one
// that was appending. Concurrent callers take turns on grove's advisory lock,
// and the ones that go second find nothing left to apply.
//
// A database migrated before this kept no record, so its first call here runs
// every migration once more. They are all written to be re-run.
func (s *Store) Migrate(ctx context.Context) error {
	orch := migrate.NewOrchestrator(pgmigrate.New(s.pg), Migrations)
	var err error
	for range 3 {
		if _, err = orch.Migrate(ctx); err == nil || !lostCreateRace(err) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("%w: %w", chronicle.ErrMigrationFailed, err)
	}
	return nil
}

// lostCreateRace reports an error from two sessions running the same CREATE
// TABLE IF NOT EXISTS at once. grove creates its own bookkeeping tables before
// it takes the migration lock, and Postgres doesn't make that statement atomic
// against itself: the loser gets 23505 on the table's row type or 42P07 on the
// table. grove swallows the first and not the second (pgdriver v1.6.4). The
// winner has committed by then, so running Migrate again gets past it.
func lostCreateRace(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42P07" || pgErr.Code == "23505"
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLSTATE 42P07") || strings.Contains(msg, "SQLSTATE 23505")
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	if s.db == nil {
		return chronicle.ErrStoreClosed
	}
	return s.db.Ping(ctx)
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db == nil {
		return chronicle.ErrStoreClosed
	}
	return s.db.Close()
}

// groveError maps a missing row onto the sentinel a caller can test for.
//
// Three checks, because the wording belongs to whichever driver grove is
// sitting on. grove's own sentinel comes first. database/sql says "sql: no rows
// in result set" and pgx says "no rows in result set", and matching only the
// second is how every sqlite miss used to reach callers as a raw driver error
// rather than ErrEventNotFound: errors.Is against the sentinel returned false,
// so an ordinary absent row looked like an internal failure. The string check
// stays as a last resort for a driver that wraps neither.
func groveError(err, notFoundErr error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, grove.ErrNoRows) || errors.Is(err, sql.ErrNoRows) ||
		strings.Contains(err.Error(), "no rows in result set") {
		return notFoundErr
	}
	return err
}
