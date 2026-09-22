package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/grove/drivers/pgdriver/pgmigrate"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
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

// New creates a new grove ORM store with the given database connection.
//
// Without WithHasher, Append re-links under a zero-value hash.Chain, which is
// SchemePlain with no key provider -- the same behavior as before this option
// existed.
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

// Migrate runs grove migrations for the Chronicle schema.
func (s *Store) Migrate(ctx context.Context) error {
	exec := pgmigrate.New(s.pg)
	for _, m := range Migrations.Migrations() {
		if m.Up != nil {
			if err := m.Up(ctx, exec); err != nil {
				return fmt.Errorf("%w: %s: %w", chronicle.ErrMigrationFailed, m.Name, err)
			}
		}
	}
	return nil
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

// groveError checks if an error indicates no rows were found and returns
// the appropriate Chronicle error.
func groveError(err, notFoundErr error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, grove.ErrNoRows) || err.Error() == "no rows in result set" {
		return notFoundErr
	}
	return err
}
