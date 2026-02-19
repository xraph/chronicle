// Package postgres implements the Chronicle store interface using PostgreSQL.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store implements the Chronicle store interface using PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
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

// New creates a new PostgreSQL store with the given connection pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Migrate runs all embedded SQL migrations in order.
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("%w: failed to read migrations: %w", chronicle.ErrMigrationFailed, err)
	}

	// Sort migration files to ensure they run in order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: failed to begin transaction: %w", chronicle.ErrMigrationFailed, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("%w: failed to read %s: %w", chronicle.ErrMigrationFailed, entry.Name(), err)
		}

		if _, err := tx.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("%w: failed to execute %s: %w", chronicle.ErrMigrationFailed, entry.Name(), err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: failed to commit migrations: %w", chronicle.ErrMigrationFailed, err)
	}

	return nil
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	if s.pool == nil {
		return chronicle.ErrStoreClosed
	}
	return s.pool.Ping(ctx)
}

// Close closes the database connection pool.
func (s *Store) Close() error {
	if s.pool == nil {
		return chronicle.ErrStoreClosed
	}
	s.pool.Close()
	return nil
}

// pgxError checks if an error is a pgx.ErrNoRows and returns the appropriate Chronicle error.
func pgxError(err, notFoundErr error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return notFoundErr
	}
	return err
}
