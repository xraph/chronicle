package bunstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

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

// Store implements the Chronicle store interface using Bun ORM.
type Store struct {
	db *bun.DB
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

// New creates a new Bun ORM store with the given database connection.
func New(db *bun.DB) *Store {
	return &Store{db: db}
}

// Migrate runs all embedded SQL migrations in order.
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("%w: failed to read migrations: %w", chronicle.ErrMigrationFailed, err)
	}

	// Sort migration files to ensure they run in order.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: failed to begin transaction: %w", chronicle.ErrMigrationFailed, err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("%w: failed to read %s: %w", chronicle.ErrMigrationFailed, entry.Name(), err)
		}

		if _, err := tx.ExecContext(ctx, string(data)); err != nil {
			return fmt.Errorf("%w: failed to execute %s: %w", chronicle.ErrMigrationFailed, entry.Name(), err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: failed to commit migrations: %w", chronicle.ErrMigrationFailed, err)
	}

	return nil
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	if s.db == nil {
		return chronicle.ErrStoreClosed
	}
	return s.db.PingContext(ctx)
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db == nil {
		return chronicle.ErrStoreClosed
	}
	return s.db.Close()
}

// bunError checks if an error is sql.ErrNoRows and returns the appropriate Chronicle error.
func bunError(err, notFoundErr error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return notFoundErr
	}
	return err
}
