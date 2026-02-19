// Package sqlite implements the Chronicle store interface using SQLite.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"time"

	_ "modernc.org/sqlite" // SQLite driver registration

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

// Store implements the Chronicle store interface using SQLite.
type Store struct {
	db *sql.DB
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

// New creates a new SQLite store with the given database connection.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Open creates a new SQLite store from a file path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Enable WAL mode for better concurrent read performance.
	if _, err := db.ExecContext(context.Background(), "PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Enable foreign key enforcement.
	if _, err := db.ExecContext(context.Background(), "PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	return New(db), nil
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
	defer func() { _ = tx.Rollback() }() //nolint:errcheck // rollback after commit is a no-op

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

// sqliteError checks if an error is sql.ErrNoRows and returns the appropriate Chronicle error.
func sqliteError(err, notFoundErr error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return notFoundErr
	}
	return err
}

// formatTime formats a time.Time to RFC3339Nano string for SQLite TEXT storage.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// parseTime parses an RFC3339Nano string from SQLite TEXT into time.Time.
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

// parseNullableTime parses an optional RFC3339Nano string from SQLite TEXT into *time.Time.
func parseNullableTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid || s.String == "" {
		return nil, nil //nolint:nilnil // nullable time
	}
	t, err := parseTime(s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
