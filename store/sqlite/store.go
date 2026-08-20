// Package sqlite implements the Chronicle store interface using grove ORM
// with the SQLite driver.
package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/grove/migrate"

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

// Store implements the Chronicle store interface using grove ORM with SQLite.
type Store struct {
	db  *grove.DB
	sdb *sqlitedriver.SqliteDB
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

// hasher re-links events into the chain inside Append's transaction. hash.Chain
// is stateless, so one package-level value is safe to share.
var hasher = &hash.Chain{}

// New creates a new grove ORM store with the given database connection.
func New(db *grove.DB) *Store {
	return &Store{
		db:  db,
		sdb: sqlitedriver.Unwrap(db),
	}
}

// Migrate runs grove migrations for the Chronicle schema.
func (s *Store) Migrate(ctx context.Context) error {
	executor, err := migrate.NewExecutorFor(s.sdb)
	if err != nil {
		return fmt.Errorf("%w: create migration executor: %w", chronicle.ErrMigrationFailed, err)
	}
	orch := migrate.NewOrchestrator(executor, Migrations)
	if _, err := orch.Migrate(ctx); err != nil {
		return fmt.Errorf("%w: %w", chronicle.ErrMigrationFailed, err)
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

// now returns the current UTC time.
func now() time.Time { return time.Now().UTC() }

// busyRetries and busyBackoff bound how long a contended write waits. SQLite
// permits a single writer and rejects the rest with SQLITE_BUSY immediately
// unless the connection sets busy_timeout, which is part of the caller's DSN and
// so not something this package can rely on.
const (
	busyRetries = 10
	busyBackoff = 5 * time.Millisecond
)

// retryOnBusy runs fn, retrying while SQLite reports the database as locked.
//
// Backoff grows linearly, capping total wait at roughly 275ms. A caller's
// context cancellation takes precedence over further retries.
func retryOnBusy(ctx context.Context, fn func() error) error {
	var err error
	for attempt := range busyRetries {
		err = fn()
		if err == nil || !isBusy(err) {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * busyBackoff):
		}
	}
	return fmt.Errorf("sqlite busy after %d attempts: %w", busyRetries, err)
}

// isBusy reports whether an error is SQLite's "database is locked" condition.
//
// The driver wraps its errors as strings by the time they reach here, so this
// matches on the message rather than a sentinel.
func isBusy(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "SQLITE_BUSY") ||
		strings.Contains(msg, "database table is locked")
}
