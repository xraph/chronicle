// Package mongo implements the Chronicle store interface using grove ORM
// with the MongoDB driver.
package mongo

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// Collection name constants.
const (
	colEvents   = "chronicle_events"
	colStreams  = "chronicle_streams"
	colErasures = "chronicle_erasures"
	colPolicies = "chronicle_retention_policies"
	colArchives = "chronicle_archives"
	colReports  = "chronicle_reports"
)

// Store implements the Chronicle store interface using grove ORM with MongoDB.
type Store struct {
	db  *grove.DB
	mdb *mongodriver.MongoDB
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

// New creates a new grove ORM store with the given database connection.
func New(db *grove.DB) *Store {
	return &Store{
		db:  db,
		mdb: mongodriver.Unwrap(db),
	}
}

// Migrate creates indexes for all chronicle collections.
func (s *Store) Migrate(ctx context.Context) error {
	indexes := migrationIndexes()

	for col, models := range indexes {
		if len(models) == 0 {
			continue
		}
		_, err := s.mdb.Collection(col).Indexes().CreateMany(ctx, models)
		if err != nil {
			return fmt.Errorf("%w: %s indexes: %w", chronicle.ErrMigrationFailed, col, err)
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

// isNoDocuments checks if an error wraps mongo.ErrNoDocuments.
func isNoDocuments(err error) bool {
	return errors.Is(err, mongo.ErrNoDocuments)
}
