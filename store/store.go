// Package store defines the composite store interface for Chronicle.
// Each subsystem defines its own store interface; the composite embeds them all.
package store

import (
	"context"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// Store is the aggregate persistence interface.
// Each subsystem store is a composable interface — same pattern as ControlPlane.
type Store interface {
	audit.Store
	stream.Store
	verify.Store
	erasure.Store
	retention.Store
	compliance.ReportStore

	// Migrate runs all schema migrations.
	Migrate(ctx context.Context) error

	// Ping checks database connectivity.
	Ping(ctx context.Context) error

	// Close closes the store connection.
	Close() error
}
