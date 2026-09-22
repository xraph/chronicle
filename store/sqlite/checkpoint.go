package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/xraph/grove"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// isUniqueViolation reports whether err is a UNIQUE constraint violation.
//
// modernc.org/sqlite reports this as "constraint failed: UNIQUE constraint
// failed: ..." (SQLITE_CONSTRAINT_UNIQUE), which sqlitedriver's Exec wraps in
// its own "sqlitedriver: exec: " prefix. Matching on the substring follows
// isBusy's precedent below: this driver's errors reach here as strings, not
// typed sentinels, so isBusy already treats them the same way.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// notFoundOnNoRows maps a no-rows Scan result to checkpoint.ErrNotFound.
//
// groveError (store.go) does not apply here: its string-literal branch checks
// for "no rows in result set", but this driver's sql.ErrNoRows carries a
// "sql: " prefix that literal never matches. That bug is tracked and fixed
// separately (see groveError's doc comment). This checks both sentinels that
// can actually come back from a single-row Scan on this backend directly,
// rather than inheriting the broken string comparison: sql.ErrNoRows is what
// the driver returns today (traced through SelectQuery.Scan ->
// sqliteRow.Scan -> *sql.Row.Scan, unwrapped), and grove.ErrNoRows is grove's
// own sentinel for the same condition, which some other code path or a later
// grove version could return instead. Checking only one leaves the other
// arriving as a raw, unclassified driver error.
func notFoundOnNoRows(err error) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, grove.ErrNoRows) {
		return checkpoint.ErrNotFound
	}
	return err
}

// AppendCheckpoint persists a checkpoint. Checkpoints are append-only: there
// is no update or delete, since a checkpoint that could be revised would
// assert nothing.
//
// UNIQUE(stream_id, to_seq) on chronicle_checkpoints is the structural
// backstop against two checkpointers racing on one stream -- a background
// ticker and an operator-triggered run can overlap -- so the loser of that
// race gets checkpoint.ErrExists straight from the database rather than from
// a read-then-insert check a concurrent writer could still slip past.
func (s *Store) AppendCheckpoint(ctx context.Context, cp *checkpoint.Checkpoint) error {
	m := fromCheckpoint(cp)
	if _, err := s.sdb.NewInsert(m).Exec(ctx); err != nil {
		if isUniqueViolation(err) {
			return checkpoint.ErrExists
		}
		return fmt.Errorf("insert checkpoint %s: %w", cp.ID, err)
	}
	return nil
}

// LatestCheckpoint returns the checkpoint with the highest ToSeq for a
// stream.
func (s *Store) LatestCheckpoint(ctx context.Context, streamID id.ID) (*checkpoint.Checkpoint, error) {
	m := new(CheckpointModel)
	err := s.sdb.NewSelect(m).
		Where("stream_id = ?", streamID.String()).
		OrderExpr("cp.to_seq DESC").
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, notFoundOnNoRows(err)
	}

	out, err := toCheckpoint(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert checkpoint model: %w", err)
	}
	return out, nil
}

// CheckpointsInRange returns every checkpoint whose range overlaps
// [fromSeq, toSeq], ascending by ToSeq.
//
// Overlap rather than containment: a caller verifying sequences 150 to 160
// still needs the checkpoint covering 101 to 200, because that is the one
// whose signed assertion those events fall under. Containment would return
// nothing for a range that sits inside a wider checkpoint.
func (s *Store) CheckpointsInRange(
	ctx context.Context, streamID id.ID, fromSeq, toSeq uint64,
) ([]*checkpoint.Checkpoint, error) {
	var models []CheckpointModel
	err := s.sdb.NewSelect(&models).
		Where("stream_id = ?", streamID.String()).
		Where("from_seq <= ?", toSeq).
		Where("to_seq >= ?", fromSeq).
		OrderExpr("cp.to_seq ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return toCheckpointSlice(models)
}

// GetCheckpoint returns one checkpoint by ID.
func (s *Store) GetCheckpoint(ctx context.Context, checkpointID id.ID) (*checkpoint.Checkpoint, error) {
	m := new(CheckpointModel)
	err := s.sdb.NewSelect(m).Where("id = ?", checkpointID.String()).Scan(ctx)
	if err != nil {
		return nil, notFoundOnNoRows(err)
	}

	out, err := toCheckpoint(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert checkpoint model: %w", err)
	}
	return out, nil
}

// ListCheckpoints returns a stream's checkpoints, newest first.
func (s *Store) ListCheckpoints(
	ctx context.Context, streamID id.ID, opts checkpoint.ListOpts,
) ([]*checkpoint.Checkpoint, error) {
	var models []CheckpointModel
	err := s.sdb.NewSelect(&models).
		Where("stream_id = ?", streamID.String()).
		OrderExpr("cp.to_seq DESC").
		Limit(opts.Limit).
		Offset(opts.Offset).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return toCheckpointSlice(models)
}

// toCheckpointSlice converts a slice of CheckpointModel to a slice of
// checkpoint.Checkpoint.
func toCheckpointSlice(models []CheckpointModel) ([]*checkpoint.Checkpoint, error) {
	out := make([]*checkpoint.Checkpoint, 0, len(models))
	for i := range models {
		cp, err := toCheckpoint(&models[i])
		if err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, nil
}
