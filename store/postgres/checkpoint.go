package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// pgUniqueViolation is the SQLSTATE Postgres reports for a UNIQUE constraint
// violation.
// https://www.postgresql.org/docs/current/errcodes-appendix.html
const pgUniqueViolation = "23505"

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation.
//
// groveError alone is the wrong tool here: a uniqueness violation is a
// different error than a missing row, and reaches this package as a typed
// *pgconn.PgError rather than pgx.ErrNoRows, wrapped by pgdriver's Exec in an
// additional "pgdriver: exec: " prefix that errors.As sees through.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

// AppendCheckpoint persists a checkpoint. Checkpoints are append-only: there
// is no update or delete, since a checkpoint that could be revised would
// assert nothing.
//
// UNIQUE(stream_id, to_seq) and UNIQUE(stream_id, from_seq) on
// chronicle_checkpoints are the structural backstop against two
// checkpointers racing on one stream -- a background ticker, an
// operator-triggered run, or a second replica's ticker -- so the loser of
// that race gets checkpoint.ErrExists straight from the database rather than
// from a read-then-insert check a concurrent writer could still slip past.
//
// Both constraints are load-bearing. See migration 007 for why to_seq alone
// lets two replicas reading different heads write overlapping checkpoints.
func (s *Store) AppendCheckpoint(ctx context.Context, cp *checkpoint.Checkpoint) error {
	m := fromCheckpoint(cp)
	if _, err := s.pg.NewInsert(m).Exec(ctx); err != nil {
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
	err := s.pg.NewSelect(m).
		Where("stream_id = ?", streamID.String()).
		OrderExpr("cp.to_seq DESC").
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, groveError(err, checkpoint.ErrNotFound)
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
	err := s.pg.NewSelect(&models).
		Where("stream_id = ?", streamID.String()).
		Where("from_seq <= ?", safeInt64(toSeq)).
		Where("to_seq >= ?", safeInt64(fromSeq)).
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
	err := s.pg.NewSelect(m).Where("id = ?", checkpointID.String()).Scan(ctx)
	if err != nil {
		return nil, groveError(err, checkpoint.ErrNotFound)
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
	err := s.pg.NewSelect(&models).
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
