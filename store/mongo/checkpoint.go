package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// AppendCheckpoint persists a checkpoint. Checkpoints are append-only: there
// is no update or delete, since a checkpoint that could be revised would
// assert nothing.
//
// The unique indexes on (stream_id, to_seq) and (stream_id, from_seq) --
// created alongside the collection in migrations.go, see checkpointIndexes
// for why both -- are the structural backstop against two checkpointers
// racing on one stream: a background ticker, an operator-triggered run, or a
// second replica's ticker, so the loser of that race gets
// checkpoint.ErrExists straight from the database rather than from a
// read-then-insert check a concurrent writer could still slip past.
func (s *Store) AppendCheckpoint(ctx context.Context, cp *checkpoint.Checkpoint) error {
	m := fromCheckpoint(cp)
	if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return checkpoint.ErrExists
		}
		return fmt.Errorf("insert checkpoint %s: %w", cp.ID, err)
	}
	return nil
}

// LatestCheckpoint returns the checkpoint with the highest ToSeq for a
// stream.
func (s *Store) LatestCheckpoint(ctx context.Context, streamID id.ID) (*checkpoint.Checkpoint, error) {
	var m CheckpointModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"stream_id": streamID.String()}).
		Sort(bson.D{{Key: "to_seq", Value: -1}}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, checkpoint.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get latest checkpoint: %w", err)
	}

	out, err := toCheckpoint(&m)
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
	err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"stream_id": streamID.String(),
			"from_seq":  bson.M{"$lte": toSeq},
			"to_seq":    bson.M{"$gte": fromSeq},
		}).
		Sort(bson.D{{Key: "to_seq", Value: 1}}).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query checkpoints in range: %w", err)
	}

	return toCheckpointSlice(models)
}

// GetCheckpoint returns one checkpoint by ID.
func (s *Store) GetCheckpoint(ctx context.Context, checkpointID id.ID) (*checkpoint.Checkpoint, error) {
	var m CheckpointModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": checkpointID.String()}).Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, checkpoint.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get checkpoint: %w", err)
	}

	out, err := toCheckpoint(&m)
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
	findQ := s.mdb.NewFind(&models).
		Filter(bson.M{"stream_id": streamID.String()}).
		Sort(bson.D{{Key: "to_seq", Value: -1}})

	if opts.Limit > 0 {
		findQ = findQ.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		findQ = findQ.Skip(int64(opts.Offset))
	}

	if err := findQ.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to list checkpoints: %w", err)
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
