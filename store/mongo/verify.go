package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// EventRange returns events in a sequence range for chain verification.
func (s *Store) EventRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error) {
	var models []EventModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"stream_id": streamID.String(),
			"sequence": bson.M{
				"$gte": fromSeq,
				"$lte": toSeq,
			},
		}).
		Sort(bson.D{{Key: "sequence", Value: 1}}).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query event range: %w", err)
	}

	return toEventSlice(models)
}

// Gaps detects missing sequence numbers in a range.
// Since MongoDB does not have generate_series, we query existing sequences
// and compute the gaps in Go.
func (s *Store) Gaps(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]uint64, error) {
	pipeline := bson.A{
		bson.M{"$match": bson.M{
			"stream_id": streamID.String(),
			"sequence": bson.M{
				"$gte": fromSeq,
				"$lte": toSeq,
			},
		}},
		bson.M{"$project": bson.M{"sequence": 1}},
		bson.M{"$sort": bson.M{"sequence": 1}},
	}

	cursor, err := s.mdb.Collection(colEvents).Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to query sequences for gap detection: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	// Collect all existing sequences into a set.
	existing := make(map[uint64]struct{})
	for cursor.Next(ctx) {
		var row struct {
			Sequence uint64 `bson:"sequence"`
		}
		if err := cursor.Decode(&row); err != nil {
			return nil, fmt.Errorf("failed to decode sequence: %w", err)
		}
		existing[row.Sequence] = struct{}{}
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate sequences: %w", err)
	}

	// Compute gaps by checking every expected sequence.
	var gaps []uint64
	for seq := fromSeq; seq <= toSeq; seq++ {
		if _, ok := existing[seq]; !ok {
			gaps = append(gaps, seq)
		}
	}

	return gaps, nil
}
