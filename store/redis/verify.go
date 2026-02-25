package redis

import (
	"context"
	"fmt"
	"sort"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// EventRange returns events in a sequence range for chain verification.
func (s *Store) EventRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error) {
	// Use the stream sorted set (scored by sequence).
	ids, err := s.zRangeByScoreIDs(ctx, zEventStream+streamID.String(),
		float64(fromSeq), float64(toSeq))
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: event range: %w", err)
	}

	events := make([]*audit.Event, 0, len(ids))
	for _, eid := range ids {
		var m eventModel
		if err := s.getEntity(ctx, entityKey(prefixEvent, eid), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		evt, err := fromEventModel(&m)
		if err != nil {
			return nil, err
		}
		events = append(events, evt)
	}

	// Ensure ascending order by sequence.
	sort.Slice(events, func(i, j int) bool {
		return events[i].Sequence < events[j].Sequence
	})

	return events, nil
}

// Gaps detects missing sequence numbers in a range.
func (s *Store) Gaps(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]uint64, error) {
	ids, err := s.zRangeByScoreIDs(ctx, zEventStream+streamID.String(),
		float64(fromSeq), float64(toSeq))
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: gaps query: %w", err)
	}

	// Collect existing sequences.
	existing := make(map[uint64]struct{}, len(ids))
	for _, eid := range ids {
		var m eventModel
		if err := s.getEntity(ctx, entityKey(prefixEvent, eid), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		existing[m.Sequence] = struct{}{}
	}

	// Compute gaps.
	var gaps []uint64
	for seq := fromSeq; seq <= toSeq; seq++ {
		if _, ok := existing[seq]; !ok {
			gaps = append(gaps, seq)
		}
	}

	return gaps, nil
}
