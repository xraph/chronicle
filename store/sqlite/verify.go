package sqlite

import (
	"context"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// EventRange returns events in a sequence range for chain verification.
func (s *Store) EventRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error) {
	var models []EventModel
	err := s.sdb.NewSelect(&models).
		Where("e.stream_id = ?", streamID.String()).
		Where("e.sequence >= ?", fromSeq).
		Where("e.sequence <= ?", toSeq).
		OrderExpr("e.sequence ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return toEventSlice(models)
}

// Gaps detects missing sequence numbers in a range.
// Since SQLite does not have generate_series by default, we query existing
// sequences and compute the gaps in Go.
func (s *Store) Gaps(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]uint64, error) {
	query := `
		SELECT sequence
		FROM chronicle_events
		WHERE stream_id = ? AND sequence >= ? AND sequence <= ?
		ORDER BY sequence ASC`

	rows, err := s.sdb.Query(ctx, query, streamID.String(), fromSeq, toSeq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	// Collect all existing sequences into a set.
	existing := make(map[uint64]struct{})
	for rows.Next() {
		var seq uint64
		if err := rows.Scan(&seq); err != nil {
			return nil, err
		}
		existing[seq] = struct{}{}
	}

	if err := rows.Err(); err != nil {
		return nil, err
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
