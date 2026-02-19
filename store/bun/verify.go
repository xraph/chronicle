package bunstore

import (
	"context"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// EventRange returns events in a sequence range for chain verification.
func (s *Store) EventRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error) {
	var models []EventModel
	err := s.db.NewSelect().Model(&models).
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
func (s *Store) Gaps(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]uint64, error) {
	// Use generate_series to find missing sequences.
	query := `
		SELECT seq
		FROM generate_series(?::BIGINT, ?::BIGINT) AS seq
		WHERE NOT EXISTS (
			SELECT 1 FROM chronicle_events
			WHERE stream_id = ? AND sequence = seq
		)
		ORDER BY seq`

	rows, err := s.db.QueryContext(ctx, query, fromSeq, toSeq, streamID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var gaps []uint64
	for rows.Next() {
		var seq uint64
		if err := rows.Scan(&seq); err != nil {
			return nil, err
		}
		gaps = append(gaps, seq)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return gaps, nil
}
