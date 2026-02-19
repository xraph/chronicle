package sqlite

import (
	"context"
	"fmt"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// EventRange returns events in a sequence range for chain verification.
func (s *Store) EventRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error) {
	query := `
		SELECT
			id, stream_id, sequence, hash, prev_hash,
			app_id, tenant_id, user_id, ip,
			action, resource, category, resource_id, metadata,
			outcome, severity, reason,
			subject_id, encryption_key_id,
			erased, erased_at, erasure_id,
			timestamp
		FROM chronicle_events
		WHERE stream_id = ? AND sequence >= ? AND sequence <= ?
		ORDER BY sequence ASC`

	rows, err := s.db.QueryContext(ctx, query, streamID.String(), fromSeq, toSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to query event range: %w", err)
	}
	defer rows.Close()

	return s.scanEvents(rows)
}

// Gaps detects missing sequence numbers in a range.
// Since SQLite does not have generate_series, we query existing sequences
// and compute the gaps in Go.
func (s *Store) Gaps(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]uint64, error) {
	query := `
		SELECT sequence
		FROM chronicle_events
		WHERE stream_id = ? AND sequence >= ? AND sequence <= ?
		ORDER BY sequence ASC`

	rows, err := s.db.QueryContext(ctx, query, streamID.String(), fromSeq, toSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to query sequences for gap detection: %w", err)
	}
	defer rows.Close()

	// Collect all existing sequences into a set.
	existing := make(map[uint64]struct{})
	for rows.Next() {
		var seq uint64
		if err := rows.Scan(&seq); err != nil {
			return nil, fmt.Errorf("failed to scan sequence: %w", err)
		}
		existing[seq] = struct{}{}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate sequence rows: %w", err)
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
