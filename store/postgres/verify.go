package postgres

import (
	"context"
	"encoding/json"
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
		WHERE stream_id = $1 AND sequence >= $2 AND sequence <= $3
		ORDER BY sequence ASC`

	rows, err := s.pool.Query(ctx, query, streamID, fromSeq, toSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*audit.Event
	for rows.Next() {
		event := &audit.Event{}
		var metadata []byte

		err := rows.Scan(
			&event.ID, &event.StreamID, &event.Sequence, &event.Hash, &event.PrevHash,
			&event.AppID, &event.TenantID, &event.UserID, &event.IP,
			&event.Action, &event.Resource, &event.Category, &event.ResourceID, &metadata,
			&event.Outcome, &event.Severity, &event.Reason,
			&event.SubjectID, &event.EncryptionKeyID,
			&event.Erased, &event.ErasedAt, &event.ErasureID,
			&event.Timestamp,
		)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

// Gaps detects missing sequence numbers in a range.
func (s *Store) Gaps(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]uint64, error) {
	// Generate a series of expected sequence numbers and find which ones are missing
	query := `
		SELECT seq
		FROM generate_series($2::BIGINT, $3::BIGINT) AS seq
		WHERE NOT EXISTS (
			SELECT 1 FROM chronicle_events
			WHERE stream_id = $1 AND sequence = seq
		)
		ORDER BY seq`

	rows, err := s.pool.Query(ctx, query, streamID, fromSeq, toSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
