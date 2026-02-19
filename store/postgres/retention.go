package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
)

// SavePolicy persists a retention policy (INSERT or UPDATE on conflict).
func (s *Store) SavePolicy(ctx context.Context, p *retention.Policy) error {
	query := `
		INSERT INTO chronicle_retention_policies (
			id, category, duration, archive, app_id, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
		ON CONFLICT (category)
		DO UPDATE SET
			duration = EXCLUDED.duration,
			archive = EXCLUDED.archive,
			app_id = EXCLUDED.app_id,
			updated_at = EXCLUDED.updated_at`

	_, err := s.pool.Exec(ctx, query,
		p.ID, p.Category, int64(p.Duration), p.Archive, p.AppID,
		p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// GetPolicy returns a retention policy by ID.
func (s *Store) GetPolicy(ctx context.Context, policyID id.ID) (*retention.Policy, error) {
	query := `
		SELECT id, category, duration, archive, app_id, created_at, updated_at
		FROM chronicle_retention_policies
		WHERE id = $1`

	p := &retention.Policy{}
	var duration int64

	err := s.pool.QueryRow(ctx, query, policyID).Scan(
		&p.ID, &p.Category, &duration, &p.Archive, &p.AppID,
		&p.CreatedAt, &p.UpdatedAt,
	)

	if err != nil {
		return nil, pgxError(err, chronicle.ErrPolicyNotFound)
	}

	p.Duration = time.Duration(duration)
	return p, nil
}

// ListPolicies returns all retention policies.
func (s *Store) ListPolicies(ctx context.Context) ([]*retention.Policy, error) {
	query := `
		SELECT id, category, duration, archive, app_id, created_at, updated_at
		FROM chronicle_retention_policies
		ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*retention.Policy
	for rows.Next() {
		p := &retention.Policy{}
		var duration int64

		err := rows.Scan(
			&p.ID, &p.Category, &duration, &p.Archive, &p.AppID,
			&p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		p.Duration = time.Duration(duration)
		policies = append(policies, p)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return policies, nil
}

// DeletePolicy removes a retention policy.
func (s *Store) DeletePolicy(ctx context.Context, policyID id.ID) error {
	query := `DELETE FROM chronicle_retention_policies WHERE id = $1`

	result, err := s.pool.Exec(ctx, query, policyID)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: policy %s", chronicle.ErrPolicyNotFound, policyID)
	}

	return nil
}

// EventsOlderThan returns events older than a given time for a category.
func (s *Store) EventsOlderThan(ctx context.Context, category string, before time.Time) ([]*audit.Event, error) {
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
		WHERE category = $1 AND timestamp < $2
		ORDER BY timestamp ASC`

	rows, err := s.pool.Query(ctx, query, category, before)
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

// PurgeEvents permanently deletes events by IDs.
func (s *Store) PurgeEvents(ctx context.Context, eventIDs []id.ID) (int64, error) {
	if len(eventIDs) == 0 {
		return 0, nil
	}

	query := `DELETE FROM chronicle_events WHERE id = ANY($1)`

	result, err := s.pool.Exec(ctx, query, eventIDs)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected(), nil
}

// RecordArchive records that a batch of events was archived.
func (s *Store) RecordArchive(ctx context.Context, a *retention.Archive) error {
	query := `
		INSERT INTO chronicle_archives (
			id, policy_id, category, event_count,
			from_timestamp, to_timestamp, sink_name, sink_ref, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)`

	_, err := s.pool.Exec(ctx, query,
		a.ID, a.PolicyID, a.Category, a.EventCount,
		a.FromTimestamp, a.ToTimestamp, a.SinkName, a.SinkRef, a.CreatedAt,
	)
	return err
}

// ListArchives returns archive records with pagination.
func (s *Store) ListArchives(ctx context.Context, opts retention.ListOpts) ([]*retention.Archive, error) {
	query := `
		SELECT
			id, policy_id, category, event_count,
			from_timestamp, to_timestamp, sink_name, sink_ref, created_at
		FROM chronicle_archives
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := s.pool.Query(ctx, query, opts.Limit, opts.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var archives []*retention.Archive
	for rows.Next() {
		a := &retention.Archive{}
		err := rows.Scan(
			&a.ID, &a.PolicyID, &a.Category, &a.EventCount,
			&a.FromTimestamp, &a.ToTimestamp, &a.SinkName, &a.SinkRef, &a.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		archives = append(archives, a)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return archives, nil
}
