package sqlite

import (
	"context"
	"fmt"
	"strings"
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
			?, ?, ?, ?, ?, ?, ?
		)
		ON CONFLICT (category)
		DO UPDATE SET
			duration = excluded.duration,
			archive = excluded.archive,
			app_id = excluded.app_id,
			updated_at = excluded.updated_at`

	_, err := s.db.ExecContext(ctx, query,
		p.ID.String(), p.Category, int64(p.Duration), boolToInt(p.Archive), p.AppID,
		formatTime(p.CreatedAt), formatTime(p.UpdatedAt),
	)
	return err
}

// GetPolicy returns a retention policy by ID.
func (s *Store) GetPolicy(ctx context.Context, policyID id.ID) (*retention.Policy, error) {
	query := `
		SELECT id, category, duration, archive, app_id, created_at, updated_at
		FROM chronicle_retention_policies
		WHERE id = ?`

	p := &retention.Policy{}
	var (
		idStr      string
		duration   int64
		archiveInt int
		createdAt  string
		updatedAt  string
	)

	err := s.db.QueryRowContext(ctx, query, policyID.String()).Scan(
		&idStr, &p.Category, &duration, &archiveInt, &p.AppID,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, sqliteError(err, chronicle.ErrPolicyNotFound)
	}

	parsedID, err := id.ParsePolicyID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy ID %q: %w", idStr, err)
	}
	p.ID = parsedID
	p.Duration = time.Duration(duration)
	p.Archive = archiveInt != 0

	p.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	p.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at: %w", err)
	}

	return p, nil
}

// ListPolicies returns all retention policies.
func (s *Store) ListPolicies(ctx context.Context) ([]*retention.Policy, error) {
	query := `
		SELECT id, category, duration, archive, app_id, created_at, updated_at
		FROM chronicle_retention_policies
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	defer rows.Close()

	var policies []*retention.Policy
	for rows.Next() {
		p := &retention.Policy{}
		var (
			idStr      string
			duration   int64
			archiveInt int
			createdAt  string
			updatedAt  string
		)

		err := rows.Scan(
			&idStr, &p.Category, &duration, &archiveInt, &p.AppID,
			&createdAt, &updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy row: %w", err)
		}

		parsedID, err := id.ParsePolicyID(idStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy ID %q: %w", idStr, err)
		}
		p.ID = parsedID
		p.Duration = time.Duration(duration)
		p.Archive = archiveInt != 0

		p.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at: %w", err)
		}

		p.UpdatedAt, err = parseTime(updatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse updated_at: %w", err)
		}

		policies = append(policies, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate policy rows: %w", err)
	}

	return policies, nil
}

// DeletePolicy removes a retention policy.
func (s *Store) DeletePolicy(ctx context.Context, policyID id.ID) error {
	query := `DELETE FROM chronicle_retention_policies WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, policyID.String())
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if n == 0 {
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
		WHERE category = ? AND timestamp < ?
		ORDER BY timestamp ASC`

	rows, err := s.db.QueryContext(ctx, query, category, formatTime(before))
	if err != nil {
		return nil, fmt.Errorf("failed to query old events: %w", err)
	}
	defer rows.Close()

	return s.scanEvents(rows)
}

// PurgeEvents permanently deletes events by IDs.
func (s *Store) PurgeEvents(ctx context.Context, eventIDs []id.ID) (int64, error) {
	if len(eventIDs) == 0 {
		return 0, nil
	}

	// Build IN (?, ?, ...) with individual placeholders.
	placeholders := make([]string, len(eventIDs))
	args := make([]interface{}, len(eventIDs))
	for i, eid := range eventIDs {
		placeholders[i] = "?"
		args[i] = eid.String()
	}

	query := fmt.Sprintf("DELETE FROM chronicle_events WHERE id IN (%s)", strings.Join(placeholders, ", ")) //nolint:gosec // placeholders are safe ? markers

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to purge events: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return n, nil
}

// RecordArchive records that a batch of events was archived.
func (s *Store) RecordArchive(ctx context.Context, a *retention.Archive) error {
	query := `
		INSERT INTO chronicle_archives (
			id, policy_id, category, event_count,
			from_timestamp, to_timestamp, sink_name, sink_ref, created_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?
		)`

	_, err := s.db.ExecContext(ctx, query,
		a.ID.String(), a.PolicyID.String(), a.Category, a.EventCount,
		formatTime(a.FromTimestamp), formatTime(a.ToTimestamp),
		a.SinkName, a.SinkRef, formatTime(a.CreatedAt),
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
		LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(ctx, query, opts.Limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list archives: %w", err)
	}
	defer rows.Close()

	var archives []*retention.Archive
	for rows.Next() {
		a := &retention.Archive{}
		var (
			idStr         string
			policyIDStr   string
			fromTimestamp string
			toTimestamp   string
			createdAt     string
		)

		err := rows.Scan(
			&idStr, &policyIDStr, &a.Category, &a.EventCount,
			&fromTimestamp, &toTimestamp, &a.SinkName, &a.SinkRef, &createdAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan archive row: %w", err)
		}

		parsedID, err := id.ParseArchiveID(idStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse archive ID %q: %w", idStr, err)
		}
		a.ID = parsedID

		parsedPolicyID, err := id.ParsePolicyID(policyIDStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy ID %q: %w", policyIDStr, err)
		}
		a.PolicyID = parsedPolicyID

		a.FromTimestamp, err = parseTime(fromTimestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse from_timestamp: %w", err)
		}

		a.ToTimestamp, err = parseTime(toTimestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse to_timestamp: %w", err)
		}

		a.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at: %w", err)
		}

		archives = append(archives, a)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate archive rows: %w", err)
	}

	return archives, nil
}
