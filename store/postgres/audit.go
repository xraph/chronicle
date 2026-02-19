package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// Append persists a single audit event.
func (s *Store) Append(ctx context.Context, event *audit.Event) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO chronicle_events (
			id, stream_id, sequence, hash, prev_hash,
			app_id, tenant_id, user_id, ip,
			action, resource, category, resource_id, metadata,
			outcome, severity, reason,
			subject_id, encryption_key_id,
			timestamp, created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13, $14,
			$15, $16, $17,
			$18, $19,
			$20, NOW()
		)`

	_, err = s.pool.Exec(ctx, query,
		event.ID, event.StreamID, event.Sequence, event.Hash, event.PrevHash,
		event.AppID, event.TenantID, event.UserID, event.IP,
		event.Action, event.Resource, event.Category, event.ResourceID, metadata,
		event.Outcome, event.Severity, event.Reason,
		event.SubjectID, event.EncryptionKeyID,
		event.Timestamp,
	)
	return err
}

// AppendBatch persists multiple events atomically in a transaction.
func (s *Store) AppendBatch(ctx context.Context, events []*audit.Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	query := `
		INSERT INTO chronicle_events (
			id, stream_id, sequence, hash, prev_hash,
			app_id, tenant_id, user_id, ip,
			action, resource, category, resource_id, metadata,
			outcome, severity, reason,
			subject_id, encryption_key_id,
			timestamp, created_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13, $14,
			$15, $16, $17,
			$18, $19,
			$20, NOW()
		)`

	for _, event := range events {
		metadata, err := json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		_, err = tx.Exec(ctx, query,
			event.ID, event.StreamID, event.Sequence, event.Hash, event.PrevHash,
			event.AppID, event.TenantID, event.UserID, event.IP,
			event.Action, event.Resource, event.Category, event.ResourceID, metadata,
			event.Outcome, event.Severity, event.Reason,
			event.SubjectID, event.EncryptionKeyID,
			event.Timestamp,
		)
		if err != nil {
			return fmt.Errorf("failed to insert event %s: %w", event.ID, err)
		}
	}

	return tx.Commit(ctx)
}

// Get returns a single event by ID.
func (s *Store) Get(ctx context.Context, eventID id.ID) (*audit.Event, error) {
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
		WHERE id = $1`

	event := &audit.Event{}
	var metadata []byte

	err := s.pool.QueryRow(ctx, query, eventID).Scan(
		&event.ID, &event.StreamID, &event.Sequence, &event.Hash, &event.PrevHash,
		&event.AppID, &event.TenantID, &event.UserID, &event.IP,
		&event.Action, &event.Resource, &event.Category, &event.ResourceID, &metadata,
		&event.Outcome, &event.Severity, &event.Reason,
		&event.SubjectID, &event.EncryptionKeyID,
		&event.Erased, &event.ErasedAt, &event.ErasureID,
		&event.Timestamp,
	)

	if err != nil {
		return nil, pgxError(err, chronicle.ErrEventNotFound)
	}

	if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return event, nil
}

// Query returns events matching filters with pagination.
func (s *Store) Query(ctx context.Context, q *audit.Query) (*audit.QueryResult, error) {
	// Build dynamic WHERE clause
	var conditions []string
	var args []interface{}
	argPos := 1

	// ALWAYS filter by app_id when present
	if q.AppID != "" {
		conditions = append(conditions, fmt.Sprintf("app_id = $%d", argPos))
		args = append(args, q.AppID)
		argPos++
	}

	// Filter by tenant_id when present
	if q.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argPos))
		args = append(args, q.TenantID)
		argPos++
	}

	// Filter by user_id
	if q.UserID != "" {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argPos))
		args = append(args, q.UserID)
		argPos++
	}

	// Time range
	if !q.After.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argPos))
		args = append(args, q.After)
		argPos++
	}
	if !q.Before.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argPos))
		args = append(args, q.Before)
		argPos++
	}

	// Categories (IN clause)
	if len(q.Categories) > 0 {
		conditions = append(conditions, fmt.Sprintf("category = ANY($%d)", argPos))
		args = append(args, q.Categories)
		argPos++
	}

	// Actions (IN clause)
	if len(q.Actions) > 0 {
		conditions = append(conditions, fmt.Sprintf("action = ANY($%d)", argPos))
		args = append(args, q.Actions)
		argPos++
	}

	// Resources (IN clause)
	if len(q.Resources) > 0 {
		conditions = append(conditions, fmt.Sprintf("resource = ANY($%d)", argPos))
		args = append(args, q.Resources)
		argPos++
	}

	// Severity (IN clause)
	if len(q.Severity) > 0 {
		conditions = append(conditions, fmt.Sprintf("severity = ANY($%d)", argPos))
		args = append(args, q.Severity)
		argPos++
	}

	// Outcome (IN clause)
	if len(q.Outcome) > 0 {
		conditions = append(conditions, fmt.Sprintf("outcome = ANY($%d)", argPos))
		args = append(args, q.Outcome)
		argPos++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching events
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM chronicle_events %s", whereClause)
	var total int64
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, err
	}

	// Order direction
	order := "DESC"
	if q.Order == "asc" {
		order = "ASC"
	}

	// Query events with pagination
	query := fmt.Sprintf(`
		SELECT
			id, stream_id, sequence, hash, prev_hash,
			app_id, tenant_id, user_id, ip,
			action, resource, category, resource_id, metadata,
			outcome, severity, reason,
			subject_id, encryption_key_id,
			erased, erased_at, erasure_id,
			timestamp
		FROM chronicle_events
		%s
		ORDER BY timestamp %s
		LIMIT $%d OFFSET $%d`,
		whereClause, order, argPos, argPos+1)

	args = append(args, q.Limit, q.Offset)

	rows, err := s.pool.Query(ctx, query, args...)
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

	hasMore := total > int64(q.Offset+len(events))

	return &audit.QueryResult{
		Events:  events,
		Total:   total,
		HasMore: hasMore,
	}, nil
}

// Aggregate returns grouped event statistics.
func (s *Store) Aggregate(ctx context.Context, q *audit.AggregateQuery) (*audit.AggregateResult, error) {
	// Build dynamic WHERE clause
	var conditions []string
	var args []interface{}
	argPos := 1

	if q.AppID != "" {
		conditions = append(conditions, fmt.Sprintf("app_id = $%d", argPos))
		args = append(args, q.AppID)
		argPos++
	}

	if q.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argPos))
		args = append(args, q.TenantID)
		argPos++
	}

	if !q.After.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argPos))
		args = append(args, q.After)
		argPos++
	}
	if !q.Before.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argPos))
		args = append(args, q.Before)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Build GROUP BY clause
	groupFields := make([]string, 0, len(q.GroupBy))
	selectFields := make([]string, 0, len(q.GroupBy))
	for _, field := range q.GroupBy {
		groupFields = append(groupFields, field)
		selectFields = append(selectFields, field)
	}

	if len(groupFields) == 0 {
		return nil, errors.New("aggregate query requires at least one group_by field")
	}

	groupByClause := strings.Join(groupFields, ", ")
	selectClause := strings.Join(selectFields, ", ")

	query := fmt.Sprintf(`
		SELECT %s, COUNT(*) as count
		FROM chronicle_events
		%s
		GROUP BY %s
		ORDER BY count DESC`,
		selectClause, whereClause, groupByClause)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []audit.AggregateGroup
	var total int64

	for rows.Next() {
		group := audit.AggregateGroup{}
		scanArgs := make([]interface{}, len(q.GroupBy)+1)

		// Map group_by fields to struct fields
		for i, field := range q.GroupBy {
			switch field {
			case "category":
				scanArgs[i] = &group.Category
			case "action":
				scanArgs[i] = &group.Action
			case "outcome":
				scanArgs[i] = &group.Outcome
			case "severity":
				scanArgs[i] = &group.Severity
			case "resource":
				scanArgs[i] = &group.Resource
			default:
				return nil, fmt.Errorf("unsupported group_by field: %s", field)
			}
		}
		scanArgs[len(q.GroupBy)] = &group.Count

		if err := rows.Scan(scanArgs...); err != nil {
			return nil, err
		}

		groups = append(groups, group)
		total += group.Count
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &audit.AggregateResult{
		Groups: groups,
		Total:  total,
	}, nil
}

// ByUser returns events for a specific user within a time range.
func (s *Store) ByUser(ctx context.Context, userID string, opts audit.TimeRange) (*audit.QueryResult, error) {
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
		WHERE user_id = $1 AND timestamp >= $2 AND timestamp <= $3
		ORDER BY timestamp DESC`

	rows, err := s.pool.Query(ctx, query, userID, opts.After, opts.Before)
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

	return &audit.QueryResult{
		Events:  events,
		Total:   int64(len(events)),
		HasMore: false,
	}, nil
}

// Count returns the total number of events matching filters.
func (s *Store) Count(ctx context.Context, q *audit.CountQuery) (int64, error) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if q.AppID != "" {
		conditions = append(conditions, fmt.Sprintf("app_id = $%d", argPos))
		args = append(args, q.AppID)
		argPos++
	}

	if q.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argPos))
		args = append(args, q.TenantID)
		argPos++
	}

	if q.Category != "" {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argPos))
		args = append(args, q.Category)
		argPos++
	}

	if !q.After.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argPos))
		args = append(args, q.After)
		argPos++
	}
	if !q.Before.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argPos))
		args = append(args, q.Before)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf("SELECT COUNT(*) FROM chronicle_events %s", whereClause)

	var count int64
	err := s.pool.QueryRow(ctx, query, args...).Scan(&count)
	return count, err
}

// LastSequence returns the highest sequence number for a stream.
func (s *Store) LastSequence(ctx context.Context, streamID id.ID) (uint64, error) {
	query := `SELECT COALESCE(MAX(sequence), 0) FROM chronicle_events WHERE stream_id = $1`

	var seq uint64
	err := s.pool.QueryRow(ctx, query, streamID).Scan(&seq)
	return seq, err
}

// LastHash returns the hash of the most recent event in a stream.
func (s *Store) LastHash(ctx context.Context, streamID id.ID) (string, error) {
	query := `SELECT hash FROM chronicle_events WHERE stream_id = $1 ORDER BY sequence DESC LIMIT 1`

	var hash string
	err := s.pool.QueryRow(ctx, query, streamID).Scan(&hash)
	if err != nil {
		return "", pgxError(err, chronicle.ErrEventNotFound)
	}
	return hash, nil
}
