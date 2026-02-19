package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

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
			?, ?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?,
			?, ?,
			?, datetime('now')
		)`

	_, err = s.db.ExecContext(ctx, query,
		event.ID.String(), event.StreamID.String(), event.Sequence, event.Hash, event.PrevHash,
		event.AppID, event.TenantID, event.UserID, event.IP,
		event.Action, event.Resource, event.Category, event.ResourceID, string(metadata),
		event.Outcome, event.Severity, event.Reason,
		event.SubjectID, event.EncryptionKeyID,
		formatTime(event.Timestamp),
	)
	return err
}

// AppendBatch persists multiple events atomically in a transaction.
func (s *Store) AppendBatch(ctx context.Context, events []*audit.Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() //nolint:errcheck // rollback after commit is a no-op

	query := `
		INSERT INTO chronicle_events (
			id, stream_id, sequence, hash, prev_hash,
			app_id, tenant_id, user_id, ip,
			action, resource, category, resource_id, metadata,
			outcome, severity, reason,
			subject_id, encryption_key_id,
			timestamp, created_at
		) VALUES (
			?, ?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?,
			?, ?,
			?, datetime('now')
		)`

	for _, event := range events {
		metadata, err := json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		_, err = tx.ExecContext(ctx, query,
			event.ID.String(), event.StreamID.String(), event.Sequence, event.Hash, event.PrevHash,
			event.AppID, event.TenantID, event.UserID, event.IP,
			event.Action, event.Resource, event.Category, event.ResourceID, string(metadata),
			event.Outcome, event.Severity, event.Reason,
			event.SubjectID, event.EncryptionKeyID,
			formatTime(event.Timestamp),
		)
		if err != nil {
			return fmt.Errorf("failed to insert event %s: %w", event.ID, err)
		}
	}

	return tx.Commit()
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
		WHERE id = ?`

	return s.scanEvent(s.db.QueryRowContext(ctx, query, eventID.String()))
}

// Query returns events matching filters with pagination.
func (s *Store) Query(ctx context.Context, q *audit.Query) (*audit.QueryResult, error) {
	var conditions []string
	var args []interface{}

	if q.AppID != "" {
		conditions = append(conditions, "app_id = ?")
		args = append(args, q.AppID)
	}

	if q.TenantID != "" {
		conditions = append(conditions, "tenant_id = ?")
		args = append(args, q.TenantID)
	}

	if q.UserID != "" {
		conditions = append(conditions, "user_id = ?")
		args = append(args, q.UserID)
	}

	if !q.After.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, formatTime(q.After))
	}
	if !q.Before.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, formatTime(q.Before))
	}

	appendInClause(&conditions, &args, "category", q.Categories)
	appendInClause(&conditions, &args, "action", q.Actions)
	appendInClause(&conditions, &args, "resource", q.Resources)
	appendInClause(&conditions, &args, "severity", q.Severity)
	appendInClause(&conditions, &args, "outcome", q.Outcome)

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching events.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM chronicle_events %s", whereClause) //nolint:gosec // query built from safe column conditions
	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count events: %w", err)
	}

	// Order direction.
	order := "DESC"
	if q.Order == "asc" {
		order = "ASC"
	}

	// Query events with pagination.
	//nolint:gosec // query built from safe column conditions, not user input
	eventsQuery := fmt.Sprintf(`
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
		LIMIT ? OFFSET ?`,
		whereClause, order)

	queryArgs := make([]interface{}, 0, len(args)+2)
	queryArgs = append(queryArgs, args...)
	queryArgs = append(queryArgs, q.Limit, q.Offset)

	rows, err := s.db.QueryContext(ctx, eventsQuery, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	events, err := s.scanEvents(rows)
	if err != nil {
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
	var conditions []string
	var args []interface{}

	if q.AppID != "" {
		conditions = append(conditions, "app_id = ?")
		args = append(args, q.AppID)
	}

	if q.TenantID != "" {
		conditions = append(conditions, "tenant_id = ?")
		args = append(args, q.TenantID)
	}

	if !q.After.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, formatTime(q.After))
	}
	if !q.Before.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, formatTime(q.Before))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Build GROUP BY clause.
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

	//nolint:gosec // query built from validated column names, not user input
	query := fmt.Sprintf(`
		SELECT %s, COUNT(*) as count
		FROM chronicle_events
		%s
		GROUP BY %s
		ORDER BY count DESC`,
		selectClause, whereClause, groupByClause)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate events: %w", err)
	}
	defer rows.Close()

	var groups []audit.AggregateGroup
	var total int64

	for rows.Next() {
		group := audit.AggregateGroup{}
		scanArgs := make([]interface{}, 0, len(q.GroupBy)+1)

		for _, field := range q.GroupBy {
			switch field {
			case "category":
				scanArgs = append(scanArgs, &group.Category)
			case "action":
				scanArgs = append(scanArgs, &group.Action)
			case "outcome":
				scanArgs = append(scanArgs, &group.Outcome)
			case "severity":
				scanArgs = append(scanArgs, &group.Severity)
			case "resource":
				scanArgs = append(scanArgs, &group.Resource)
			default:
				return nil, fmt.Errorf("unsupported group_by field: %s", field)
			}
		}
		scanArgs = append(scanArgs, &group.Count)

		if err := rows.Scan(scanArgs...); err != nil {
			return nil, fmt.Errorf("failed to scan aggregate row: %w", err)
		}

		groups = append(groups, group)
		total += group.Count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate aggregate rows: %w", err)
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
		WHERE user_id = ? AND timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp DESC`

	rows, err := s.db.QueryContext(ctx, query, userID, formatTime(opts.After), formatTime(opts.Before))
	if err != nil {
		return nil, fmt.Errorf("failed to query events by user: %w", err)
	}
	defer rows.Close()

	events, err := s.scanEvents(rows)
	if err != nil {
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

	if q.AppID != "" {
		conditions = append(conditions, "app_id = ?")
		args = append(args, q.AppID)
	}

	if q.TenantID != "" {
		conditions = append(conditions, "tenant_id = ?")
		args = append(args, q.TenantID)
	}

	if q.Category != "" {
		conditions = append(conditions, "category = ?")
		args = append(args, q.Category)
	}

	if !q.After.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, formatTime(q.After))
	}
	if !q.Before.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, formatTime(q.Before))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf("SELECT COUNT(*) FROM chronicle_events %s", whereClause) //nolint:gosec // query built from safe column conditions

	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// LastSequence returns the highest sequence number for a stream.
func (s *Store) LastSequence(ctx context.Context, streamID id.ID) (uint64, error) {
	query := `SELECT COALESCE(MAX(sequence), 0) FROM chronicle_events WHERE stream_id = ?`

	var seq uint64
	err := s.db.QueryRowContext(ctx, query, streamID.String()).Scan(&seq)
	return seq, err
}

// LastHash returns the hash of the most recent event in a stream.
func (s *Store) LastHash(ctx context.Context, streamID id.ID) (string, error) {
	query := `SELECT hash FROM chronicle_events WHERE stream_id = ? ORDER BY sequence DESC LIMIT 1`

	var hash string
	err := s.db.QueryRowContext(ctx, query, streamID.String()).Scan(&hash)
	if err != nil {
		return "", sqliteError(err, chronicle.ErrEventNotFound)
	}
	return hash, nil
}

// scanEvent scans a single event row.
func (s *Store) scanEvent(row *sql.Row) (*audit.Event, error) {
	event := &audit.Event{}
	var (
		idStr       string
		streamIDStr string
		metadata    string
		timestamp   string
		erasedInt   int
		erasedAt    sql.NullString
		erasureID   sql.NullString
	)

	err := row.Scan(
		&idStr, &streamIDStr, &event.Sequence, &event.Hash, &event.PrevHash,
		&event.AppID, &event.TenantID, &event.UserID, &event.IP,
		&event.Action, &event.Resource, &event.Category, &event.ResourceID, &metadata,
		&event.Outcome, &event.Severity, &event.Reason,
		&event.SubjectID, &event.EncryptionKeyID,
		&erasedInt, &erasedAt, &erasureID,
		&timestamp,
	)
	if err != nil {
		return nil, sqliteError(err, chronicle.ErrEventNotFound)
	}

	return s.hydrateEvent(event, idStr, streamIDStr, metadata, timestamp, erasedInt, erasedAt, erasureID)
}

// scanEvents scans multiple event rows.
func (s *Store) scanEvents(rows *sql.Rows) ([]*audit.Event, error) {
	var events []*audit.Event
	for rows.Next() {
		event := &audit.Event{}
		var (
			idStr       string
			streamIDStr string
			metadata    string
			timestamp   string
			erasedInt   int
			erasedAt    sql.NullString
			erasureID   sql.NullString
		)

		err := rows.Scan(
			&idStr, &streamIDStr, &event.Sequence, &event.Hash, &event.PrevHash,
			&event.AppID, &event.TenantID, &event.UserID, &event.IP,
			&event.Action, &event.Resource, &event.Category, &event.ResourceID, &metadata,
			&event.Outcome, &event.Severity, &event.Reason,
			&event.SubjectID, &event.EncryptionKeyID,
			&erasedInt, &erasedAt, &erasureID,
			&timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event row: %w", err)
		}

		event, err = s.hydrateEvent(event, idStr, streamIDStr, metadata, timestamp, erasedInt, erasedAt, erasureID)
		if err != nil {
			return nil, err
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate event rows: %w", err)
	}

	return events, nil
}

// hydrateEvent populates an event's parsed fields from raw SQLite column values.
func (s *Store) hydrateEvent(
	event *audit.Event,
	idStr, streamIDStr, metadata, timestamp string,
	erasedInt int, erasedAt sql.NullString, erasureID sql.NullString,
) (*audit.Event, error) {
	// Parse IDs.
	parsedID, err := id.ParseAuditID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse audit ID %q: %w", idStr, err)
	}
	event.ID = parsedID

	parsedStreamID, err := id.ParseStreamID(streamIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream ID %q: %w", streamIDStr, err)
	}
	event.StreamID = parsedStreamID

	// Parse metadata JSON.
	if err = json.Unmarshal([]byte(metadata), &event.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Parse timestamp.
	var ts time.Time
	ts, err = parseTime(timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}
	event.Timestamp = ts

	// Parse erasure fields.
	event.Erased = erasedInt != 0

	event.ErasedAt, err = parseNullableTime(erasedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse erased_at: %w", err)
	}

	if erasureID.Valid {
		event.ErasureID = erasureID.String
	}

	return event, nil
}

// appendInClause appends an IN (?, ?, ...) condition for a string slice filter.
func appendInClause(conditions *[]string, args *[]interface{}, column string, values []string) {
	if len(values) == 0 {
		return
	}
	placeholders := make([]string, len(values))
	for i, v := range values {
		placeholders[i] = "?"
		*args = append(*args, v)
	}
	*conditions = append(*conditions, fmt.Sprintf("%s IN (%s)", column, strings.Join(placeholders, ", ")))
}
