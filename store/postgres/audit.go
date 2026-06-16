package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xraph/grove/drivers/pgdriver"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// Append persists a single audit event, allocating its sequence number
// authoritatively inside a transaction.
//
// The sequence is a positional counter and is NOT part of the hash chain (see
// hash.Chain.Compute), so the store owns its allocation. Chronicle.Record
// precomputes event.Sequence from the stream's tracked head, but that head can
// fall behind the events table — e.g. a crash between Append and
// UpdateStreamHead, or a bulk import — after which every subsequent append
// recomputes the same value and collides on UNIQUE(stream_id, sequence),
// permanently wedging the stream. To be both self-healing and safe under
// concurrent appends, derive the next sequence from the greater of the stored
// head and the actual MAX(sequence) while holding a row lock on the stream, and
// advance the head in the same transaction so it can never lag again.
func (s *Store) Append(ctx context.Context, event *audit.Event) error {
	tx, err := s.pg.BeginTxQuery(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	streamID := event.StreamID.String()

	// Lock the stream row so concurrent appends to the same stream serialize.
	var headSeq int64
	if err := tx.NewRaw(
		"SELECT head_seq FROM chronicle_streams WHERE id = $1 FOR UPDATE", streamID,
	).Scan(ctx, &headSeq); err != nil {
		return fmt.Errorf("lock stream %s: %w", streamID, err)
	}

	// Reconcile against the authoritative max in case the head desynced.
	var maxSeq int64
	if err := tx.NewRaw(
		"SELECT COALESCE(MAX(sequence), 0) FROM chronicle_events WHERE stream_id = $1", streamID,
	).Scan(ctx, &maxSeq); err != nil {
		return fmt.Errorf("max sequence for stream %s: %w", streamID, err)
	}

	next := headSeq
	if maxSeq > next {
		next = maxSeq
	}
	next++

	event.Sequence = safeUint64(next)
	m := fromEvent(event)
	if _, err := tx.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("insert event %s: %w", event.ID, err)
	}

	// Advance the stream head in the same transaction so head_seq never lags
	// the events it points at again. Record also calls UpdateStreamHead after
	// Append; that becomes an idempotent no-op on the same value.
	if _, err := tx.NewRaw(
		"UPDATE chronicle_streams SET head_seq = $1, head_hash = $2, updated_at = NOW() WHERE id = $3",
		next, event.Hash, streamID,
	).Exec(ctx); err != nil {
		return fmt.Errorf("update stream head %s: %w", streamID, err)
	}

	return tx.Commit()
}

// AppendBatch persists multiple events atomically in a transaction.
func (s *Store) AppendBatch(ctx context.Context, events []*audit.Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.pg.BeginTxQuery(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, event := range events {
		m := fromEvent(event)
		if _, err := tx.NewInsert(m).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert event %s: %w", event.ID, err)
		}
	}

	return tx.Commit()
}

// Get returns a single event by ID.
func (s *Store) Get(ctx context.Context, eventID id.ID) (*audit.Event, error) {
	m := new(EventModel)
	err := s.pg.NewSelect(m).Where("id = ?", eventID.String()).Scan(ctx)
	if err != nil {
		return nil, groveError(err, chronicle.ErrEventNotFound)
	}

	event, err := toEvent(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert event model: %w", err)
	}

	return event, nil
}

// Query returns events matching filters with pagination.
func (s *Store) Query(ctx context.Context, q *audit.Query) (*audit.QueryResult, error) {
	// Build count query with the same conditions.
	countQuery := s.pg.NewSelect((*EventModel)(nil)).ColumnExpr("COUNT(*)")
	applyEventFilters(countQuery, q)

	var total int64
	if err := countQuery.Scan(ctx, &total); err != nil {
		return nil, err
	}

	// Build select query.
	var models []EventModel
	selectQuery := s.pg.NewSelect(&models)
	applyEventFilters(selectQuery, q)

	// Order direction.
	order := "e.timestamp DESC"
	if q.Order == "asc" {
		order = "e.timestamp ASC"
	}
	selectQuery = selectQuery.OrderExpr(order)

	if q.Limit > 0 {
		selectQuery = selectQuery.Limit(q.Limit)
	}
	selectQuery = selectQuery.Offset(q.Offset)

	if err := selectQuery.Scan(ctx); err != nil {
		return nil, err
	}

	events, err := toEventSlice(models)
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
	if len(q.GroupBy) == 0 {
		return nil, errors.New("aggregate query requires at least one group_by field")
	}

	// Build dynamic WHERE clause using raw SQL.
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

	// Build GROUP BY clause.
	groupFields := make([]string, 0, len(q.GroupBy))
	selectFields := make([]string, 0, len(q.GroupBy))
	for _, field := range q.GroupBy {
		groupFields = append(groupFields, field)
		selectFields = append(selectFields, field)
	}

	groupByClause := strings.Join(groupFields, ", ")
	selectClause := strings.Join(selectFields, ", ")

	query := fmt.Sprintf(
		"SELECT %s, COUNT(*) as count FROM chronicle_events %s GROUP BY %s ORDER BY count DESC",
		selectClause, whereClause, groupByClause,
	)

	rows, err := s.pg.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var groups []audit.AggregateGroup
	var total int64

	for rows.Next() {
		group := audit.AggregateGroup{}
		scanArgs := make([]interface{}, len(q.GroupBy)+1)

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
	var models []EventModel

	err := s.pg.NewSelect(&models).
		Where("e.user_id = ?", userID).
		Where("e.timestamp >= ?", opts.After).
		Where("e.timestamp <= ?", opts.Before).
		OrderExpr("e.timestamp DESC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	events, err := toEventSlice(models)
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
	countQuery := s.pg.NewSelect((*EventModel)(nil)).ColumnExpr("COUNT(*)")

	if q.AppID != "" {
		countQuery = countQuery.Where("e.app_id = ?", q.AppID)
	}
	if q.TenantID != "" {
		countQuery = countQuery.Where("e.tenant_id = ?", q.TenantID)
	}
	if q.Category != "" {
		countQuery = countQuery.Where("e.category = ?", q.Category)
	}
	if !q.After.IsZero() {
		countQuery = countQuery.Where("e.timestamp >= ?", q.After)
	}
	if !q.Before.IsZero() {
		countQuery = countQuery.Where("e.timestamp <= ?", q.Before)
	}

	var count int64
	err := countQuery.Scan(ctx, &count)
	return count, err
}

// LastSequence returns the highest sequence number for a stream.
func (s *Store) LastSequence(ctx context.Context, streamID id.ID) (uint64, error) {
	var seq int64
	err := s.pg.NewSelect((*EventModel)(nil)).
		ColumnExpr("COALESCE(MAX(sequence), 0)").
		Where("stream_id = ?", streamID.String()).
		Scan(ctx, &seq)
	return safeUint64(seq), err
}

// LastHash returns the hash of the most recent event in a stream.
func (s *Store) LastHash(ctx context.Context, streamID id.ID) (string, error) {
	var hash string
	err := s.pg.NewSelect((*EventModel)(nil)).
		Column("hash").
		Where("stream_id = ?", streamID.String()).
		OrderExpr("sequence DESC").
		Limit(1).
		Scan(ctx, &hash)
	if err != nil {
		return "", groveError(err, chronicle.ErrEventNotFound)
	}
	return hash, nil
}

// applyEventFilters applies common query filters to a pgdriver select query.
func applyEventFilters(q *pgdriver.SelectQuery, f *audit.Query) {
	if f.AppID != "" {
		q.Where("e.app_id = ?", f.AppID)
	}
	if f.TenantID != "" {
		q.Where("e.tenant_id = ?", f.TenantID)
	}
	if f.UserID != "" {
		q.Where("e.user_id = ?", f.UserID)
	}
	if !f.After.IsZero() {
		q.Where("e.timestamp >= ?", f.After)
	}
	if !f.Before.IsZero() {
		q.Where("e.timestamp <= ?", f.Before)
	}
	if len(f.Categories) > 0 {
		q.WhereArray("e.category", "= ANY", f.Categories)
	}
	if len(f.Actions) > 0 {
		q.WhereArray("e.action", "= ANY", f.Actions)
	}
	if len(f.Resources) > 0 {
		q.WhereArray("e.resource", "= ANY", f.Resources)
	}
	if len(f.Severity) > 0 {
		q.WhereArray("e.severity", "= ANY", f.Severity)
	}
	if len(f.Outcome) > 0 {
		q.WhereArray("e.outcome", "= ANY", f.Outcome)
	}
}

// toEventSlice converts a slice of EventModel to a slice of audit.Event.
func toEventSlice(models []EventModel) ([]*audit.Event, error) {
	events := make([]*audit.Event, 0, len(models))
	for i := range models {
		event, err := toEvent(&models[i])
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}
