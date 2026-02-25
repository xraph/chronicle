package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xraph/grove/drivers/sqlitedriver"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// Append persists a single audit event.
func (s *Store) Append(ctx context.Context, event *audit.Event) error {
	m := fromEvent(event)
	_, err := s.sdb.NewInsert(m).Exec(ctx)
	return err
}

// AppendBatch persists multiple events atomically in a transaction.
func (s *Store) AppendBatch(ctx context.Context, events []*audit.Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.sdb.BeginTxQuery(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			_ = rbErr // best-effort rollback
		}
	}()

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
	err := s.sdb.NewSelect(m).Where("id = ?", eventID.String()).Scan(ctx)
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
	countQuery := applyEventFilters(
		s.sdb.NewSelect((*EventModel)(nil)).ColumnExpr("COUNT(*)"), q)

	var total int64
	if err := countQuery.Scan(ctx, &total); err != nil {
		return nil, err
	}

	// Build select query.
	var models []EventModel
	selectQuery := applyEventFilters(s.sdb.NewSelect(&models), q)

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

	// Build dynamic WHERE clause.
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
		args = append(args, q.After.UTC().Format(time.RFC3339Nano))
	}
	if !q.Before.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, q.Before.UTC().Format(time.RFC3339Nano))
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

	rows, err := s.sdb.Query(ctx, query, args...)
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

	err := s.sdb.NewSelect(&models).
		Where("e.user_id = ?", userID).
		Where("e.timestamp >= ?", opts.After.UTC().Format(time.RFC3339Nano)).
		Where("e.timestamp <= ?", opts.Before.UTC().Format(time.RFC3339Nano)).
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
	countQuery := s.sdb.NewSelect((*EventModel)(nil)).ColumnExpr("COUNT(*)")

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
		countQuery = countQuery.Where("e.timestamp >= ?", q.After.UTC().Format(time.RFC3339Nano))
	}
	if !q.Before.IsZero() {
		countQuery = countQuery.Where("e.timestamp <= ?", q.Before.UTC().Format(time.RFC3339Nano))
	}

	var count int64
	err := countQuery.Scan(ctx, &count)
	return count, err
}

// LastSequence returns the highest sequence number for a stream.
func (s *Store) LastSequence(ctx context.Context, streamID id.ID) (uint64, error) {
	var seq uint64
	err := s.sdb.NewSelect((*EventModel)(nil)).
		ColumnExpr("COALESCE(MAX(sequence), 0)").
		Where("stream_id = ?", streamID.String()).
		Scan(ctx, &seq)
	return seq, err
}

// LastHash returns the hash of the most recent event in a stream.
func (s *Store) LastHash(ctx context.Context, streamID id.ID) (string, error) {
	var hash string
	err := s.sdb.NewSelect((*EventModel)(nil)).
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

// applyEventFilters applies common query filters to a sqlitedriver select query.
// It returns the modified query since sqlitedriver.SelectQuery methods are chainable.
func applyEventFilters(q *sqlitedriver.SelectQuery, f *audit.Query) *sqlitedriver.SelectQuery {
	if f.AppID != "" {
		q = q.Where("e.app_id = ?", f.AppID)
	}
	if f.TenantID != "" {
		q = q.Where("e.tenant_id = ?", f.TenantID)
	}
	if f.UserID != "" {
		q = q.Where("e.user_id = ?", f.UserID)
	}
	if !f.After.IsZero() {
		q = q.Where("e.timestamp >= ?", f.After.UTC().Format(time.RFC3339Nano))
	}
	if !f.Before.IsZero() {
		q = q.Where("e.timestamp <= ?", f.Before.UTC().Format(time.RFC3339Nano))
	}
	if len(f.Categories) > 0 {
		q = q.Where("e.category IN (?)", f.Categories)
	}
	if len(f.Actions) > 0 {
		q = q.Where("e.action IN (?)", f.Actions)
	}
	if len(f.Resources) > 0 {
		q = q.Where("e.resource IN (?)", f.Resources)
	}
	if len(f.Severity) > 0 {
		q = q.Where("e.severity IN (?)", f.Severity)
	}
	if len(f.Outcome) > 0 {
		q = q.Where("e.outcome IN (?)", f.Outcome)
	}
	return q
}
