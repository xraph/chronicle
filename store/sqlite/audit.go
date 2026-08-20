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

// Append persists a single audit event, allocating its sequence number
// authoritatively inside a transaction.
//
// This mirrors the postgres backend: the sequence is a positional counter and
// is not part of the hash chain, so the store owns its allocation. Deriving the
// next value from the greater of the stored head and the actual MAX(sequence)
// makes a desynced head self-healing, and doing it inside the transaction that
// inserts the event keeps concurrent appends from colliding on
// UNIQUE(stream_id, sequence).
func (s *Store) Append(ctx context.Context, event *audit.Event) error {
	// SQLite allows one writer at a time and returns SQLITE_BUSY to the losers
	// rather than queueing them, so a contended append has to be retried.
	return retryOnBusy(ctx, func() error { return s.appendOnce(ctx, event) })
}

func (s *Store) appendOnce(ctx context.Context, event *audit.Event) error {
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			_ = rbErr // best-effort rollback
		}
	}()

	streamID := event.StreamID.String()

	// SQLite has no SELECT ... FOR UPDATE; the transaction's write lock on
	// first mutation serialises appends to the same database instead.
	var headSeq int64
	var headHash string
	if err := tx.NewRaw(
		"SELECT head_seq, head_hash FROM chronicle_streams WHERE id = ?", streamID,
	).Scan(ctx, &headSeq, &headHash); err != nil {
		return fmt.Errorf("read stream head %s: %w", streamID, err)
	}

	var maxSeq int64
	if err := tx.NewRaw(
		"SELECT COALESCE(MAX(sequence), 0) FROM chronicle_events WHERE stream_id = ?", streamID,
	).Scan(ctx, &maxSeq); err != nil {
		return fmt.Errorf("max sequence for stream %s: %w", streamID, err)
	}

	next := headSeq
	if maxSeq > next {
		next = maxSeq
	}
	next++

	event.Sequence = safeUint64(next)

	// Re-link the chain inside the transaction.
	//
	// Chronicle.Record derives PrevHash and Hash from the head it read before
	// calling Append, so two writers can read the same head and produce two
	// events claiming the same predecessor. Deriving both here keeps the chain
	// linked.
	//
	// This is also required for correctness rather than just concurrency: the
	// sequence is part of the hashed content, and it is allocated above, so the
	// hash has to be computed after it is known.
	event.PrevHash = headHash
	event.Hash = hasher.Compute(event.PrevHash, event)

	m := fromEvent(event)
	if _, err := tx.NewInsert(m).Exec(ctx); err != nil {
		return fmt.Errorf("insert event %s: %w", event.ID, err)
	}

	// Advance the head in the same transaction so it can never lag the events
	// it points at. Record also calls UpdateStreamHead; that becomes a no-op.
	if _, err := tx.NewRaw(
		"UPDATE chronicle_streams SET head_seq = ?, head_hash = ?, updated_at = ? WHERE id = ?",
		next, event.Hash, now().Format(time.RFC3339Nano), streamID,
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
	// Build count query with the same conditions. Use grove's Count (a proper
	// scalar scan via QueryRow) rather than ColumnExpr("COUNT(*)").Scan(&total):
	// the model scanner rejects a scalar dest and leaks the pooled connection on
	// that error, because it acquires a row but never scans it.
	countQuery := applyEventFilters(s.sdb.NewSelect((*EventModel)(nil)), q)

	total, err := countQuery.Count(ctx)
	if err != nil {
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

	if scanErr := selectQuery.Scan(ctx); scanErr != nil {
		return nil, scanErr
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
	// Resolve the grouping columns BEFORE building any SQL. An identifier
	// cannot be a bound placeholder, so the SELECT and GROUP BY clauses below
	// are interpolated — they must only ever be interpolated with the constant
	// column names this returns, never with q.GroupBy itself.
	columns, err := audit.ResolveGroupBy(q.GroupBy)
	if err != nil {
		return nil, err
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

	// Safe: every element of columns is a constant from audit's whitelist.
	columnList := strings.Join(columns, ", ")

	query := fmt.Sprintf(
		"SELECT %s, COUNT(*) as count FROM chronicle_events %s GROUP BY %s ORDER BY count DESC",
		columnList, whereClause, columnList,
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
		scanArgs := make([]interface{}, 0, len(q.GroupBy)+1)

		for _, field := range q.GroupBy {
			target, ptrErr := audit.GroupFieldPointer(&group, field)
			if ptrErr != nil {
				return nil, ptrErr
			}
			scanArgs = append(scanArgs, target)
		}
		scanArgs = append(scanArgs, &group.Count)

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

	q := s.sdb.NewSelect(&models).Where("e.user_id = ?", userID)

	// A zero After/Before means "unbounded". Applying them unconditionally
	// compares every row against year 1 and matches nothing.
	if !opts.After.IsZero() {
		q = q.Where("e.timestamp >= ?", opts.After.UTC().Format(time.RFC3339Nano))
	}
	if !opts.Before.IsZero() {
		q = q.Where("e.timestamp <= ?", opts.Before.UTC().Format(time.RFC3339Nano))
	}
	if opts.AppID != "" {
		q = q.Where("e.app_id = ?", opts.AppID)
	}
	if opts.TenantID != "" {
		q = q.Where("e.tenant_id = ?", opts.TenantID)
	}

	q = q.OrderExpr("e.timestamp DESC")
	if limit := opts.EffectiveLimit(); limit > 0 {
		q = q.Limit(limit)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	events, err := toEventSlice(models)
	if err != nil {
		return nil, err
	}

	return &audit.QueryResult{
		Events:  events,
		Total:   int64(len(events)),
		HasMore: opts.EffectiveLimit() > 0 && len(events) == opts.EffectiveLimit(),
	}, nil
}

// Count returns the total number of events matching filters.
func (s *Store) Count(ctx context.Context, q *audit.CountQuery) (int64, error) {
	// Use grove's Count rather than ColumnExpr("COUNT(*)").Scan(&count): the
	// model scanner can't scan into a scalar and leaks the connection on error.
	countQuery := s.sdb.NewSelect((*EventModel)(nil))

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

	return countQuery.Count(ctx)
}

// LastSequence returns the highest sequence number for a stream.
func (s *Store) LastSequence(ctx context.Context, streamID id.ID) (uint64, error) {
	// Raw scalar query: grove's model SelectQuery.Scan rejects a scalar dest and
	// leaks the pooled connection on the error. NewRaw.Scan scans scalars
	// directly via QueryRow.
	var seq int64
	err := s.sdb.NewRaw(
		"SELECT COALESCE(MAX(sequence), 0) FROM chronicle_events WHERE stream_id = ?",
		streamID.String(),
	).Scan(ctx, &seq)
	return safeUint64(seq), err
}

// LastHash returns the hash of the most recent event in a stream.
func (s *Store) LastHash(ctx context.Context, streamID id.ID) (string, error) {
	var hash string
	err := s.sdb.NewRaw(
		"SELECT hash FROM chronicle_events WHERE stream_id = ? ORDER BY sequence DESC LIMIT 1",
		streamID.String(),
	).Scan(ctx, &hash)
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
