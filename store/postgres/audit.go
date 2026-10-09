package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/xraph/grove/drivers/pgdriver"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/audit"
	chash "github.com/xraph/chronicle/hash"
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
	return s.AppendWithChain(ctx, event, s.hasher)
}

// AppendWithChain uses the caller's configured hasher under the stream lock.
func (s *Store) AppendWithChain(ctx context.Context, event *audit.Event, h *chash.Chain) error {
	tx, err := s.pg.BeginTxQuery(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.appendInTx(ctx, tx, event, h); err != nil {
		return err
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
	// Build count query with the same conditions. Use grove's Count (a proper
	// scalar scan) rather than ColumnExpr("COUNT(*)").Scan(&total): the model
	// scanner rejects a scalar dest and, worse, leaks the pooled connection on
	// that error (it acquires a row via QueryRow but never scans it).
	countQuery := s.pg.NewSelect((*EventModel)(nil))
	applyEventFilters(countQuery, q)

	total, err := countQuery.Count(ctx)
	if err != nil {
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

	if err2 := selectQuery.Scan(ctx); err2 != nil {
		return nil, err2
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

// selectExpr renders one group_by field for the SELECT and GROUP BY clauses.
// Bucket fields become a date_trunc, everything else is the whitelisted
// column. Both come from ResolveGroupBy, so neither is caller input.
//
// timestamp is TIMESTAMPTZ, and date_trunc on a TIMESTAMPTZ truncates in the
// SESSION time zone, not UTC. `column AT TIME ZONE 'UTC'` converts it to the
// UTC wall-clock value as a plain timestamp first, so the truncation below is
// always UTC regardless of what time zone the connection happens to be in.
// Without this, day and hour boundaries shift on any server whose session
// time zone is not UTC, even though every test here (run in a UTC container)
// would still pass.
func selectExpr(field, column string) string {
	switch field {
	case "day":
		return "to_char(date_trunc('day', " + column + " AT TIME ZONE 'UTC'), 'YYYY-MM-DD')"
	case "hour":
		return `to_char(date_trunc('hour', ` + column + ` AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:00:00"Z"')`
	default:
		return column
	}
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

	// Safe: every element of columns is a constant from audit's whitelist, and
	// q.GroupBy[i] pairs with columns[i] one-for-one (see audit.ResolveGroupBy),
	// so selectExpr only ever sees the field name that produced that column.
	exprs := make([]string, len(columns))
	for i, column := range columns {
		exprs[i] = selectExpr(q.GroupBy[i], column)
	}
	exprList := strings.Join(exprs, ", ")

	query := fmt.Sprintf(
		"SELECT %s, COUNT(*) as count FROM chronicle_events %s GROUP BY %s ORDER BY count DESC",
		exprList, whereClause, exprList,
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

	q := s.pg.NewSelect(&models)
	q.Where("e.user_id = ?", userID)

	// A zero After/Before means "unbounded". Applying them unconditionally
	// compares every row against year 1 and matches nothing.
	if !opts.After.IsZero() {
		q.Where("e.timestamp >= ?", opts.After)
	}
	if !opts.Before.IsZero() {
		q.Where("e.timestamp <= ?", opts.Before)
	}
	if opts.AppID != "" {
		q.Where("e.app_id = ?", opts.AppID)
	}
	if opts.TenantID != "" {
		q.Where("e.tenant_id = ?", opts.TenantID)
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
	countQuery := s.pg.NewSelect((*EventModel)(nil))

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

	return countQuery.Count(ctx)
}

// LastSequence returns the highest sequence number for a stream.
func (s *Store) LastSequence(ctx context.Context, streamID id.ID) (uint64, error) {
	// Raw scalar query: grove's model SelectQuery.Scan rejects a scalar dest
	// and leaks the pooled connection on the error. NewRaw.Scan scans scalars
	// directly via QueryRow.
	var seq int64
	err := s.pg.NewRaw(
		"SELECT COALESCE(MAX(sequence), 0) FROM chronicle_events WHERE stream_id = $1",
		streamID.String(),
	).Scan(ctx, &seq)
	return safeUint64(seq), err
}

// LastHash returns the hash of the most recent event in a stream.
func (s *Store) LastHash(ctx context.Context, streamID id.ID) (string, error) {
	var hash string
	err := s.pg.NewRaw(
		"SELECT hash FROM chronicle_events WHERE stream_id = $1 ORDER BY sequence DESC LIMIT 1",
		streamID.String(),
	).Scan(ctx, &hash)
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
	if f.SessionID != "" {
		q.Where("e.session_id = ?", f.SessionID)
	}
	if f.RequestID != "" {
		q.Where("e.request_id = ?", f.RequestID)
	}
	if !f.After.IsZero() {
		q.Where("e.timestamp >= ?", f.After)
	}
	if !f.Before.IsZero() {
		q.Where("e.timestamp <= ?", f.Before)
	}
	// WhereArray quotes its column as one identifier, so "e.category" became
	// the nonexistent column "e.category" and every filtered query failed.
	// The bare name is unambiguous: these queries read one table.
	if len(f.Categories) > 0 {
		q.WhereArray("category", "= ANY", f.Categories)
	}
	if len(f.Actions) > 0 {
		q.WhereArray("action", "= ANY", f.Actions)
	}
	if len(f.Resources) > 0 {
		q.WhereArray("resource", "= ANY", f.Resources)
	}
	if len(f.Severity) > 0 {
		q.WhereArray("severity", "= ANY", f.Severity)
	}
	if len(f.Outcome) > 0 {
		q.WhereArray("outcome", "= ANY", f.Outcome)
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

func (s *Store) appendInTx(ctx context.Context, tx *pgdriver.PgTx, event *audit.Event, h *chash.Chain) error {
	streamID := event.StreamID.String()

	// Lock the stream row so concurrent appends to the same stream serialize.
	var headSeq int64
	var headHash, scheme string
	if err := tx.NewRaw(
		"SELECT head_seq, head_hash, scheme FROM chronicle_streams WHERE id = $1 FOR UPDATE", streamID,
	).Scan(ctx, &headSeq, &headHash, &scheme); err != nil {
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

	if scheme != "" && scheme != string(chash.SchemeLegacy) && chash.Rank(chash.Scheme(scheme)) == 0 {
		return acceptance.ErrInvalid
	}
	if chash.Rank(h.Scheme()) < chash.Rank(chash.Scheme(scheme)) {
		return chronicle.ErrSchemeWeakeningRefused
	}
	if scheme != string(h.Scheme()) {
		if _, err := tx.NewRaw("UPDATE chronicle_streams SET scheme=$1, scheme_since=$2 WHERE id=$3", string(h.Scheme()), next, streamID).Exec(ctx); err != nil {
			return err
		}
	}
	if maxSeq > headSeq {
		if err := tx.NewRaw("SELECT hash FROM chronicle_events WHERE stream_id=$1 AND sequence=$2", streamID, maxSeq).Scan(ctx, &headHash); err != nil {
			return err
		}
	}

	event.Sequence = safeUint64(next)

	// Re-link the chain under the row lock.
	//
	// Chronicle.Record derives PrevHash and Hash from the head it read before
	// calling Append. With several replicas writing to one database, two of them
	// can read the same head and produce two events claiming the same
	// predecessor. Deriving both here, while the lock is held, is what keeps the
	// chain linked across processes.
	//
	// This is also required for correctness rather than just concurrency: the
	// sequence is part of the hashed content, and it is allocated above, so the
	// hash has to be computed after it is known.
	event.PrevHash = headHash
	digest, keyID, hErr := h.Compute(ctx, event.PrevHash, event)
	if hErr != nil {
		return fmt.Errorf("compute hash for event %s: %w", event.ID, hErr)
	}
	event.Hash = digest
	event.HashScheme = string(h.Scheme())
	event.HashKeyID = keyID

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

	return nil
}
