package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// Append persists a single audit event.
func (s *Store) Append(ctx context.Context, event *audit.Event) error {
	m := fromEvent(event)
	_, err := s.mdb.NewInsert(m).Exec(ctx)
	return err
}

// AppendBatch persists multiple events atomically.
func (s *Store) AppendBatch(ctx context.Context, events []*audit.Event) error {
	if len(events) == 0 {
		return nil
	}

	for _, event := range events {
		m := fromEvent(event)
		if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert event %s: %w", event.ID, err)
		}
	}

	return nil
}

// Get returns a single event by ID.
func (s *Store) Get(ctx context.Context, eventID id.ID) (*audit.Event, error) {
	var m EventModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": eventID.String()}).Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, chronicle.ErrEventNotFound
		}
		return nil, fmt.Errorf("failed to get event: %w", err)
	}

	event, err := toEvent(&m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert event model: %w", err)
	}

	return event, nil
}

// Query returns events matching filters with pagination.
func (s *Store) Query(ctx context.Context, q *audit.Query) (*audit.QueryResult, error) {
	filter := buildEventFilter(q)

	// Count total.
	total, err := s.mdb.Collection(colEvents).CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count events: %w", err)
	}

	// Build select query.
	var models []EventModel
	findQ := s.mdb.NewFind(&models).Filter(filter)

	// Order direction.
	sortDir := -1
	if q.Order == "asc" {
		sortDir = 1
	}
	findQ = findQ.Sort(bson.D{{Key: "timestamp", Value: sortDir}})

	if q.Limit > 0 {
		findQ = findQ.Limit(int64(q.Limit))
	}
	if q.Offset > 0 {
		findQ = findQ.Skip(int64(q.Offset))
	}

	if scanErr := findQ.Scan(ctx); scanErr != nil {
		return nil, fmt.Errorf("failed to query events: %w", scanErr)
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

	// Build match stage.
	match := bson.M{}
	if q.AppID != "" {
		match["app_id"] = q.AppID
	}
	if q.TenantID != "" {
		match["tenant_id"] = q.TenantID
	}
	if !q.After.IsZero() || !q.Before.IsZero() {
		ts := bson.M{}
		if !q.After.IsZero() {
			ts["$gte"] = q.After
		}
		if !q.Before.IsZero() {
			ts["$lte"] = q.Before
		}
		match["timestamp"] = ts
	}

	// Build group key.
	groupID := bson.M{}
	for _, field := range q.GroupBy {
		groupID[field] = "$" + field
	}

	pipeline := bson.A{
		bson.M{"$match": match},
		bson.M{"$group": bson.M{
			"_id":   groupID,
			"count": bson.M{"$sum": 1},
		}},
		bson.M{"$sort": bson.M{"count": -1}},
	}

	cursor, err := s.mdb.Collection(colEvents).Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate events: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var groups []audit.AggregateGroup
	var total int64

	for cursor.Next(ctx) {
		var raw struct {
			ID    bson.M `bson:"_id"`
			Count int64  `bson:"count"`
		}
		if err := cursor.Decode(&raw); err != nil {
			return nil, fmt.Errorf("failed to decode aggregate row: %w", err)
		}

		group := audit.AggregateGroup{Count: raw.Count}
		for _, field := range q.GroupBy {
			var val string
			if v, ok := raw.ID[field].(string); ok {
				val = v
			}
			switch field {
			case "category":
				group.Category = val
			case "action":
				group.Action = val
			case "outcome":
				group.Outcome = val
			case "severity":
				group.Severity = val
			case "resource":
				group.Resource = val
			default:
				return nil, fmt.Errorf("unsupported group_by field: %s", field)
			}
		}

		groups = append(groups, group)
		total += raw.Count
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate aggregate results: %w", err)
	}

	return &audit.AggregateResult{
		Groups: groups,
		Total:  total,
	}, nil
}

// ByUser returns events for a specific user within a time range.
func (s *Store) ByUser(ctx context.Context, userID string, opts audit.TimeRange) (*audit.QueryResult, error) {
	filter := bson.M{
		"user_id": userID,
		"timestamp": bson.M{
			"$gte": opts.After,
			"$lte": opts.Before,
		},
	}

	var models []EventModel
	err := s.mdb.NewFind(&models).
		Filter(filter).
		Sort(bson.D{{Key: "timestamp", Value: -1}}).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query events by user: %w", err)
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
	filter := bson.M{}

	if q.AppID != "" {
		filter["app_id"] = q.AppID
	}
	if q.TenantID != "" {
		filter["tenant_id"] = q.TenantID
	}
	if q.Category != "" {
		filter["category"] = q.Category
	}
	if !q.After.IsZero() || !q.Before.IsZero() {
		ts := bson.M{}
		if !q.After.IsZero() {
			ts["$gte"] = q.After
		}
		if !q.Before.IsZero() {
			ts["$lte"] = q.Before
		}
		filter["timestamp"] = ts
	}

	count, err := s.mdb.Collection(colEvents).CountDocuments(ctx, filter)
	return count, err
}

// LastSequence returns the highest sequence number for a stream.
func (s *Store) LastSequence(ctx context.Context, streamID id.ID) (uint64, error) {
	pipeline := bson.A{
		bson.M{"$match": bson.M{"stream_id": streamID.String()}},
		bson.M{"$group": bson.M{
			"_id":     nil,
			"max_seq": bson.M{"$max": "$sequence"},
		}},
	}

	cursor, err := s.mdb.Collection(colEvents).Aggregate(ctx, pipeline)
	if err != nil {
		return 0, err
	}
	defer func() { _ = cursor.Close(ctx) }()

	var result struct {
		MaxSeq uint64 `bson:"max_seq"`
	}
	if cursor.Next(ctx) {
		if err := cursor.Decode(&result); err != nil {
			return 0, err
		}
	}
	return result.MaxSeq, nil
}

// LastHash returns the hash of the most recent event in a stream.
func (s *Store) LastHash(ctx context.Context, streamID id.ID) (string, error) {
	var m EventModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"stream_id": streamID.String()}).
		Sort(bson.D{{Key: "sequence", Value: -1}}).
		Limit(1).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return "", chronicle.ErrEventNotFound
		}
		return "", err
	}
	return m.Hash, nil
}

// buildEventFilter builds a bson.M filter from an audit.Query.
func buildEventFilter(q *audit.Query) bson.M {
	filter := bson.M{}

	if q.AppID != "" {
		filter["app_id"] = q.AppID
	}
	if q.TenantID != "" {
		filter["tenant_id"] = q.TenantID
	}
	if q.UserID != "" {
		filter["user_id"] = q.UserID
	}
	if !q.After.IsZero() || !q.Before.IsZero() {
		ts := bson.M{}
		if !q.After.IsZero() {
			ts["$gte"] = q.After
		}
		if !q.Before.IsZero() {
			ts["$lte"] = q.Before
		}
		filter["timestamp"] = ts
	}
	if len(q.Categories) > 0 {
		filter["category"] = bson.M{"$in": q.Categories}
	}
	if len(q.Actions) > 0 {
		filter["action"] = bson.M{"$in": q.Actions}
	}
	if len(q.Resources) > 0 {
		filter["resource"] = bson.M{"$in": q.Resources}
	}
	if len(q.Severity) > 0 {
		filter["severity"] = bson.M{"$in": q.Severity}
	}
	if len(q.Outcome) > 0 {
		filter["outcome"] = bson.M{"$in": q.Outcome}
	}

	return filter
}

// ensure import is used
var _ = time.Now
