package redis

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// eventModel is the JSON representation stored in Redis.
type eventModel struct {
	ID              string         `json:"id"`
	StreamID        string         `json:"stream_id"`
	Sequence        uint64         `json:"sequence"`
	Hash            string         `json:"hash"`
	PrevHash        string         `json:"prev_hash"`
	AppID           string         `json:"app_id"`
	TenantID        string         `json:"tenant_id"`
	UserID          string         `json:"user_id"`
	IP              string         `json:"ip"`
	Action          string         `json:"action"`
	Resource        string         `json:"resource"`
	Category        string         `json:"category"`
	ResourceID      string         `json:"resource_id"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	Outcome         string         `json:"outcome"`
	Severity        string         `json:"severity"`
	Reason          string         `json:"reason"`
	SubjectID       string         `json:"subject_id"`
	EncryptionKeyID string         `json:"encryption_key_id"`
	Erased          bool           `json:"erased"`
	ErasedAt        *time.Time     `json:"erased_at,omitempty"`
	ErasureID       string         `json:"erasure_id,omitempty"`
	Timestamp       time.Time      `json:"timestamp"`
	CreatedAt       time.Time      `json:"created_at"`
}

func toEventModel(e *audit.Event) *eventModel {
	return &eventModel{
		ID:              e.ID.String(),
		StreamID:        e.StreamID.String(),
		Sequence:        e.Sequence,
		Hash:            e.Hash,
		PrevHash:        e.PrevHash,
		AppID:           e.AppID,
		TenantID:        e.TenantID,
		UserID:          e.UserID,
		IP:              e.IP,
		Action:          e.Action,
		Resource:        e.Resource,
		Category:        e.Category,
		ResourceID:      e.ResourceID,
		Metadata:        e.Metadata,
		Outcome:         e.Outcome,
		Severity:        e.Severity,
		Reason:          e.Reason,
		SubjectID:       e.SubjectID,
		EncryptionKeyID: e.EncryptionKeyID,
		Erased:          e.Erased,
		ErasedAt:        e.ErasedAt,
		ErasureID:       e.ErasureID,
		Timestamp:       e.Timestamp,
		CreatedAt:       now(),
	}
}

func fromEventModel(m *eventModel) (*audit.Event, error) {
	eventID, err := id.ParseAuditID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse audit ID %q: %w", m.ID, err)
	}

	streamID, err := id.ParseStreamID(m.StreamID)
	if err != nil {
		return nil, fmt.Errorf("parse stream ID %q: %w", m.StreamID, err)
	}

	return &audit.Event{
		ID:              eventID,
		StreamID:        streamID,
		Sequence:        m.Sequence,
		Hash:            m.Hash,
		PrevHash:        m.PrevHash,
		AppID:           m.AppID,
		TenantID:        m.TenantID,
		UserID:          m.UserID,
		IP:              m.IP,
		Action:          m.Action,
		Resource:        m.Resource,
		Category:        m.Category,
		ResourceID:      m.ResourceID,
		Metadata:        m.Metadata,
		Outcome:         m.Outcome,
		Severity:        m.Severity,
		Reason:          m.Reason,
		SubjectID:       m.SubjectID,
		EncryptionKeyID: m.EncryptionKeyID,
		Erased:          m.Erased,
		ErasedAt:        m.ErasedAt,
		ErasureID:       m.ErasureID,
		Timestamp:       m.Timestamp,
	}, nil
}

// Append persists a single audit event.
func (s *Store) Append(ctx context.Context, event *audit.Event) error {
	return s.storeEvent(ctx, event)
}

// AppendBatch persists multiple events atomically using a pipeline.
func (s *Store) AppendBatch(ctx context.Context, events []*audit.Event) error {
	if len(events) == 0 {
		return nil
	}

	for _, event := range events {
		if err := s.storeEvent(ctx, event); err != nil {
			return fmt.Errorf("failed to store event %s: %w", event.ID, err)
		}
	}

	return nil
}

// storeEvent stores a single event and updates all indexes.
func (s *Store) storeEvent(ctx context.Context, event *audit.Event) error {
	m := toEventModel(event)
	key := entityKey(prefixEvent, m.ID)

	if err := s.setEntity(ctx, key, m); err != nil {
		return fmt.Errorf("chronicle/redis: store event: %w", err)
	}

	score := scoreFromTime(m.Timestamp)

	pipe := s.rdb.Pipeline()
	pipe.ZAdd(ctx, zEventAll, goredis.Z{Score: score, Member: m.ID})
	pipe.ZAdd(ctx, zEventStream+m.StreamID, goredis.Z{Score: float64(m.Sequence), Member: m.ID})
	pipe.ZAdd(ctx, zEventScope+m.AppID+":"+m.TenantID, goredis.Z{Score: score, Member: m.ID})
	if m.Category != "" {
		pipe.ZAdd(ctx, zEventCategory+m.Category, goredis.Z{Score: score, Member: m.ID})
	}
	if m.UserID != "" {
		pipe.ZAdd(ctx, zEventUser+m.UserID, goredis.Z{Score: score, Member: m.ID})
	}
	if m.SubjectID != "" {
		pipe.ZAdd(ctx, zEventSubject+m.SubjectID, goredis.Z{Score: score, Member: m.ID})
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("chronicle/redis: store event indexes: %w", err)
	}
	return nil
}

// Get returns a single event by ID.
func (s *Store) Get(ctx context.Context, eventID id.ID) (*audit.Event, error) {
	var m eventModel
	if err := s.getEntity(ctx, entityKey(prefixEvent, eventID.String()), &m); err != nil {
		if isNotFound(err) {
			return nil, chronicle.ErrEventNotFound
		}
		return nil, fmt.Errorf("chronicle/redis: get event: %w", err)
	}
	return fromEventModel(&m)
}

// Query returns events matching filters with pagination.
func (s *Store) Query(ctx context.Context, q *audit.Query) (*audit.QueryResult, error) {
	// Determine the best index to scan.
	var zKey string
	switch {
	case q.AppID != "" && q.TenantID != "":
		zKey = zEventScope + q.AppID + ":" + q.TenantID
	case len(q.Categories) == 1:
		zKey = zEventCategory + q.Categories[0]
	case q.UserID != "":
		zKey = zEventUser + q.UserID
	default:
		zKey = zEventAll
	}

	minScore := math.Inf(-1)
	maxScore := math.Inf(1)
	if !q.After.IsZero() {
		minScore = scoreFromTime(q.After)
	}
	if !q.Before.IsZero() {
		maxScore = scoreFromTime(q.Before)
	}

	ids, err := s.zRangeByScoreIDs(ctx, zKey, minScore, maxScore)
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: query events: %w", err)
	}

	// Fetch and filter events (reverse for DESC).
	var allEvents []*audit.Event
	for i := len(ids) - 1; i >= 0; i-- {
		var m eventModel
		if err := s.getEntity(ctx, entityKey(prefixEvent, ids[i]), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		if !matchesEventFilter(&m, q) {
			continue
		}
		evt, err := fromEventModel(&m)
		if err != nil {
			return nil, err
		}
		allEvents = append(allEvents, evt)
	}

	if q.Order == "asc" {
		sort.Slice(allEvents, func(i, j int) bool {
			return allEvents[i].Timestamp.Before(allEvents[j].Timestamp)
		})
	}

	total := int64(len(allEvents))
	paged := applyPagination(allEvents, q.Offset, q.Limit)
	hasMore := total > int64(q.Offset+len(paged))

	return &audit.QueryResult{
		Events:  paged,
		Total:   total,
		HasMore: hasMore,
	}, nil
}

// Aggregate returns grouped event statistics.
func (s *Store) Aggregate(ctx context.Context, q *audit.AggregateQuery) (*audit.AggregateResult, error) {
	if len(q.GroupBy) == 0 {
		return nil, errors.New("aggregate query requires at least one group_by field")
	}

	minScore := math.Inf(-1)
	maxScore := math.Inf(1)
	if !q.After.IsZero() {
		minScore = scoreFromTime(q.After)
	}
	if !q.Before.IsZero() {
		maxScore = scoreFromTime(q.Before)
	}

	// Determine index key.
	zKey := zEventAll
	if q.AppID != "" && q.TenantID != "" {
		zKey = zEventScope + q.AppID + ":" + q.TenantID
	}

	ids, err := s.zRangeByScoreIDs(ctx, zKey, minScore, maxScore)
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: aggregate: %w", err)
	}

	// Count groups.
	type groupKey string
	counts := make(map[groupKey]*audit.AggregateGroup)

	for _, eid := range ids {
		var m eventModel
		if err := s.getEntity(ctx, entityKey(prefixEvent, eid), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}

		// Apply scope filters.
		if q.AppID != "" && m.AppID != q.AppID {
			continue
		}
		if q.TenantID != "" && m.TenantID != q.TenantID {
			continue
		}

		// Build group key.
		parts := make([]string, 0, len(q.GroupBy))
		for _, field := range q.GroupBy {
			switch field {
			case "category":
				parts = append(parts, m.Category)
			case "action":
				parts = append(parts, m.Action)
			case "outcome":
				parts = append(parts, m.Outcome)
			case "severity":
				parts = append(parts, m.Severity)
			case "resource":
				parts = append(parts, m.Resource)
			default:
				return nil, fmt.Errorf("unsupported group_by field: %s", field)
			}
		}

		gk := groupKey(strings.Join(parts, "\x00"))
		if _, ok := counts[gk]; !ok {
			g := &audit.AggregateGroup{}
			for i, field := range q.GroupBy {
				switch field {
				case "category":
					g.Category = parts[i]
				case "action":
					g.Action = parts[i]
				case "outcome":
					g.Outcome = parts[i]
				case "severity":
					g.Severity = parts[i]
				case "resource":
					g.Resource = parts[i]
				}
			}
			counts[gk] = g
		}
		counts[gk].Count++
	}

	groups := make([]audit.AggregateGroup, 0, len(counts))
	var total int64
	for _, g := range counts {
		groups = append(groups, *g)
		total += g.Count
	}

	// Sort by count DESC.
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Count > groups[j].Count
	})

	return &audit.AggregateResult{
		Groups: groups,
		Total:  total,
	}, nil
}

// ByUser returns events for a specific user within a time range.
func (s *Store) ByUser(ctx context.Context, userID string, opts audit.TimeRange) (*audit.QueryResult, error) {
	minScore := scoreFromTime(opts.After)
	maxScore := scoreFromTime(opts.Before)

	ids, err := s.zRangeByScoreIDs(ctx, zEventUser+userID, minScore, maxScore)
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: events by user: %w", err)
	}

	events := make([]*audit.Event, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- { // reverse for DESC
		var m eventModel
		if err := s.getEntity(ctx, entityKey(prefixEvent, ids[i]), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		evt, err := fromEventModel(&m)
		if err != nil {
			return nil, err
		}
		events = append(events, evt)
	}

	return &audit.QueryResult{
		Events:  events,
		Total:   int64(len(events)),
		HasMore: false,
	}, nil
}

// Count returns the total number of events matching filters.
func (s *Store) Count(ctx context.Context, q *audit.CountQuery) (int64, error) {
	// Determine the best index.
	zKey := zEventAll
	if q.AppID != "" && q.TenantID != "" {
		zKey = zEventScope + q.AppID + ":" + q.TenantID
	} else if q.Category != "" {
		zKey = zEventCategory + q.Category
	}

	minScore := math.Inf(-1)
	maxScore := math.Inf(1)
	if !q.After.IsZero() {
		minScore = scoreFromTime(q.After)
	}
	if !q.Before.IsZero() {
		maxScore = scoreFromTime(q.Before)
	}

	ids, err := s.zRangeByScoreIDs(ctx, zKey, minScore, maxScore)
	if err != nil {
		return 0, err
	}

	// If we used a narrow index that already filters, just count.
	if q.AppID != "" && q.TenantID != "" && q.Category == "" {
		return int64(len(ids)), nil
	}
	if q.Category != "" && q.AppID == "" {
		return int64(len(ids)), nil
	}

	// Otherwise we need to post-filter.
	var count int64
	for _, eid := range ids {
		var m eventModel
		if err := s.getEntity(ctx, entityKey(prefixEvent, eid), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return 0, err
		}
		if q.AppID != "" && m.AppID != q.AppID {
			continue
		}
		if q.TenantID != "" && m.TenantID != q.TenantID {
			continue
		}
		if q.Category != "" && m.Category != q.Category {
			continue
		}
		count++
	}
	return count, nil
}

// LastSequence returns the highest sequence number for a stream.
func (s *Store) LastSequence(ctx context.Context, streamID id.ID) (uint64, error) {
	// Get the highest scored member from the stream's sorted set.
	ids, err := s.rdb.ZRevRangeWithScores(ctx, zEventStream+streamID.String(), 0, 0).Result()
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	return uint64(ids[0].Score), nil
}

// LastHash returns the hash of the most recent event in a stream.
func (s *Store) LastHash(ctx context.Context, streamID id.ID) (string, error) {
	ids, err := s.rdb.ZRevRange(ctx, zEventStream+streamID.String(), 0, 0).Result()
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", chronicle.ErrEventNotFound
	}

	var m eventModel
	if err := s.getEntity(ctx, entityKey(prefixEvent, ids[0]), &m); err != nil {
		if isNotFound(err) {
			return "", chronicle.ErrEventNotFound
		}
		return "", err
	}
	return m.Hash, nil
}

// matchesEventFilter checks if an event model matches all the filter criteria.
func matchesEventFilter(m *eventModel, q *audit.Query) bool {
	if q.AppID != "" && m.AppID != q.AppID {
		return false
	}
	if q.TenantID != "" && m.TenantID != q.TenantID {
		return false
	}
	if q.UserID != "" && m.UserID != q.UserID {
		return false
	}
	if len(q.Categories) > 0 && !containsStr(q.Categories, m.Category) {
		return false
	}
	if len(q.Actions) > 0 && !containsStr(q.Actions, m.Action) {
		return false
	}
	if len(q.Resources) > 0 && !containsStr(q.Resources, m.Resource) {
		return false
	}
	if len(q.Severity) > 0 && !containsStr(q.Severity, m.Severity) {
		return false
	}
	if len(q.Outcome) > 0 && !containsStr(q.Outcome, m.Outcome) {
		return false
	}
	return true
}

// containsStr checks if a string slice contains a value.
func containsStr(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
