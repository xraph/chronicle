package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// streamModel is the JSON representation stored in Redis.
type streamModel struct {
	ID        string    `json:"id"`
	AppID     string    `json:"app_id"`
	TenantID  string    `json:"tenant_id"`
	HeadHash  string    `json:"head_hash"`
	HeadSeq   uint64    `json:"head_seq"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toStreamModel(st *stream.Stream) *streamModel {
	return &streamModel{
		ID:        st.ID.String(),
		AppID:     st.AppID,
		TenantID:  st.TenantID,
		HeadHash:  st.HeadHash,
		HeadSeq:   st.HeadSeq,
		CreatedAt: st.CreatedAt,
		UpdatedAt: st.UpdatedAt,
	}
}

func fromStreamModel(m *streamModel) (*stream.Stream, error) {
	streamID, err := id.ParseStreamID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse stream ID %q: %w", m.ID, err)
	}
	return &stream.Stream{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		},
		ID:       streamID,
		AppID:    m.AppID,
		TenantID: m.TenantID,
		HeadHash: m.HeadHash,
		HeadSeq:  m.HeadSeq,
	}, nil
}

// CreateStream initializes a new hash chain stream.
func (s *Store) CreateStream(ctx context.Context, st *stream.Stream) error {
	m := toStreamModel(st)
	key := entityKey(prefixStream, m.ID)

	if err := s.setEntity(ctx, key, m); err != nil {
		return fmt.Errorf("chronicle/redis: create stream: %w", err)
	}

	pipe := s.rdb.Pipeline()
	pipe.ZAdd(ctx, zStreamAll, goredis.Z{Score: scoreFromTime(m.CreatedAt), Member: m.ID})
	// Unique scope index.
	pipe.Set(ctx, uniqueStreamScope+m.AppID+":"+m.TenantID, m.ID, 0)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("chronicle/redis: create stream indexes: %w", err)
	}
	return nil
}

// GetStream returns a stream by ID.
func (s *Store) GetStream(ctx context.Context, streamID id.ID) (*stream.Stream, error) {
	var m streamModel
	if err := s.getEntity(ctx, entityKey(prefixStream, streamID.String()), &m); err != nil {
		if isNotFound(err) {
			return nil, chronicle.ErrStreamNotFound
		}
		return nil, fmt.Errorf("chronicle/redis: get stream: %w", err)
	}
	return fromStreamModel(&m)
}

// GetStreamByScope returns the stream for a given app+tenant scope.
func (s *Store) GetStreamByScope(ctx context.Context, appID, tenantID string) (*stream.Stream, error) {
	scopeKey := uniqueStreamScope + appID + ":" + tenantID
	streamID, err := s.rdb.Get(ctx, scopeKey).Result()
	if err != nil {
		if isRedisNil(err) {
			return nil, chronicle.ErrStreamNotFound
		}
		return nil, fmt.Errorf("chronicle/redis: get stream by scope: %w", err)
	}

	var m streamModel
	if err := s.getEntity(ctx, entityKey(prefixStream, streamID), &m); err != nil {
		if isNotFound(err) {
			return nil, chronicle.ErrStreamNotFound
		}
		return nil, err
	}
	return fromStreamModel(&m)
}

// ListStreams returns all streams with pagination.
func (s *Store) ListStreams(ctx context.Context, opts stream.ListOpts) ([]*stream.Stream, error) {
	ids, err := s.rdb.ZRevRange(ctx, zStreamAll, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: list streams: %w", err)
	}

	result := make([]*stream.Stream, 0, len(ids))
	for _, entryID := range ids {
		var m streamModel
		if err := s.getEntity(ctx, entityKey(prefixStream, entryID), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		st, err := fromStreamModel(&m)
		if err != nil {
			return nil, err
		}
		result = append(result, st)
	}

	return applyPagination(result, opts.Offset, opts.Limit), nil
}

// UpdateStreamHead updates the stream's head hash and sequence after append.
func (s *Store) UpdateStreamHead(ctx context.Context, streamID id.ID, hash string, seq uint64) error {
	key := entityKey(prefixStream, streamID.String())

	var m streamModel
	if err := s.getEntity(ctx, key, &m); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("%w: stream %s", chronicle.ErrStreamNotFound, streamID)
		}
		return fmt.Errorf("chronicle/redis: update stream head get: %w", err)
	}

	m.HeadHash = hash
	m.HeadSeq = seq
	m.UpdatedAt = now()

	if err := s.setEntity(ctx, key, &m); err != nil {
		return fmt.Errorf("chronicle/redis: update stream head: %w", err)
	}
	return nil
}
