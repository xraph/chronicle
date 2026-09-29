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
	ID          string    `json:"id"`
	AppID       string    `json:"app_id"`
	TenantID    string    `json:"tenant_id"`
	HeadHash    string    `json:"head_hash"`
	HeadSeq     uint64    `json:"head_seq"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Scheme      string    `json:"scheme"`
	SchemeSince uint64    `json:"scheme_since"`
}

func toStreamModel(st *stream.Stream) *streamModel {
	return &streamModel{
		ID:          st.ID.String(),
		AppID:       st.AppID,
		TenantID:    st.TenantID,
		HeadHash:    st.HeadHash,
		HeadSeq:     st.HeadSeq,
		CreatedAt:   st.CreatedAt,
		UpdatedAt:   st.UpdatedAt,
		Scheme:      st.Scheme,
		SchemeSince: st.SchemeSince,
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
		ID:          streamID,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		HeadHash:    m.HeadHash,
		HeadSeq:     m.HeadSeq,
		Scheme:      m.Scheme,
		SchemeSince: m.SchemeSince,
	}, nil
}

// CreateStream initializes a new hash chain stream.
func (s *Store) CreateStream(ctx context.Context, st *stream.Stream) error {
	m := toStreamModel(st)
	key := entityKey(s.key(prefixStream), m.ID)

	if err := s.setEntity(ctx, key, m); err != nil {
		return fmt.Errorf("chronicle/redis: create stream: %w", err)
	}

	pipe := s.rdb.Pipeline()
	pipe.ZAdd(ctx, s.key(zStreamAll), goredis.Z{Score: scoreFromTime(m.CreatedAt), Member: m.ID})
	// Unique scope index.
	pipe.Set(ctx, s.streamScopeKey(m.AppID, m.TenantID), m.ID, 0)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("chronicle/redis: create stream indexes: %w", err)
	}
	return nil
}

// GetStream returns a stream by ID.
func (s *Store) GetStream(ctx context.Context, streamID id.ID) (*stream.Stream, error) {
	var m streamModel
	if err := s.getEntity(ctx, entityKey(s.key(prefixStream), streamID.String()), &m); err != nil {
		if isNotFound(err) {
			return nil, chronicle.ErrStreamNotFound
		}
		return nil, fmt.Errorf("chronicle/redis: get stream: %w", err)
	}
	return fromStreamModel(&m)
}

// GetStreamByScope returns the stream for a given app+tenant scope.
//
// Chronicle.resolveStream creates a new stream on ErrStreamNotFound, so a miss
// has to be true. Before Migrate has moved the scope index to the v2 format,
// every existing scope misses, and reporting that would start a second chain
// for each tenant. Until then a miss returns ErrScopeKeysNotMigrated instead.
// The check costs one EXISTS, and only on a miss.
func (s *Store) GetStreamByScope(ctx context.Context, appID, tenantID string) (*stream.Stream, error) {
	streamID, err := s.rdb.Get(ctx, s.streamScopeKey(appID, tenantID)).Result()
	if err != nil {
		if !isRedisNil(err) {
			return nil, fmt.Errorf("chronicle/redis: get stream by scope: %w", err)
		}
		migrated, existsErr := s.rdb.Exists(ctx, s.key(scopeKeyFormatMarker)).Result()
		if existsErr != nil {
			return nil, fmt.Errorf("chronicle/redis: get stream by scope: check scope key format: %w", existsErr)
		}
		if migrated == 0 {
			return nil, ErrScopeKeysNotMigrated
		}
		return nil, chronicle.ErrStreamNotFound
	}

	var m streamModel
	if err := s.getEntity(ctx, entityKey(s.key(prefixStream), streamID), &m); err != nil {
		if isNotFound(err) {
			return nil, chronicle.ErrStreamNotFound
		}
		return nil, err
	}
	return fromStreamModel(&m)
}

// ListStreams returns all streams with pagination.
func (s *Store) ListStreams(ctx context.Context, opts stream.ListOpts) ([]*stream.Stream, error) {
	ids, err := s.rdb.ZRevRange(ctx, s.key(zStreamAll), 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: list streams: %w", err)
	}

	result := make([]*stream.Stream, 0, len(ids))
	for _, entryID := range ids {
		var m streamModel
		if err := s.getEntity(ctx, entityKey(s.key(prefixStream), entryID), &m); err != nil {
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

// UpdateStreamScheme moves the stream's digest pin to scheme, applying from
// sequence since.
func (s *Store) UpdateStreamScheme(ctx context.Context, streamID id.ID, scheme string, since uint64) error {
	key := entityKey(s.key(prefixStream), streamID.String())

	var m streamModel
	if err := s.getEntity(ctx, key, &m); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("%w: stream %s", chronicle.ErrStreamNotFound, streamID)
		}
		return fmt.Errorf("chronicle/redis: update stream scheme get: %w", err)
	}

	m.Scheme = scheme
	m.SchemeSince = since
	m.UpdatedAt = now()

	if err := s.setEntity(ctx, key, &m); err != nil {
		return fmt.Errorf("chronicle/redis: update stream scheme: %w", err)
	}
	return nil
}

// UpdateStreamHead updates the stream's head hash and sequence after append.
func (s *Store) UpdateStreamHead(ctx context.Context, streamID id.ID, hash string, seq uint64) error {
	key := entityKey(s.key(prefixStream), streamID.String())

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
