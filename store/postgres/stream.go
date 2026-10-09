package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/acceptance"
	chash "github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// CreateStream initializes a new hash chain stream.
func (s *Store) CreateStream(ctx context.Context, st *stream.Stream) error {
	m := fromStream(st)
	_, err := s.pg.NewInsert(m).Exec(ctx)
	return err
}

// GetStream returns a stream by ID.
func (s *Store) GetStream(ctx context.Context, streamID id.ID) (*stream.Stream, error) {
	m := new(StreamModel)
	err := s.pg.NewSelect(m).Where("id = ?", streamID.String()).Scan(ctx)
	if err != nil {
		return nil, groveError(err, chronicle.ErrStreamNotFound)
	}

	st, err := toStream(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert stream model: %w", err)
	}

	return st, nil
}

// GetStreamByScope returns the stream for a given app+tenant scope.
func (s *Store) GetStreamByScope(ctx context.Context, appID, tenantID string) (*stream.Stream, error) {
	m := new(StreamModel)
	err := s.pg.NewSelect(m).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		return nil, groveError(err, chronicle.ErrStreamNotFound)
	}

	st, err := toStream(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert stream model: %w", err)
	}

	return st, nil
}

// ListStreams returns all streams with pagination.
func (s *Store) ListStreams(ctx context.Context, opts stream.ListOpts) ([]*stream.Stream, error) {
	var models []StreamModel
	err := s.pg.NewSelect(&models).
		OrderExpr("s.created_at DESC").
		Limit(opts.Limit).
		Offset(opts.Offset).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	streams := make([]*stream.Stream, 0, len(models))
	for i := range models {
		st, err := toStream(&models[i])
		if err != nil {
			return nil, err
		}
		streams = append(streams, st)
	}

	return streams, nil
}

// UpdateStreamScheme moves the stream's digest pin to scheme, applying from
// sequence since.
func (s *Store) UpdateStreamScheme(ctx context.Context, streamID id.ID, scheme string, since uint64) error {
	tx, err := s.pg.BeginTxQuery(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var current string
	if scanErr := tx.NewRaw("SELECT scheme FROM chronicle_streams WHERE id=$1 FOR UPDATE", streamID.String()).Scan(ctx, &current); scanErr != nil {
		return groveError(scanErr, chronicle.ErrStreamNotFound)
	}
	if chash.Rank(chash.Scheme(scheme)) < chash.Rank(chash.Scheme(current)) {
		return chronicle.ErrSchemeWeakeningRefused
	}
	if current == scheme {
		return nil
	}
	if _, err = tx.NewRaw("UPDATE chronicle_streams SET scheme=$1,scheme_since=GREATEST($2,head_seq+1),updated_at=NOW() WHERE id=$3", scheme, safeInt64(since), streamID.String()).Exec(ctx); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateStreamHead ignores late writers and rejects conflicting equal positions.
func (s *Store) UpdateStreamHead(ctx context.Context, streamID id.ID, hash string, seq uint64) error {
	tx, err := s.pg.BeginTxQuery(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var currentSeq int64
	var currentHash string
	if scanErr := tx.NewRaw("SELECT head_seq,head_hash FROM chronicle_streams WHERE id=$1 FOR UPDATE", streamID.String()).Scan(ctx, &currentSeq, &currentHash); scanErr != nil {
		return groveError(scanErr, chronicle.ErrStreamNotFound)
	}
	if safeInt64(seq) < currentSeq {
		return nil
	}
	if safeInt64(seq) == currentSeq {
		if hash != currentHash {
			return acceptance.ErrHeadConflict
		}
		return nil
	}
	if _, err = tx.NewRaw("UPDATE chronicle_streams SET head_seq=$1,head_hash=$2,updated_at=NOW() WHERE id=$3", safeInt64(seq), hash, streamID.String()).Exec(ctx); err != nil {
		return err
	}
	return tx.Commit()
}
