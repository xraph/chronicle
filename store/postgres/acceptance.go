package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
)

// Accept commits stream creation, pin, event, head and receipt in one transaction.
func (s *Store) Accept(ctx context.Context, request acceptance.Request, h *hash.Chain, prepare func(*audit.Event) error) (*acceptance.Receipt, error) {
	r, fp, err := acceptance.Normalize(request)
	if err != nil {
		return nil, err
	}
	tx, err := s.pg.BeginTxQuery(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	identity := acceptance.Identity(r)
	// Hash collisions only serialize unrelated callers. Full identity remains
	// the primary key and every recovered receipt checks its content binding.
	if _, err = tx.NewRaw("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", identity).Exec(ctx); err != nil {
		return nil, err
	}
	var raw string
	err = tx.NewRaw("SELECT receipt FROM chronicle_acceptances WHERE source_identity=$1", identity).Scan(ctx, &raw)
	if err == nil {
		var receipt acceptance.Receipt
		if decodeErr := json.Unmarshal([]byte(raw), &receipt); decodeErr != nil {
			return nil, decodeErr
		}
		return acceptance.Match(&receipt, fp)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if h == nil {
		return nil, acceptance.ErrInvalid
	}
	e := r.Event
	e.ExactMetadata = true
	if _, err = tx.NewRaw(`INSERT INTO chronicle_streams (id,app_id,tenant_id,scheme,scheme_since) VALUES ($1,$2,$3,$4,1) ON CONFLICT (app_id,tenant_id) DO NOTHING`, id.NewStreamID().String(), e.AppID, e.TenantID, string(h.Scheme())).Exec(ctx); err != nil {
		return nil, err
	}
	var streamID string
	if scanErr := tx.NewRaw("SELECT id FROM chronicle_streams WHERE app_id=$1 AND tenant_id=$2 FOR UPDATE", e.AppID, e.TenantID).Scan(ctx, &streamID); scanErr != nil {
		return nil, scanErr
	}
	e.StreamID, err = id.ParseStreamID(streamID)
	if err != nil {
		return nil, err
	}
	e.ID = id.NewAuditID()
	if prepare != nil {
		if sealErr := prepare(e); sealErr != nil {
			return nil, sealErr
		}
	}
	if appendErr := s.appendInTx(ctx, tx, e, h); appendErr != nil {
		return nil, appendErr
	}
	receipt := acceptance.NewReceipt(r, fp, e)
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	if _, err = tx.NewRaw("INSERT INTO chronicle_acceptances (source_identity,receipt) VALUES ($1,$2::jsonb)", identity, string(encoded)).Exec(ctx); err != nil {
		return nil, fmt.Errorf("insert acceptance: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return receipt, nil
}
