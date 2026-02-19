package erasure

import (
	"context"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/id"
)

// Service performs GDPR crypto-erasure operations.
type Service struct {
	store    Store
	keyStore crypto.KeyStore
}

// NewService creates a new erasure Service.
func NewService(store Store, keyStore crypto.KeyStore) *Service {
	return &Service{
		store:    store,
		keyStore: keyStore,
	}
}

// Erase performs a GDPR erasure for a subject:
// 1. Count events affected
// 2. Delete the subject's encryption key (making data irrecoverable)
// 3. Mark events as erased in the store
// 4. Record the erasure event
func (s *Service) Erase(ctx context.Context, input *Input, appID, tenantID string) (*Result, error) {
	// 1. Count events for subject.
	count, err := s.store.CountBySubject(ctx, input.SubjectID)
	if err != nil {
		return nil, err
	}

	// 2. Delete the encryption key.
	keyDestroyed := false
	delErr := s.keyStore.Delete(input.SubjectID)
	if delErr == nil {
		keyDestroyed = true
	}

	// 3. Create erasure record.
	erasureID := id.NewErasureID()
	rec := &Erasure{
		Entity:         chronicle.NewEntity(),
		ID:             erasureID,
		SubjectID:      input.SubjectID,
		Reason:         input.Reason,
		RequestedBy:    input.RequestedBy,
		EventsAffected: count,
		KeyDestroyed:   keyDestroyed,
		AppID:          appID,
		TenantID:       tenantID,
	}

	err = s.store.RecordErasure(ctx, rec)
	if err != nil {
		return nil, err
	}

	// 4. Mark events as erased.
	affected, err := s.store.MarkErased(ctx, input.SubjectID, erasureID)
	if err != nil {
		return nil, err
	}

	return &Result{
		ID:             erasureID,
		SubjectID:      input.SubjectID,
		EventsAffected: affected,
		KeyDestroyed:   keyDestroyed,
	}, nil
}
