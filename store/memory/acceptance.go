package memory

import (
	"context"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// Accept commits the event, stream and receipt under the shared store lock.
func (s *Store) Accept(ctx context.Context, request acceptance.Request, h *hash.Chain, prepare func(*audit.Event) error) (*acceptance.Receipt, error) {
	r, fp, err := acceptance.Normalize(request)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, chronicle.ErrStoreClosed
	}
	key := acceptance.Identity(r)
	if existing := s.receipts[key]; existing != nil {
		return acceptance.Match(existing, fp)
	}
	if h == nil {
		return nil, acceptance.ErrInvalid
	}
	e := r.Event
	e.ExactMetadata = true
	var st *stream.Stream
	for _, candidate := range s.streams {
		if candidate.AppID == e.AppID && candidate.TenantID == e.TenantID {
			snapshot := *candidate
			st = &snapshot
			break
		}
	}
	fresh := st == nil
	if fresh {
		st = &stream.Stream{Entity: chronicle.NewEntity(), ID: id.NewStreamID(), AppID: e.AppID, TenantID: e.TenantID}
	}
	if err := s.pin(st, h); err != nil {
		return nil, err
	}
	e.ID = id.NewAuditID()
	e.StreamID = st.ID
	if prepare != nil {
		if err := prepare(e); err != nil {
			return nil, err
		}
	}
	if err := s.link(ctx, e, st, h); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fresh {
		s.streams = append(s.streams, st)
	} else {
		for _, v := range s.streams {
			if v.ID == st.ID {
				*v = *st
				break
			}
		}
	}
	s.events = append(s.events, cloneEvent(e))
	receipt := acceptance.NewReceipt(r, fp, e)
	if s.receipts == nil {
		s.receipts = map[string]*acceptance.Receipt{}
	}
	s.receipts[key] = receipt
	return acceptance.Match(receipt, fp)
}

// AppendWithChain links a legacy event under the same lock as Accept.
func (s *Store) AppendWithChain(ctx context.Context, e *audit.Event, h *hash.Chain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return chronicle.ErrStoreClosed
	}
	for _, st := range s.streams {
		if st.ID != e.StreamID {
			continue
		}
		snapshot := *st
		if err := s.pin(&snapshot, h); err != nil {
			return err
		}
		if err := s.link(ctx, e, &snapshot, h); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		*st = snapshot
		s.events = append(s.events, cloneEvent(e))
		return nil
	}
	return chronicle.ErrStreamNotFound
}

func (s *Store) pin(st *stream.Stream, h *hash.Chain) error {
	if h == nil {
		return acceptance.ErrInvalid
	}
	if st.Scheme != "" && st.Scheme != string(hash.SchemeLegacy) && hash.Rank(hash.Scheme(st.Scheme)) == 0 {
		return acceptance.ErrInvalid
	}
	if hash.Rank(h.Scheme()) < hash.Rank(hash.Scheme(st.Scheme)) {
		return chronicle.ErrSchemeWeakeningRefused
	}
	for _, e := range s.events {
		if e.StreamID == st.ID && e.Sequence > st.HeadSeq {
			st.HeadSeq = e.Sequence
			st.HeadHash = e.Hash
		}
	}
	if st.Scheme != string(h.Scheme()) {
		st.Scheme = string(h.Scheme())
		st.SchemeSince = st.HeadSeq + 1
	}
	return nil
}

func (s *Store) link(ctx context.Context, e *audit.Event, st *stream.Stream, h *hash.Chain) error {
	e.Sequence = st.HeadSeq + 1
	e.PrevHash = st.HeadHash
	digest, key, err := h.Compute(ctx, e.PrevHash, e)
	if err != nil {
		return err
	}
	e.Hash = digest
	e.HashKeyID = key
	e.HashScheme = string(h.Scheme())
	st.HeadSeq = e.Sequence
	st.HeadHash = e.Hash
	return nil
}
