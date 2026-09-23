package contract

import (
	"context"
	"errors"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// MineInput is empty: there is exactly one stream per app and tenant, so the
// chain resolves from scope and cannot be named by the caller.
type MineInput struct{}

// MineResponse carries a nil Stream when this scope has never recorded an
// event, which is a real and common state rather than an error. Chronicle
// creates a stream lazily on the first Record.
type MineResponse struct {
	Stream *StreamSummary `json:"stream,omitempty"`
}

// StreamListInput pages through the chains the viewer owns.
type StreamListInput struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// StreamListResponse is one page of the viewer's chains. Total counts every
// chain the viewer owns, not every chain in the store.
type StreamListResponse struct {
	Streams []StreamSummary `json:"streams"`
	Total   int64           `json:"total"`
	HasMore bool            `json:"hasMore"`
}

const (
	defaultStreamListLimit = 50
	maxStreamListLimit     = 200

	// streamScanBatch is how many streams streams.list reads from the store
	// per round trip while it filters them down to the viewer's own.
	streamScanBatch = 200
)

func streamsRegistrations() []registration {
	return []registration{
		query("streams.mine", streamsMineHandler),
		query("streams.list", streamsListHandler),
	}
}

func streamsMineHandler(deps Deps) func(context.Context, MineInput, fcontract.Principal) (MineResponse, error) {
	return func(ctx context.Context, _ MineInput, p fcontract.Principal) (MineResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return MineResponse{}, err
		}

		st, err := deps.Store.GetStreamByScope(ctx, v.AppID, v.TenantID)
		if err != nil {
			if errors.Is(err, chronicle.ErrStreamNotFound) {
				// No events recorded yet in this scope. Not an error.
				return MineResponse{}, nil
			}
			return MineResponse{}, mapStoreError(err)
		}
		if st == nil {
			// A store that answers a miss with (nil, nil) rather than
			// ErrStreamNotFound means the same thing.
			return MineResponse{}, nil
		}

		// GetStreamByScope matches on both columns exactly, so this cannot
		// fail today. It is here so that a backend that ever widens that
		// match fails closed instead of handing over another scope's chain.
		if st.AppID != v.AppID || st.TenantID != v.TenantID {
			return MineResponse{}, &fcontract.Error{Code: fcontract.CodeInternal, Message: "the audit store returned a chain outside this scope"}
		}

		summary, err := projectStream(ctx, deps, st)
		if err != nil {
			return MineResponse{}, err
		}
		return MineResponse{Stream: summary}, nil
	}
}

// streamsListHandler lists the chains inside the viewer's own scope.
//
// The store cannot do the filtering. stream.Store.ListStreams takes only a
// limit and an offset and returns every app's chains, so this handler reads
// the store in batches, keeps what the viewer owns, and pages over that. The
// page, the total and hasMore all describe the viewer's chains alone; paging
// over the store's own offsets would leak how many chains other apps hold.
func streamsListHandler(deps Deps) func(context.Context, StreamListInput, fcontract.Principal) (StreamListResponse, error) {
	return func(ctx context.Context, in StreamListInput, p fcontract.Principal) (StreamListResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return StreamListResponse{}, err
		}

		if in.Limit < 0 || in.Offset < 0 {
			return StreamListResponse{}, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: "limit and offset cannot be negative"}
		}
		limit := in.Limit
		if limit == 0 {
			limit = defaultStreamListLimit
		}
		if limit > maxStreamListLimit {
			limit = maxStreamListLimit
		}

		page, total, err := scanOwnedStreams(ctx, deps.Store, v, in.Offset, limit)
		if err != nil {
			return StreamListResponse{}, err
		}

		out := StreamListResponse{
			Streams: make([]StreamSummary, 0, len(page)),
			Total:   total,
			HasMore: int64(in.Offset+len(page)) < total,
		}
		for _, st := range page {
			summary, err := projectStream(ctx, deps, st)
			if err != nil {
				return StreamListResponse{}, err
			}
			out.Streams = append(out.Streams, *summary)
		}
		return out, nil
	}
}

// scanOwnedStreams walks every stream in the store, keeping the ones v owns.
// It returns the owned streams at [offset, offset+limit) and the count of all
// owned streams.
//
// It tracks the IDs it has seen and stops on a batch that adds nothing new.
// Without that, a store whose offset handling misbehaves past the end (the
// in-memory store returns everything again when the offset reaches its
// length) would keep answering full batches and loop forever.
func scanOwnedStreams(ctx context.Context, s stream.Store, v viewScope, offset, limit int) ([]*stream.Stream, int64, error) {
	var (
		page  []*stream.Stream
		total int64
		seen  = map[string]struct{}{}
	)

	for storeOffset := 0; ; storeOffset += streamScanBatch {
		batch, err := s.ListStreams(ctx, stream.ListOpts{Limit: streamScanBatch, Offset: storeOffset})
		if err != nil {
			return nil, 0, mapStoreError(err)
		}

		fresh := 0
		for _, st := range batch {
			if st == nil {
				continue
			}
			key := st.ID.String()
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			fresh++

			if !v.owns(st.AppID, st.TenantID) {
				continue
			}
			if total >= int64(offset) && len(page) < limit {
				page = append(page, st)
			}
			total++
		}

		if len(batch) < streamScanBatch || fresh == 0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, 0, mapStoreError(err)
		}
	}

	return page, total, nil
}

// coverageCeiling is the best level verification could report for this chain
// without walking it: keyed if the chain is pinned to a keyed scheme, signed
// if this deployment also holds checkpoints and a signer to check them under.
//
// Signed does not require a keyed chain. verify.Verifier raises any span at
// or above the stream's pin to LevelSigned once a valid checkpoint covers it,
// whatever the scheme, and extension.go wires checkpoint verification
// independently of the digest because a signature over an unkeyed chain
// still makes a later rewrite provable. A ceiling below what verification
// then reports would read as a contradiction on the page.
//
// It never returns anchored. Nothing in chronicle emits LevelAnchored yet;
// external anchoring is the next piece of work, and claiming it here would be
// the exact overstatement this field exists to prevent.
func coverageCeiling(deps Deps, st *stream.Stream) string {
	level := verify.LevelUnkeyed
	if hash.Keyed(hash.Scheme(st.Scheme)) {
		level = verify.LevelKeyed
	}
	if deps.checkpointingConfigured() {
		level = verify.LevelSigned
	}
	return string(level)
}
