package contract

import (
	"context"
	"errors"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// MineInput optionally names one of the viewer's chains.
//
// StreamID empty means the viewer's own chain: the one for exactly the
// viewer's app and tenant. An app-wide viewer's own chain is the app-level
// one (tenant ""), which is empty when every event was recorded under a
// tenant. Such a viewer finds each tenant's chain through streams.list and
// passes its ID here. A StreamID the viewer does not own answers NOT_FOUND,
// the same as one that does not exist.
type MineInput struct {
	StreamID string `json:"streamId,omitempty"`
}

// MineResponse carries a nil Stream when the selected scope has no chain, which
// is a real and common state rather than an error. Chronicle creates a stream
// lazily on the first Record, and it keeps one per app and tenant, so an
// app-wide viewer whose events all sit under tenants has no app-level chain
// even though its tenants have chains of their own. A nil Stream says nothing
// about those; streams.list does.
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
	// per round trip while it filters an app-wide viewer's chains out of
	// every app's. It is large because on redis ListStreams loads every
	// stream and then slices, so each batch costs a full load and the scan
	// costs about N^2/streamScanBatch reads per call.
	streamScanBatch = 1000
)

func streamsRegistrations() []registration {
	return []registration{
		query("streams.mine", streamsMineHandler),
		query("streams.list", streamsListHandler),
	}
}

func streamsMineHandler(deps Deps) func(context.Context, MineInput, fcontract.Principal) (MineResponse, error) {
	return func(ctx context.Context, in MineInput, p fcontract.Principal) (MineResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return MineResponse{}, err
		}

		st, err := selectStream(ctx, deps, "streams.mine", v, in.StreamID)
		if err != nil || st == nil {
			return MineResponse{}, err
		}

		summary, err := projectStream(ctx, deps, st)
		if err != nil {
			return MineResponse{}, err
		}
		return MineResponse{Stream: summary}, nil
	}
}

// scopedStream returns the one chain for exactly v's app and tenant, or nil
// when that scope has never recorded an event.
//
// It re-checks the returned stream's scope against v and refuses a mismatch.
// GetStreamByScope is meant to match both columns exactly, but a backend can
// get that wrong: store/redis builds its scope key as appID + ":" + tenantID,
// so app "a:b" with tenant "c" and app "a" with tenant "b:c" land on the same
// key. Without this check that collision would hand one scope's chain to the
// other.
func scopedStream(ctx context.Context, deps Deps, op string, v viewScope) (*stream.Stream, error) {
	st, err := deps.Store.GetStreamByScope(ctx, v.AppID, v.TenantID)
	if err != nil {
		if errors.Is(err, chronicle.ErrStreamNotFound) {
			// No events recorded yet in this scope. Not an error.
			return nil, nil
		}
		return nil, deps.mapStoreError(op, err)
	}
	if st == nil {
		// A store that answers a miss with (nil, nil) rather than
		// ErrStreamNotFound means the same thing.
		return nil, nil
	}
	if st.AppID != v.AppID || st.TenantID != v.TenantID {
		deps.logger().Error("chronicle/contract: store returned a chain outside the requested scope",
			log.String("op", op),
			log.String("stream_id", st.ID.String()),
		)
		return nil, &fcontract.Error{Code: fcontract.CodeInternal, Message: "the audit store returned a chain outside this scope"}
	}
	return st, nil
}

// selectStream resolves the chain an intent should act on.
//
// An empty streamID means the viewer's own scope, exactly as scopedStream
// answers it, including nil for a scope that has never recorded an event.
// A non-empty streamID names one chain by ID, which is how an app-wide viewer
// reaches a tenant's chain: streams.list shows it, and the other stream
// intents take its ID. The ID is a lookup key and never a grant. A chain the
// viewer does not own (a sibling tenant's, another app's) answers NOT_FOUND,
// the same as an ID that does not parse or does not exist, so a caller cannot
// probe which chains exist. Ownership is the strict owns, so a tenant viewer
// can select only its own tenant's chain.
//
// The chosen chain is then resolved a second time through scopedStream, from
// its own app and tenant, and refused if that lands on a different row. That
// keeps the redis scope-key collision guard in force for selected chains too:
// GetStream fetches by ID and would otherwise never notice two scopes sharing
// a key.
//
// Everything downstream of a selected chain must use the chain's own scope,
// never the viewer's: an app-wide viewer's scope is not the tenant's.
func selectStream(ctx context.Context, deps Deps, op string, v viewScope, streamID string) (*stream.Stream, error) {
	if streamID == "" {
		return scopedStream(ctx, deps, op, v)
	}

	sid, err := id.ParseStreamID(streamID)
	if err != nil {
		return nil, errNotFound()
	}

	st, err := deps.Store.GetStream(ctx, sid)
	if err != nil {
		return nil, deps.mapStoreError(op, err)
	}
	if st == nil || !v.owns(st.AppID, st.TenantID) {
		return nil, errNotFound()
	}

	resolved, err := scopedStream(ctx, deps, op, viewScope{AppID: st.AppID, TenantID: st.TenantID})
	if err != nil {
		return nil, err
	}
	if resolved == nil || resolved.ID != st.ID {
		resolvedID := "none"
		if resolved != nil {
			resolvedID = resolved.ID.String()
		}
		deps.logger().Error("chronicle/contract: a selected chain does not match the chain its own scope resolves to",
			log.String("op", op),
			log.String("stream_id", st.ID.String()),
			log.String("resolved_stream_id", resolvedID),
		)
		return nil, &fcontract.Error{Code: fcontract.CodeInternal, Message: "the audit store returned a chain outside this scope"}
	}
	return st, nil
}

// streamsListHandler lists the chains inside the viewer's own scope.
//
// A tenant viewer owns at most one chain, the one GetStreamByScope returns
// for its app and tenant, so that case is answered directly with no scan.
// Only an app-wide viewer, who owns every chain in its app, needs the scan.
func streamsListHandler(deps Deps) func(context.Context, StreamListInput, fcontract.Principal) (StreamListResponse, error) {
	return func(ctx context.Context, in StreamListInput, p fcontract.Principal) (StreamListResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return StreamListResponse{}, err
		}

		limit, offset, err := pageBounds(in.Limit, in.Offset, defaultStreamListLimit, maxStreamListLimit)
		if err != nil {
			return StreamListResponse{}, err
		}

		var (
			page  []*stream.Stream
			total int64
		)
		if v.TenantID != "" {
			st, scopeErr := scopedStream(ctx, deps, "streams.list", v)
			if scopeErr != nil {
				return StreamListResponse{}, scopeErr
			}
			if st != nil {
				total = 1
				if offset == 0 {
					page = []*stream.Stream{st}
				}
			}
		} else {
			page, total, err = scanOwnedStreams(ctx, deps, v, offset, limit)
			if err != nil {
				return StreamListResponse{}, err
			}
		}

		out := StreamListResponse{
			Streams: make([]StreamSummary, 0, len(page)),
			Total:   total,
			HasMore: int64(offset+len(page)) < total,
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
// This scan is a workaround. The real fix is an app-scoped ListStreams in
// stream.Store, which does not exist: ListStreams takes only a limit and an
// offset and returns every app's chains, so the only way to page over one
// app's is to read them all and filter here. Paging over the store's own
// offsets instead would also leak how many chains other apps hold.
//
// It tracks the IDs it has seen and stops on a batch that adds nothing new,
// counting unseen rows rather than owned ones: a batch of nothing but other
// apps' chains is not the end. Tracking IDs also stops a store whose offset
// handling misbehaves past the end (the in-memory store returns everything
// again when the offset reaches its length) from looping forever.
func scanOwnedStreams(ctx context.Context, deps Deps, v viewScope, offset, limit int) ([]*stream.Stream, int64, error) {
	var (
		page  []*stream.Stream
		total int64
		seen  = map[string]struct{}{}
	)

	for storeOffset := 0; ; storeOffset += streamScanBatch {
		batch, err := deps.Store.ListStreams(ctx, stream.ListOpts{Limit: streamScanBatch, Offset: storeOffset})
		if err != nil {
			return nil, 0, deps.mapStoreError("streams.list", err)
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
			return nil, 0, deps.mapStoreError("streams.list", err)
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
// It is capped at unkeyed when the chain holds no events at or above its pin
// (HeadSeq < SchemeSince), which covers a stream with no events yet and one
// whose pin just moved with no append since. verify's gradeCoverage grades a
// range that lies wholly below the pin as unkeyed, and upgradeSpan never
// raises such a span to signed, so nothing better is reachable. An empty
// chain (HeadSeq 0) is capped the same way even with a zero pin: there is
// nothing to verify, so there is no assurance to claim.
//
// It never returns anchored. Nothing in chronicle emits LevelAnchored yet;
// external anchoring is the next piece of work, and claiming it here would be
// the exact overstatement this field exists to prevent.
func coverageCeiling(deps Deps, st *stream.Stream) string {
	if st.HeadSeq == 0 || st.HeadSeq < st.SchemeSince {
		return string(verify.LevelUnkeyed)
	}
	level := verify.LevelUnkeyed
	if hash.Keyed(hash.Scheme(st.Scheme)) {
		level = verify.LevelKeyed
	}
	if deps.checkpointingConfigured() {
		level = verify.LevelSigned
	}
	return string(level)
}
