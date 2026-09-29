package contract

import (
	"context"
	"errors"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

const (
	defaultCheckpointListLimit = 50
	maxCheckpointListLimit     = 200
)

// GetCheckpointInput names one checkpoint by ID.
type GetCheckpointInput struct {
	ID string `json:"id"`
}

// GetCheckpointResponse is one checkpoint, projected the same way every other
// checkpoint reference on the wire is (see CheckpointSummary in project.go).
type GetCheckpointResponse struct {
	Checkpoint CheckpointSummary `json:"checkpoint"`
}

// CheckpointListInput pages through one chain's checkpoints.
//
// StreamID empty means the viewer's own chain (its exact app and tenant). An
// app-wide viewer passes a tenant's chain ID, taken from streams.list, to
// list that tenant's checkpoints. A chain the viewer does not own answers
// NOT_FOUND.
type CheckpointListInput struct {
	StreamID string `json:"streamId,omitempty"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
}

// TakeCheckpointInput optionally names the chain to checkpoint. Empty means
// the viewer's own chain; see CheckpointListInput for what a StreamID is.
type TakeCheckpointInput struct {
	StreamID string `json:"streamId,omitempty"`
}

// CheckpointListResponse is one page of the viewer's chain's checkpoints.
//
// RULING 1: there is deliberately no Total field. checkpoint.ListOpts is
// {Limit, Offset} and checkpoint.Store has no count method, so a real total
// could only be produced by scanning every checkpoint the chain holds on
// every call to this intent. HasMore is computed instead, by asking the
// store for one row past the requested page and trimming it off below: that
// costs nothing beyond what the page already reads, unlike a count.
type CheckpointListResponse struct {
	Checkpoints []CheckpointSummary `json:"checkpoints"`
	HasMore     bool                `json:"hasMore"`

	// Supported distinguishes two different reasons a list can come back
	// empty. False means this deployment cannot answer checkpoint questions
	// at all: no store or signer configured (checkpointsAvailable), or a
	// backend that holds no checkpoints by design, such as redis, which
	// implements checkpoint.Store and answers every call with
	// checkpoint.ErrUnsupported. True with an empty Checkpoints means
	// checkpointing works here and this particular chain simply has none
	// yet. The page needs to tell an operator "this backend holds none"
	// apart from "none yet", and Supported is the only field that can.
	Supported bool `json:"supported"`
}

// TakeCheckpointResponse is the result of checkpoints.take.
//
// RULING 2: taking a checkpoint over a stream that gained nothing since its
// last one, or losing a race to a concurrent checkpointer that already
// landed at the same sequence, are both ordinary outcomes on a healthy
// deployment, not failures -- see checkpoint.ErrNothingToCheckpoint and
// checkpoint.ErrExists. Both come back here as UpToDate true with a nil
// Checkpoint and no error, rather than as CodeInternal, which would alarm an
// operator over a normal no-op.
type TakeCheckpointResponse struct {
	Checkpoint *CheckpointSummary `json:"checkpoint,omitempty"`
	UpToDate   bool               `json:"upToDate"`
}

func checkpointsRegistrations() []registration {
	return []registration{
		query("checkpoints.list", checkpointsListHandler),
		query("checkpoints.detail", checkpointsDetailHandler),
		// RULING 3: write, not admin, and no `requires` predicate. Taking a
		// checkpoint creates a record and destroys nothing; it is the one
		// write in this contributor that makes a future verification
		// stronger rather than weaker.
		command("checkpoints.take", checkpointsTakeHandler),
	}
}

// checkpointsAvailable reports whether this deployment can answer checkpoint
// questions at all. Nil store or nil signer both mean no: a store without a
// signer cannot prove a checkpoint is genuine, so reporting its rows would
// present unverifiable data as evidence.
//
// This is a static, configuration-level check. It says nothing about
// whether the configured store actually accepts checkpoint calls at
// runtime -- that is what checkpoint.ErrUnsupported reports, from an actual
// call, and the two are deliberately different mechanisms: redis satisfies
// this check (it implements checkpoint.Store) but still refuses every call.
func checkpointsAvailable(deps Deps) bool {
	return deps.CheckpointStore != nil && deps.CheckpointSigner != nil
}

func checkpointsListHandler(deps Deps) func(context.Context, CheckpointListInput, fcontract.Principal) (CheckpointListResponse, error) {
	return func(ctx context.Context, in CheckpointListInput, p fcontract.Principal) (CheckpointListResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return CheckpointListResponse{}, err
		}

		if in.Limit < 0 || in.Offset < 0 {
			return CheckpointListResponse{}, &fcontract.Error{
				Code: fcontract.CodeBadRequest, Message: "limit and offset cannot be negative",
			}
		}

		// Deliberately checked before touching either store: an unconfigured
		// deployment (deps.CheckpointStore or deps.CheckpointSigner nil)
		// answers Supported:false with no store call at all, the same as
		// TestCheckpointsListWithNoStoreConfigured requires.
		if !checkpointsAvailable(deps) {
			return CheckpointListResponse{}, nil
		}

		limit := in.Limit
		if limit == 0 {
			limit = defaultCheckpointListLimit
		}
		if limit > maxCheckpointListLimit {
			limit = maxCheckpointListLimit
		}

		// A scope with no chain yet has no stream ID to list checkpoints
		// under. id.Nil stands in for it: a backend that actually supports
		// checkpoints answers a query for a nonexistent stream ID with zero
		// rows and no error, the same result this scope would get once it
		// does have a chain with no checkpoints yet, while a backend that
		// refuses every call (redis) answers ErrUnsupported regardless of
		// which ID it was asked about. Either way the single call below
		// gives the right answer without a special case for "no chain".
		streamID := id.Nil
		st, err := selectStream(ctx, deps, "checkpoints.list", v, in.StreamID)
		if err != nil {
			return CheckpointListResponse{}, err
		}
		if st != nil {
			streamID = st.ID
		}

		// Ask for one row past the requested page; RULING 1's HasMore, not a
		// Total, is what that extra row is for.
		cps, err := deps.CheckpointStore.ListCheckpoints(ctx, streamID, checkpoint.ListOpts{
			Limit: limit + 1, Offset: in.Offset,
		})
		if err != nil {
			if errors.Is(err, checkpoint.ErrUnsupported) {
				return CheckpointListResponse{}, nil
			}
			return CheckpointListResponse{}, deps.mapStoreError("checkpoints.list", err)
		}

		out := CheckpointListResponse{Supported: true}
		if len(cps) > limit {
			out.HasMore = true
			cps = cps[:limit]
		}
		out.Checkpoints = make([]CheckpointSummary, 0, len(cps))
		for _, cp := range cps {
			out.Checkpoints = append(out.Checkpoints, *projectCheckpoint(cp))
		}
		return out, nil
	}
}

func checkpointsDetailHandler(deps Deps) func(context.Context, GetCheckpointInput, fcontract.Principal) (GetCheckpointResponse, error) {
	return func(ctx context.Context, in GetCheckpointInput, p fcontract.Principal) (GetCheckpointResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return GetCheckpointResponse{}, err
		}

		// No store or signer configured: there is nothing this deployment
		// could ever have signed, so the honest answer is the same NOT_FOUND
		// a real miss gets, not a different error that would tell a prober
		// checkpointing exists but is switched off.
		if !checkpointsAvailable(deps) {
			return GetCheckpointResponse{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		cpID, err := id.ParseCheckpointID(in.ID)
		if err != nil {
			// An ID that does not even parse cannot name a real checkpoint.
			// Answering the same NOT_FOUND as a real miss tells a prober
			// nothing about which is true.
			return GetCheckpointResponse{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		cp, err := deps.CheckpointStore.GetCheckpoint(ctx, cpID)
		switch {
		case err == nil:
			// fall through
		case errors.Is(err, checkpoint.ErrNotFound), errors.Is(err, checkpoint.ErrUnsupported):
			return GetCheckpointResponse{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		default:
			return GetCheckpointResponse{}, deps.mapStoreError("checkpoints.detail", err)
		}

		// Security-critical: a checkpoint fetched by ID bypasses every list
		// filter, so without this a caller could read another tenant's
		// checkpoint by guessing its ID. CodeNotFound, not
		// CodePermissionDenied, so the answer does not confirm the ID names
		// a real record outside the caller's scope.
		if !v.owns(cp.AppID, cp.TenantID) {
			return GetCheckpointResponse{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		// Also confirm the checkpoint belongs to the chain its own scope
		// resolves to, the same collision guard scopedStream carries for a
		// chain fetched by scope (store/redis builds its scope key as
		// appID + ":" + tenantID, so distinct scopes can collide on it). The
		// scope is the record's, not the viewer's, so an app-wide viewer can
		// read a tenant's checkpoint, as verify.event does for an event.
		// Cheap: every app/tenant pair owns exactly one stream, so this is
		// one more scope-keyed lookup, not a scan.
		st, err := scopedStream(ctx, deps, "checkpoints.detail", viewScope{AppID: cp.AppID, TenantID: cp.TenantID})
		if err != nil {
			return GetCheckpointResponse{}, err
		}
		if st == nil || st.ID != cp.StreamID {
			return GetCheckpointResponse{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		return GetCheckpointResponse{Checkpoint: *projectCheckpoint(cp)}, nil
	}
}

func checkpointsTakeHandler(deps Deps) func(context.Context, TakeCheckpointInput, fcontract.Principal) (TakeCheckpointResponse, error) {
	return func(ctx context.Context, in TakeCheckpointInput, p fcontract.Principal) (TakeCheckpointResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return TakeCheckpointResponse{}, err
		}

		if deps.Checkpointer == nil {
			return TakeCheckpointResponse{}, &fcontract.Error{
				Code:    fcontract.CodeUnavailable,
				Message: "this deployment takes no checkpoints",
			}
		}

		st, err := selectStream(ctx, deps, "checkpoints.take", v, in.StreamID)
		if err != nil {
			return TakeCheckpointResponse{}, err
		}
		if st == nil {
			return TakeCheckpointResponse{}, &fcontract.Error{
				Code:    fcontract.CodeNotFound,
				Message: "this scope has not recorded any events yet, so there is nothing to checkpoint",
			}
		}

		// The head comes off the stream row scopedStream just resolved,
		// never from the request: a caller that could name its own head
		// could sign a checkpoint asserting whatever it liked.
		cp, err := deps.Checkpointer.CheckpointStream(ctx, checkpoint.StreamHead{
			ID:       st.ID,
			AppID:    st.AppID,
			TenantID: st.TenantID,
			HeadSeq:  st.HeadSeq,
			HeadHash: st.HeadHash,
		})
		if err != nil {
			// RULING 2: both are ordinary "nothing to do" outcomes, checked
			// with errors.Is because CheckpointStream's own callers (and any
			// store implementation) may wrap them.
			if errors.Is(err, checkpoint.ErrNothingToCheckpoint) || errors.Is(err, checkpoint.ErrExists) {
				return TakeCheckpointResponse{UpToDate: true}, nil
			}
			return TakeCheckpointResponse{}, deps.mapStoreError("checkpoints.take", err)
		}

		return TakeCheckpointResponse{Checkpoint: projectCheckpoint(cp)}, nil
	}
}
