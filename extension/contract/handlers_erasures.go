package contract

import (
	"context"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
)

// defaultErasureListLimit and maxErasureListLimit are the erasure list's page
// size and cap. See pageBounds for how a limit and offset are treated.
const (
	defaultErasureListLimit = 50
	maxErasureListLimit     = 1000
)

// ErasureSummary is one erasure record as the dashboard reads it: the
// evidence that a data subject's right to erasure was honoured.
type ErasureSummary struct {
	ID             string `json:"id"`
	SubjectID      string `json:"subjectId"`
	Reason         string `json:"reason"`
	RequestedBy    string `json:"requestedBy"`
	EventsAffected int64  `json:"eventsAffected"`
	KeyDestroyed   bool   `json:"keyDestroyed"`
	CreatedAt      string `json:"createdAt"`
}

// ErasureListInput pages through the viewer's own scope's erasure records.
// There is deliberately no appId or tenantId field: scope comes from the
// principal, through scopeFromPrincipal, and never from the request.
type ErasureListInput struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// ErasureListResponse is one page of erasure records. Total comes from
// CountErasures, never from len(Erasures): that method exists precisely so
// a caller wanting a total does not have to count a bounded list, and the
// page caption would understate the real count on every page after the
// first if it did.
type ErasureListResponse struct {
	Erasures []ErasureSummary `json:"erasures"`
	Total    int64            `json:"total"`
	HasMore  bool             `json:"hasMore"`
}

// GetErasureInput names one erasure record by ID.
type GetErasureInput struct {
	ID string `json:"id"`
}

// ErasurePreviewInput names the subject a prospective erasure would target.
type ErasurePreviewInput struct {
	SubjectID string `json:"subjectId"`
}

// ErasurePreviewResponse is the count a confirm dialog shows before an
// erasure command fires.
//
// EventsAffected covers only the viewer's own scope: it comes from
// CountBySubject scoped to the caller's app and tenant, which is the most
// this contract is allowed to reveal about another tenant's data. A subject
// ID is not unique to one app or tenant, and crypto.KeyStore currently keys
// its encryption key by subject ID alone, so an actual erasure for this
// subject would destroy a key shared with every other app or tenant using
// the same subject ID. Until that is fixed, this count understates what an
// erasure would really destroy.
type ErasurePreviewResponse struct {
	SubjectID      string `json:"subjectId"`
	EventsAffected int64  `json:"eventsAffected"`
}

func erasuresRegistrations() []registration {
	return []registration{
		query("erasures.list", erasuresListHandler),
		query("erasures.detail", erasuresDetailHandler),
		query("erasures.preview", erasuresPreviewHandler),
	}
}

// projectErasureSummary turns a stored erasure record into its wire summary.
func projectErasureSummary(e *erasure.Erasure) ErasureSummary {
	return ErasureSummary{
		ID:             e.ID.String(),
		SubjectID:      e.SubjectID,
		Reason:         e.Reason,
		RequestedBy:    e.RequestedBy,
		EventsAffected: e.EventsAffected,
		KeyDestroyed:   e.KeyDestroyed,
		CreatedAt:      formatTime(e.CreatedAt),
	}
}

func erasuresListHandler(deps Deps) func(context.Context, ErasureListInput, fcontract.Principal) (ErasureListResponse, error) {
	return func(ctx context.Context, in ErasureListInput, p fcontract.Principal) (ErasureListResponse, error) {
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return ErasureListResponse{}, err
		}

		limit, offset, err := pageBounds(in.Limit, in.Offset, defaultErasureListLimit, maxErasureListLimit)
		if err != nil {
			return ErasureListResponse{}, err
		}

		scope := erasure.Scope{AppID: v.AppID, TenantID: v.TenantID}

		// erasure.Scope's own doc says a zero Scope matches every app and
		// tenant, and Chronicle's stores treat an empty AppID as matching
		// everything, so AppID and TenantID are stamped by hand on both
		// calls below rather than left to whatever the request carried --
		// there is no appId or tenantId field on ErasureListInput to carry
		// one.
		total, err := deps.Store.CountErasures(ctx, scope)
		if err != nil {
			return ErasureListResponse{}, deps.mapStoreError("erasures.list", err)
		}

		list, err := deps.Store.ListErasures(ctx, erasure.ListOpts{
			Scope:  scope,
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			return ErasureListResponse{}, deps.mapStoreError("erasures.list", err)
		}

		out := ErasureListResponse{
			Erasures: make([]ErasureSummary, 0, len(list)),
			Total:    total,
			HasMore:  int64(offset+len(list)) < total,
		}
		for _, e := range list {
			if e == nil {
				continue
			}
			out.Erasures = append(out.Erasures, projectErasureSummary(e))
		}
		return out, nil
	}
}

func erasuresDetailHandler(deps Deps) func(context.Context, GetErasureInput, fcontract.Principal) (ErasureSummary, error) {
	return func(ctx context.Context, in GetErasureInput, p fcontract.Principal) (ErasureSummary, error) {
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return ErasureSummary{}, err
		}

		erasureID, err := id.ParseErasureID(in.ID)
		if err != nil {
			// An ID that does not even parse cannot name a real erasure
			// record. Answering the same NOT_FOUND as a real miss tells a
			// prober nothing about which is true, and the store is never
			// touched.
			return ErasureSummary{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		e, err := deps.Store.GetErasure(ctx, erasureID)
		if err != nil {
			return ErasureSummary{}, deps.mapStoreError("erasures.detail", err)
		}
		if e == nil {
			return ErasureSummary{}, errNotFound()
		}

		// Security-critical: a detail intent resolves by ID and bypasses
		// every list filter, so without this a caller could read another
		// tenant's or app's erasure record by guessing its ID. The templ
		// dashboard's renderErasureDetail carried no such check at all,
		// unlike every other detail renderer it shipped alongside; this
		// closes that gap rather than carrying it forward. CodeNotFound,
		// not CodePermissionDenied, so the answer does not confirm the ID
		// names a real record outside the caller's scope.
		if !v.owns(e.AppID, e.TenantID) {
			return ErasureSummary{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		return projectErasureSummary(e), nil
	}
}

func erasuresPreviewHandler(deps Deps) func(context.Context, ErasurePreviewInput, fcontract.Principal) (ErasurePreviewResponse, error) {
	return func(ctx context.Context, in ErasurePreviewInput, p fcontract.Principal) (ErasurePreviewResponse, error) {
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return ErasurePreviewResponse{}, err
		}

		if in.SubjectID == "" {
			return ErasurePreviewResponse{}, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: "subjectId is required"}
		}

		// CountBySubject's own doc says an implementation must honour the
		// scope, because an unscoped count reveals how much data other
		// tenants hold on this subject. The scope is stamped by hand here,
		// the same as erasures.list: SubjectQuery embeds Scope and there is
		// no field on ErasurePreviewInput a caller could use to widen it.
		count, err := deps.Store.CountBySubject(ctx, erasure.SubjectQuery{
			Scope:     erasure.Scope{AppID: v.AppID, TenantID: v.TenantID},
			SubjectID: in.SubjectID,
		})
		if err != nil {
			return ErasurePreviewResponse{}, deps.mapStoreError("erasures.preview", err)
		}

		return ErasurePreviewResponse{SubjectID: in.SubjectID, EventsAffected: count}, nil
	}
}
