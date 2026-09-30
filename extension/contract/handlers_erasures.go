package contract

import (
	"context"
	"errors"
	"unicode"
	"unicode/utf8"

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
//
// Status is "pending" or "completed". A pending erasure did not finish: its
// events may be marked and some of its keys may be gone, but KeyDestroyed is
// false because not every key is confirmed destroyed. The page should say so
// and point the operator at running the erasure again, which finishes it
// under a new record. Records from before erasures had a status read as
// completed.
//
// LegacyKeyRetained means the same as on ErasureResult. Both fields are
// always on the wire, false and "completed" included, for the same reason.
type ErasureSummary struct {
	ID                string `json:"id"`
	SubjectID         string `json:"subjectId"`
	Reason            string `json:"reason"`
	RequestedBy       string `json:"requestedBy"`
	EventsAffected    int64  `json:"eventsAffected"`
	KeyDestroyed      bool   `json:"keyDestroyed"`
	Status            string `json:"status"`
	LegacyKeyRetained bool   `json:"legacyKeyRetained"`
	CreatedAt         string `json:"createdAt"`
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
// ID is not unique to one app or tenant, and an erasure is confined to the
// viewer's scope the same way, so this is the number erasures.request will
// report as eventsAffected.
type ErasurePreviewResponse struct {
	SubjectID      string `json:"subjectId"`
	EventsAffected int64  `json:"eventsAffected"`
}

// Bounds on an erasures.request. Both count runes, not bytes, so a subject ID
// or reason in a non-Latin script is not cut short by its encoding.
const (
	maxErasureSubjectLen = 256
	maxErasureReasonLen  = 2000
)

// RequestErasureInput is what an operator supplies to erase a data subject.
// There is no requestedBy field, and no appId or tenantId: who asked comes
// from the session and where it runs comes from scopeFromPrincipal, so
// neither can be named by the request.
type RequestErasureInput struct {
	SubjectID string `json:"subjectId"`
	Reason    string `json:"reason"`
}

// ErasureResult is the outcome of erasures.request, for the page to report.
//
// EventsAffected is how many of the subject's events in the viewer's own app
// and tenant were marked erased. Nothing outside that scope is counted or
// touched.
//
// KeyDestroyed is true when the encryption key or keys those events were
// sealed under are gone, which is what makes the payload unrecoverable.
//
// LegacyKeyRetained is true only alongside KeyDestroyed false. It means the
// events are marked erased and no read path shows their payload, but they
// were sealed before keys were scoped, under a key that live events in
// another app or tenant still depend on, so the key was kept. It goes the
// first time an erasure finds no other scope still using it, and running the
// erasure again later is how it is cleaned up. The page should say the
// erasure is not yet cryptographic when it sees this.
//
// LegacyKeyRetained is always on the wire, false included: a page cannot
// tell "not retained" from "an older server that never said" if the field
// disappears when false.
type ErasureResult struct {
	ID                string `json:"id"`
	SubjectID         string `json:"subjectId"`
	EventsAffected    int64  `json:"eventsAffected"`
	KeyDestroyed      bool   `json:"keyDestroyed"`
	LegacyKeyRetained bool   `json:"legacyKeyRetained"`
}

func erasuresRegistrations() []registration {
	return []registration{
		query("erasures.list", erasuresListHandler),
		query("erasures.detail", erasuresDetailHandler),
		query("erasures.preview", erasuresPreviewHandler),
		command("erasures.request", erasuresRequestHandler),
	}
}

// projectErasureSummary turns a stored erasure record into its wire summary.
func projectErasureSummary(e *erasure.Erasure) ErasureSummary {
	status := erasure.StatusCompleted
	if e.Pending() {
		status = erasure.StatusPending
	}
	return ErasureSummary{
		ID:                e.ID.String(),
		SubjectID:         e.SubjectID,
		Reason:            e.Reason,
		RequestedBy:       e.RequestedBy,
		EventsAffected:    e.EventsAffected,
		KeyDestroyed:      e.KeyDestroyed,
		Status:            string(status),
		LegacyKeyRetained: e.LegacyKeyRetained,
		CreatedAt:         formatTime(e.CreatedAt),
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

// errNilErasureResult is what erasures.request logs when the service answers
// with neither a result nor an error. It maps to a generic internal error, so
// a caller is never told an erasure succeeded on the strength of no answer.
var errNilErasureResult = errors.New("erasure service returned no result and no error")

// erasureRequestRefusal is a CodeBadRequest for an erasures.request.
func erasureRequestRefusal(msg string) error {
	return &fcontract.Error{Code: fcontract.CodeBadRequest, Message: msg}
}

// checkErasureSubjectID refuses a subject ID that cannot be a real one. The
// ID is compared exactly and used to derive an encryption key ID, so a value
// with edge whitespace or a control character would name a subject that looks
// like the real one on every page and matches none of its events. It is
// refused rather than trimmed, the same rule a policy category follows.
func checkErasureSubjectID(subjectID string) error {
	if subjectID == "" {
		return erasureRequestRefusal("subjectId is required")
	}
	if !utf8.ValidString(subjectID) {
		return erasureRequestRefusal("subjectId is not valid UTF-8")
	}
	if utf8.RuneCountInString(subjectID) > maxErasureSubjectLen {
		return erasureRequestRefusal("subjectId is longer than 256 characters")
	}
	for _, r := range subjectID {
		if unicode.Is(unicode.Cc, r) {
			return erasureRequestRefusal("subjectId contains a control character")
		}
	}
	first, _ := utf8.DecodeRuneInString(subjectID)
	last, _ := utf8.DecodeLastRuneInString(subjectID)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return erasureRequestRefusal("subjectId has leading or trailing whitespace; it is compared exactly, so remove it")
	}
	return nil
}

// checkErasureReason refuses a reason that is empty, all whitespace, too long,
// or carries a control character other than a newline. The reason is stored
// as evidence and shown on the erasure record, and a paragraph is a normal
// thing to write there, so newlines stay; nothing else that can hide or
// reshape text is allowed. It is stored as written, never trimmed.
func checkErasureReason(reason string) error {
	if !utf8.ValidString(reason) {
		return erasureRequestRefusal("reason is not valid UTF-8")
	}
	blank := true
	for _, r := range reason {
		if !unicode.IsSpace(r) {
			blank = false
		}
		if r != '\n' && unicode.Is(unicode.Cc, r) {
			return erasureRequestRefusal("reason contains a control character other than a newline")
		}
	}
	if blank {
		return erasureRequestRefusal("reason is required")
	}
	if utf8.RuneCountInString(reason) > maxErasureReasonLen {
		return erasureRequestRefusal("reason is longer than 2000 characters")
	}
	return nil
}

// erasureScope returns the app and tenant an erasure may run in, and refuses
// a scope with no app. Chronicle's stores read an empty AppID as every app,
// and Service.Erase counts, marks and destroys keys by that same rule, so an
// empty one here would erase the subject in every app at once.
// scopeFromPrincipal cannot produce one; this is the last check before the
// call that would act on it, and it does not rely on that staying true.
func erasureScope(v viewScope) (appID, tenantID string, err error) {
	if v.AppID == "" {
		return "", "", &fcontract.Error{
			Code:    fcontract.CodePermissionDenied,
			Message: "no app scope on this session: an erasure with no app would cover every app",
		}
	}
	return v.AppID, v.TenantID, nil
}

// erasuresRequestHandler erases a data subject in the viewer's own app and
// tenant: it destroys the subject's encryption keys there and marks their
// events erased. It cannot be undone.
func erasuresRequestHandler(deps Deps) func(context.Context, RequestErasureInput, fcontract.Principal) (ErasureResult, error) {
	return func(ctx context.Context, in RequestErasureInput, p fcontract.Principal) (ErasureResult, error) {
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return ErasureResult{}, err
		}

		// Erasure needs the service, which the extension builds only when
		// crypto-erasure is on. Without it nothing was encrypted under a key
		// that could be destroyed, so there is nothing this command can honour.
		if deps.Erasure == nil {
			return ErasureResult{}, &fcontract.Error{
				Code: fcontract.CodeUnavailable,
				Message: "erasure is not enabled on this deployment: set chronicle.enable_crypto_erasure " +
					"to true and give the extension a key store",
			}
		}

		if err := checkErasureSubjectID(in.SubjectID); err != nil {
			return ErasureResult{}, err
		}
		if err := checkErasureReason(in.Reason); err != nil {
			return ErasureResult{}, err
		}

		appID, tenantID, err := erasureScope(v)
		if err != nil {
			return ErasureResult{}, err
		}

		// Security-critical: the scope handed to Erase is the viewer's and
		// nothing else, and RequestedBy is the signed-in user, never a field
		// of the request. Erase is the one call in this contract that destroys
		// data outside the store's own scoping rules if given a wider scope.
		res, err := deps.Erasure.Erase(ctx, &erasure.Input{
			SubjectID:   in.SubjectID,
			Reason:      in.Reason,
			RequestedBy: p.User.Subject,
		}, appID, tenantID)
		if err != nil {
			return ErasureResult{}, deps.mapStoreError("erasures.request", err)
		}
		if res == nil {
			return ErasureResult{}, deps.mapStoreError("erasures.request", errNilErasureResult)
		}

		return ErasureResult{
			ID:                res.ID.String(),
			SubjectID:         res.SubjectID,
			EventsAffected:    res.EventsAffected,
			KeyDestroyed:      res.KeyDestroyed,
			LegacyKeyRetained: res.LegacyKeyRetained,
		}, nil
	}
}
