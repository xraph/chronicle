package contract

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
)

// previewCap bounds how many events retention.preview loads per policy. The
// store has no method that counts eligible events, so the preview has to
// load them, and a deployment with years of backlog would otherwise pull
// every one of them into memory to draw a number on a confirm dialog. Past
// the cap the answer is "at least this many", and the response says so.
const previewCap = 10000

// defaultArchiveListLimit and maxArchiveListLimit mirror events.list's own
// clamp, so every list in this contract pages the same way.
const (
	defaultArchiveListLimit = 50
	maxArchiveListLimit     = 1000
)

// PolicySummary is one retention policy as the dashboard reads it.
//
// Duration is Go's duration string ("720h0m0s"), which time.ParseDuration
// reads back, so the page can round-trip it through retention.savePolicy
// unchanged.
type PolicySummary struct {
	ID        string `json:"id"`
	Category  string `json:"category"`
	Duration  string `json:"duration"`
	Archive   bool   `json:"archive"`
	AppID     string `json:"appId"`
	TenantID  string `json:"tenantId,omitempty"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// PolicyListResponse is every retention policy in the viewer's scope.
//
// It is not paged. A policy is unique per (app, tenant, category), so a
// scope holds one policy per category it governs, and that set is small.
// Loading all of it is what makes Total a true count rather than the length
// of a page.
type PolicyListResponse struct {
	Policies []PolicySummary `json:"policies"`
	Total    int             `json:"total"`
}

// GetPolicyInput names one retention policy by ID.
type GetPolicyInput struct {
	ID string `json:"id"`
}

// SavePolicyInput creates or updates a retention policy.
//
// Every field is a pointer so an update can leave one alone. A plain bool
// Archive would be false on every update that did not mention it, and would
// quietly stop a policy archiving before it purges.
//
// ID absent means create: Category and Duration are then required, and the
// policy is stamped with the viewer's own app and tenant. ID present means
// update: the handler fetches the policy, checks the viewer owns it, and
// applies only the fields that were supplied. There is deliberately no
// appId or tenantId field. A policy whose scope came from the request could
// be written with an empty AppID, which the stores read as "every app", and
// the next enforcement run would purge every tenant's history.
type SavePolicyInput struct {
	ID       *string `json:"id,omitempty"`
	Category *string `json:"category,omitempty"`
	Duration *string `json:"duration,omitempty"`
	Archive  *bool   `json:"archive,omitempty"`
}

// DeletePolicyInput names the retention policy to delete.
type DeletePolicyInput struct {
	ID string `json:"id"`
}

// DeletePolicyResponse echoes the ID that was deleted.
type DeletePolicyResponse struct {
	ID string `json:"id"`
}

// PolicyPreview is what one policy would select if enforcement ran now.
//
// EventCount is capped at previewCap; Capped true means the policy selects
// at least that many. Two policies in one scope can select the same event
// (a "*" policy overlaps every category, and an app-level policy overlaps
// its tenants), so these counts can add up to more than the response's own
// EventCount, which counts each event once.
type PolicyPreview struct {
	PolicyID   string `json:"policyId"`
	Category   string `json:"category"`
	EventCount int64  `json:"eventCount"`
	Capped     bool   `json:"capped"`
}

// RetentionPreviewResponse describes the events the viewer's policies make
// eligible for purging right now, for the confirm dialog that stands in
// front of retention.enforce.
//
// The counts are eligible events, not what one enforce pass will delete.
// The preview counts up to previewCap (10,000) events per policy, and one
// pass purges at most retention.DefaultPurgeBatchSize (5,000) per policy, so
// a large backlog takes several passes. EnforceResponse.MoreRemain is what
// says another one is needed.
//
// EventCount is the number of distinct events the viewer's policies select.
// Capped true means at least one policy hit previewCap, so the real number
// is at least EventCount. NoPolicies true means the scope has no policies
// at all, which is a different answer from zero-because-nothing-is-old, and
// the page has to be able to say which one it is.
type RetentionPreviewResponse struct {
	EventCount int64           `json:"eventCount"`
	Capped     bool            `json:"capped"`
	NoPolicies bool            `json:"noPolicies"`
	ByPolicy   []PolicyPreview `json:"byPolicy"`
}

// EnforceResponse is the outcome of one retention.enforce pass.
//
// MoreRemain is true when eligible events are still there after the pass.
// One pass loads at most retention.DefaultPurgeBatchSize events per policy,
// so a large backlog takes several, and the library's own result has no way
// to say so.
//
// Failed is true when a policy failed part-way. The counts are still the
// true counts of what was archived and purged before the failure, and that
// purge is permanent, which is why this is a successful response carrying a
// flag rather than an error that would throw the counts away.
type EnforceResponse struct {
	Archived   int64 `json:"archived"`
	Purged     int64 `json:"purged"`
	Retained   int64 `json:"retained"`
	MoreRemain bool  `json:"moreRemain"`
	Failed     bool  `json:"failed"`
}

// ArchiveSummary is one archived batch as the dashboard lists it.
type ArchiveSummary struct {
	ID            string `json:"id"`
	PolicyID      string `json:"policyId"`
	Category      string `json:"category"`
	EventCount    int64  `json:"eventCount"`
	FromTimestamp string `json:"fromTimestamp"`
	ToTimestamp   string `json:"toTimestamp"`
	SinkName      string `json:"sinkName"`
	SinkRef       string `json:"sinkRef,omitempty"`
	TenantID      string `json:"tenantId,omitempty"`
	CreatedAt     string `json:"createdAt"`
}

// ArchiveListInput pages through the viewer's own scope's archive records.
type ArchiveListInput struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// ArchiveListResponse is one page of archive records. There is no total:
// retention.Store has no archive count method, and counting a page would
// state the page size as the total. HasMore comes from fetching one row
// past the page.
type ArchiveListResponse struct {
	Archives []ArchiveSummary `json:"archives"`
	HasMore  bool             `json:"hasMore"`
}

func retentionRegistrations() []registration {
	return []registration{
		query("retention.policies", retentionPoliciesHandler),
		query("retention.policyDetail", retentionPolicyDetailHandler),
		command("retention.savePolicy", retentionSavePolicyHandler),
		command("retention.deletePolicy", retentionDeletePolicyHandler),
		query("retention.preview", retentionPreviewHandler),
		command("retention.enforce", retentionEnforceHandler),
		query("retention.archives", retentionArchivesHandler),
	}
}

// retentionScope is the viewer's scope in the retention package's terms.
// Both fields are always set from the viewer, TenantID included when it is
// empty, so no store call here ever carries a scope the request chose.
func (v viewScope) retentionScope() retention.Scope {
	return retention.Scope{AppID: v.AppID, TenantID: v.TenantID}
}

// purgeQueryFor builds the query retention enforcement runs for p, bounded
// to limit rows.
//
// It must stay identical to what retention.Enforcer's enforcePolicy builds:
// the policy's own scope (not the viewer's), the policy's category, and a
// cutoff of now minus the policy's duration. The preview and the moreRemain
// check both go through here, so they describe exactly the rows enforcement
// selects. If enforcePolicy ever changes how it builds its query, this has
// to change with it, or the confirm dialog shows one number and enforcement
// deletes another.
func purgeQueryFor(p *retention.Policy, limit int) retention.PurgeQuery {
	return retention.PurgeQuery{
		Scope:    p.Scope(),
		Category: p.Category,
		Before:   time.Now().Add(-p.Duration),
		Limit:    limit,
	}
}

// listViewerPolicies returns every policy in the viewer's scope, the same
// set retention.Enforcer.EnforceScope runs for this viewer. Limit -1 means
// unbounded.
func listViewerPolicies(ctx context.Context, deps Deps, v viewScope) ([]*retention.Policy, error) {
	return deps.Store.ListPolicies(ctx, retention.ListPoliciesOpts{
		Scope: v.retentionScope(),
		Limit: -1,
	})
}

// projectPolicy turns a stored policy into its wire summary.
func projectPolicy(p *retention.Policy) PolicySummary {
	return PolicySummary{
		ID:        p.ID.String(),
		Category:  p.Category,
		Duration:  p.Duration.String(),
		Archive:   p.Archive,
		AppID:     p.AppID,
		TenantID:  p.TenantID,
		CreatedAt: formatTime(p.CreatedAt),
		UpdatedAt: formatTime(p.UpdatedAt),
	}
}

// projectArchive turns a stored archive record into its wire summary.
func projectArchive(a *retention.Archive) ArchiveSummary {
	return ArchiveSummary{
		ID:            a.ID.String(),
		PolicyID:      a.PolicyID.String(),
		Category:      a.Category,
		EventCount:    a.EventCount,
		FromTimestamp: formatTime(a.FromTimestamp),
		ToTimestamp:   formatTime(a.ToTimestamp),
		SinkName:      a.SinkName,
		SinkRef:       a.SinkRef,
		TenantID:      a.TenantID,
		CreatedAt:     formatTime(a.CreatedAt),
	}
}

// maxPolicyCategoryLen bounds a policy category, in characters.
const maxPolicyCategoryLen = 64

// validPolicyCategory reports whether c may be used as the category of a new
// policy: exactly "*" (every category), or 1 to 64 characters with no ":",
// no control characters, and no leading or trailing whitespace.
//
// ":" is the one character that matters for safety. store/redis joins app,
// tenant and category with ":" into one lookup key, and deletes whatever
// different policy it finds under that key, so a category carrying ":" can
// name another tenant's key: tenant "t" creating "x:auth" lands on tenant
// "t:x"'s "auth" key and deletes that policy. Control characters and edge
// whitespace are refused because a category that looks like another one on
// the page is its own trap. Everything else operators really use, such as
// "auth/session", "user login" or non-ASCII names, is allowed.
//
// It is checked on create only. An update may not change the category at
// all, and an unchanged category writes no new key.
func validPolicyCategory(c string) bool {
	if c == "*" {
		return true
	}
	if c == "" || !utf8.ValidString(c) || utf8.RuneCountInString(c) > maxPolicyCategoryLen {
		return false
	}
	for _, r := range c {
		if r == ':' || unicode.Is(unicode.Cc, r) {
			return false
		}
	}
	first, _ := utf8.DecodeRuneInString(c)
	last, _ := utf8.DecodeLastRuneInString(c)
	return !unicode.IsSpace(first) && !unicode.IsSpace(last)
}

// errPolicyNotFound is the answer for a policy ID that does not parse, does
// not exist, or belongs to someone else. All three look the same, so a
// caller cannot probe which IDs exist in other tenants.
func errPolicyNotFound() error {
	return &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
}

// ownedPolicy fetches a policy by ID and returns it only if the viewer owns
// it. Every path that acts on a policy by ID goes through here, before it
// reads, changes or deletes anything.
func ownedPolicy(ctx context.Context, deps Deps, op string, v viewScope, rawID string) (*retention.Policy, error) {
	policyID, err := id.ParsePolicyID(rawID)
	if err != nil {
		// An ID that does not parse cannot name a real policy, and the
		// store is never touched.
		return nil, errPolicyNotFound()
	}

	pol, err := deps.Store.GetPolicy(ctx, policyID)
	if err != nil {
		return nil, deps.mapStoreError(op, err)
	}
	if pol == nil {
		return nil, errPolicyNotFound()
	}

	// Security-critical: GetPolicy resolves by ID alone and bypasses every
	// scope filter. Without this, a caller who guessed an ID could read,
	// rewrite or delete another tenant's retention policy.
	if !v.owns(pol.AppID, pol.TenantID) {
		return nil, errPolicyNotFound()
	}
	return pol, nil
}

// parsePolicyDuration reads a policy duration, refusing anything that is not
// strictly positive. enforcePolicy's cutoff is now minus the duration, so a
// zero duration puts the cutoff at now and a negative one in the future, and
// either makes the next enforcement run purge the category's entire history.
func parsePolicyDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: "duration is not a valid duration, such as 720h"}
	}
	if d <= 0 {
		return 0, &fcontract.Error{
			Code:    fcontract.CodeBadRequest,
			Message: "duration must be greater than zero: a zero or negative duration purges the category's entire history",
		}
	}
	return d, nil
}

func retentionPoliciesHandler(deps Deps) func(context.Context, struct{}, fcontract.Principal) (PolicyListResponse, error) {
	return func(ctx context.Context, _ struct{}, p fcontract.Principal) (PolicyListResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return PolicyListResponse{}, err
		}

		policies, err := listViewerPolicies(ctx, deps, v)
		if err != nil {
			return PolicyListResponse{}, deps.mapStoreError("retention.policies", err)
		}

		out := PolicyListResponse{Policies: make([]PolicySummary, 0, len(policies))}
		for _, pol := range policies {
			if pol == nil {
				continue
			}
			out.Policies = append(out.Policies, projectPolicy(pol))
		}
		out.Total = len(out.Policies)
		return out, nil
	}
}

func retentionPolicyDetailHandler(deps Deps) func(context.Context, GetPolicyInput, fcontract.Principal) (PolicySummary, error) {
	return func(ctx context.Context, in GetPolicyInput, p fcontract.Principal) (PolicySummary, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return PolicySummary{}, err
		}

		pol, err := ownedPolicy(ctx, deps, "retention.policyDetail", v, in.ID)
		if err != nil {
			return PolicySummary{}, err
		}
		return projectPolicy(pol), nil
	}
}

func retentionSavePolicyHandler(deps Deps) func(context.Context, SavePolicyInput, fcontract.Principal) (PolicySummary, error) {
	return func(ctx context.Context, in SavePolicyInput, p fcontract.Principal) (PolicySummary, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return PolicySummary{}, err
		}

		var category *string
		if in.Category != nil {
			// Taken exactly as supplied, with no trimming. createPolicy
			// validates it; updatePolicy only allows it to equal the stored
			// category.
			c := *in.Category
			category = &c
		}

		var duration *time.Duration
		if in.Duration != nil {
			d, err := parsePolicyDuration(*in.Duration)
			if err != nil {
				return PolicySummary{}, err
			}
			duration = &d
		}

		if in.ID != nil {
			return updatePolicy(ctx, deps, v, *in.ID, category, duration, in.Archive)
		}
		return createPolicy(ctx, deps, v, category, duration, in.Archive)
	}
}

// updatePolicy applies only the supplied fields to a policy the viewer owns.
// The policy keeps its ID, AppID and TenantID whoever edits it: an app-wide
// operator editing a tenant's policy must not move it to app level.
func updatePolicy(
	ctx context.Context, deps Deps, v viewScope, rawID string,
	category *string, duration *time.Duration, archive *bool,
) (PolicySummary, error) {
	existing, err := ownedPolicy(ctx, deps, "retention.savePolicy", v, rawID)
	if err != nil {
		return PolicySummary{}, err
	}

	// A policy's category is part of its identity: the stores key it by
	// (app, tenant, category), and they disagree about what a changed
	// category on an existing ID does. SQLite, Postgres and Mongo reject the
	// write on the ID collision; Redis writes it and leaves the old
	// category's index pointing at this policy, so a later create for the
	// old category deletes it. Refusing here keeps all four the same.
	if category != nil && *category != existing.Category {
		return PolicySummary{}, &fcontract.Error{
			Code:    fcontract.CodeBadRequest,
			Message: "a policy's category cannot be changed: delete it and create a policy for the new category",
		}
	}

	updated := *existing
	if duration != nil {
		updated.Duration = *duration
	}
	if archive != nil {
		updated.Archive = *archive
	}
	updated.UpdatedAt = time.Now().UTC()

	if err := deps.Store.SavePolicy(ctx, &updated); err != nil {
		return PolicySummary{}, deps.mapStoreError("retention.savePolicy", err)
	}
	return projectPolicy(&updated), nil
}

// createPolicy creates a policy in the viewer's own scope.
//
// Every backend's SavePolicy upserts on (app, tenant, category): a second
// policy for a category that already has one silently replaces the first's
// duration and archive setting. That is refused here as a conflict. The
// page has to update the existing policy by ID, so the operator sees which
// policy they are changing.
func createPolicy(
	ctx context.Context, deps Deps, v viewScope,
	category *string, duration *time.Duration, archive *bool,
) (PolicySummary, error) {
	if category == nil {
		return PolicySummary{}, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: "category is required"}
	}
	if duration == nil {
		return PolicySummary{}, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: "duration is required"}
	}
	if !validPolicyCategory(*category) {
		return PolicySummary{}, &fcontract.Error{
			Code:    fcontract.CodeBadRequest,
			Message: `category must be "*" or 1 to 64 characters with no ':', no control characters, and no leading or trailing spaces`,
		}
	}

	existing, err := listViewerPolicies(ctx, deps, v)
	if err != nil {
		return PolicySummary{}, deps.mapStoreError("retention.savePolicy", err)
	}
	for _, pol := range existing {
		// The exact triple, TenantID included. An app-wide viewer's listing
		// also returns its tenants' policies, and a tenant's policy for the
		// same category is a different policy, not a collision.
		if pol != nil && pol.AppID == v.AppID && pol.TenantID == v.TenantID && pol.Category == *category {
			return PolicySummary{}, &fcontract.Error{
				Code:    fcontract.CodeConflict,
				Message: "a retention policy for this category already exists in this scope",
			}
		}
	}

	pol := &retention.Policy{
		Entity:   chronicle.NewEntity(),
		ID:       id.NewPolicyID(),
		Category: *category,
		Duration: *duration,
		// Security-critical: the scope comes from the viewer, never the
		// request. The stores read an empty AppID as every app.
		AppID:    v.AppID,
		TenantID: v.TenantID,
	}
	if archive != nil {
		pol.Archive = *archive
	}

	if err := deps.Store.SavePolicy(ctx, pol); err != nil {
		return PolicySummary{}, deps.mapStoreError("retention.savePolicy", err)
	}
	return projectPolicy(pol), nil
}

func retentionDeletePolicyHandler(deps Deps) func(context.Context, DeletePolicyInput, fcontract.Principal) (DeletePolicyResponse, error) {
	return func(ctx context.Context, in DeletePolicyInput, p fcontract.Principal) (DeletePolicyResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return DeletePolicyResponse{}, err
		}

		// Fetch and check ownership first. DeletePolicy takes an ID and
		// nothing else, so it would delete any tenant's policy it was
		// handed, and deleting a policy switches off that tenant's
		// retention.
		pol, err := ownedPolicy(ctx, deps, "retention.deletePolicy", v, in.ID)
		if err != nil {
			return DeletePolicyResponse{}, err
		}

		if err := deps.Store.DeletePolicy(ctx, pol.ID); err != nil {
			return DeletePolicyResponse{}, deps.mapStoreError("retention.deletePolicy", err)
		}
		return DeletePolicyResponse{ID: pol.ID.String()}, nil
	}
}

func retentionPreviewHandler(deps Deps) func(context.Context, struct{}, fcontract.Principal) (RetentionPreviewResponse, error) {
	return func(ctx context.Context, _ struct{}, p fcontract.Principal) (RetentionPreviewResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return RetentionPreviewResponse{}, err
		}

		policies, err := listViewerPolicies(ctx, deps, v)
		if err != nil {
			return RetentionPreviewResponse{}, deps.mapStoreError("retention.preview", err)
		}

		out := RetentionPreviewResponse{ByPolicy: make([]PolicyPreview, 0, len(policies))}
		distinct := map[string]struct{}{}
		for _, pol := range policies {
			if pol == nil {
				continue
			}

			// One row past the cap is how the preview knows it was capped.
			events, err := deps.Store.EventsOlderThan(ctx, purgeQueryFor(pol, previewCap+1))
			if err != nil {
				return RetentionPreviewResponse{}, deps.mapStoreError("retention.preview", err)
			}

			capped := len(events) > previewCap
			if capped {
				events = events[:previewCap]
				out.Capped = true
			}

			var n int64
			for _, ev := range events {
				if ev == nil {
					continue
				}
				n++
				distinct[ev.ID.String()] = struct{}{}
			}

			out.ByPolicy = append(out.ByPolicy, PolicyPreview{
				PolicyID:   pol.ID.String(),
				Category:   pol.Category,
				EventCount: n,
				Capped:     capped,
			})
		}

		out.NoPolicies = len(out.ByPolicy) == 0
		// Distinct events, not the sum of the per-policy counts: enforcement
		// purges an event once however many policies select it, and the
		// confirm dialog has to show what will actually be deleted.
		out.EventCount = int64(len(distinct))
		return out, nil
	}
}

func retentionEnforceHandler(deps Deps) func(context.Context, struct{}, fcontract.Principal) (EnforceResponse, error) {
	return func(ctx context.Context, _ struct{}, p fcontract.Principal) (EnforceResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return EnforceResponse{}, err
		}

		if deps.Enforcer == nil {
			return EnforceResponse{}, &fcontract.Error{
				Code:    fcontract.CodeUnavailable,
				Message: "retention enforcement is not configured on this deployment",
			}
		}

		// Security-critical: EnforceScope, never Enforce. Enforce runs every
		// app's and every tenant's policies and belongs to the background
		// scheduler; from a request it would let one operator purge every
		// customer's expired history on demand. EnforceScope runs only the
		// policies ListPolicies returns for the viewer's scope, and each one
		// purges under its own policy scope.
		res, err := deps.Enforcer.EnforceScope(ctx, v.retentionScope())
		if err != nil && res == nil {
			// Nothing ran: the policy listing itself failed.
			return EnforceResponse{}, deps.mapStoreError("retention.enforce", err)
		}

		out := EnforceResponse{
			Archived: res.Archived,
			Purged:   res.Purged,
			Retained: res.Retained,
		}

		if err != nil {
			// A policy failed part-way, and whatever the others purged is
			// already gone. An error response would drop these counts and
			// stop the command's invalidations firing, leaving every list on
			// the page showing events that no longer exist. So the answer is
			// a success that says it failed, and the cause goes to the log.
			out.Failed = true
			deps.logger().Error("chronicle/contract: retention enforcement failed part-way",
				log.String("contributor", contributorName),
				log.String("op", "retention.enforce"),
				log.String("app_id", v.AppID),
				log.String("tenant_id", v.TenantID),
				log.Int64("purged", res.Purged),
				log.Error(err),
			)
		}

		out.MoreRemain = retentionMoreRemain(ctx, deps, v)
		return out, nil
	}
}

// retentionMoreRemain reports whether any of the viewer's policies still
// selects an event after an enforcement pass.
//
// It answers true when it cannot tell. The purge has already happened, so
// failing the command here would hide its counts, and answering false would
// tell the operator the backlog is cleared when nobody checked. "More may
// remain" sends them back to the preview, which will surface the store
// error if it persists.
func retentionMoreRemain(ctx context.Context, deps Deps, v viewScope) bool {
	policies, err := listViewerPolicies(ctx, deps, v)
	if err != nil {
		deps.logger().Error("chronicle/contract: retention moreRemain check failed",
			log.String("contributor", contributorName),
			log.String("op", "retention.enforce"),
			log.Error(err),
		)
		return true
	}

	for _, pol := range policies {
		if pol == nil {
			continue
		}
		events, err := deps.Store.EventsOlderThan(ctx, purgeQueryFor(pol, 1))
		if err != nil {
			deps.logger().Error("chronicle/contract: retention moreRemain check failed",
				log.String("contributor", contributorName),
				log.String("op", "retention.enforce"),
				log.String("policy_id", pol.ID.String()),
				log.Error(err),
			)
			return true
		}
		if len(events) > 0 {
			return true
		}
	}
	return false
}

// clampArchiveListLimit mirrors clampEventListLimit: zero or less becomes
// the default page size, and anything above the cap is capped.
func clampArchiveListLimit(limit int) int {
	if limit <= 0 {
		return defaultArchiveListLimit
	}
	if limit > maxArchiveListLimit {
		return maxArchiveListLimit
	}
	return limit
}

func retentionArchivesHandler(deps Deps) func(context.Context, ArchiveListInput, fcontract.Principal) (ArchiveListResponse, error) {
	return func(ctx context.Context, in ArchiveListInput, p fcontract.Principal) (ArchiveListResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return ArchiveListResponse{}, err
		}

		if in.Offset < 0 {
			return ArchiveListResponse{}, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: "offset cannot be negative"}
		}

		limit := clampArchiveListLimit(in.Limit)
		list, err := deps.Store.ListArchives(ctx, retention.ListOpts{
			Scope:  v.retentionScope(),
			Limit:  limit + 1,
			Offset: in.Offset,
		})
		if err != nil {
			return ArchiveListResponse{}, deps.mapStoreError("retention.archives", err)
		}

		out := ArchiveListResponse{HasMore: len(list) > limit}
		if out.HasMore {
			list = list[:limit]
		}
		out.Archives = make([]ArchiveSummary, 0, len(list))
		for _, a := range list {
			if a == nil {
				continue
			}
			out.Archives = append(out.Archives, projectArchive(a))
		}
		return out, nil
	}
}
