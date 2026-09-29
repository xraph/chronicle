package contract

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
)

// ──────────────────────────────────────────────────
// Test doubles and seeding. Named after this task so they cannot collide
// with another task's.
// ──────────────────────────────────────────────────

// retentionListSpy records every ListPolicies call and answers with a fixed
// set of policies. It is what proves enforcement ran under the viewer's
// scope: EnforceScope lists with that scope, the global Enforce lists with a
// zero one.
type retentionListSpy struct {
	stubStore
	policies  []*retention.Policy
	listCalls []retention.ListPoliciesOpts
}

func (s *retentionListSpy) ListPolicies(_ context.Context, opts retention.ListPoliciesOpts) ([]*retention.Policy, error) {
	s.listCalls = append(s.listCalls, opts)
	return s.policies, nil
}

// retentionFailingPurgeStore holds two policies, each selecting three
// events. The first purge succeeds and the second fails, which is a policy
// failing part-way through a pass that has already deleted something.
type retentionFailingPurgeStore struct {
	stubStore
	policies   []*retention.Policy
	purgeCalls int
}

func (s *retentionFailingPurgeStore) ListPolicies(context.Context, retention.ListPoliciesOpts) ([]*retention.Policy, error) {
	return s.policies, nil
}

func (s *retentionFailingPurgeStore) EventsOlderThan(context.Context, retention.PurgeQuery) ([]*audit.Event, error) {
	return retentionFakeEvents(3), nil
}

func (s *retentionFailingPurgeStore) PurgeEvents(_ context.Context, ids []id.ID) (int64, error) {
	s.purgeCalls++
	if s.purgeCalls == 1 {
		return int64(len(ids)), nil
	}
	return 0, errors.New("disk I/O error")
}

// retentionCapStore answers EventsOlderThan with as many events as the query
// asks for, so a test can reach the preview cap without seeding 10,001 rows.
type retentionCapStore struct {
	stubStore
	policies []*retention.Policy
	limits   []int
}

func (s *retentionCapStore) ListPolicies(context.Context, retention.ListPoliciesOpts) ([]*retention.Policy, error) {
	return s.policies, nil
}

func (s *retentionCapStore) EventsOlderThan(_ context.Context, q retention.PurgeQuery) ([]*audit.Event, error) {
	s.limits = append(s.limits, q.Limit)
	return retentionFakeEvents(q.Limit), nil
}

// retentionPolicySpy is a store holding one policy, recording what the
// handlers do to it. GetPolicy answers with the policy whatever ID it is
// asked for, so the ownership check is the only thing standing between a
// request and the write.
type retentionPolicySpy struct {
	stubStore
	existing    *retention.Policy
	gets        int
	saveCalls   int
	deleteCalls int
}

func (s *retentionPolicySpy) GetPolicy(context.Context, id.ID) (*retention.Policy, error) {
	s.gets++
	if s.existing == nil {
		return nil, chronicle.ErrPolicyNotFound
	}
	cp := *s.existing
	return &cp, nil
}

func (s *retentionPolicySpy) SavePolicy(context.Context, *retention.Policy) error {
	s.saveCalls++
	return nil
}

func (s *retentionPolicySpy) DeletePolicy(context.Context, id.ID) error {
	s.deleteCalls++
	return nil
}

// retentionEventsFailStore lists policies but cannot query events.
type retentionEventsFailStore struct {
	stubStore
	policies []*retention.Policy
}

func (s *retentionEventsFailStore) ListPolicies(context.Context, retention.ListPoliciesOpts) ([]*retention.Policy, error) {
	return s.policies, nil
}

func (s *retentionEventsFailStore) EventsOlderThan(context.Context, retention.PurgeQuery) ([]*audit.Event, error) {
	return nil, errors.New("query timeout")
}

func retentionFakeEvents(n int) []*audit.Event {
	out := make([]*audit.Event, n)
	for i := range out {
		out[i] = &audit.Event{ID: id.NewAuditID(), Timestamp: time.Now().Add(-1000 * time.Hour)}
	}
	return out
}

func retentionPolicy(appID, tenantID, category string, d time.Duration) *retention.Policy {
	return &retention.Policy{
		Entity:   chronicle.NewEntity(),
		ID:       id.NewPolicyID(),
		Category: category,
		Duration: d,
		AppID:    appID,
		TenantID: tenantID,
	}
}

// retentionSeeder appends events to a real store, one stream per scope, with
// sequences that stay unique within each stream.
type retentionSeeder struct {
	t       *testing.T
	s       store.Store
	streams map[string]id.ID
	seq     map[string]uint64
}

func newRetentionSeeder(t *testing.T, s store.Store) *retentionSeeder {
	return &retentionSeeder{t: t, s: s, streams: map[string]id.ID{}, seq: map[string]uint64{}}
}

// events appends n events of the given category, all aged age, and returns
// them. Timestamps are whole seconds so the stored text compares cleanly.
func (r *retentionSeeder) events(appID, tenantID, category string, age time.Duration, n int) []*audit.Event {
	r.t.Helper()
	key := appID + "\x00" + tenantID
	streamID, ok := r.streams[key]
	if !ok {
		streamID = eventsSeedStream(r.t, r.s, appID, tenantID)
		r.streams[key] = streamID
	}
	ts := time.Now().Add(-age).UTC().Truncate(time.Second)

	out := make([]*audit.Event, n)
	for i := range out {
		r.seq[key]++
		out[i] = &audit.Event{
			ID:        id.NewAuditID(),
			StreamID:  streamID,
			Sequence:  r.seq[key],
			Hash:      fmt.Sprintf("hash-%s-%d", key, r.seq[key]),
			AppID:     appID,
			TenantID:  tenantID,
			Action:    "test.action",
			Resource:  "test",
			Category:  category,
			Outcome:   "success",
			Severity:  "info",
			Timestamp: ts,
		}
	}
	if err := r.s.AppendBatch(context.Background(), out); err != nil {
		r.t.Fatalf("append %d events: %v", n, err)
	}
	return out
}

func retentionSavePolicyIn(t *testing.T, s store.Store, p *retention.Policy) *retention.Policy {
	t.Helper()
	if err := s.SavePolicy(context.Background(), p); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	return p
}

// retentionAssertGone and retentionAssertKept check each event by ID against
// the real store.
func retentionAssertGone(t *testing.T, s store.Store, label string, evs []*audit.Event) {
	t.Helper()
	for _, ev := range evs {
		if _, err := s.Get(context.Background(), ev.ID); !errors.Is(err, chronicle.ErrEventNotFound) {
			t.Fatalf("%s: event %s should have been purged, Get = %v", label, ev.ID, err)
		}
	}
}

func retentionAssertKept(t *testing.T, s store.Store, label string, evs []*audit.Event) {
	t.Helper()
	for _, ev := range evs {
		if _, err := s.Get(context.Background(), ev.ID); err != nil {
			t.Fatalf("%s: event %s should still exist, Get = %v", label, ev.ID, err)
		}
	}
}

func retentionErrCode(t *testing.T, err error) fcontract.ErrorCode {
	t.Helper()
	var ce *fcontract.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v (%T), want a contract error", err, err)
	}
	return ce.Code
}

func retentionStr(s string) *string { return &s }
func retentionBool(b bool) *bool    { return &b }

var (
	retentionApp1TenantA = map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}
	retentionApp1Wide    = map[string]any{"app_id": "app-1"}
)

// ──────────────────────────────────────────────────
// retention.enforce
// ──────────────────────────────────────────────────

// The single most dangerous call in this contract. Enforce covers every app
// and belongs to the background scheduler; a dashboard request must go
// through EnforceScope with the viewer's own scope. The enforcer lists
// policies with exactly the scope it was given, so the listing is what shows
// which one ran.
func TestRetentionEnforceUsesTheViewersScopeAndNotTheGlobalEnforce(t *testing.T) {
	spy := &retentionListSpy{policies: []*retention.Policy{
		retentionPolicy("app-1", "tenant-a", "auth", 24*time.Hour),
	}}
	h := retentionEnforceHandler(Deps{Store: spy, Enforcer: retention.NewEnforcer(spy, nil, nil)})

	if _, err := h(context.Background(), struct{}{}, principalWith(retentionApp1TenantA)); err != nil {
		t.Fatalf("retention.enforce: %v", err)
	}

	if len(spy.listCalls) == 0 {
		t.Fatal("enforcement never listed policies")
	}
	want := retention.Scope{AppID: "app-1", TenantID: "tenant-a"}
	for i, c := range spy.listCalls {
		if c.Scope != want {
			t.Fatalf("ListPolicies call %d ran under scope %+v, want %+v: a zero scope is the global Enforce, which purges every app",
				i, c.Scope, want)
		}
	}
}

// End to end on a real store: two apps with the same policy and the same
// mix of old and new events. Enforcing as app-1 must purge only app-1's old
// events in the governed category.
func TestRetentionEnforcePurgesOnlyTheViewersOwnOldEvents(t *testing.T) {
	s := newSQLiteStore(t)
	seed := newRetentionSeeder(t, s)

	retentionSavePolicyIn(t, s, retentionPolicy("app-1", "", "auth", 24*time.Hour))
	retentionSavePolicyIn(t, s, retentionPolicy("app-2", "", "auth", 24*time.Hour))

	app1Old := seed.events("app-1", "", "auth", 48*time.Hour, 4)
	app1New := seed.events("app-1", "", "auth", time.Hour, 2)
	app1OtherCategory := seed.events("app-1", "", "billing", 48*time.Hour, 3)
	app2Old := seed.events("app-2", "", "auth", 48*time.Hour, 5)
	app2New := seed.events("app-2", "", "auth", time.Hour, 2)

	h := retentionEnforceHandler(Deps{Store: s, Enforcer: retention.NewEnforcer(s, nil, nil)})
	out, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.enforce: %v", err)
	}

	if out.Purged != 4 || out.Archived != 0 || out.Failed || out.MoreRemain {
		t.Fatalf("enforce = %+v, want purged 4, archived 0, not failed, nothing remaining", out)
	}
	retentionAssertGone(t, s, "app-1 old auth", app1Old)
	retentionAssertKept(t, s, "app-1 new auth", app1New)
	retentionAssertKept(t, s, "app-1 billing, which no policy governs", app1OtherCategory)
	retentionAssertKept(t, s, "app-2 old auth", app2Old)
	retentionAssertKept(t, s, "app-2 new auth", app2New)
}

// The same inside one app: a tenant operator's enforcement runs its own
// tenant's policy and never the sibling tenant's.
func TestRetentionEnforceAsATenantLeavesTheSiblingTenantAlone(t *testing.T) {
	s := newSQLiteStore(t)
	seed := newRetentionSeeder(t, s)

	retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-a", "auth", 24*time.Hour))
	retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-b", "auth", 24*time.Hour))

	aOld := seed.events("app-1", "tenant-a", "auth", 48*time.Hour, 3)
	bOld := seed.events("app-1", "tenant-b", "auth", 48*time.Hour, 3)

	h := retentionEnforceHandler(Deps{Store: s, Enforcer: retention.NewEnforcer(s, nil, nil)})
	out, err := h(context.Background(), struct{}{}, principalWith(retentionApp1TenantA))
	if err != nil {
		t.Fatalf("retention.enforce: %v", err)
	}
	if out.Purged != 3 {
		t.Fatalf("purged = %d, want 3", out.Purged)
	}
	retentionAssertGone(t, s, "tenant-a old", aOld)
	retentionAssertKept(t, s, "tenant-b old", bOld)
}

// One pass loads at most DefaultPurgeBatchSize events per policy, and the
// library's result cannot say more are waiting. moreRemain re-queries after
// the pass so the page can tell the operator to run it again.
func TestRetentionEnforceReportsMoreRemainUntilTheBacklogIsCleared(t *testing.T) {
	s := newSQLiteStore(t)
	seed := newRetentionSeeder(t, s)

	retentionSavePolicyIn(t, s, retentionPolicy("app-1", "", "auth", 24*time.Hour))
	extra := 10
	seed.events("app-1", "", "auth", 48*time.Hour, retention.DefaultPurgeBatchSize+extra)

	h := retentionEnforceHandler(Deps{Store: s, Enforcer: retention.NewEnforcer(s, nil, nil)})

	first, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("first retention.enforce: %v", err)
	}
	if first.Purged != int64(retention.DefaultPurgeBatchSize) || !first.MoreRemain {
		t.Fatalf("first pass = %+v, want purged %d and moreRemain true", first, retention.DefaultPurgeBatchSize)
	}

	second, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("second retention.enforce: %v", err)
	}
	if second.Purged != int64(extra) || second.MoreRemain {
		t.Fatalf("second pass = %+v, want purged %d and moreRemain false", second, extra)
	}
}

// A policy failing part-way leaves a purge that has already happened. The
// command must still succeed, with the true counts and failed set, so the
// page learns what was deleted and its invalidations fire.
func TestRetentionEnforceFailingPartWayAnswersWithTheTrueCounts(t *testing.T) {
	st := &retentionFailingPurgeStore{policies: []*retention.Policy{
		retentionPolicy("app-1", "", "auth", 24*time.Hour),
		retentionPolicy("app-1", "", "billing", 24*time.Hour),
	}}
	h := retentionEnforceHandler(Deps{Store: st, Enforcer: retention.NewEnforcer(st, nil, nil)})

	out, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.enforce returned an error after purging events: %v", err)
	}
	if !out.Failed {
		t.Error("failed = false, want true: the second policy's purge failed")
	}
	if out.Purged != 3 {
		t.Errorf("purged = %d, want 3, the first policy's purge that did happen", out.Purged)
	}
	if !out.MoreRemain {
		t.Error("moreRemain = false, want true: the failed policy's events are still there")
	}
}

// When nothing ran at all (the policy listing failed) there are no counts to
// protect, and the error goes through mapStoreError like any other.
func TestRetentionEnforceWithNothingRunIsAnError(t *testing.T) {
	st := storeReturning(errors.New("connection refused"))
	h := retentionEnforceHandler(Deps{Store: st, Enforcer: retention.NewEnforcer(st, nil, nil)})

	_, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if got := retentionErrCode(t, err); got != fcontract.CodeInternal {
		t.Fatalf("code = %s, want %s", got, fcontract.CodeInternal)
	}
}

func TestRetentionEnforceWithoutAnEnforcerIsUnavailable(t *testing.T) {
	h := retentionEnforceHandler(Deps{Store: newStubStore()})
	_, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if got := retentionErrCode(t, err); got != fcontract.CodeUnavailable {
		t.Fatalf("code = %s, want %s", got, fcontract.CodeUnavailable)
	}
}

func TestRetentionEnforceRefusesAPrincipalWithNoApp(t *testing.T) {
	spy := &retentionListSpy{}
	h := retentionEnforceHandler(Deps{Store: spy, Enforcer: retention.NewEnforcer(spy, nil, nil)})
	_, err := h(context.Background(), struct{}{}, principalWith(nil))
	if !errors.Is(err, fcontract.ErrPermissionDenied) {
		t.Fatalf("err = %v, want PERMISSION_DENIED", err)
	}
	if len(spy.listCalls) != 0 {
		t.Fatal("enforcement ran for a principal with no app scope")
	}
}

// ──────────────────────────────────────────────────
// retention.preview
// ──────────────────────────────────────────────────

// Events a few minutes either side of the cutoff, so a cutoff built any
// differently from enforcePolicy's moves an event across the line.
func TestRetentionPreviewCountsExactlyWhatThePolicySelects(t *testing.T) {
	s := newSQLiteStore(t)
	seed := newRetentionSeeder(t, s)

	pol := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "", "auth", 24*time.Hour))
	seed.events("app-1", "", "auth", 24*time.Hour+10*time.Minute, 3)
	seed.events("app-1", "", "auth", 24*time.Hour-10*time.Minute, 2)
	seed.events("app-1", "", "billing", 48*time.Hour, 4)
	seed.events("app-2", "", "auth", 48*time.Hour, 6)

	h := retentionPreviewHandler(Deps{Store: s})
	out, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.preview: %v", err)
	}

	want := RetentionPreviewResponse{
		EventCount: 3,
		ByPolicy:   []PolicyPreview{{PolicyID: pol.ID.String(), Category: "auth", EventCount: 3}},
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("preview = %+v, want %+v", out, want)
	}
}

// The preview runs each policy under the policy's own scope, as enforcement
// does. An app-wide viewer looking at a tenant's policy must see only that
// tenant's events: the viewer's scope would select every tenant's.
func TestRetentionPreviewUsesThePolicysScopeNotTheViewers(t *testing.T) {
	s := newSQLiteStore(t)
	seed := newRetentionSeeder(t, s)

	retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-a", "auth", 24*time.Hour))
	seed.events("app-1", "tenant-a", "auth", 48*time.Hour, 2)
	seed.events("app-1", "tenant-b", "auth", 48*time.Hour, 5)

	h := retentionPreviewHandler(Deps{Store: s})
	out, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.preview: %v", err)
	}
	if out.EventCount != 2 {
		t.Fatalf("eventCount = %d, want 2, tenant-a's events only", out.EventCount)
	}
}

// The preview exists so the confirm dialog shows what enforce will delete.
// Overlapping policies ("*" covers auth too) select some events twice, and
// enforcement purges each of them once.
func TestRetentionPreviewMatchesWhatEnforceThenPurges(t *testing.T) {
	s := newSQLiteStore(t)
	seed := newRetentionSeeder(t, s)

	retentionSavePolicyIn(t, s, retentionPolicy("app-1", "", "*", 48*time.Hour))
	retentionSavePolicyIn(t, s, retentionPolicy("app-1", "", "auth", 24*time.Hour))
	retentionSavePolicyIn(t, s, retentionPolicy("app-2", "", "*", time.Hour))

	seed.events("app-1", "", "auth", 72*time.Hour, 4)    // both policies select these
	seed.events("app-1", "", "auth", 36*time.Hour, 3)    // only the auth policy
	seed.events("app-1", "", "billing", 72*time.Hour, 2) // only "*"
	kept := seed.events("app-1", "", "billing", 36*time.Hour, 5)
	other := seed.events("app-2", "", "auth", 72*time.Hour, 7)

	deps := Deps{Store: s, Enforcer: retention.NewEnforcer(s, nil, nil)}
	preview, err := retentionPreviewHandler(deps)(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.preview: %v", err)
	}
	if preview.EventCount != 9 || preview.Capped || preview.NoPolicies {
		t.Fatalf("preview = %+v, want 9 distinct events, not capped", preview)
	}

	out, err := retentionEnforceHandler(deps)(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.enforce: %v", err)
	}
	if out.Purged != preview.EventCount {
		t.Fatalf("enforce purged %d, the preview promised %d", out.Purged, preview.EventCount)
	}
	retentionAssertKept(t, s, "app-1 billing inside the window", kept)
	retentionAssertKept(t, s, "app-2", other)
}

func TestRetentionPreviewPastTheCapSaysSo(t *testing.T) {
	st := &retentionCapStore{policies: []*retention.Policy{
		retentionPolicy("app-1", "", "auth", 24*time.Hour),
	}}
	h := retentionPreviewHandler(Deps{Store: st})
	out, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.preview: %v", err)
	}
	if !out.Capped || out.EventCount != previewCap {
		t.Fatalf("preview = capped %v, eventCount %d; want capped at %d", out.Capped, out.EventCount, previewCap)
	}
	if len(out.ByPolicy) != 1 || !out.ByPolicy[0].Capped || out.ByPolicy[0].EventCount != previewCap {
		t.Fatalf("byPolicy = %+v, want one capped policy at %d", out.ByPolicy, previewCap)
	}
	if len(st.limits) != 1 || st.limits[0] != previewCap+1 {
		t.Fatalf("EventsOlderThan limits = %v, want [%d]", st.limits, previewCap+1)
	}
}

// Nothing configured and nothing old enough are different answers, and the
// page has to tell them apart.
func TestRetentionPreviewWithNoPoliciesSaysSo(t *testing.T) {
	s := newSQLiteStore(t)
	newRetentionSeeder(t, s).events("app-1", "", "auth", 48*time.Hour, 3)

	h := retentionPreviewHandler(Deps{Store: s})
	out, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.preview: %v", err)
	}
	if out.EventCount != 0 || !out.NoPolicies || out.ByPolicy == nil {
		t.Fatalf("preview = %+v, want zero, noPolicies true and an empty (not null) byPolicy", out)
	}

	// A policy with nothing old enough is zero for the other reason.
	retentionSavePolicyIn(t, s, retentionPolicy("app-1", "", "auth", 72*time.Hour))
	out, err = h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.preview: %v", err)
	}
	if out.EventCount != 0 || out.NoPolicies {
		t.Fatalf("preview = %+v, want zero with noPolicies false", out)
	}
}

// ──────────────────────────────────────────────────
// retention.savePolicy
// ──────────────────────────────────────────────────

// A zero duration puts enforcement's cutoff at now and a negative one in
// the future, and either purges the category's whole history next run.
func TestRetentionSavePolicyRefusesADurationThatIsNotPositive(t *testing.T) {
	for _, dur := range []string{"0s", "0", "-1h", "abc", ""} {
		t.Run(dur, func(t *testing.T) {
			spy := &retentionPolicySpy{}
			h := retentionSavePolicyHandler(Deps{Store: spy})
			_, err := h(context.Background(), SavePolicyInput{Category: retentionStr("auth"), Duration: retentionStr(dur)},
				principalWith(retentionApp1Wide))
			if got := retentionErrCode(t, err); got != fcontract.CodeBadRequest {
				t.Fatalf("code = %s, want %s", got, fcontract.CodeBadRequest)
			}
			if spy.saveCalls != 0 {
				t.Fatal("SavePolicy was called with a refused duration")
			}
		})
	}
}

// The same refusal on an update, where a stored policy would be rewritten.
func TestRetentionSavePolicyRefusesAZeroDurationOnUpdate(t *testing.T) {
	existing := retentionPolicy("app-1", "", "auth", 720*time.Hour)
	spy := &retentionPolicySpy{existing: existing}
	h := retentionSavePolicyHandler(Deps{Store: spy})
	_, err := h(context.Background(), SavePolicyInput{ID: retentionStr(existing.ID.String()), Duration: retentionStr("0s")},
		principalWith(retentionApp1Wide))
	if got := retentionErrCode(t, err); got != fcontract.CodeBadRequest {
		t.Fatalf("code = %s, want %s", got, fcontract.CodeBadRequest)
	}
	if spy.saveCalls != 0 {
		t.Fatal("SavePolicy was called with a zero duration")
	}
}

func TestRetentionSavePolicyRequiresCategoryAndDurationOnCreate(t *testing.T) {
	for name, in := range map[string]SavePolicyInput{
		"no category":    {Duration: retentionStr("720h")},
		"blank category": {Category: retentionStr("  "), Duration: retentionStr("720h")},
		"no duration":    {Category: retentionStr("auth")},
	} {
		t.Run(name, func(t *testing.T) {
			spy := &retentionPolicySpy{}
			_, err := retentionSavePolicyHandler(Deps{Store: spy})(context.Background(), in, principalWith(retentionApp1Wide))
			if got := retentionErrCode(t, err); got != fcontract.CodeBadRequest {
				t.Fatalf("code = %s, want %s", got, fcontract.CodeBadRequest)
			}
			if spy.saveCalls != 0 {
				t.Fatal("SavePolicy was called")
			}
		})
	}
}

// An unscoped policy would purge every app's events on the next run, so a
// created policy carries the viewer's scope and nothing else. Read back from
// a real store.
func TestRetentionSavePolicyStampsTheViewersScope(t *testing.T) {
	s := newSQLiteStore(t)
	h := retentionSavePolicyHandler(Deps{Store: s})
	out, err := h(context.Background(),
		SavePolicyInput{Category: retentionStr("auth"), Duration: retentionStr("720h"), Archive: retentionBool(true)},
		principalWith(retentionApp1TenantA))
	if err != nil {
		t.Fatalf("savePolicy: %v", err)
	}

	pid, err := id.ParsePolicyID(out.ID)
	if err != nil {
		t.Fatalf("returned id %q does not parse: %v", out.ID, err)
	}
	got, err := s.GetPolicy(context.Background(), pid)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.AppID != "app-1" || got.TenantID != "tenant-a" || got.Category != "auth" ||
		got.Duration != 720*time.Hour || !got.Archive {
		t.Fatalf("stored policy = %+v, want app-1/tenant-a auth 720h archive", got)
	}
}

// Pointers distinguish "leave alone" from "set to empty". On a real store,
// an update that names only the duration keeps the archive flag, the
// category, the ID and the owning scope.
func TestRetentionSavePolicyUpdateLeavesUnsuppliedFieldsAlone(t *testing.T) {
	s := newSQLiteStore(t)
	existing := retentionPolicy("app-1", "tenant-a", "auth", 720*time.Hour)
	existing.Archive = true
	retentionSavePolicyIn(t, s, existing)

	// An app-wide operator editing a tenant's policy must not move it.
	h := retentionSavePolicyHandler(Deps{Store: s})
	out, err := h(context.Background(),
		SavePolicyInput{ID: retentionStr(existing.ID.String()), Duration: retentionStr("1440h")},
		principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("savePolicy: %v", err)
	}
	if out.ID != existing.ID.String() {
		t.Fatalf("update returned id %s, want %s", out.ID, existing.ID)
	}

	got, err := s.GetPolicy(context.Background(), existing.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Duration != 1440*time.Hour {
		t.Errorf("duration = %v, want 1440h", got.Duration)
	}
	if !got.Archive {
		t.Error("archive was cleared by an update that never mentioned it")
	}
	if got.Category != "auth" || got.AppID != "app-1" || got.TenantID != "tenant-a" {
		t.Errorf("stored policy = %+v, want category, app and tenant unchanged", got)
	}

	all, err := s.ListPolicies(context.Background(), retention.ListPoliciesOpts{Scope: retention.Scope{AppID: "app-1"}, Limit: -1})
	if err != nil || len(all) != 1 {
		t.Fatalf("policies after update = %d (%v), want exactly 1", len(all), err)
	}

	// And the other direction: an update naming only archive keeps the
	// new duration.
	if _, err := h(context.Background(),
		SavePolicyInput{ID: retentionStr(existing.ID.String()), Archive: retentionBool(false)},
		principalWith(retentionApp1Wide)); err != nil {
		t.Fatalf("savePolicy archive only: %v", err)
	}
	got, _ = s.GetPolicy(context.Background(), existing.ID)
	if got.Archive || got.Duration != 1440*time.Hour {
		t.Fatalf("after archive-only update = %+v, want archive false and duration 1440h", got)
	}
}

// Update by ID bypasses every list filter, so ownership is checked before
// anything is written: a same-app other tenant, another app, and a tenant
// operator reaching for an app-level policy.
func TestRetentionSavePolicyCannotUpdateAPolicyTheViewerDoesNotOwn(t *testing.T) {
	cases := map[string]struct {
		policy *retention.Policy
		viewer map[string]any
	}{
		"same app, other tenant": {retentionPolicy("app-1", "tenant-b", "auth", 720*time.Hour), retentionApp1TenantA},
		"other app":              {retentionPolicy("app-2", "", "auth", 720*time.Hour), retentionApp1Wide},
		"tenant on app level":    {retentionPolicy("app-1", "", "auth", 720*time.Hour), retentionApp1TenantA},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSQLiteStore(t)
			retentionSavePolicyIn(t, s, tc.policy)

			h := retentionSavePolicyHandler(Deps{Store: s})
			_, err := h(context.Background(),
				SavePolicyInput{ID: retentionStr(tc.policy.ID.String()), Duration: retentionStr("1s")},
				principalWith(tc.viewer))
			if got := retentionErrCode(t, err); got != fcontract.CodeNotFound {
				t.Fatalf("code = %s, want %s", got, fcontract.CodeNotFound)
			}

			got, err := s.GetPolicy(context.Background(), tc.policy.ID)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if got.Duration != 720*time.Hour {
				t.Fatalf("another scope's policy was rewritten to %v", got.Duration)
			}
		})
	}
}

// Every backend's SavePolicy upserts on (app, tenant, category), so a second
// create for a category would silently rewrite the first policy.
func TestRetentionSavePolicyCreateCollidingOnCategoryIsAConflict(t *testing.T) {
	s := newSQLiteStore(t)
	existing := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-a", "auth", 720*time.Hour))

	h := retentionSavePolicyHandler(Deps{Store: s})
	_, err := h(context.Background(),
		SavePolicyInput{Category: retentionStr("auth"), Duration: retentionStr("1h")},
		principalWith(retentionApp1TenantA))
	if got := retentionErrCode(t, err); got != fcontract.CodeConflict {
		t.Fatalf("code = %s, want %s", got, fcontract.CodeConflict)
	}

	got, err := s.GetPolicy(context.Background(), existing.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Duration != 720*time.Hour {
		t.Fatalf("the existing policy was overwritten to %v", got.Duration)
	}
}

// A tenant's policy for the same category is a different policy. The
// app-wide viewer's listing returns it, and it must not read as a collision.
func TestRetentionSavePolicyCreateBesideATenantsPolicyIsNotAConflict(t *testing.T) {
	s := newSQLiteStore(t)
	retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-a", "auth", 720*time.Hour))

	h := retentionSavePolicyHandler(Deps{Store: s})
	out, err := h(context.Background(),
		SavePolicyInput{Category: retentionStr("auth"), Duration: retentionStr("1440h")},
		principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("savePolicy: %v", err)
	}
	if out.TenantID != "" || out.AppID != "app-1" {
		t.Fatalf("created %+v, want an app-level policy", out)
	}
}

// A policy's category is its identity in every store, and the stores
// disagree about what changing it under an existing ID does.
func TestRetentionSavePolicyRefusesToChangeACategory(t *testing.T) {
	existing := retentionPolicy("app-1", "", "auth", 720*time.Hour)
	spy := &retentionPolicySpy{existing: existing}
	h := retentionSavePolicyHandler(Deps{Store: spy})
	_, err := h(context.Background(),
		SavePolicyInput{ID: retentionStr(existing.ID.String()), Category: retentionStr("billing")},
		principalWith(retentionApp1Wide))
	if got := retentionErrCode(t, err); got != fcontract.CodeBadRequest {
		t.Fatalf("code = %s, want %s", got, fcontract.CodeBadRequest)
	}
	if spy.saveCalls != 0 {
		t.Fatal("SavePolicy was called")
	}

	// Naming the same category is not a change.
	if _, err := h(context.Background(),
		SavePolicyInput{ID: retentionStr(existing.ID.String()), Category: retentionStr("auth")},
		principalWith(retentionApp1Wide)); err != nil {
		t.Fatalf("savePolicy with the unchanged category: %v", err)
	}
}

func TestRetentionSavePolicyWithAnUnparseableIDNeverTouchesTheStore(t *testing.T) {
	spy := &retentionPolicySpy{existing: retentionPolicy("app-1", "", "auth", time.Hour)}
	_, err := retentionSavePolicyHandler(Deps{Store: spy})(context.Background(),
		SavePolicyInput{ID: retentionStr("pol_1"), Duration: retentionStr("1h")}, principalWith(retentionApp1Wide))
	if got := retentionErrCode(t, err); got != fcontract.CodeNotFound {
		t.Fatalf("code = %s, want %s", got, fcontract.CodeNotFound)
	}
	if spy.gets != 0 || spy.saveCalls != 0 {
		t.Fatal("the store was touched for an ID that does not parse")
	}
}

// ──────────────────────────────────────────────────
// retention.deletePolicy
// ──────────────────────────────────────────────────

// Without the ownership check any viewer could switch off another tenant's
// retention by guessing an ID. DeletePolicy takes an ID and nothing else, so
// it must never be reached.
func TestRetentionDeletePolicyRefusesAPolicyTheViewerDoesNotOwn(t *testing.T) {
	cases := map[string]struct {
		policy *retention.Policy
		viewer map[string]any
	}{
		"same app, other tenant": {retentionPolicy("app-1", "tenant-b", "auth", time.Hour), retentionApp1TenantA},
		"other app":              {retentionPolicy("app-2", "", "auth", time.Hour), retentionApp1Wide},
		"other app, tenant":      {retentionPolicy("app-2", "tenant-a", "auth", time.Hour), retentionApp1TenantA},
		"tenant on app level":    {retentionPolicy("app-1", "", "auth", time.Hour), retentionApp1TenantA},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			spy := &retentionPolicySpy{existing: tc.policy}
			h := retentionDeletePolicyHandler(Deps{Store: spy})
			_, err := h(context.Background(), DeletePolicyInput{ID: tc.policy.ID.String()}, principalWith(tc.viewer))
			if got := retentionErrCode(t, err); got != fcontract.CodeNotFound {
				t.Fatalf("code = %s, want %s", got, fcontract.CodeNotFound)
			}
			if spy.gets != 1 {
				t.Fatalf("GetPolicy calls = %d, want 1: the refusal must come from the ownership check", spy.gets)
			}
			if spy.deleteCalls != 0 {
				t.Fatal("DeletePolicy was called for a policy the viewer does not own")
			}
		})
	}
}

func TestRetentionDeletePolicyDeletesTheViewersOwnPolicy(t *testing.T) {
	s := newSQLiteStore(t)
	own := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-a", "auth", time.Hour))
	other := retentionSavePolicyIn(t, s, retentionPolicy("app-2", "tenant-a", "auth", time.Hour))

	out, err := retentionDeletePolicyHandler(Deps{Store: s})(context.Background(),
		DeletePolicyInput{ID: own.ID.String()}, principalWith(retentionApp1TenantA))
	if err != nil {
		t.Fatalf("deletePolicy: %v", err)
	}
	if out.ID != own.ID.String() {
		t.Fatalf("deleted id = %s, want %s", out.ID, own.ID)
	}
	if _, err := s.GetPolicy(context.Background(), own.ID); !errors.Is(err, chronicle.ErrPolicyNotFound) {
		t.Fatalf("own policy after delete: %v, want not found", err)
	}
	if _, err := s.GetPolicy(context.Background(), other.ID); err != nil {
		t.Fatalf("other app's policy after delete: %v", err)
	}
}

func TestRetentionDeletePolicyWithAnUnparseableIDNeverTouchesTheStore(t *testing.T) {
	spy := &retentionPolicySpy{existing: retentionPolicy("app-1", "", "auth", time.Hour)}
	_, err := retentionDeletePolicyHandler(Deps{Store: spy})(context.Background(),
		DeletePolicyInput{ID: "pol_1"}, principalWith(retentionApp1Wide))
	if got := retentionErrCode(t, err); got != fcontract.CodeNotFound {
		t.Fatalf("code = %s, want %s", got, fcontract.CodeNotFound)
	}
	if spy.gets != 0 || spy.deleteCalls != 0 {
		t.Fatal("the store was touched for an ID that does not parse")
	}
}

// ──────────────────────────────────────────────────
// retention.policies and retention.policyDetail
// ──────────────────────────────────────────────────

func TestRetentionPoliciesListsOnlyTheViewersScope(t *testing.T) {
	s := newSQLiteStore(t)
	a := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-a", "auth", time.Hour))
	b := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-b", "auth", time.Hour))
	appLevel := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "", "billing", time.Hour))
	retentionSavePolicyIn(t, s, retentionPolicy("app-2", "", "auth", time.Hour))
	retentionSavePolicyIn(t, s, retentionPolicy("app-2", "tenant-a", "auth", time.Hour))

	h := retentionPoliciesHandler(Deps{Store: s})
	ids := func(out PolicyListResponse) map[string]bool {
		m := map[string]bool{}
		for _, p := range out.Policies {
			m[p.ID] = true
		}
		return m
	}

	wide, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.policies app-wide: %v", err)
	}
	want := map[string]bool{a.ID.String(): true, b.ID.String(): true, appLevel.ID.String(): true}
	if !reflect.DeepEqual(ids(wide), want) || wide.Total != 3 {
		t.Fatalf("app-wide policies = %v (total %d), want app-1's three", ids(wide), wide.Total)
	}

	tenant, err := h(context.Background(), struct{}{}, principalWith(retentionApp1TenantA))
	if err != nil {
		t.Fatalf("retention.policies tenant: %v", err)
	}
	if !reflect.DeepEqual(ids(tenant), map[string]bool{a.ID.String(): true}) || tenant.Total != 1 {
		t.Fatalf("tenant policies = %v (total %d), want tenant-a's one", ids(tenant), tenant.Total)
	}
}

func TestRetentionPolicyDetailRefusesAPolicyTheViewerDoesNotOwn(t *testing.T) {
	s := newSQLiteStore(t)
	other := retentionSavePolicyIn(t, s, retentionPolicy("app-2", "", "auth", time.Hour))
	own := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "", "auth", time.Hour))

	h := retentionPolicyDetailHandler(Deps{Store: s})
	_, err := h(context.Background(), GetPolicyInput{ID: other.ID.String()}, principalWith(retentionApp1Wide))
	if got := retentionErrCode(t, err); got != fcontract.CodeNotFound {
		t.Fatalf("other app's policy: code = %s, want %s", got, fcontract.CodeNotFound)
	}

	out, err := h(context.Background(), GetPolicyInput{ID: own.ID.String()}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("own policy: %v", err)
	}
	if out.ID != own.ID.String() || out.Duration != "1h0m0s" || out.Category != "auth" {
		t.Fatalf("detail = %+v", out)
	}
}

// ──────────────────────────────────────────────────
// retention.archives
// ──────────────────────────────────────────────────

func TestRetentionArchivesListsOnlyTheViewersScopeAndPages(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()
	record := func(appID, tenantID string, created time.Time) *retention.Archive {
		a := &retention.Archive{
			Entity:        chronicle.Entity{CreatedAt: created, UpdatedAt: created},
			ID:            id.NewArchiveID(),
			PolicyID:      id.NewPolicyID(),
			Category:      "auth",
			EventCount:    10,
			FromTimestamp: created.Add(-time.Hour),
			ToTimestamp:   created,
			SinkName:      "s3",
			AppID:         appID,
			TenantID:      tenantID,
		}
		if err := s.RecordArchive(ctx, a); err != nil {
			t.Fatalf("record archive: %v", err)
		}
		return a
	}

	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	own := []*retention.Archive{
		record("app-1", "", base.Add(3*time.Minute)),
		record("app-1", "", base.Add(2*time.Minute)),
		record("app-1", "", base.Add(1*time.Minute)),
	}
	record("app-2", "", base.Add(4*time.Minute))

	h := retentionArchivesHandler(Deps{Store: s})
	page, err := h(ctx, ArchiveListInput{Limit: 2}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.archives: %v", err)
	}
	if len(page.Archives) != 2 || !page.HasMore {
		t.Fatalf("first page = %d archives, hasMore %v; want 2 and true", len(page.Archives), page.HasMore)
	}
	if page.Archives[0].ID != own[0].ID.String() || page.Archives[1].ID != own[1].ID.String() {
		t.Fatalf("first page = %+v, want app-1's two newest", page.Archives)
	}

	rest, err := h(ctx, ArchiveListInput{Limit: 2, Offset: 2}, principalWith(retentionApp1Wide))
	if err != nil {
		t.Fatalf("retention.archives page 2: %v", err)
	}
	if len(rest.Archives) != 1 || rest.HasMore || rest.Archives[0].ID != own[2].ID.String() {
		t.Fatalf("second page = %+v, hasMore %v; want app-1's last one and no more", rest.Archives, rest.HasMore)
	}

	_, err = h(ctx, ArchiveListInput{Offset: -1}, principalWith(retentionApp1Wide))
	if got := retentionErrCode(t, err); got != fcontract.CodeBadRequest {
		t.Fatalf("negative offset: code = %s, want %s", got, fcontract.CodeBadRequest)
	}
}

// store/redis keys a policy as app:tenant:category, and a save that finds a
// different policy under that key deletes it. Tenant "t" creating "x:auth"
// lands on tenant "t:x"'s "auth" key, so a new category may not carry ":".
// Control characters and edge whitespace are refused too, and so is a
// category over 64 characters.
func TestRetentionSavePolicyCreateRefusesAnUnsafeCategory(t *testing.T) {
	viewer := map[string]any{"app_id": "app-1", "tenant_id": "t"}
	for _, cat := range []string{
		"x:auth", "a:b", ":auth", "x:auth\n", "", strings.Repeat("a", 65), strings.Repeat("é", 65),
		" auth", "auth ", "a\tb", "a\x7fb", "\xff",
	} {
		t.Run(fmt.Sprintf("%q", cat), func(t *testing.T) {
			spy := &retentionPolicySpy{}
			_, err := retentionSavePolicyHandler(Deps{Store: spy})(context.Background(),
				SavePolicyInput{Category: retentionStr(cat), Duration: retentionStr("720h")}, principalWith(viewer))
			if got := retentionErrCode(t, err); got != fcontract.CodeBadRequest {
				t.Fatalf("category %q: code = %s, want %s", cat, got, fcontract.CodeBadRequest)
			}
			if spy.saveCalls != 0 {
				t.Fatalf("SavePolicy was called with category %q", cat)
			}
		})
	}
}

// Anything without ":" and without control characters or edge whitespace
// cannot collide, and operators use slashes, spaces and non-ASCII names.
func TestRetentionSavePolicyCreateAcceptsCategoriesOperatorsUse(t *testing.T) {
	for _, cat := range []string{
		"*", "auth", "user.login", "billing-v2", "auth/session", "user login", "a|b",
		"Überprüfung", "支払い", strings.Repeat("a", 64), strings.Repeat("é", 64),
	} {
		t.Run(cat, func(t *testing.T) {
			s := newSQLiteStore(t)
			out, err := retentionSavePolicyHandler(Deps{Store: s})(context.Background(),
				SavePolicyInput{Category: retentionStr(cat), Duration: retentionStr("720h")}, principalWith(retentionApp1TenantA))
			if err != nil {
				t.Fatalf("category %q refused: %v", cat, err)
			}
			if out.Category != cat {
				t.Fatalf("stored category %q, want %q", out.Category, cat)
			}
		})
	}
}

// A legacy policy created through the HTTP API can carry a category the
// create rule now refuses. Resending it unchanged on an update must still
// work, since an unchanged category writes no new key; changing it is still
// refused.
func TestRetentionSavePolicyUpdateKeepsALegacyCategory(t *testing.T) {
	s := newSQLiteStore(t)
	legacy := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-a", "user:login", 720*time.Hour))
	h := retentionSavePolicyHandler(Deps{Store: s})

	out, err := h(context.Background(),
		SavePolicyInput{ID: retentionStr(legacy.ID.String()), Category: retentionStr("user:login"), Duration: retentionStr("1440h")},
		principalWith(retentionApp1TenantA))
	if err != nil {
		t.Fatalf("updating a legacy policy's duration: %v", err)
	}
	if out.Category != "user:login" || out.Duration != "1440h0m0s" {
		t.Fatalf("updated = %+v, want user:login at 1440h", out)
	}

	if _, err = h(context.Background(),
		SavePolicyInput{ID: retentionStr(legacy.ID.String()), Duration: retentionStr("48h")},
		principalWith(retentionApp1TenantA)); err != nil {
		t.Fatalf("updating a legacy policy without naming its category: %v", err)
	}

	_, err = h(context.Background(),
		SavePolicyInput{ID: retentionStr(legacy.ID.String()), Category: retentionStr("user-login")},
		principalWith(retentionApp1TenantA))
	if got := retentionErrCode(t, err); got != fcontract.CodeBadRequest {
		t.Fatalf("changing the category: code = %s, want %s", got, fcontract.CodeBadRequest)
	}
	got, _ := s.GetPolicy(context.Background(), legacy.ID)
	if got.Category != "user:login" || got.Duration != 48*time.Hour {
		t.Fatalf("stored = %+v, want user:login at 48h", got)
	}
}

// Every earlier detail intent is tested against a same-app, other-tenant
// record as well as another app's.
func TestRetentionPolicyDetailRefusesASiblingTenantsPolicy(t *testing.T) {
	s := newSQLiteStore(t)
	sibling := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-b", "auth", time.Hour))
	own := retentionSavePolicyIn(t, s, retentionPolicy("app-1", "tenant-a", "auth", time.Hour))

	h := retentionPolicyDetailHandler(Deps{Store: s})
	_, err := h(context.Background(), GetPolicyInput{ID: sibling.ID.String()}, principalWith(retentionApp1TenantA))
	if got := retentionErrCode(t, err); got != fcontract.CodeNotFound {
		t.Fatalf("sibling tenant's policy: code = %s, want %s", got, fcontract.CodeNotFound)
	}
	if _, err := h(context.Background(), GetPolicyInput{ID: own.ID.String()}, principalWith(retentionApp1TenantA)); err != nil {
		t.Fatalf("own policy: %v", err)
	}
}

// Archives carry the tenant as well as the app, and a tenant operator must
// see only its own tenant's.
func TestRetentionArchivesAsATenantListsOnlyThatTenant(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()
	record := func(tenantID string) *retention.Archive {
		now := time.Now().UTC().Truncate(time.Second)
		a := &retention.Archive{
			Entity:        chronicle.Entity{CreatedAt: now, UpdatedAt: now},
			ID:            id.NewArchiveID(),
			PolicyID:      id.NewPolicyID(),
			Category:      "auth",
			EventCount:    1,
			FromTimestamp: now.Add(-time.Hour),
			ToTimestamp:   now,
			SinkName:      "s3",
			AppID:         "app-1",
			TenantID:      tenantID,
		}
		if err := s.RecordArchive(ctx, a); err != nil {
			t.Fatalf("record archive: %v", err)
		}
		return a
	}
	own := record("tenant-a")
	record("tenant-b")
	record("")

	out, err := retentionArchivesHandler(Deps{Store: s})(ctx, ArchiveListInput{}, principalWith(retentionApp1TenantA))
	if err != nil {
		t.Fatalf("retention.archives: %v", err)
	}
	if len(out.Archives) != 1 || out.Archives[0].ID != own.ID.String() || out.HasMore {
		t.Fatalf("tenant-a archives = %+v, want only its own one", out.Archives)
	}
}

// moreRemain answers true when its own check fails. False would tell the
// operator the backlog is clear when nobody could look. The enforcer here
// runs cleanly over an empty store, and only the re-check is broken.
func TestRetentionEnforceMoreRemainIsTrueWhenTheCheckFails(t *testing.T) {
	cases := map[string]store.Store{
		"listing policies fails": storeReturning(errors.New("connection refused")),
		"querying events fails": &retentionEventsFailStore{policies: []*retention.Policy{
			retentionPolicy("app-1", "", "auth", 24*time.Hour),
		}},
	}
	for name, depsStore := range cases {
		t.Run(name, func(t *testing.T) {
			clean := &retentionListSpy{}
			h := retentionEnforceHandler(Deps{Store: depsStore, Enforcer: retention.NewEnforcer(clean, nil, nil)})
			out, err := h(context.Background(), struct{}{}, principalWith(retentionApp1Wide))
			if err != nil {
				t.Fatalf("retention.enforce: %v", err)
			}
			if !out.MoreRemain {
				t.Fatal("moreRemain = false after a failed check; that claims nothing remains when nobody could tell")
			}
			if out.Failed {
				t.Fatal("failed = true, but enforcement itself ran cleanly")
			}
		})
	}
}

// ──────────────────────────────────────────────────
// Manifest
// ──────────────────────────────────────────────────

// retentionManifestIntents loads the manifest and indexes its intents.
func retentionManifestIntents(t *testing.T) map[string]fcontract.Intent {
	t.Helper()
	m, err := loader.Load(bytes.NewReader(manifestYAML), "manifest.yaml")
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	intents := map[string]fcontract.Intent{}
	for _, in := range m.Intents {
		intents[in.Name] = in
	}
	return intents
}

func retentionAssertAdminCommand(t *testing.T, intents map[string]fcontract.Intent, name string) {
	t.Helper()
	in, ok := intents[name]
	if !ok {
		t.Fatalf("%s is not in the manifest", name)
	}
	if in.Kind != fcontract.IntentKindCommand || in.Capability != fcontract.CapWrite {
		t.Errorf("%s: kind %s capability %s, want command/write", name, in.Kind, in.Capability)
	}
	if !reflect.DeepEqual(in.Requires.All, []string{"scope:chronicle.admin"}) {
		t.Errorf("%s requires %+v, want all: [scope:chronicle.admin]", name, in.Requires)
	}
}

// The two intents that destroy something directly carry the explicit admin
// scope on top of write, which the transport checks before the handler
// runs. Losing it in a manifest edit would hand purge rights to every
// writer. enforce's invalidations are pinned here too: a purge changes
// every list of events, and verification of the chain it cut through.
func TestRetentionDestructiveCommandsRequireTheAdminScope(t *testing.T) {
	intents := retentionManifestIntents(t)
	for _, name := range []string{"retention.deletePolicy", "retention.enforce"} {
		retentionAssertAdminCommand(t, intents, name)
	}

	wantInvalidates := []string{
		"retention.policies", "retention.archives", "retention.preview",
		"events.list", "events.detail", "events.aggregate", "events.byUser",
		"overview.stats", "streams.mine", "verify.run", "verify.event",
		"erasures.preview",
	}
	if got := intents["retention.enforce"].Invalidates; !reflect.DeepEqual(got, wantInvalidates) {
		t.Errorf("retention.enforce invalidates %v, want %v", got, wantInvalidates)
	}
}

// Saving a policy purges nothing itself, but the background scheduler
// enforces every policy on its next run. A "*" policy with a tiny duration,
// or a shortened existing one, purges history without anyone calling
// retention.enforce, so savePolicy needs the same admin scope.
func TestRetentionSavePolicyRequiresTheAdminScope(t *testing.T) {
	retentionAssertAdminCommand(t, retentionManifestIntents(t), "retention.savePolicy")
}

// Changing or removing a policy changes the policy list, the policy's own
// detail, and what a preview would show.
func TestRetentionPolicyCommandsDeclareTheirInvalidations(t *testing.T) {
	intents := retentionManifestIntents(t)
	want := []string{"retention.policies", "retention.policyDetail", "retention.preview"}
	for _, name := range []string{"retention.savePolicy", "retention.deletePolicy"} {
		if got := intents[name].Invalidates; !reflect.DeepEqual(got, want) {
			t.Errorf("%s invalidates %v, want %v", name, got, want)
		}
	}
}
