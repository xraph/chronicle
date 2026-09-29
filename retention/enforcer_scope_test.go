package retention_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store/memory"
)

// misbehavingPolicyStore answers every ListPolicies call with a fixed set of
// policies, whatever scope was asked for, and records what the enforcer
// then does with them. The rest is a real memory store, so the events a
// query selects are the ones a correct backend would select.
type misbehavingPolicyStore struct {
	*memory.Store
	policies []*retention.Policy

	queried []retention.Scope
	purged  []id.ID
}

func (s *misbehavingPolicyStore) ListPolicies(context.Context, retention.ListPoliciesOpts) ([]*retention.Policy, error) {
	return s.policies, nil
}

func (s *misbehavingPolicyStore) EventsOlderThan(ctx context.Context, q retention.PurgeQuery) ([]*audit.Event, error) {
	s.queried = append(s.queried, q.Scope)
	return s.Store.EventsOlderThan(ctx, q)
}

func (s *misbehavingPolicyStore) PurgeEvents(ctx context.Context, ids []id.ID) (int64, error) {
	s.purged = append(s.purged, ids...)
	return s.Store.PurgeEvents(ctx, ids)
}

func scopedPolicy(appID, tenantID string) *retention.Policy {
	p := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: time.Hour,
		AppID:    appID,
		TenantID: tenantID,
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	return p
}

// reviewerStore is the case a reviewer hit: a tenant-a viewer's listing comes
// back with its own policy, another app's, and one with no app at all, and
// every one of those scopes has expired events waiting.
func reviewerStore(t *testing.T) (*misbehavingPolicyStore, []*audit.Event) {
	t.Helper()
	s := &misbehavingPolicyStore{
		Store: memory.New(),
		policies: []*retention.Policy{
			scopedPolicy("app-1", "tenant-a"),
			scopedPolicy("app-2", ""),
			scopedPolicy("", ""),
		},
	}
	own := seedEventsForApp(t, s.Store, "app-1", "tenant-a", "auth", 2, 48*time.Hour)
	seedEventsForApp(t, s.Store, "app-2", "", "auth", 3, 48*time.Hour)
	seedEventsForApp(t, s.Store, "", "", "auth", 4, 48*time.Hour)
	return s, own
}

// assertOnlyOwnScopeTouched checks that app-1/tenant-a is the only scope the
// enforcer queried and that it purged exactly that scope's events.
func assertOnlyOwnScopeTouched(t *testing.T, s *misbehavingPolicyStore, own []*audit.Event) {
	t.Helper()
	want := retention.Scope{AppID: "app-1", TenantID: "tenant-a"}
	for _, q := range s.queried {
		if q != want {
			t.Errorf("EventsOlderThan queried %+v; only %+v belongs to the viewer", q, want)
		}
	}
	if len(s.purged) != len(own) {
		t.Fatalf("purged %d events, want %d (the viewer's own)", len(s.purged), len(own))
	}
	ownIDs := make(map[id.ID]bool, len(own))
	for _, e := range own {
		ownIDs[e.ID] = true
	}
	for _, pid := range s.purged {
		if !ownIDs[pid] {
			t.Errorf("purged event %s, which is not the viewer's", pid)
		}
	}
}

// TestEnforceScopeIgnoresPoliciesOutsideTheScope covers a store whose
// ListPolicies ignores the scope. EnforceScope must still run only the
// policies inside the scope it was given.
func TestEnforceScopeIgnoresPoliciesOutsideTheScope(t *testing.T) {
	s, own := reviewerStore(t)

	_, err := retention.NewEnforcer(s, nil, nil, retention.WithUnrecordedPurge()).
		EnforceScope(context.Background(), retention.Scope{AppID: "app-1", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("EnforceScope: %v", err)
	}

	assertOnlyOwnScopeTouched(t, s, own)
}

// TestEnforceScopeFuncRunsOnlyWhatTheFilterKeeps is the hook a caller with
// its own ownership rule uses. Here the viewer is app-level, so a tenant's
// policy is inside the listing scope, and the filter still turns it away.
func TestEnforceScopeFuncRunsOnlyWhatTheFilterKeeps(t *testing.T) {
	s := &misbehavingPolicyStore{
		Store: memory.New(),
		policies: []*retention.Policy{
			scopedPolicy("app-1", "tenant-a"),
			scopedPolicy("app-1", "tenant-b"),
		},
	}
	own := seedEventsForApp(t, s.Store, "app-1", "tenant-a", "auth", 2, 48*time.Hour)
	spared := seedEventsForApp(t, s.Store, "app-1", "tenant-b", "auth", 3, 48*time.Hour)

	keep := func(p *retention.Policy) bool { return p.TenantID == "tenant-a" }
	_, err := retention.NewEnforcer(s, nil, nil, retention.WithUnrecordedPurge()).
		EnforceScopeFunc(context.Background(), retention.Scope{AppID: "app-1"}, keep)
	if err != nil {
		t.Fatalf("EnforceScopeFunc: %v", err)
	}

	assertOnlyOwnScopeTouched(t, s, own)
	for _, e := range spared {
		if _, getErr := s.Get(context.Background(), e.ID); getErr != nil {
			t.Errorf("tenant-b event %s was purged against the filter: %v", e.ID, getErr)
		}
	}
}

// TestEnforceScopeFuncWithTheReviewersListing replays the reviewer's spy: the
// filter admits only the viewer's own policy, and nothing else reaches the
// store's purge path.
func TestEnforceScopeFuncWithTheReviewersListing(t *testing.T) {
	s, own := reviewerStore(t)

	owns := func(p *retention.Policy) bool { return p.AppID == "app-1" && p.TenantID == "tenant-a" }
	_, err := retention.NewEnforcer(s, nil, nil, retention.WithUnrecordedPurge()).
		EnforceScopeFunc(context.Background(), retention.Scope{AppID: "app-1", TenantID: "tenant-a"}, owns)
	if err != nil {
		t.Fatalf("EnforceScopeFunc: %v", err)
	}

	assertOnlyOwnScopeTouched(t, s, own)
}

// TestEnforceRefusesAPolicyWithNoApp covers the background run, which lists
// with a zero scope and so cannot drop anything by scope. A policy with no
// AppID must still never reach the purge path.
func TestEnforceRefusesAPolicyWithNoApp(t *testing.T) {
	s := &misbehavingPolicyStore{
		Store:    memory.New(),
		policies: []*retention.Policy{scopedPolicy("", "")},
	}
	seedEventsForApp(t, s.Store, "", "", "auth", 4, 48*time.Hour)

	_, err := retention.NewEnforcer(s, nil, nil, retention.WithUnrecordedPurge()).Enforce(context.Background())
	if !errors.Is(err, retention.ErrPolicyWithoutApp) {
		t.Fatalf("Enforce error = %v, want ErrPolicyWithoutApp", err)
	}
	if len(s.queried) != 0 {
		t.Errorf("EventsOlderThan queried %+v for a policy with no app", s.queried)
	}
	if len(s.purged) != 0 {
		t.Errorf("purged %d events for a policy with no app", len(s.purged))
	}
}

// TestEnforceStillRunsOtherPoliciesAfterRefusingOne makes sure the refusal is
// per policy: one bad row does not stop the rest of the background run.
func TestEnforceStillRunsOtherPoliciesAfterRefusingOne(t *testing.T) {
	s := &misbehavingPolicyStore{
		Store: memory.New(),
		policies: []*retention.Policy{
			scopedPolicy("", ""),
			scopedPolicy("app-1", "tenant-a"),
		},
	}
	own := seedEventsForApp(t, s.Store, "app-1", "tenant-a", "auth", 2, 48*time.Hour)

	res, err := retention.NewEnforcer(s, nil, nil, retention.WithUnrecordedPurge()).Enforce(context.Background())
	if !errors.Is(err, retention.ErrPolicyWithoutApp) {
		t.Fatalf("Enforce error = %v, want ErrPolicyWithoutApp", err)
	}
	if res == nil || res.Purged != int64(len(own)) {
		t.Fatalf("result = %+v, want %d purged by the valid policy", res, len(own))
	}
	assertOnlyOwnScopeTouched(t, s, own)
}
