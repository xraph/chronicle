package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
)

// collidingScopes returns two scopes whose app and tenant, joined with a bare
// ":", read the same: "<app>:b" + ":" + "c" and "<app>" + ":" + "b:c".
func collidingScopes(t *testing.T) (first, second retention.Scope) {
	t.Helper()
	app := "app-" + runSuffix(t)
	return retention.Scope{AppID: app + ":b", TenantID: "c"},
		retention.Scope{AppID: app, TenantID: "b:c"}
}

func recordIn(ctx context.Context, t *testing.T, c *chronicle.Chronicle, sc retention.Scope) *audit.Event {
	t.Helper()
	evt := &audit.Event{
		AppID:    sc.AppID,
		TenantID: sc.TenantID,
		Action:   "test.record",
		Resource: "doc",
		Category: "test",
		Outcome:  audit.OutcomeSuccess,
		Severity: audit.SeverityInfo,
	}
	if err := c.Record(ctx, evt); err != nil {
		t.Fatalf("record in %q/%q: %v", sc.AppID, sc.TenantID, err)
	}
	return evt
}

// Two scopes whose app and tenant join to the same string must still get two
// streams. Before the key carried each part's length, the second scope found
// the first one's stream and appended its events into that tenant's chain.
func TestCollidingScopesGetDifferentStreams(t *testing.T) {
	s, _ := openTestStore(t, true)
	ctx := context.Background()

	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	first, second := collidingScopes(t)
	a := recordIn(ctx, t, c, first)
	b := recordIn(ctx, t, c, second)

	if a.StreamID.String() == b.StreamID.String() {
		t.Fatalf("scopes %q/%q and %q/%q share stream %s: one tenant's events went into the other's chain",
			first.AppID, first.TenantID, second.AppID, second.TenantID, a.StreamID)
	}

	for _, tc := range []struct {
		scope retention.Scope
		want  id.ID
	}{{first, a.StreamID}, {second, b.StreamID}} {
		st, err := s.GetStreamByScope(ctx, tc.scope.AppID, tc.scope.TenantID)
		if err != nil {
			t.Fatalf("GetStreamByScope(%q, %q): %v", tc.scope.AppID, tc.scope.TenantID, err)
		}
		if st.ID.String() != tc.want.String() {
			t.Errorf("GetStreamByScope(%q, %q) = %s, want %s", tc.scope.AppID, tc.scope.TenantID, st.ID, tc.want)
		}
		if st.AppID != tc.scope.AppID || st.TenantID != tc.scope.TenantID {
			t.Errorf("GetStreamByScope(%q, %q) returned a stream owned by %q/%q",
				tc.scope.AppID, tc.scope.TenantID, st.AppID, st.TenantID)
		}
	}
}

// Count's app+tenant path returns the size of the scope index without reading
// the events back, so a shared index key over-counted one tenant with the
// other's events.
func TestCollidingScopesCountSeparately(t *testing.T) {
	s, _ := openTestStore(t, true)
	ctx := context.Background()

	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	first, second := collidingScopes(t)
	recordIn(ctx, t, c, first)
	recordIn(ctx, t, c, second)
	recordIn(ctx, t, c, second)

	for _, tc := range []struct {
		scope retention.Scope
		want  int64
	}{{first, 1}, {second, 2}} {
		got, err := s.Count(ctx, &audit.CountQuery{AppID: tc.scope.AppID, TenantID: tc.scope.TenantID})
		if err != nil {
			t.Fatalf("Count(%q, %q): %v", tc.scope.AppID, tc.scope.TenantID, err)
		}
		if got != tc.want {
			t.Errorf("Count(%q, %q) = %d, want %d", tc.scope.AppID, tc.scope.TenantID, got, tc.want)
		}
	}
}

// A policy is unique per (app, tenant, category). When the uniqueness key was a
// bare join, saving one scope's policy deleted the colliding scope's policy
// for the same category.
func TestCollidingPolicyScopesKeepBothPolicies(t *testing.T) {
	s, _ := openTestStore(t, true)
	ctx := context.Background()

	first, second := collidingScopes(t)
	pa := &retention.Policy{
		ID: id.NewPolicyID(), Category: "auth", Duration: time.Hour,
		AppID: first.AppID, TenantID: first.TenantID,
	}
	pb := &retention.Policy{
		ID: id.NewPolicyID(), Category: "auth", Duration: 2 * time.Hour,
		AppID: second.AppID, TenantID: second.TenantID,
	}
	for _, p := range []*retention.Policy{pa, pb} {
		if err := s.SavePolicy(ctx, p); err != nil {
			t.Fatalf("SavePolicy %s: %v", p.ID, err)
		}
	}

	for _, p := range []*retention.Policy{pa, pb} {
		if _, err := s.GetPolicy(ctx, p.ID); err != nil {
			if errors.Is(err, chronicle.ErrPolicyNotFound) {
				t.Errorf("policy %s for %q/%q was deleted by the colliding scope's save", p.ID, p.AppID, p.TenantID)
				continue
			}
			t.Fatalf("GetPolicy %s: %v", p.ID, err)
		}
	}
}
