// Package retentiontest holds checks that every retention.Store backend must
// pass, so the five stores are held to one definition of a purge scope.
package retentiontest

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/stream"
)

// Store is what PurgeScope needs from a backend: the retention methods under
// test, plus enough of the event and stream API to seed events.
type Store interface {
	retention.Store
	Append(ctx context.Context, event *audit.Event) error
	CreateStream(ctx context.Context, s *stream.Stream) error
}

// PurgeScope checks that EventsOlderThan matches a purge query's scope
// exactly. An empty TenantID selects the app's untenanted events and nothing
// else, and an empty AppID selects events with no app. Neither is a wildcard:
// a policy saved at app level must not reach into its tenants' history.
//
// s must start empty of events for the IDs used here. run is appended to every
// app and tenant ID, so backends shared between tests can pass a random value.
func PurgeScope(t *testing.T, s Store, run string) {
	t.Helper()
	ctx := context.Background()

	appA, appB := "app-a-"+run, "app-b-"+run
	t1, t2 := "t1-"+run, "t2-"+run
	auth, billing := "auth-"+run, "billing-"+run

	old := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Millisecond)
	cutoff := time.Now().UTC().Add(-time.Hour)

	type seed struct {
		label                 string
		app, tenant, category string
		count                 int
		ts                    time.Time
	}
	seeds := []seed{
		{"A/untenanted/auth", appA, "", auth, 2, old},
		{"A/untenanted/billing", appA, "", billing, 1, old},
		{"A/untenanted/auth/recent", appA, "", auth, 1, time.Now().UTC()},
		{"A/t1/auth", appA, t1, auth, 2, old},
		{"A/t1/billing", appA, t1, billing, 1, old},
		{"A/t2/auth", appA, t2, auth, 1, old},
		{"B/untenanted/auth", appB, "", auth, 1, old},
		{"no-app/untenanted/auth", "", "", auth, 1, old},
		{"no-app/t1/auth", "", t1, auth, 1, old},
	}

	type streamState struct {
		id  id.ID
		seq uint64
	}
	streams := map[[2]string]*streamState{}
	labelOf := map[string]string{}

	for _, sd := range seeds {
		key := [2]string{sd.app, sd.tenant}
		st := streams[key]
		if st == nil {
			st = &streamState{id: id.NewStreamID()}
			if err := s.CreateStream(ctx, &stream.Stream{
				ID: st.id, AppID: sd.app, TenantID: sd.tenant,
			}); err != nil {
				t.Fatalf("create stream %s: %v", sd.label, err)
			}
			streams[key] = st
		}
		for i := range sd.count {
			st.seq++
			e := &audit.Event{
				ID:        id.NewAuditID(),
				StreamID:  st.id,
				Sequence:  st.seq,
				Hash:      "hash-" + sd.label,
				AppID:     sd.app,
				TenantID:  sd.tenant,
				Action:    "test.action",
				Resource:  "retention",
				Category:  sd.category,
				Outcome:   audit.OutcomeSuccess,
				Severity:  audit.SeverityInfo,
				Timestamp: sd.ts.Add(time.Duration(i) * time.Millisecond),
			}
			if err := s.Append(ctx, e); err != nil {
				t.Fatalf("append %s: %v", sd.label, err)
			}
			labelOf[e.ID.String()] = sd.label
		}
	}

	cases := []struct {
		name     string
		scope    retention.Scope
		category string
		want     []string // seed labels, one entry per event
	}{
		{
			name:     "untenanted policy selects only untenanted events",
			scope:    retention.Scope{AppID: appA},
			category: auth,
			want:     []string{"A/untenanted/auth", "A/untenanted/auth"},
		},
		{
			name:     "untenanted wildcard policy selects only untenanted events",
			scope:    retention.Scope{AppID: appA},
			category: "*",
			want:     []string{"A/untenanted/auth", "A/untenanted/auth", "A/untenanted/billing"},
		},
		{
			name:     "tenant policy selects only that tenant",
			scope:    retention.Scope{AppID: appA, TenantID: t1},
			category: auth,
			want:     []string{"A/t1/auth", "A/t1/auth"},
		},
		{
			name:     "tenant wildcard policy selects only that tenant",
			scope:    retention.Scope{AppID: appA, TenantID: t1},
			category: "*",
			want:     []string{"A/t1/auth", "A/t1/auth", "A/t1/billing"},
		},
		{
			name:     "other app's untenanted policy stays in its app",
			scope:    retention.Scope{AppID: appB},
			category: auth,
			want:     []string{"B/untenanted/auth"},
		},
		{
			name:     "empty app selects only events with no app",
			scope:    retention.Scope{},
			category: auth,
			want:     []string{"no-app/untenanted/auth"},
		},
		{
			name:     "tenant with empty app does not match that tenant in other apps",
			scope:    retention.Scope{TenantID: t1},
			category: auth,
			want:     []string{"no-app/t1/auth"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.EventsOlderThan(ctx, retention.PurgeQuery{
				Scope:    tc.scope,
				Category: tc.category,
				Before:   cutoff,
				Limit:    -1,
			})
			if err != nil {
				t.Fatalf("EventsOlderThan: %v", err)
			}

			gotLabels := make([]string, 0, len(got))
			for _, e := range got {
				label, ok := labelOf[e.ID.String()]
				if !ok {
					label = "unseeded:" + e.AppID + "/" + e.TenantID + "/" + e.Category
				}
				gotLabels = append(gotLabels, label)
			}
			sort.Strings(gotLabels)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)

			if strings.Join(gotLabels, ",") != strings.Join(want, ",") {
				t.Errorf("EventsOlderThan(%+v, %q)\n got %v\nwant %v",
					tc.scope, tc.category, gotLabels, want)
			}
		})
	}
}
