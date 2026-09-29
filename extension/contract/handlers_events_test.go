package contract

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/stream"
)

// ──────────────────────────────────────────────────
// Test doubles. Each is named for the group it serves, so it cannot collide
// with another group's in this package.
// ──────────────────────────────────────────────────

// querySpy is a store.Store that records the last audit.Query it was asked,
// so a test can prove the outgoing query carries the viewer's own scope
// rather than one the request could set itself.
type querySpy struct {
	stubStore
	last *audit.Query
}

func (s *querySpy) Query(_ context.Context, q *audit.Query) (*audit.QueryResult, error) {
	s.last = q
	return &audit.QueryResult{}, nil
}

// storeQueryingStore is a store.Store whose Query always answers a fixed
// result, whatever query it was asked.
type storeQueryingStore struct {
	stubStore
	result *audit.QueryResult
}

func (s *storeQueryingStore) Query(context.Context, *audit.Query) (*audit.QueryResult, error) {
	return s.result, nil
}

// storeQuerying returns a store.Store whose Query answers result.
func storeQuerying(result *audit.QueryResult) store.Store {
	return &storeQueryingStore{result: result}
}

// aggregateSpy is a store.Store that records the last audit.AggregateQuery
// it was asked, and answers a fixed result.
type aggregateSpy struct {
	stubStore
	last   *audit.AggregateQuery
	result *audit.AggregateResult
}

func (s *aggregateSpy) Aggregate(_ context.Context, q *audit.AggregateQuery) (*audit.AggregateResult, error) {
	s.last = q
	if s.result != nil {
		return s.result, nil
	}
	return &audit.AggregateResult{}, nil
}

// storeAggregating returns a store.Store whose Aggregate answers result.
func storeAggregating(result *audit.AggregateResult) store.Store {
	return &aggregateSpy{result: result}
}

// storeWithEventStore is a store.Store whose Get always answers a fixed
// event, whatever ID it was asked for.
type storeWithEventStore struct {
	stubStore
	event *audit.Event
}

func (s *storeWithEventStore) Get(context.Context, id.ID) (*audit.Event, error) {
	return s.event, nil
}

// storeWithEvent returns a store.Store whose Get answers event.
func storeWithEvent(event *audit.Event) store.Store {
	return &storeWithEventStore{event: event}
}

// eventsTouchedStore records whether a handler reached the store at all, and
// through which method, so a refusal test can prove the refusal happened
// before the first store call.
type eventsTouchedStore struct {
	stubStore
	queries    int
	gets       int
	aggregates int
}

func (s *eventsTouchedStore) Query(context.Context, *audit.Query) (*audit.QueryResult, error) {
	s.queries++
	return &audit.QueryResult{}, nil
}

func (s *eventsTouchedStore) Get(context.Context, id.ID) (*audit.Event, error) {
	s.gets++
	return nil, chronicle.ErrEventNotFound
}

func (s *eventsTouchedStore) Aggregate(context.Context, *audit.AggregateQuery) (*audit.AggregateResult, error) {
	s.aggregates++
	return &audit.AggregateResult{}, nil
}

func (s *eventsTouchedStore) calls() int { return s.queries + s.gets + s.aggregates }

// eventsSeedStream creates a stream row so events can satisfy the FK on the
// SQL backends.
func eventsSeedStream(t *testing.T, s store.Store, appID, tenantID string) id.ID {
	t.Helper()
	st := &stream.Stream{ID: id.NewStreamID(), AppID: appID, TenantID: tenantID}
	if err := s.CreateStream(context.Background(), st); err != nil {
		t.Fatalf("create stream %s/%s: %v", appID, tenantID, err)
	}
	return st.ID
}

// eventsSeed appends one event and returns it, for a test to assert against
// afterwards.
func eventsSeed(t *testing.T, s store.Store, streamID id.ID, appID, tenantID, userID, category string, ts time.Time) *audit.Event {
	t.Helper()
	ev := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  streamID,
		Hash:      "hash-" + userID + "-" + ts.Format(time.RFC3339Nano),
		AppID:     appID,
		TenantID:  tenantID,
		UserID:    userID,
		Action:    "test.action",
		Resource:  "test",
		Category:  category,
		Outcome:   "success",
		Severity:  "info",
		Timestamp: ts,
	}
	if err := s.Append(context.Background(), ev); err != nil {
		t.Fatalf("append event: %v", err)
	}
	return ev
}

// ──────────────────────────────────────────────────
// events.list
// ──────────────────────────────────────────────────

// Total comes from the store's own count and not from len(Events). The page
// captions "50 of 12,431 events", and counting the rows on screen would make
// that caption a lie on every page after the first.
func TestEventListReportsTheStoreTotalNotThePageLength(t *testing.T) {
	h := eventsListHandler(Deps{Store: storeQuerying(&audit.QueryResult{
		Events:  make([]*audit.Event, 50),
		Total:   12431,
		HasMore: true,
	})})
	out, err := h(context.Background(), EventListInput{Limit: 50}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("events.list: %v", err)
	}
	if out.Total != 12431 {
		t.Errorf("Total = %d, want 12431", out.Total)
	}
	if !out.HasMore {
		t.Error("HasMore did not survive")
	}
}

// The scope on the outgoing query must come from the principal. A request
// that could set its own AppID could read every tenant's audit log.
func TestEventListStampsTheViewersScope(t *testing.T) {
	spy := &querySpy{}
	h := eventsListHandler(Deps{Store: spy})
	if _, err := h(context.Background(), EventListInput{},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})); err != nil {
		t.Fatalf("events.list: %v", err)
	}
	if spy.last.AppID != "app-1" || spy.last.TenantID != "tenant-a" {
		t.Fatalf("outgoing query scope = %q/%q, want app-1/tenant-a", spy.last.AppID, spy.last.TenantID)
	}
}

func TestEventListDefaultsOrderToDesc(t *testing.T) {
	spy := &querySpy{}
	h := eventsListHandler(Deps{Store: spy})
	if _, err := h(context.Background(), EventListInput{}, principalWith(map[string]any{"app_id": "app-1"})); err != nil {
		t.Fatalf("events.list: %v", err)
	}
	if spy.last.Order != "desc" {
		t.Fatalf("order = %q, want desc", spy.last.Order)
	}
}

func TestEventListDefaultsAndCapsTheLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		want  int
	}{
		{"zero becomes default", 0, 50},
		{"over the cap is capped", 5000, 1000},
		{"within range is untouched", 200, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &querySpy{}
			h := eventsListHandler(Deps{Store: spy})
			if _, err := h(context.Background(), EventListInput{Limit: tc.limit}, principalWith(map[string]any{"app_id": "app-1"})); err != nil {
				t.Fatalf("events.list: %v", err)
			}
			if spy.last.Limit != tc.want {
				t.Fatalf("limit %d clamped to %d, want %d", tc.limit, spy.last.Limit, tc.want)
			}
		})
	}
}

// Every filter field on EventListInput has to reach the outgoing
// audit.Query, or that filter silently stops narrowing the results: dropping
// Categories, say, would widen every filtered list back to "everything",
// and the "N of total"/"no events match" states built on it would be wrong
// without the caller ever finding out. This sets every field to a
// distinguishable value and checks each one lands on the query the store
// sees, so a mutation that drops or mis-wires any single field fails here.
func TestEventListForwardsEveryFilterToTheStore(t *testing.T) {
	spy := &querySpy{}
	h := eventsListHandler(Deps{Store: spy})

	in := EventListInput{
		After:      "2026-01-01T00:00:00Z",
		Before:     "2026-02-01T00:00:00Z",
		UserID:     "alice",
		Categories: []string{"auth", "data"},
		Actions:    []string{"login", "logout"},
		Resources:  []string{"doc", "user"},
		Severity:   []string{"info", "warning"},
		Outcome:    []string{"success", "failure"},
		Order:      "asc",
		Limit:      37,
		Offset:     9,
	}
	if _, err := h(context.Background(), in, principalWith(map[string]any{"app_id": "app-1"})); err != nil {
		t.Fatalf("events.list: %v", err)
	}

	wantAfter, _ := time.Parse(time.RFC3339, in.After)
	wantBefore, _ := time.Parse(time.RFC3339, in.Before)
	got := spy.last

	if !got.After.Equal(wantAfter) {
		t.Errorf("After = %v, want %v", got.After, wantAfter)
	}
	if !got.Before.Equal(wantBefore) {
		t.Errorf("Before = %v, want %v", got.Before, wantBefore)
	}
	if got.UserID != in.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, in.UserID)
	}
	if !reflect.DeepEqual(got.Categories, in.Categories) {
		t.Errorf("Categories = %v, want %v", got.Categories, in.Categories)
	}
	if !reflect.DeepEqual(got.Actions, in.Actions) {
		t.Errorf("Actions = %v, want %v", got.Actions, in.Actions)
	}
	if !reflect.DeepEqual(got.Resources, in.Resources) {
		t.Errorf("Resources = %v, want %v", got.Resources, in.Resources)
	}
	if !reflect.DeepEqual(got.Severity, in.Severity) {
		t.Errorf("Severity = %v, want %v", got.Severity, in.Severity)
	}
	if !reflect.DeepEqual(got.Outcome, in.Outcome) {
		t.Errorf("Outcome = %v, want %v", got.Outcome, in.Outcome)
	}
	if got.Order != in.Order {
		t.Errorf("Order = %q, want %q", got.Order, in.Order)
	}
	if got.Limit != in.Limit {
		t.Errorf("Limit = %d, want %d", got.Limit, in.Limit)
	}
	if got.Offset != in.Offset {
		t.Errorf("Offset = %d, want %d", got.Offset, in.Offset)
	}
}

// A malformed after/before must be refused, not silently treated as the zero
// time -- that would widen the query to the beginning of time. Bad order and
// a negative offset are refused for the same reason: input the store was
// never asked to accept. All three are refused before the store is touched.
func TestEventListRefusesBadInputBeforeTouchingTheStore(t *testing.T) {
	for name, in := range map[string]EventListInput{
		"malformed after":    {After: "not-a-timestamp"},
		"malformed before":   {Before: "yesterday"},
		"unrecognised order": {Order: "sideways"},
		"negative offset":    {Offset: -1},
		"negative limit":     {Limit: -1},
	} {
		t.Run(name, func(t *testing.T) {
			spy := &eventsTouchedStore{}
			h := eventsListHandler(Deps{Store: spy})
			_, err := h(context.Background(), in, principalWith(map[string]any{"app_id": "app-1"}))
			if !errors.Is(err, fcontract.ErrBadRequest) {
				t.Fatalf("err = %v, want BAD_REQUEST", err)
			}
			if spy.calls() != 0 {
				t.Fatalf("handler reached the store %d time(s) before refusing", spy.calls())
			}
		})
	}
}

// ──────────────────────────────────────────────────
// events.detail
// ──────────────────────────────────────────────────

// The store is really reached and the ownership check is what refuses the
// call: a real, parseable ID, an event in a different app AND a different
// tenant from the viewer.
func TestEventDetailRefusesAnotherTenantsEventWithAParseableID(t *testing.T) {
	realID := id.NewAuditID()
	h := eventsDetailHandler(Deps{Store: storeWithEvent(&audit.Event{
		ID: realID, AppID: "app-2", TenantID: "tenant-b",
	})})
	_, err := h(context.Background(), GetEventInput{ID: realID.String()},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

// A tenant viewer must not own a same-app event that belongs to a DIFFERENT
// tenant. This isolates the AppID-matches/TenantID-differs case from
// TestEventDetailRefusesAnotherTenantsEventWithAParseableID, which changes
// both dimensions at once and so cannot tell v.owns(event.AppID, event.TenantID)
// apart from the wrong-argument mutation v.owns(event.AppID, v.TenantID) --
// that mutation compares the viewer's own TenantID to itself and always
// answers true, regardless of which tenant the event actually belongs to.
func TestEventDetailRefusesASameAppOtherTenantsEvent(t *testing.T) {
	realID := id.NewAuditID()
	h := eventsDetailHandler(Deps{Store: storeWithEvent(&audit.Event{
		ID: realID, AppID: "app-1", TenantID: "tenant-b",
	})})
	_, err := h(context.Background(), GetEventInput{ID: realID.String()},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

// An app-wide viewer (no tenant claim) must not own an event in a DIFFERENT
// app. This isolates the AppID-differs case from the same test above, and
// catches the wrong-argument mutation v.owns(v.AppID, event.TenantID) --
// that mutation compares the viewer's own AppID to itself, which always
// answers true for the app check regardless of which app the event actually
// belongs to, so an app-wide viewer would read any app's events.
func TestEventDetailRefusesAnotherAppsEventForAnAppWideViewer(t *testing.T) {
	realID := id.NewAuditID()
	h := eventsDetailHandler(Deps{Store: storeWithEvent(&audit.Event{
		ID: realID, AppID: "app-2", TenantID: "",
	})})
	_, err := h(context.Background(), GetEventInput{ID: realID.String()},
		principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

func TestEventDetailRefusesAnUnparseableIDBeforeTouchingTheStore(t *testing.T) {
	spy := &eventsTouchedStore{}
	h := eventsDetailHandler(Deps{Store: spy})
	_, err := h(context.Background(), GetEventInput{ID: "not-an-id"},
		principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
	if spy.calls() != 0 {
		t.Fatalf("handler reached the store %d time(s) for an unparseable ID", spy.calls())
	}
}

// An event whose subject's key has been destroyed is still readable, never
// an error: the sealed fields read as crypto.ErasedMarker and Erased is
// true, and the detail projection must carry both through unchanged.
func TestEventDetailProjectsAnErasedEventUnchanged(t *testing.T) {
	realID := id.NewAuditID()
	erasedAt := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	h := eventsDetailHandler(Deps{Store: storeWithEvent(&audit.Event{
		ID:        realID,
		AppID:     "app-1",
		Reason:    crypto.ErasedMarker,
		IP:        crypto.ErasedMarker,
		Erased:    true,
		ErasedAt:  &erasedAt,
		ErasureID: "erasure-1",
	})})
	out, err := h(context.Background(), GetEventInput{ID: realID.String()},
		principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("events.detail on an erased event: %v", err)
	}
	if !out.Erased {
		t.Error("Erased did not survive projection")
	}
	if out.Reason != crypto.ErasedMarker {
		t.Errorf("Reason = %q, want the erased marker", out.Reason)
	}
	if out.IP != crypto.ErasedMarker {
		t.Errorf("IP = %q, want the erased marker", out.IP)
	}
	if out.ErasureID != "erasure-1" {
		t.Errorf("ErasureID = %q, want erasure-1", out.ErasureID)
	}
	if out.ErasedAt == "" {
		t.Error("ErasedAt did not survive projection")
	}
}

// ──────────────────────────────────────────────────
// events.aggregate
// ──────────────────────────────────────────────────

func TestEventAggregateRejectsAnUnsupportedGroupBy(t *testing.T) {
	h := eventsAggregateHandler(Deps{Store: newStubStore()})
	_, err := h(context.Background(), AggregateInput{GroupBy: []string{"week"}},
		principalWith(map[string]any{"app_id": "app-1"}))
	if err == nil {
		t.Fatal("accepted an unwhitelisted group_by field")
	}
}

// A bad group_by must be refused before the store is ever asked,
// so it answers BAD_REQUEST with the caller's mistake rather than
// mapStoreError's generic INTERNAL, which would misrepresent bad input as a
// store failure.
func TestEventAggregateRefusesBadGroupByBeforeTouchingTheStoreAndAnswersBadRequest(t *testing.T) {
	for name, groupBy := range map[string][]string{
		"empty":       nil,
		"unsupported": {"week"},
		"duplicate":   {"category", "category"},
		"two buckets": {"day", "hour"},
	} {
		t.Run(name, func(t *testing.T) {
			spy := &eventsTouchedStore{}
			h := eventsAggregateHandler(Deps{Store: spy})
			_, err := h(context.Background(), AggregateInput{GroupBy: groupBy},
				principalWith(map[string]any{"app_id": "app-1"}))
			if !errors.Is(err, fcontract.ErrBadRequest) {
				t.Fatalf("err = %v, want BAD_REQUEST", err)
			}
			if spy.calls() != 0 {
				t.Fatalf("handler reached the store %d time(s) before refusing group_by %v", spy.calls(), groupBy)
			}
		})
	}
}

// A bucketed group (grouping by day) carries its bucket onto the wire.
func TestEventAggregateCarriesTheBucket(t *testing.T) {
	h := eventsAggregateHandler(Deps{Store: storeAggregating(&audit.AggregateResult{
		Groups: []audit.AggregateGroup{{Bucket: "2026-09-20", Count: 2}},
		Total:  2,
	})})
	out, err := h(context.Background(), AggregateInput{GroupBy: []string{"day"}},
		principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("events.aggregate: %v", err)
	}
	if out.Groups[0].Bucket != "2026-09-20" {
		t.Errorf("bucket = %q, want 2026-09-20", out.Groups[0].Bucket)
	}
}

// applyQuery only takes *audit.Query, so AggregateQuery's scope has to be
// stamped by hand. This proves it still happens.
func TestEventAggregateStampsTheViewersScope(t *testing.T) {
	spy := &aggregateSpy{}
	h := eventsAggregateHandler(Deps{Store: spy})
	_, err := h(context.Background(), AggregateInput{GroupBy: []string{"category"}},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))
	if err != nil {
		t.Fatalf("events.aggregate: %v", err)
	}
	if spy.last.AppID != "app-1" || spy.last.TenantID != "tenant-a" {
		t.Fatalf("outgoing aggregate scope = %q/%q, want app-1/tenant-a", spy.last.AppID, spy.last.TenantID)
	}
}

// After, Before and GroupBy all have to reach the outgoing AggregateQuery:
// a dropped After/Before would widen the bucket, and a dropped GroupBy would
// change what the response even means.
func TestEventAggregateForwardsAfterBeforeAndGroupByToTheStore(t *testing.T) {
	spy := &aggregateSpy{}
	h := eventsAggregateHandler(Deps{Store: spy})

	in := AggregateInput{
		After:   "2026-01-01T00:00:00Z",
		Before:  "2026-02-01T00:00:00Z",
		GroupBy: []string{"category", "day"},
	}
	if _, err := h(context.Background(), in, principalWith(map[string]any{"app_id": "app-1"})); err != nil {
		t.Fatalf("events.aggregate: %v", err)
	}

	wantAfter, _ := time.Parse(time.RFC3339, in.After)
	wantBefore, _ := time.Parse(time.RFC3339, in.Before)
	got := spy.last

	if !got.After.Equal(wantAfter) {
		t.Errorf("After = %v, want %v", got.After, wantAfter)
	}
	if !got.Before.Equal(wantBefore) {
		t.Errorf("Before = %v, want %v", got.Before, wantBefore)
	}
	if !reflect.DeepEqual(got.GroupBy, in.GroupBy) {
		t.Errorf("GroupBy = %v, want %v", got.GroupBy, in.GroupBy)
	}
}

// ──────────────────────────────────────────────────
// events.byUser
// ──────────────────────────────────────────────────

// An empty userId is refused before the store is touched.
func TestEventByUserRefusesAnEmptyUserIDBeforeTouchingTheStore(t *testing.T) {
	spy := &eventsTouchedStore{}
	h := eventsByUserHandler(Deps{Store: spy})
	_, err := h(context.Background(), EventsByUserInput{},
		principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrBadRequest) {
		t.Fatalf("err = %v, want BAD_REQUEST", err)
	}
	if spy.calls() != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing an empty userId", spy.calls())
	}
}

// events.byUser goes through Store.Query, not Store.ByUser, and
// the viewer's scope must land on that outgoing Query.
func TestEventByUserGoesThroughQueryWithTheViewersScope(t *testing.T) {
	spy := &querySpy{}
	h := eventsByUserHandler(Deps{Store: spy})
	_, err := h(context.Background(), EventsByUserInput{UserID: "alice"},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))
	if err != nil {
		t.Fatalf("events.byUser: %v", err)
	}
	if spy.last.UserID != "alice" {
		t.Fatalf("outgoing query userID = %q, want alice", spy.last.UserID)
	}
	if spy.last.AppID != "app-1" || spy.last.TenantID != "tenant-a" {
		t.Fatalf("outgoing query scope = %q/%q, want app-1/tenant-a", spy.last.AppID, spy.last.TenantID)
	}
}

func TestEventByUserRefusesAMalformedAfterBeforeTouchingTheStore(t *testing.T) {
	spy := &eventsTouchedStore{}
	h := eventsByUserHandler(Deps{Store: spy})
	_, err := h(context.Background(), EventsByUserInput{UserID: "alice", After: "not-a-timestamp"},
		principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrBadRequest) {
		t.Fatalf("err = %v, want BAD_REQUEST", err)
	}
	if spy.calls() != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing", spy.calls())
	}
}

// A negative offset is refused before the store is touched, the same as
// events.list.
func TestEventByUserRefusesANegativeOffsetBeforeTouchingTheStore(t *testing.T) {
	spy := &eventsTouchedStore{}
	h := eventsByUserHandler(Deps{Store: spy})
	_, err := h(context.Background(), EventsByUserInput{UserID: "alice", Offset: -1},
		principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrBadRequest) {
		t.Fatalf("err = %v, want BAD_REQUEST", err)
	}
	if spy.calls() != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing", spy.calls())
	}
}

// A limit of zero reaching the store as-is would be unlimited on every
// backend (sqlite/postgres skip their LIMIT clause entirely when Limit <= 0,
// and store/redis's applyPagination treats a non-positive limit as "no
// cap") -- an unbounded read of one user's entire audit history. So it gets
// the same default and cap as events.list.
func TestEventByUserDefaultsAndCapsTheLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		want  int
	}{
		{"zero becomes default", 0, 50},
		{"over the cap is capped", 5000, 1000},
		{"within range is untouched", 200, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &querySpy{}
			h := eventsByUserHandler(Deps{Store: spy})
			in := EventsByUserInput{UserID: "alice", Limit: tc.limit}
			if _, err := h(context.Background(), in, principalWith(map[string]any{"app_id": "app-1"})); err != nil {
				t.Fatalf("events.byUser: %v", err)
			}
			if spy.last.Limit != tc.want {
				t.Fatalf("limit %d clamped to %d, want %d", tc.limit, spy.last.Limit, tc.want)
			}
		})
	}
}

// UserID, After, Before, Limit and Offset all have to reach the outgoing
// audit.Query, the same requirement events.list carries for its own filters.
func TestEventByUserForwardsEveryFieldToTheStore(t *testing.T) {
	spy := &querySpy{}
	h := eventsByUserHandler(Deps{Store: spy})

	in := EventsByUserInput{
		UserID: "alice",
		After:  "2026-01-01T00:00:00Z",
		Before: "2026-02-01T00:00:00Z",
		Limit:  37,
		Offset: 9,
	}
	if _, err := h(context.Background(), in, principalWith(map[string]any{"app_id": "app-1"})); err != nil {
		t.Fatalf("events.byUser: %v", err)
	}

	wantAfter, _ := time.Parse(time.RFC3339, in.After)
	wantBefore, _ := time.Parse(time.RFC3339, in.Before)
	got := spy.last

	if got.UserID != in.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, in.UserID)
	}
	if !got.After.Equal(wantAfter) {
		t.Errorf("After = %v, want %v", got.After, wantAfter)
	}
	if !got.Before.Equal(wantBefore) {
		t.Errorf("Before = %v, want %v", got.Before, wantBefore)
	}
	if got.Limit != in.Limit {
		t.Errorf("Limit = %d, want %d", got.Limit, in.Limit)
	}
	if got.Offset != in.Offset {
		t.Errorf("Offset = %d, want %d", got.Offset, in.Offset)
	}
}

// ──────────────────────────────────────────────────
// Real sqlite, two apps: the scope hazard end to end.
// ──────────────────────────────────────────────────

// Chronicle's stores treat an empty AppID as matching every app, so every
// store call this group makes has to carry the viewer's own scope. This
// drives events.list, events.byUser and events.aggregate against a real
// sqlite store seeded with two apps, and checks each stays inside app-1:
// more events are seeded than the page limit, so Total has to come from the
// store's own count, not from what happened to land on the page.
func TestEventsStayInsideTheViewersAppOnSQLite(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()

	streamOne := eventsSeedStream(t, s, "app-1", "")
	streamTwo := eventsSeedStream(t, s, "app-2", "")

	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	const appOneCount = 12
	const pageLimit = 5

	appOneIDs := map[string]bool{}
	for i := range appOneCount {
		ev := eventsSeed(t, s, streamOne, "app-1", "", "alice", "auth", base.Add(time.Duration(i)*time.Minute))
		appOneIDs[ev.ID.String()] = true
	}
	appTwoIDs := map[string]bool{}
	for i := range 6 {
		// Same user and category as app-1's events on purpose: only the app
		// boundary must be what keeps these out of app-1's results.
		ev := eventsSeed(t, s, streamTwo, "app-2", "", "alice", "auth", base.Add(time.Duration(i)*time.Minute))
		appTwoIDs[ev.ID.String()] = true
	}

	viewer := principalWith(map[string]any{"app_id": "app-1"})

	t.Run("events.list", func(t *testing.T) {
		h := eventsListHandler(Deps{Store: s})
		out, err := h(ctx, EventListInput{Limit: pageLimit}, viewer)
		if err != nil {
			t.Fatalf("events.list: %v", err)
		}
		if out.Total != appOneCount {
			t.Fatalf("Total = %d, want %d", out.Total, appOneCount)
		}
		if len(out.Events) != pageLimit {
			t.Fatalf("page length = %d, want %d", len(out.Events), pageLimit)
		}
		if !out.HasMore {
			t.Fatal("HasMore = false, want true: more events exist beyond this page")
		}
		for _, e := range out.Events {
			if !appOneIDs[e.ID] {
				t.Fatalf("events.list returned an event outside app-1: %s", e.ID)
			}
			if appTwoIDs[e.ID] {
				t.Fatalf("events.list leaked an app-2 event: %s", e.ID)
			}
		}
	})

	t.Run("events.byUser", func(t *testing.T) {
		h := eventsByUserHandler(Deps{Store: s})
		out, err := h(ctx, EventsByUserInput{UserID: "alice", Limit: pageLimit}, viewer)
		if err != nil {
			t.Fatalf("events.byUser: %v", err)
		}
		if out.Total != appOneCount {
			t.Fatalf("Total = %d, want %d (app-2's events for the same user must not count)", out.Total, appOneCount)
		}
		if len(out.Events) != pageLimit {
			t.Fatalf("page length = %d, want %d", len(out.Events), pageLimit)
		}
		if !out.HasMore {
			t.Fatal("HasMore = false, want true")
		}
		for _, e := range out.Events {
			if !appOneIDs[e.ID] {
				t.Fatalf("events.byUser returned an event outside app-1: %s", e.ID)
			}
		}
	})

	// Offset has to actually page: HasMore true with no way to move past the
	// first page would strand the caller on it forever.
	t.Run("events.byUser paging", func(t *testing.T) {
		h := eventsByUserHandler(Deps{Store: s})
		seen := map[string]bool{}
		for offset := 0; offset < appOneCount; offset += pageLimit {
			out, err := h(ctx, EventsByUserInput{UserID: "alice", Limit: pageLimit, Offset: offset}, viewer)
			if err != nil {
				t.Fatalf("events.byUser at offset %d: %v", offset, err)
			}
			if out.Total != appOneCount {
				t.Fatalf("offset %d: Total = %d, want %d", offset, out.Total, appOneCount)
			}
			for _, e := range out.Events {
				if seen[e.ID] {
					t.Fatalf("offset %d repeated event %s", offset, e.ID)
				}
				seen[e.ID] = true
				if !appOneIDs[e.ID] {
					t.Fatalf("offset %d returned an event outside app-1: %s", offset, e.ID)
				}
			}
		}
		if len(seen) != appOneCount {
			t.Fatalf("paging visited %d events, want %d", len(seen), appOneCount)
		}
	})

	t.Run("events.aggregate", func(t *testing.T) {
		h := eventsAggregateHandler(Deps{Store: s})
		out, err := h(ctx, AggregateInput{GroupBy: []string{"category"}}, viewer)
		if err != nil {
			t.Fatalf("events.aggregate: %v", err)
		}
		if out.Total != appOneCount {
			t.Fatalf("Total = %d, want %d (app-2's events must not be counted)", out.Total, appOneCount)
		}
		if len(out.Groups) != 1 || out.Groups[0].Category != "auth" || out.Groups[0].Count != appOneCount {
			t.Fatalf("groups = %+v, want a single auth group with count %d", out.Groups, appOneCount)
		}
	})
}
