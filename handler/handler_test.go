package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/handler"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

const (
	testAppID    = "app_test"
	testTenantID = "tenant_test"
	testUserID   = "user_test"
)

// testSetup creates a handler with a seeded in-memory store.
type testSetup struct {
	handler http.Handler
	store   *memory.Store
	events  []*audit.Event
}

func newTestSetup(t *testing.T) *testSetup {
	t.Helper()

	store := memory.New()
	logger := log.NewNoopLogger()

	// Create a compliance engine for report testing.
	engine := compliance.NewEngine(store, store, store, logger)

	// Create a retention enforcer (nil archive sink for tests).
	enforcer := retention.NewEnforcer(store, nil, logger)

	router := forge.NewRouter()
	api := handler.New(handler.Dependencies{
		AuditStore:     store,
		VerifyStore:    store,
		StreamStore:    store,
		ErasureStore:   store,
		RetentionStore: store,
		ReportStore:    store,
		Compliance:     engine,
		Retention:      enforcer,
		Logger:         logger,
	}, router)
	api.RegisterRoutes(router)

	// Seed test events.
	events := seedEvents(t, store)

	return &testSetup{
		handler: router.Handler(),
		store:   store,
		events:  events,
	}
}

func seedEvents(t *testing.T, store *memory.Store) []*audit.Event {
	t.Helper()

	now := time.Now().UTC()
	events := []*audit.Event{
		{
			ID:        id.NewAuditID(),
			Timestamp: now.Add(-2 * time.Hour),
			AppID:     testAppID,
			TenantID:  testTenantID,
			UserID:    testUserID,
			Action:    "login",
			Resource:  "session",
			Category:  "auth",
			Outcome:   audit.OutcomeSuccess,
			Severity:  audit.SeverityInfo,
		},
		{
			ID:        id.NewAuditID(),
			Timestamp: now.Add(-1 * time.Hour),
			AppID:     testAppID,
			TenantID:  testTenantID,
			UserID:    testUserID,
			Action:    "read",
			Resource:  "document",
			Category:  "data",
			Outcome:   audit.OutcomeSuccess,
			Severity:  audit.SeverityInfo,
		},
		{
			ID:        id.NewAuditID(),
			Timestamp: now.Add(-30 * time.Minute),
			AppID:     testAppID,
			TenantID:  testTenantID,
			UserID:    "user_other",
			Action:    "delete",
			Resource:  "document",
			Category:  "data",
			Outcome:   audit.OutcomeFailure,
			Severity:  audit.SeverityWarning,
			SubjectID: "subject_1",
		},
		{
			ID:        id.NewAuditID(),
			Timestamp: now,
			AppID:     testAppID,
			TenantID:  "tenant_other",
			UserID:    "user_alien",
			Action:    "login",
			Resource:  "session",
			Category:  "auth",
			Outcome:   audit.OutcomeSuccess,
			Severity:  audit.SeverityInfo,
		},
	}

	ctx := context.Background()
	for _, ev := range events {
		if err := store.Append(ctx, ev); err != nil {
			t.Fatalf("failed to seed event: %v", err)
		}
	}

	return events
}

// scopedContext returns a context with the test app and tenant scope set.
// Uses both chronicle scope (for scope.FromContext) and forge scope (for forge.ScopeFrom).
func scopedContext(ctx context.Context) context.Context {
	ctx = scope.WithAppID(ctx, testAppID)
	ctx = scope.WithTenantID(ctx, testTenantID)
	// Also set forge scope so the scope bridging works.
	ctx = forge.WithScope(ctx, forge.NewOrgScope(testAppID, testTenantID))
	return ctx
}

// do performs an HTTP request with proper scope context.
func (ts *testSetup) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return ts.doWithContext(scopedContext(context.Background()), t, method, path, body)
}

// doWithContext performs an HTTP request with the provided context.
func (ts *testSetup) doWithContext(ctx context.Context, t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reqBody *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = &bytes.Buffer{}
	}

	req, err := http.NewRequestWithContext(ctx, method, path, reqBody)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)
	return rec
}

// ──────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────

func TestListEvents(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/events", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result audit.QueryResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Only events matching the scoped tenant should be returned.
	for _, ev := range result.Events {
		if ev.TenantID != testTenantID {
			t.Errorf("expected tenant_id %q, got %q", testTenantID, ev.TenantID)
		}
	}
}

func TestListEventsWithFilters(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/events?category=auth&order=asc", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result audit.QueryResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	for _, ev := range result.Events {
		if ev.Category != "auth" {
			t.Errorf("expected category 'auth', got %q", ev.Category)
		}
	}
}

func TestGetEvent(t *testing.T) {
	ts := newTestSetup(t)

	// Get the first event (which belongs to our test tenant).
	eventID := ts.events[0].ID.String()
	rec := ts.do(t, http.MethodGet, "/v1/events/"+eventID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var event audit.Event
	if err := json.NewDecoder(rec.Body).Decode(&event); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if event.ID.String() != eventID {
		t.Errorf("expected event id %q, got %q", eventID, event.ID.String())
	}
}

func TestGetEventNotFound(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/events/audit_00000000000000000000000000", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetEventWrongTenant(t *testing.T) {
	ts := newTestSetup(t)

	// Event at index 3 belongs to "tenant_other", which should be blocked by scope.
	eventID := ts.events[3].ID.String()
	rec := ts.do(t, http.MethodGet, "/v1/events/"+eventID, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404 for cross-tenant access, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEventsByUser(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/events/user/"+testUserID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result audit.QueryResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	for _, ev := range result.Events {
		if ev.UserID != testUserID {
			t.Errorf("expected user_id %q, got %q", testUserID, ev.UserID)
		}
	}
}

func TestAggregateEvents(t *testing.T) {
	ts := newTestSetup(t)

	body := audit.AggregateQuery{
		GroupBy: []string{"category"},
	}

	rec := ts.do(t, http.MethodPost, "/v1/events/aggregate", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result audit.AggregateResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Total == 0 {
		t.Error("expected non-zero total in aggregate result")
	}
}

func TestUnauthorizedNoScope(t *testing.T) {
	ts := newTestSetup(t)

	// Request without scope context.
	rec := ts.doWithContext(context.Background(), t, http.MethodGet, "/v1/events", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTenantIsolation(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/events", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var result audit.QueryResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Ensure none of the returned events belong to another tenant.
	for _, ev := range result.Events {
		if ev.TenantID != testTenantID {
			t.Errorf("tenant isolation breach: expected %q, got %q for event %s",
				testTenantID, ev.TenantID, ev.ID.String())
		}
	}
}

func TestListPolicies(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/retention", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSaveAndDeletePolicy(t *testing.T) {
	ts := newTestSetup(t)

	body := map[string]any{
		"category": "auth",
		"duration": "720h",
		"archive":  true,
	}

	// Save
	rec := ts.do(t, http.MethodPost, "/v1/retention", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var policy retention.Policy
	if err := json.NewDecoder(rec.Body).Decode(&policy); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if policy.Category != "auth" {
		t.Errorf("expected category 'auth', got %q", policy.Category)
	}
	if !policy.Archive {
		t.Error("expected archive to be true")
	}

	// Delete
	rec = ts.do(t, http.MethodDelete, "/v1/retention/"+policy.ID.String(), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Confirm it's gone.
	rec = ts.do(t, http.MethodGet, "/v1/retention", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var policies []*retention.Policy
	if err := json.NewDecoder(rec.Body).Decode(&policies); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	for _, p := range policies {
		if p.ID.String() == policy.ID.String() {
			t.Error("policy should have been deleted")
		}
	}
}

func TestGetStats(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/stats", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var stats map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := stats["total_events"]; !ok {
		t.Error("expected total_events in stats response")
	}
}

func TestRequestErasure(t *testing.T) {
	ts := newTestSetup(t)

	body := map[string]any{
		"subject_id":   "subject_1",
		"reason":       "GDPR request",
		"requested_by": "admin",
	}

	rec := ts.do(t, http.MethodPost, "/v1/erasures", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := result["id"]; !ok {
		t.Error("expected id in erasure result")
	}
}

func TestListErasures(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/erasures", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEnforceRetention(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodPost, "/v1/retention/enforce", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestListArchives(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/retention/archives", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestListReports(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodGet, "/v1/reports", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGenerateSOC2Report(t *testing.T) {
	ts := newTestSetup(t)

	body := compliance.SOC2Input{
		Period: compliance.DateRange{
			From: time.Now().Add(-24 * time.Hour),
			To:   time.Now(),
		},
		GeneratedBy: "admin",
	}

	rec := ts.do(t, http.MethodPost, "/v1/reports/soc2", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var report compliance.Report
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if report.Type != "soc2" {
		t.Errorf("expected report type 'soc2', got %q", report.Type)
	}
	if report.AppID != testAppID {
		t.Errorf("expected app_id %q, got %q", testAppID, report.AppID)
	}
}

// ──────────────────────────────────────────────────
// Response shape
// ──────────────────────────────────────────────────

// TestResponsesCarryExactlyOneJSONDocument pins the double-serialisation fix.
//
// Handlers used to both call ctx.JSON and return the value; forge serialises a
// non-nil first return too, so every body contained the payload twice. A
// json.Decoder stops after the first document, which is why the other tests
// never noticed — this one asserts nothing follows it.
func TestResponsesCarryExactlyOneJSONDocument(t *testing.T) {
	ts := newTestSetup(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		status int
	}{
		{"listEvents", http.MethodGet, "/v1/events", nil, http.StatusOK},
		{"eventsByUser", http.MethodGet, "/v1/events/user/" + testUserID, nil, http.StatusOK},
		{"stats", http.MethodGet, "/v1/stats", nil, http.StatusOK},
		{"listErasures", http.MethodGet, "/v1/erasures", nil, http.StatusOK},
		{"listPolicies", http.MethodGet, "/v1/retention", nil, http.StatusOK},
		{"listArchives", http.MethodGet, "/v1/retention/archives", nil, http.StatusOK},
		{"listReports", http.MethodGet, "/v1/reports", nil, http.StatusOK},
		{
			"aggregateEvents", http.MethodPost, "/v1/events/aggregate",
			map[string]any{"group_by": []string{"category"}}, http.StatusOK,
		},
		{
			"savePolicy", http.MethodPost, "/v1/retention",
			map[string]any{"category": "auth", "duration": "720h", "archive": false},
			http.StatusCreated,
		},
		{
			"requestErasure", http.MethodPost, "/v1/erasures",
			map[string]any{
				"subject_id":   "subject_1",
				"reason":       "GDPR request",
				"requested_by": testUserID,
			},
			http.StatusCreated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := ts.do(t, tc.method, tc.path, tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}

			dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))

			var first json.RawMessage
			if err := dec.Decode(&first); err != nil {
				t.Fatalf("decode first document: %v (body %q)", err, rec.Body.String())
			}

			// Anything left after the first document means the body was written
			// twice.
			var extra json.RawMessage
			if err := dec.Decode(&extra); err == nil {
				t.Fatalf("body contains a second JSON document: %q", rec.Body.String())
			} else if !errors.Is(err, io.EOF) {
				t.Fatalf("expected EOF after the first document, got %v (body %q)", err, rec.Body.String())
			}
		})
	}
}

// TestAggregateRejectsInjectedGroupBy pins that the HTTP layer refuses an
// injected group_by rather than passing it to the store.
func TestAggregateRejectsInjectedGroupBy(t *testing.T) {
	ts := newTestSetup(t)

	rec := ts.do(t, http.MethodPost, "/v1/events/aggregate", map[string]any{
		"group_by": []string{"category, (SELECT COUNT(*) FROM chronicle_streams)"},
	})

	if rec.Code == http.StatusOK {
		t.Fatalf("injected group_by was accepted: %s", rec.Body.String())
	}
}

// TestCrossTenantReadsAreNotVisible pins that a caller scoped to one app cannot
// read another app's events, erasures, policies or reports.
func TestCrossTenantReadsAreNotVisible(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()

	// Seed a record owned by a different app.
	otherEvent := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  id.NewStreamID(),
		Sequence:  1,
		Hash:      "other-hash",
		AppID:     "app_other",
		TenantID:  "tenant_other",
		UserID:    testUserID,
		Action:    "other.action",
		Resource:  "other",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Timestamp: time.Now().UTC(),
	}
	if err := ts.store.Append(ctx, otherEvent); err != nil {
		t.Fatalf("seed other-app event: %v", err)
	}

	t.Run("listEvents", func(t *testing.T) {
		rec := ts.do(t, http.MethodGet, "/v1/events", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var result audit.QueryResult
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, e := range result.Events {
			if e.AppID != testAppID {
				t.Fatalf("leaked event from app %q", e.AppID)
			}
		}
	})

	t.Run("getEvent", func(t *testing.T) {
		rec := ts.do(t, http.MethodGet, "/v1/events/"+otherEvent.ID.String(), nil)
		if rec.Code == http.StatusOK {
			t.Fatalf("another app's event was readable by ID: %s", rec.Body.String())
		}
	})

	t.Run("eventsByUser", func(t *testing.T) {
		rec := ts.do(t, http.MethodGet, "/v1/events/user/"+testUserID, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var result audit.QueryResult
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(result.Events) == 0 {
			t.Fatal("expected the caller's own events to be returned")
		}
		for _, e := range result.Events {
			if e.AppID != testAppID {
				t.Fatalf("leaked event from app %q", e.AppID)
			}
		}
	})
}

// TestEnforceRetentionDoesNotPurgeOtherApps pins that the enforce endpoint runs
// only the caller's policies.
func TestEnforceRetentionDoesNotPurgeOtherApps(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()

	victim := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  id.NewStreamID(),
		Sequence:  1,
		Hash:      "victim-hash",
		AppID:     "app_other",
		TenantID:  "tenant_other",
		Action:    "other.action",
		Resource:  "other",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Timestamp: time.Now().UTC().Add(-72 * time.Hour),
	}
	if err := ts.store.Append(ctx, victim); err != nil {
		t.Fatalf("seed other-app event: %v", err)
	}

	// The caller registers an aggressive policy on the same category.
	rec := ts.do(t, http.MethodPost, "/v1/retention", map[string]any{
		"category": "auth",
		"duration": "1h",
		"archive":  false,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("savePolicy status = %d: %s", rec.Code, rec.Body.String())
	}

	rec = ts.do(t, http.MethodPost, "/v1/retention/enforce", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("enforce status = %d: %s", rec.Code, rec.Body.String())
	}

	if _, err := ts.store.Get(ctx, victim.ID); err != nil {
		t.Fatalf("another app's event was purged by the caller's policy: %v", err)
	}
}

// TestVerifyChainRejectsOtherTenantsStream pins that chain verification confirms
// stream ownership. A stream is per app+tenant, so verifying someone else's
// leaks its event count, sequence range and integrity status.
func TestVerifyChainRejectsOtherTenantsStream(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()

	other := &stream.Stream{
		ID:       id.NewStreamID(),
		AppID:    "app_other",
		TenantID: "tenant_other",
	}
	if err := ts.store.CreateStream(ctx, other); err != nil {
		t.Fatalf("create other stream: %v", err)
	}

	rec := ts.do(t, http.MethodPost, "/v1/verify", map[string]any{
		"stream_id": other.ID.String(),
		"from_seq":  1,
		"to_seq":    10,
	})

	if rec.Code == http.StatusOK {
		t.Fatalf("verified another tenant's stream: %s", rec.Body.String())
	}
}

// TestVerifyChainAcceptsOwnStream keeps the endpoint working for its owner.
func TestVerifyChainAcceptsOwnStream(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()

	own := &stream.Stream{
		ID:       id.NewStreamID(),
		AppID:    testAppID,
		TenantID: testTenantID,
	}
	if err := ts.store.CreateStream(ctx, own); err != nil {
		t.Fatalf("create own stream: %v", err)
	}

	rec := ts.do(t, http.MethodPost, "/v1/verify", map[string]any{
		"stream_id": own.ID.String(),
		"from_seq":  1,
		"to_seq":    10,
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// TestVerifyChainDefaultsToGenesisThroughHead pins the behaviour this task
// changes: POST /v1/verify used to reject a request with no to_seq outright
// ("to_seq must be greater than 0"). Omitting the range now means "verify
// genesis to head", and the report says so: not Partial, and HeadMatch true
// against the stream's own recorded head.
func TestVerifyChainDefaultsToGenesisThroughHead(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()

	st := &stream.Stream{
		ID:       id.NewStreamID(),
		AppID:    testAppID,
		TenantID: testTenantID,
	}
	if err := ts.store.CreateStream(ctx, st); err != nil {
		t.Fatalf("create stream: %v", err)
	}

	event := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  st.ID,
		Sequence:  1,
		Timestamp: time.Now().UTC(),
		AppID:     testAppID,
		TenantID:  testTenantID,
		Action:    "login",
		Resource:  "session",
		Category:  "auth",
	}
	var plain hash.Chain
	digest, _, err := plain.Compute(ctx, "", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme = digest, string(hash.SchemePlain)

	if err := ts.store.Append(ctx, event); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := ts.store.UpdateStreamHead(ctx, st.ID, event.Hash, event.Sequence); err != nil {
		t.Fatalf("UpdateStreamHead: %v", err)
	}

	rec := ts.do(t, http.MethodPost, "/v1/verify", map[string]any{
		"stream_id": st.ID.String(),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var report verify.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !report.Valid {
		t.Fatalf("report = %+v, want Valid", report)
	}
	if report.Partial {
		t.Error("a request with no from_seq/to_seq should not be Partial")
	}
	if !report.HeadMatch {
		t.Error("HeadMatch is false even though the verified tail is the stream's recorded head")
	}
	if report.Verified != 1 {
		t.Errorf("Verified = %d, want 1", report.Verified)
	}
}

// TestVerifyChainDetectsSchemeDowngrade pins that POST /v1/verify actually
// uses the stream's pin. A pin the handler never builds cannot expose a
// downgrade: hash.Chain.VerifyWithPin only flags one when the event's
// sequence is at or above pin.Since, and a zero-value Pin has Since 0 and
// Scheme "", which disables the check entirely (see hash/chain.go).
//
// The event below claims the weaker chronicle/v2 scheme while its stream is
// pinned to chronicle/v3 from sequence 1 -- exactly what an attacker gets by
// relabeling a tampered event and recomputing under the weaker algorithm.
func TestVerifyChainDetectsSchemeDowngrade(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()

	st := &stream.Stream{
		ID:          id.NewStreamID(),
		AppID:       testAppID,
		TenantID:    testTenantID,
		Scheme:      "chronicle/v3",
		SchemeSince: 1,
	}
	if err := ts.store.CreateStream(ctx, st); err != nil {
		t.Fatalf("create stream: %v", err)
	}

	// Append bypasses Chronicle, so nothing here recomputes the digest; this
	// stands in for an event an attacker already downgraded and relabeled.
	if err := ts.store.Append(ctx, &audit.Event{
		ID:         id.NewAuditID(),
		StreamID:   st.ID,
		Sequence:   1,
		Timestamp:  time.Now().UTC(),
		AppID:      testAppID,
		TenantID:   testTenantID,
		Action:     "login",
		Resource:   "session",
		Category:   "auth",
		HashScheme: "chronicle/v2",
		Hash:       "does-not-matter-for-downgrade-detection",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	rec := ts.do(t, http.MethodPost, "/v1/verify", map[string]any{
		"stream_id": st.ID.String(),
		"from_seq":  1,
		"to_seq":    1,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var report verify.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if len(report.Downgrades) != 1 || report.Downgrades[0] != 1 {
		t.Fatalf("Downgrades = %v, want [1]; stream pinned to chronicle/v3 but event 1 claims chronicle/v2", report.Downgrades)
	}
}

// stubHandlerKeyProvider mirrors the stub key providers used elsewhere
// (chronicle_test.go, hash/scheme_test.go, store/sqlite/scheme_test.go,
// extension/tamper_evidence_test.go): a fixed key behind keys.Provider.
type stubHandlerKeyProvider struct {
	key      []byte
	activeID string
}

func (s stubHandlerKeyProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return s.key, s.activeID, nil
}

func (s stubHandlerKeyProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != s.activeID {
		return nil, keys.ErrKeyNotFound
	}
	return s.key, nil
}

// verifyEventWithChain builds a fresh API over store with the given
// HashChain (nil is valid: handler.New defaults it to a plain, unkeyed
// chain) and POSTs /v1/verify for the given stream/range.
func verifyEventWithChain(t *testing.T, store *memory.Store, chain *hash.Chain, streamID string) *httptest.ResponseRecorder {
	t.Helper()

	router := forge.NewRouter()
	api := handler.New(handler.Dependencies{
		AuditStore:  store,
		VerifyStore: store,
		StreamStore: store,
		Logger:      log.NewNoopLogger(),
		HashChain:   chain,
	}, router)
	api.RegisterRoutes(router)

	body, err := json.Marshal(map[string]any{"stream_id": streamID, "from_seq": 1, "to_seq": 1})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequestWithContext(scopedContext(context.Background()), http.MethodPost, "/v1/verify", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	router.Handler().ServeHTTP(rec, req)
	return rec
}

// TestVerifyChainVerifiesUnderTheConfiguredHMACChain closes a gap
// TestVerifyChainDetectsSchemeDowngrade leaves open: that test's downgrade is
// reported by hash.Chain.VerifyWithPin's rank comparison alone, before any
// digest is recomputed (see hash/chain.go), so it proves Pin reached the
// verifier but nothing about a.deps.HashChain. Deleting HashChain from the
// Dependencies literal, or reverting verify.NewVerifierWithChain back to
// NewVerifier, leaves it passing.
//
// This test carries a genuine HMAC digest (computed with the same chain the
// "with" case verifies under) on an event whose stream is pinned to the same
// scheme it claims, so Pin's rank comparison alone cannot explain a pass:
// only recomputing under the real keyed chain can.
func TestVerifyChainVerifiesUnderTheConfiguredHMACChain(t *testing.T) {
	store := memory.New()
	ctx := context.Background()

	provider := stubHandlerKeyProvider{key: make([]byte, 32), activeID: "hmac-1"}
	chain, err := hash.NewChain(hash.SchemeHMAC, provider)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	st := &stream.Stream{
		ID:          id.NewStreamID(),
		AppID:       testAppID,
		TenantID:    testTenantID,
		Scheme:      "chronicle/v3",
		SchemeSince: 1,
	}
	if createErr := store.CreateStream(ctx, st); createErr != nil {
		t.Fatalf("create stream: %v", createErr)
	}

	event := &audit.Event{
		ID: id.NewAuditID(), StreamID: st.ID, Sequence: 1, Timestamp: time.Now().UTC(),
		AppID: testAppID, TenantID: testTenantID,
		Action: "login", Resource: "session", Category: "auth",
	}
	digest, keyID, err := chain.Compute(ctx, "", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash = digest
	event.HashKeyID = keyID
	event.HashScheme = string(hash.SchemeHMAC)
	if err := store.Append(ctx, event); err != nil {
		t.Fatalf("append: %v", err)
	}

	t.Run("with the keyed chain, verification succeeds", func(t *testing.T) {
		rec := verifyEventWithChain(t, store, chain, st.ID.String())
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		var report verify.Report
		if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &report); unmarshalErr != nil {
			t.Fatalf("decode report: %v", unmarshalErr)
		}
		if !report.Valid || len(report.Tampered) != 0 || len(report.Downgrades) != 0 {
			t.Fatalf("report = %+v, want Valid with no Tampered/Downgrades", report)
		}
	})

	t.Run("without the keyed chain, verification fails or errors", func(t *testing.T) {
		rec := verifyEventWithChain(t, store, nil, st.ID.String())
		if rec.Code == http.StatusOK {
			var report verify.Report
			if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &report); unmarshalErr == nil && report.Valid {
				t.Fatalf("report = %+v, want an HTTP error or Valid == false: a plain chain has no key "+
					"provider and cannot recompute an HMAC digest", report)
			}
		}
	})
}
