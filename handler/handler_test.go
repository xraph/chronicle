package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/handler"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store/memory"
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

	req := httptest.NewRequest(method, path, reqBody)
	req = req.WithContext(ctx)
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
