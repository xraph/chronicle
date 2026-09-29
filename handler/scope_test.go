package handler_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/stream"
)

// appOnlyContext is a caller scoped to the test app with no tenant: the app
// admin who owns the app's untenanted records.
func appOnlyContext(ctx context.Context) context.Context {
	ctx = scope.WithAppID(ctx, testAppID)
	return forge.WithScope(ctx, forge.NewAppScope(testAppID))
}

// seedAppLevelPolicy saves a retention policy owned by the test app with no
// tenant, the kind an app-scoped caller creates.
func seedAppLevelPolicy(t *testing.T, ts *testSetup) *retention.Policy {
	t.Helper()

	p := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: time.Hour,
		AppID:    testAppID,
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	if err := ts.store.SavePolicy(context.Background(), p); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}
	return p
}

// TestTenantCannotDeleteAppLevelPolicy pins that a tenant-scoped caller cannot
// delete the app's untenanted retention policy. ownedByCaller used to treat an
// empty TenantID on the record as a wildcard, so any tenant could remove the
// policy the app admin set for the whole app.
func TestTenantCannotDeleteAppLevelPolicy(t *testing.T) {
	ts := newTestSetup(t)
	p := seedAppLevelPolicy(t, ts)

	rec := ts.do(t, http.MethodDelete, "/v1/retention/"+p.ID.String(), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}

	if _, err := ts.store.GetPolicy(context.Background(), p.ID); err != nil {
		t.Fatalf("a tenant deleted the app-level policy: %v", err)
	}
}

// TestAppCallerCanDeleteAppLevelPolicy keeps the owner's path working.
func TestAppCallerCanDeleteAppLevelPolicy(t *testing.T) {
	ts := newTestSetup(t)
	p := seedAppLevelPolicy(t, ts)

	rec := ts.doWithContext(appOnlyContext(context.Background()), t,
		http.MethodDelete, "/v1/retention/"+p.ID.String(), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", rec.Code, rec.Body.String())
	}

	if _, err := ts.store.GetPolicy(context.Background(), p.ID); err == nil {
		t.Fatal("the app caller's own policy should have been deleted")
	}
}

// TestTenantCannotVerifyAppLevelStream covers the read side of the same check.
// The app's untenanted stream is never listed for a tenant, so it must not be
// reachable by ID either.
func TestTenantCannotVerifyAppLevelStream(t *testing.T) {
	ts := newTestSetup(t)

	st := &stream.Stream{ID: id.NewStreamID(), AppID: testAppID}
	if err := ts.store.CreateStream(context.Background(), st); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	rec := ts.do(t, http.MethodPost, "/v1/verify", map[string]any{
		"stream_id": st.ID.String(),
		"from_seq":  1,
		"to_seq":    10,
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}
