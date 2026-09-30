package dashboard_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
)

// appViewerCtx is a request context scoped to the viewer's app with no tenant.
func appViewerCtx() context.Context {
	return scope.WithAppID(context.Background(), viewerApp)
}

// seedAppLevelPolicy saves a retention policy owned by the viewer's app with no
// tenant, the kind an app-scoped viewer creates.
func seedAppLevelPolicy(t *testing.T, ts *dashSetup) *retention.Policy {
	t.Helper()

	p := &retention.Policy{
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: time.Hour,
		AppID:    viewerApp,
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	if err := ts.store.SavePolicy(context.Background(), p); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}
	return p
}

// TestDashboardTenantCannotDeleteAppLevelPolicy pins that a tenant viewer
// cannot delete the app's untenanted retention policy. inScope used to treat an
// empty TenantID on the record as a wildcard, so any tenant in the app could
// remove it.
func TestDashboardTenantCannotDeleteAppLevelPolicy(t *testing.T) {
	ts := newDashSetup(t, true)
	p := seedAppLevelPolicy(t, ts)

	if _, err := ts.contributor.RenderPage(viewerCtx(), "/retention", contributor.Params{
		QueryParams: map[string]string{"action": "delete", "id": p.ID.String()},
	}); err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	if _, err := ts.store.GetPolicy(context.Background(), p.ID); err != nil {
		t.Fatalf("a tenant viewer deleted the app-level policy: %v", err)
	}
}

// TestDashboardAppViewerCanDeleteAppLevelPolicy keeps the owner's path working.
func TestDashboardAppViewerCanDeleteAppLevelPolicy(t *testing.T) {
	ts := newDashSetup(t, true)
	p := seedAppLevelPolicy(t, ts)

	if _, err := ts.contributor.RenderPage(appViewerCtx(), "/retention", contributor.Params{
		QueryParams: map[string]string{"action": "delete", "id": p.ID.String()},
	}); err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	if _, err := ts.store.GetPolicy(context.Background(), p.ID); err == nil {
		t.Fatal("the app viewer's own policy should have been deleted")
	}
}

// TestDashboardTenantCannotReadAppLevelPolicy covers the detail page. The
// retention list never shows a tenant the app-level policy, so the detail page
// must not render it by ID either.
func TestDashboardTenantCannotReadAppLevelPolicy(t *testing.T) {
	ts := newDashSetup(t, false)
	p := seedAppLevelPolicy(t, ts)

	_, err := ts.contributor.RenderPage(viewerCtx(), "/retention/detail", contributor.Params{
		QueryParams: map[string]string{"id": p.ID.String()},
	})
	if !errors.Is(err, contributor.ErrPageNotFound) {
		t.Fatalf("err = %v, want ErrPageNotFound", err)
	}

	if _, err := ts.contributor.RenderPage(appViewerCtx(), "/retention/detail", contributor.Params{
		QueryParams: map[string]string{"id": p.ID.String()},
	}); err != nil {
		t.Fatalf("the app viewer could not read its own policy: %v", err)
	}
}

// seedErasure records an erasure in the given scope.
func seedErasure(t *testing.T, ts *dashSetup, e *erasure.Erasure) *erasure.Erasure {
	t.Helper()

	e.Entity = chronicle.NewEntity()
	e.ID = id.NewErasureID()
	if e.SubjectID == "" {
		e.SubjectID = "user-42"
	}
	e.Reason = "GDPR Article 17"
	e.RequestedBy = "dpo@example.com"
	if err := ts.store.RecordErasure(context.Background(), e); err != nil {
		t.Fatalf("RecordErasure: %v", err)
	}
	return e
}

// TestDashboardCannotReadAnotherScopesErasure covers the erasure detail page.
// A record carries the subject ID, the reason and who asked, so resolving it by
// ID must not reach past the viewer's scope, any more than the list does.
func TestDashboardCannotReadAnotherScopesErasure(t *testing.T) {
	ts := newDashSetup(t, false)
	theirs := seedErasure(t, ts, &erasure.Erasure{AppID: otherApp, TenantID: viewerTenant})
	appLevel := seedErasure(t, ts, &erasure.Erasure{AppID: viewerApp})
	mine := seedErasure(t, ts, &erasure.Erasure{AppID: viewerApp, TenantID: viewerTenant})

	for name, e := range map[string]*erasure.Erasure{"another app": theirs, "app level": appLevel} {
		_, err := ts.contributor.RenderPage(viewerCtx(), "/erasures/detail", contributor.Params{
			QueryParams: map[string]string{"id": e.ID.String()},
		})
		if !errors.Is(err, contributor.ErrPageNotFound) {
			t.Errorf("%s: err = %v, want ErrPageNotFound", name, err)
		}
	}

	if _, err := ts.contributor.RenderPage(viewerCtx(), "/erasures/detail", contributor.Params{
		QueryParams: map[string]string{"id": mine.ID.String()},
	}); err != nil {
		t.Fatalf("the viewer could not read its own erasure: %v", err)
	}
}
