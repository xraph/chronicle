package contract

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
)

// ──────────────────────────────────────────────────
// Test doubles. Each is named for the group it serves, so it cannot collide
// with another group's in this package.
// ──────────────────────────────────────────────────

// erasuresScopeSpy is a store.Store that records every scope it was asked
// to count or list under, so a test can prove erasures.list (both its page
// and its total) and erasures.preview each stamp the viewer's own AppID and
// TenantID rather than leaving them to whatever the request carried.
type erasuresScopeSpy struct {
	stubStore
	countErasuresCalls []erasure.Scope
	listErasuresCalls  []erasure.ListOpts
	countSubjectCalls  []erasure.SubjectQuery
}

func (s *erasuresScopeSpy) CountErasures(_ context.Context, sc erasure.Scope) (int64, error) {
	s.countErasuresCalls = append(s.countErasuresCalls, sc)
	return 0, nil
}

func (s *erasuresScopeSpy) ListErasures(_ context.Context, opts erasure.ListOpts) ([]*erasure.Erasure, error) {
	s.listErasuresCalls = append(s.listErasuresCalls, opts)
	return nil, nil
}

func (s *erasuresScopeSpy) CountBySubject(_ context.Context, q erasure.SubjectQuery) (int64, error) {
	s.countSubjectCalls = append(s.countSubjectCalls, q)
	return 0, nil
}

// erasuresTouchedStore counts calls to GetErasure, so a refusal test can
// prove the refusal happened before the store was ever reached.
type erasuresTouchedStore struct {
	stubStore
	getErasureCalls int
}

func (s *erasuresTouchedStore) GetErasure(context.Context, id.ID) (*erasure.Erasure, error) {
	s.getErasureCalls++
	return nil, chronicle.ErrErasureNotFound
}

// storeWithErasureStore is a store.Store whose GetErasure always answers a
// fixed record, whatever ID it was asked for.
type storeWithErasureStore struct {
	stubStore
	e *erasure.Erasure
}

func (s *storeWithErasureStore) GetErasure(context.Context, id.ID) (*erasure.Erasure, error) {
	return s.e, nil
}

// storeWithErasure returns a store.Store whose GetErasure answers e.
func storeWithErasure(e *erasure.Erasure) store.Store {
	return &storeWithErasureStore{e: e}
}

// erasuresListFixedStore answers CountErasures and ListErasures with fixed
// values, whatever it was asked, so HasMore's arithmetic can be driven
// directly without seeding a real store.
type erasuresListFixedStore struct {
	stubStore
	total int64
	list  []*erasure.Erasure
}

func (s *erasuresListFixedStore) CountErasures(context.Context, erasure.Scope) (int64, error) {
	return s.total, nil
}

func (s *erasuresListFixedStore) ListErasures(context.Context, erasure.ListOpts) ([]*erasure.Erasure, error) {
	return s.list, nil
}

// erasuresSeedErasure records one erasure via Store.RecordErasure directly,
// so a list or detail test controls exactly what the record says instead of
// deriving it from a real erasure.
func erasuresSeedErasure(t *testing.T, s store.Store, appID, tenantID, subjectID string) *erasure.Erasure {
	t.Helper()
	now := time.Now().UTC()
	rec := &erasure.Erasure{
		Entity:         chronicle.NewEntity(),
		ID:             id.NewErasureID(),
		SubjectID:      subjectID,
		Reason:         "gdpr article 17",
		RequestedBy:    "operator-1",
		EventsAffected: 1,
		KeyDestroyed:   true,
		AppID:          appID,
		TenantID:       tenantID,
	}
	rec.CreatedAt = now
	rec.UpdatedAt = now
	if err := s.RecordErasure(context.Background(), rec); err != nil {
		t.Fatalf("record erasure %s/%s: %v", appID, tenantID, err)
	}
	return rec
}

// erasuresSeedEvent appends one event carrying a subject ID, so
// CountBySubject has something to count. streamID must already exist (see
// eventsSeedStream), the same FK requirement events.list's own tests carry.
func erasuresSeedEvent(t *testing.T, s store.Store, streamID id.ID, appID, tenantID, subjectID string, ts time.Time) {
	t.Helper()
	ev := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  streamID,
		Hash:      "hash-" + appID + "-" + subjectID + "-" + ts.Format(time.RFC3339Nano),
		AppID:     appID,
		TenantID:  tenantID,
		SubjectID: subjectID,
		UserID:    "user-1",
		Action:    "test.action",
		Resource:  "test",
		Category:  "data",
		Outcome:   "success",
		Severity:  "info",
		Timestamp: ts,
	}
	if err := s.Append(context.Background(), ev); err != nil {
		t.Fatalf("append event: %v", err)
	}
}

// ──────────────────────────────────────────────────
// erasures.list
// ──────────────────────────────────────────────────

// Total comes from CountErasures, not from len(Erasures): that method exists
// precisely so a caller wanting a total does not have to count a bounded
// list.
func TestErasureListReportsCountErasuresNotThePageLength(t *testing.T) {
	list := []*erasure.Erasure{{ID: id.NewErasureID()}, {ID: id.NewErasureID()}}
	h := erasuresListHandler(Deps{Store: &erasuresListFixedStore{total: 412, list: list}})
	out, err := h(context.Background(), ErasureListInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("erasures.list: %v", err)
	}
	if out.Total != 412 {
		t.Errorf("Total = %d, want 412", out.Total)
	}
	if len(out.Erasures) != len(list) {
		t.Errorf("page length = %d, want %d", len(out.Erasures), len(list))
	}
}

func TestErasureListDefaultsAndCapsTheLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		want  int
	}{
		{"zero becomes default", 0, defaultErasureListLimit},
		{"over the cap is capped", 5000, maxErasureListLimit},
		{"within range is untouched", 200, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &erasuresScopeSpy{}
			h := erasuresListHandler(Deps{Store: spy})
			if _, err := h(context.Background(), ErasureListInput{Limit: tc.limit}, principalWith(map[string]any{"app_id": "app-1"})); err != nil {
				t.Fatalf("erasures.list: %v", err)
			}
			if len(spy.listErasuresCalls) != 1 || spy.listErasuresCalls[0].Limit != tc.want {
				t.Fatalf("limit %d clamped to %+v, want %d", tc.limit, spy.listErasuresCalls, tc.want)
			}
		})
	}
}

func TestErasureListRejectsNegativeOffsetBeforeTouchingTheStore(t *testing.T) {
	spy := &erasuresScopeSpy{}
	h := erasuresListHandler(Deps{Store: spy})
	_, err := h(context.Background(), ErasureListInput{Offset: -1}, principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrBadRequest) {
		t.Fatalf("err = %v, want BAD_REQUEST", err)
	}
	if len(spy.countErasuresCalls) != 0 || len(spy.listErasuresCalls) != 0 {
		t.Fatal("handler reached the store before refusing a negative offset")
	}
}

// HasMore has to come from offset+page-length against the real total, since
// ListErasures itself carries no such signal: driving it directly (rather
// than through a real store) pins the arithmetic at both boundaries.
func TestErasureListComputesHasMoreFromOffsetAndTotal(t *testing.T) {
	for name, tc := range map[string]struct {
		total    int64
		n        int
		offset   int
		wantMore bool
	}{
		"exactly a full page, nothing beyond it":     {total: 2, n: 2, offset: 0, wantMore: false},
		"one row past the page":                      {total: 3, n: 2, offset: 0, wantMore: true},
		"last page, offset lands exactly on the end": {total: 5, n: 2, offset: 3, wantMore: false},
	} {
		t.Run(name, func(t *testing.T) {
			list := make([]*erasure.Erasure, tc.n)
			for i := range list {
				list[i] = &erasure.Erasure{ID: id.NewErasureID()}
			}
			deps := Deps{Store: &erasuresListFixedStore{total: tc.total, list: list}}
			out, err := erasuresListHandler(deps)(context.Background(),
				ErasureListInput{Limit: 2, Offset: tc.offset}, principalWith(map[string]any{"app_id": "app-1"}))
			if err != nil {
				t.Fatalf("erasures.list: %v", err)
			}
			if out.HasMore != tc.wantMore {
				t.Fatalf("HasMore = %v, want %v", out.HasMore, tc.wantMore)
			}
			if out.Total != tc.total {
				t.Fatalf("Total = %d, want %d", out.Total, tc.total)
			}
		})
	}
}

// ──────────────────────────────────────────────────
// erasures.detail
// ──────────────────────────────────────────────────

func TestErasureDetailRefusesAnUnparseableIDBeforeTouchingTheStore(t *testing.T) {
	spy := &erasuresTouchedStore{}
	h := erasuresDetailHandler(Deps{Store: spy})
	_, err := h(context.Background(), GetErasureInput{ID: "not-an-id"},
		principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
	if spy.getErasureCalls != 0 {
		t.Fatalf("handler reached the store %d time(s) for an unparseable ID", spy.getErasureCalls)
	}
}

// A tenant viewer must not own a same-app erasure record that belongs to a
// DIFFERENT tenant. A real, parseable ID exercises v.owns itself (never the
// ID-parse refusal), and this isolates the AppID-matches/TenantID-differs
// case: the wrong-argument mutation v.owns(e.AppID, v.TenantID) compares the
// viewer's own TenantID to itself and always answers true, so only this
// case (not one that also changes AppID) can catch it.
func TestErasureDetailRefusesASameAppOtherTenantsRecord(t *testing.T) {
	realID := id.NewErasureID()
	h := erasuresDetailHandler(Deps{Store: storeWithErasure(&erasure.Erasure{
		ID: realID, AppID: "app-1", TenantID: "tenant-b",
	})})
	_, err := h(context.Background(), GetErasureInput{ID: realID.String()},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

// An app-wide viewer (no tenant claim) must not own an erasure record in a
// DIFFERENT app. This isolates the AppID-differs case, and catches the
// wrong-argument mutation v.owns(v.AppID, e.TenantID), which compares the
// viewer's own AppID to itself and always answers true for the app check.
func TestErasureDetailRefusesAnotherAppsRecordForAnAppWideViewer(t *testing.T) {
	realID := id.NewErasureID()
	h := erasuresDetailHandler(Deps{Store: storeWithErasure(&erasure.Erasure{
		ID: realID, AppID: "app-2", TenantID: "",
	})})
	_, err := h(context.Background(), GetErasureInput{ID: realID.String()},
		principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

func TestErasureDetailProjectsEveryField(t *testing.T) {
	realID := id.NewErasureID()
	created := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	h := erasuresDetailHandler(Deps{Store: storeWithErasure(&erasure.Erasure{
		Entity:         chronicle.Entity{CreatedAt: created},
		ID:             realID,
		AppID:          "app-1",
		SubjectID:      "subject-1",
		Reason:         "gdpr article 17",
		RequestedBy:    "operator-1",
		EventsAffected: 42,
		KeyDestroyed:   true,
	})})
	out, err := h(context.Background(), GetErasureInput{ID: realID.String()},
		principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("erasures.detail: %v", err)
	}
	if out.ID != realID.String() {
		t.Errorf("ID = %q, want %q", out.ID, realID.String())
	}
	if out.SubjectID != "subject-1" {
		t.Errorf("SubjectID = %q, want subject-1", out.SubjectID)
	}
	if out.Reason != "gdpr article 17" {
		t.Errorf("Reason = %q, want gdpr article 17", out.Reason)
	}
	if out.RequestedBy != "operator-1" {
		t.Errorf("RequestedBy = %q, want operator-1", out.RequestedBy)
	}
	if out.EventsAffected != 42 {
		t.Errorf("EventsAffected = %d, want 42", out.EventsAffected)
	}
	if !out.KeyDestroyed {
		t.Error("KeyDestroyed did not survive projection")
	}
	if out.CreatedAt == "" {
		t.Error("CreatedAt did not survive projection")
	}
}

// ──────────────────────────────────────────────────
// erasures.preview
// ──────────────────────────────────────────────────

func TestErasurePreviewRefusesAnEmptySubjectIDBeforeTouchingTheStore(t *testing.T) {
	spy := &erasuresScopeSpy{}
	h := erasuresPreviewHandler(Deps{Store: spy})
	_, err := h(context.Background(), ErasurePreviewInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrBadRequest) {
		t.Fatalf("err = %v, want BAD_REQUEST", err)
	}
	if len(spy.countSubjectCalls) != 0 {
		t.Fatal("handler reached the store for an empty subjectId")
	}
}

// ──────────────────────────────────────────────────
// Scope stamping. list, its total, and preview each make their own store
// call, so each has to be proved separately: applyQuery cannot help here
// (erasure.Scope and erasure.SubjectQuery are stamped by hand), and
// Chronicle's stores treat an empty AppID as matching every app.
// ──────────────────────────────────────────────────

func TestErasureListStampsTheViewersScopeOnBothTheTotalAndThePage(t *testing.T) {
	spy := &erasuresScopeSpy{}
	h := erasuresListHandler(Deps{Store: spy})
	_, _ = h(context.Background(), ErasureListInput{},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))

	if len(spy.countErasuresCalls) != 1 {
		t.Fatalf("CountErasures called %d time(s), want 1", len(spy.countErasuresCalls))
	}
	if got := spy.countErasuresCalls[0]; got.AppID != "app-1" || got.TenantID != "tenant-a" {
		t.Fatalf("CountErasures scope = %+v, want app-1/tenant-a", got)
	}

	if len(spy.listErasuresCalls) != 1 {
		t.Fatalf("ListErasures called %d time(s), want 1", len(spy.listErasuresCalls))
	}
	if got := spy.listErasuresCalls[0]; got.AppID != "app-1" || got.TenantID != "tenant-a" {
		t.Fatalf("ListErasures scope = %+v, want app-1/tenant-a", got)
	}
}

func TestErasurePreviewIsScopedToTheViewer(t *testing.T) {
	spy := &erasuresScopeSpy{}
	h := erasuresPreviewHandler(Deps{Store: spy})
	_, _ = h(context.Background(), ErasurePreviewInput{SubjectID: "subj-1"},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))

	if len(spy.countSubjectCalls) != 1 {
		t.Fatalf("CountBySubject called %d time(s), want 1", len(spy.countSubjectCalls))
	}
	got := spy.countSubjectCalls[0]
	if got.AppID != "app-1" || got.TenantID != "tenant-a" {
		t.Fatalf("CountBySubject scope = %q/%q, want app-1/tenant-a", got.AppID, got.TenantID)
	}
	if got.SubjectID != "subj-1" {
		t.Fatalf("CountBySubject subject = %q, want subj-1", got.SubjectID)
	}
}

// ──────────────────────────────────────────────────
// Real sqlite, two apps: the scope hazard end to end.
// ──────────────────────────────────────────────────

// Chronicle's stores treat an empty AppID as matching every app, so every
// store call this group makes has to carry the viewer's own scope. This
// seeds erasure records in two apps (via RecordErasure directly, never
// erasure.Service.Erase -- see erasuresSeedErasure) and events for the same
// subject in both apps, then checks erasures.list, erasures.detail and
// erasures.preview each stay inside app-1.
func TestErasuresStayInsideTheViewersAppOnSQLite(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()

	streamOne := eventsSeedStream(t, s, "app-1", "")
	streamTwo := eventsSeedStream(t, s, "app-2", "")

	const appOneErasureCount = 7
	const pageLimit = 3

	appOneIDs := map[string]bool{}
	for i := 0; i < appOneErasureCount; i++ {
		rec := erasuresSeedErasure(t, s, "app-1", "", fmt.Sprintf("subj-app1-%d", i))
		appOneIDs[rec.ID.String()] = true
	}
	var appTwoErasureID string
	for i := 0; i < 4; i++ {
		rec := erasuresSeedErasure(t, s, "app-2", "", fmt.Sprintf("subj-app2-%d", i))
		appTwoErasureID = rec.ID.String()
	}

	// Same subject, both apps: only the app boundary must keep app-2's
	// events out of app-1's preview count.
	const sharedSubject = "subj-shared"
	const appOneEventCount = 5
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < appOneEventCount; i++ {
		erasuresSeedEvent(t, s, streamOne, "app-1", "", sharedSubject, base.Add(time.Duration(i)*time.Minute))
	}
	for i := 0; i < 9; i++ {
		erasuresSeedEvent(t, s, streamTwo, "app-2", "", sharedSubject, base.Add(time.Duration(i)*time.Minute))
	}

	viewer := principalWith(map[string]any{"app_id": "app-1"})

	t.Run("erasures.list", func(t *testing.T) {
		h := erasuresListHandler(Deps{Store: s})
		out, err := h(ctx, ErasureListInput{Limit: pageLimit}, viewer)
		if err != nil {
			t.Fatalf("erasures.list: %v", err)
		}
		if out.Total != appOneErasureCount {
			t.Fatalf("Total = %d, want %d", out.Total, appOneErasureCount)
		}
		if len(out.Erasures) != pageLimit {
			t.Fatalf("page length = %d, want %d", len(out.Erasures), pageLimit)
		}
		if !out.HasMore {
			t.Fatal("HasMore = false, want true: more records exist beyond this page")
		}
		for _, e := range out.Erasures {
			if !appOneIDs[e.ID] {
				t.Fatalf("erasures.list returned a record outside app-1: %s", e.ID)
			}
		}
	})

	t.Run("erasures.detail refuses the other app's record", func(t *testing.T) {
		h := erasuresDetailHandler(Deps{Store: s})
		_, err := h(ctx, GetErasureInput{ID: appTwoErasureID}, viewer)
		if !errors.Is(err, fcontract.ErrNotFound) {
			t.Fatalf("err = %v, want NOT_FOUND", err)
		}
	})

	t.Run("erasures.detail serves the viewer's own record", func(t *testing.T) {
		h := erasuresDetailHandler(Deps{Store: s})
		var anyAppOneID string
		for idStr := range appOneIDs {
			anyAppOneID = idStr
			break
		}
		out, err := h(ctx, GetErasureInput{ID: anyAppOneID}, viewer)
		if err != nil {
			t.Fatalf("erasures.detail: %v", err)
		}
		if out.ID != anyAppOneID {
			t.Fatalf("ID = %q, want %q", out.ID, anyAppOneID)
		}
	})

	t.Run("erasures.preview counts only app-1's events", func(t *testing.T) {
		h := erasuresPreviewHandler(Deps{Store: s})
		out, err := h(ctx, ErasurePreviewInput{SubjectID: sharedSubject}, viewer)
		if err != nil {
			t.Fatalf("erasures.preview: %v", err)
		}
		if out.EventsAffected != appOneEventCount {
			t.Fatalf("EventsAffected = %d, want %d (app-2's events must not count)", out.EventsAffected, appOneEventCount)
		}
	})
}
