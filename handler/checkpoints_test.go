package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate" // registers the sqlite migrate executor

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/handler"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/stream"
)

type cpSetup struct {
	handler http.Handler
	store   *memory.Store
}

func newCheckpointSetup(t *testing.T) *cpSetup {
	t.Helper()
	store := memory.New()
	router := forge.NewRouter()
	api := handler.New(handler.Dependencies{
		AuditStore:      store,
		VerifyStore:     store,
		StreamStore:     store,
		ErasureStore:    store,
		RetentionStore:  store,
		ReportStore:     store,
		CheckpointStore: store,
		Logger:          log.NewNoopLogger(),
	}, router)
	api.RegisterRoutes(router)
	return &cpSetup{handler: router.Handler(), store: store}
}

func (s *cpSetup) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf := &bytes.Buffer{}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		buf = bytes.NewBuffer(b)
	}
	req, err := http.NewRequestWithContext(scopedContext(context.Background()), method, path, buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

// seedCheckpoint records a checkpoint against a real, registered stream.
//
// checkpointsForScope (checkpoints.go) has exactly one way to answer a
// scope-wide listing: resolve the caller's stream through StreamStore, then
// list that stream's checkpoints. A checkpoint recorded against a stream ID
// nothing ever registered -- the brief's original fixture -- could only be
// found by a since-removed memory-only shortcut that no other backend
// shared, so the fallback every real backend actually takes went untested.
// Creating the stream here, rather than restoring that shortcut, means
// TestListCheckpointsIsTenantScoped exercises the code every deployment
// runs.
//
//nolint:unparam // appID is always testAppID at every call site in this file; kept for symmetry with tenantID, same shape as newSigner/newCP elsewhere in this plan.
func seedCheckpoint(t *testing.T, s *cpSetup, appID, tenantID string) *checkpoint.Checkpoint {
	t.Helper()
	ctx := context.Background()

	streamID := id.NewStreamID()
	if err := s.store.CreateStream(ctx, &stream.Stream{
		ID: streamID, AppID: appID, TenantID: tenantID,
	}); err != nil {
		t.Fatalf("create stream: %v", err)
	}

	cp := &checkpoint.Checkpoint{
		ID: id.NewCheckpointID(), StreamID: streamID,
		AppID: appID, TenantID: tenantID,
		FromSeq: 1, ToSeq: 10, FromHash: "", ToHash: "head",
		EventCount: 10, Algorithm: checkpoint.AlgorithmEd25519,
		SignKeyID: "cp-1", Signature: []byte("sig"),
		CreatedAt: time.Now().UTC(),
	}
	cp.SignedPayload = checkpoint.CanonicalPayload(cp)
	if err := s.store.AppendCheckpoint(ctx, cp); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	return cp
}

// seedVerifiableStream creates a stream through s.store and records one
// event into it, returning the stream ID. Modeled on the seeding
// TestVerifyChainDefaultsToGenesisThroughHead does in handler_test.go: a
// stream, one plain-hashed event at sequence 1, and the stream head advanced
// to match, so POST /v1/verify has a genesis-to-head range to report on.
func seedVerifiableStream(t *testing.T, s *cpSetup) string {
	t.Helper()
	ctx := context.Background()

	st := &stream.Stream{
		ID:       id.NewStreamID(),
		AppID:    testAppID,
		TenantID: testTenantID,
	}
	if err := s.store.CreateStream(ctx, st); err != nil {
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
		t.Fatalf("compute hash: %v", err)
	}
	event.Hash, event.HashScheme = digest, string(hash.SchemePlainV4)

	if err := s.store.Append(ctx, event); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if err := s.store.UpdateStreamHead(ctx, st.ID, event.Hash, event.Sequence); err != nil {
		t.Fatalf("update stream head: %v", err)
	}

	return st.ID.String()
}

// Checkpoints name a stream and a scope, so the listing has to be scoped the
// same way events and erasures already are.
func TestListCheckpointsIsTenantScoped(t *testing.T) {
	s := newCheckpointSetup(t)
	mine := seedCheckpoint(t, s, testAppID, testTenantID)
	seedCheckpoint(t, s, testAppID, "someone-else")

	rec := s.do(t, http.MethodGet, "/v1/checkpoints", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got []checkpoint.Checkpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if len(got) != 1 {
		t.Fatalf("got %d checkpoints, want only the caller's 1", len(got))
	}
	if got[0].ID.String() != mine.ID.String() {
		t.Errorf("returned another tenant's checkpoint")
	}
}

// newSQLiteCheckpointStore opens a migrated, file-backed SQLite store.
//
// checkpointsForScope's only path for a scope-wide listing goes through
// StreamStore.GetStreamByScope, and the in-memory store used by every other
// test in this file cannot exercise what that call actually returns on a
// real backend: it returns chronicle.ErrStreamNotFound directly for an
// unknown scope, which isNotFound already recognizes. SQLite's GetStreamByScope
// goes through groveError instead, which does not recognize this driver's
// actual not-found error (see TestListCheckpointsOnAnUnseenScopeIsEmptyNotAnError).
// Reproducing that needs a real SQL driver, and SQLite is the one this repo
// can run without a live server.
func newSQLiteCheckpointStore(t *testing.T) *sqlite.Store {
	t.Helper()

	dsn := filepath.Join(t.TempDir(), "chronicle_checkpoints_test.db")
	sdb := sqlitedriver.New()
	if err := sdb.Open(context.Background(), dsn); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := sqlite.New(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// TestListCheckpointsOnAnUnseenScopeIsEmptyNotAnError is a regression test
// for a real defect that every SQL backend has today: GetStreamByScope's
// groveError mapping (store/sqlite/store.go, store/postgres/store.go) checks
// errors.Is(err, grove.ErrNoRows) and the literal string "no rows in result
// set", but this driver's actual not-found error is sql.ErrNoRows, whose
// message carries a "sql: " prefix that literal never matches. So a scope
// that has never recorded a stream gets the raw sql.ErrNoRows back from
// GetStreamByScope instead of chronicle.ErrStreamNotFound, and before
// checkpointsForScope also recognized sql.ErrNoRows directly, that raw error
// propagated all the way out as a 500 -- for a caller who did nothing wrong
// and simply hasn't written anything yet.
func TestListCheckpointsOnAnUnseenScopeIsEmptyNotAnError(t *testing.T) {
	store := newSQLiteCheckpointStore(t)

	router := forge.NewRouter()
	api := handler.New(handler.Dependencies{
		AuditStore:      store,
		VerifyStore:     store,
		StreamStore:     store,
		ErasureStore:    store,
		RetentionStore:  store,
		ReportStore:     store,
		CheckpointStore: store,
		Logger:          log.NewNoopLogger(),
	}, router)
	api.RegisterRoutes(router)

	req, err := http.NewRequestWithContext(scopedContext(context.Background()), http.MethodGet, "/v1/checkpoints", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	rec := httptest.NewRecorder()
	router.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a scope that has never recorded a stream: %s", rec.Code, rec.Body.String())
	}

	var got []checkpoint.Checkpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if len(got) != 0 {
		t.Errorf("got %d checkpoints, want 0", len(got))
	}
}

// 404 rather than 403, matching getEvent and getErasure, so an ID cannot be
// probed for existence across a tenant boundary.
func TestGetCheckpointRefusesAnotherTenantsIDAsNotFound(t *testing.T) {
	s := newCheckpointSetup(t)
	theirs := seedCheckpoint(t, s, testAppID, "someone-else")

	rec := s.do(t, http.MethodGet, "/v1/checkpoints/"+theirs.ID.String(), nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for another tenant's checkpoint", rec.Code)
	}
}

func TestGetCheckpointReturnsTheCallersOwn(t *testing.T) {
	s := newCheckpointSetup(t)
	mine := seedCheckpoint(t, s, testAppID, testTenantID)

	rec := s.do(t, http.MethodGet, "/v1/checkpoints/"+mine.ID.String(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got checkpoint.Checkpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SignedPayload != mine.SignedPayload {
		t.Error("SignedPayload did not survive the response; a verifier needs the exact bytes")
	}
}

// With no checkpointer configured the route must say so rather than 500, the
// way generateSOC2 handles a nil compliance engine.
func TestForceCheckpointWithoutACheckpointerIsUnavailable(t *testing.T) {
	s := newCheckpointSetup(t) // no Checkpointer in Dependencies
	rec := s.do(t, http.MethodPost, "/v1/checkpoints", map[string]any{})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when no checkpointer is configured", rec.Code)
	}
}

// The verify response is what an auditor reads, so coverage and the head
// assertion have to be in the JSON, not just in the Go struct.
func TestVerifyResponseCarriesCoverageAndHeadMatch(t *testing.T) {
	s := newCheckpointSetup(t)

	// Seed a stream and one event so verification has something to report on.
	// Follow seedEvents in handler_test.go for the shape.
	rec := s.do(t, http.MethodPost, "/v1/verify", map[string]any{
		"stream_id": seedVerifiableStream(t, s),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["coverage"]; !ok {
		t.Error("verify response has no coverage field")
	}
	if _, ok := body["head_match"]; !ok {
		t.Error("verify response has no head_match field")
	}
}
