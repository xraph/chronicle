package extension_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/xraph/forge"
	"github.com/xraph/forge/extensions/dashboard/contributor"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate" // registers the sqlite migrate executor
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/scope"
	sqlitestore "github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

const (
	tamperTestAppID = "app1"
)

// stubKeyProvider is a keys.Provider backed by a fixed key, mirroring the ones
// in chronicle_test.go, hash/scheme_test.go, and store/sqlite/scheme_test.go.
type stubKeyProvider struct {
	key      []byte
	activeID string
}

func (s stubKeyProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return s.key, s.activeID, nil
}

func (s stubKeyProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != s.activeID {
		return nil, keys.ErrKeyNotFound
	}
	return s.key, nil
}

// newSQLiteGroveDB opens a grove.DB backed by a temp file, matching
// store/sqlite's own test helper. A file is used rather than :memory: because
// grove pools connections and each pooled connection would otherwise get its
// own empty in-memory database.
func newSQLiteGroveDB(t *testing.T) *grove.DB {
	t.Helper()

	dsn := filepath.Join(t.TempDir(), "chronicle_tamper_evidence_test.db")
	sdb := sqlitedriver.New()
	if err := sdb.Open(context.Background(), dsn); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedStream pre-creates the chronicle_streams row Chronicle.Record would
// otherwise create itself on the first event for a new app scope.
//
// store/sqlite/store.go's groveError maps a query miss to
// chronicle.ErrStreamNotFound by checking errors.Is against grove.ErrNoRows or
// the literal string "no rows in result set"; on this grove version,
// GetStreamByScope's miss surfaces as the stdlib database/sql.ErrNoRows
// instead ("sql: no rows in result set"), which matches neither check. That
// leaves Chronicle.resolveStream's "create it if missing" branch unreachable
// through the sqlite backend -- a pre-existing bug independent of tamper
// evidence, filed separately; this works around it so the HMAC-reaches-the-
// store assertion below is not blocked by an unrelated defect.
func seedStream(t *testing.T, db *grove.DB, scheme hash.Scheme) {
	t.Helper()

	st := &stream.Stream{
		ID:          id.NewStreamID(),
		AppID:       tamperTestAppID,
		Scheme:      string(scheme),
		SchemeSince: 1,
	}
	if err := sqlitestore.New(db).CreateStream(context.Background(), st); err != nil {
		t.Fatalf("seed stream: %v", err)
	}
}

// TestHMACConfigReachesTheStore is the end-to-end proof Part B exists for.
//
// Chronicle.Record computes a digest, but the SQL backend's Append recomputes
// it: it re-derives the sequence and prev_hash under a row lock, and the
// sequence is part of the hashed content. If the store built from a
// tamper_evidence: {digest: hmac} config were left on its default plain
// chain, Append would silently overwrite every keyed digest with an unkeyed
// one and stamp hash_scheme = "chronicle/v2", while the operator believes the
// chain is keyed -- exactly the bug WithHasher exists to close, one layer
// down.
//
// This configures the extension for HMAC via the grove-auto-discovery path
// (buildStoreFromGroveDB), the same path a real deployment uses, records one
// event through the resulting Chronicle instance, and reads the row back
// through an independent store handle on the same database file to confirm
// the persisted hash_scheme is chronicle/v3 rather than the store's default
// chronicle/v2.
func TestHMACConfigReachesTheStore(t *testing.T) {
	db := newSQLiteGroveDB(t)

	app := forge.New(forge.WithAppName("t"))
	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}

	ext := extension.New(
		extension.WithUnauthenticatedAPI(),
		extension.WithDigestScheme("hmac"),
		extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "hmac-1"}),
	)

	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	seedStream(t, db, hash.SchemeHMACV5)

	ctx := context.Background()
	event := &audit.Event{
		AppID:    tamperTestAppID,
		Action:   "login",
		Resource: "session",
		Category: "auth",
	}
	if err := ext.Chronicle().Record(ctx, event); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if event.ID.String() == "" {
		t.Fatal("Record did not assign an event ID")
	}

	// Read the row back through a fresh store handle on the same database, so
	// this observes what was actually persisted rather than what Chronicle.
	// Record computed before Append re-derived and overwrote it.
	verifyStore := sqlitestore.New(db)
	got, err := verifyStore.Get(ctx, event.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.HashScheme != string(hash.SchemeHMACV5) {
		t.Fatalf("HashScheme = %q, want %q; the store re-linked under a chain the extension did not configure",
			got.HashScheme, hash.SchemeHMACV5)
	}
	if got.HashKeyID == "" {
		t.Error("HashKeyID is empty; the key used for the digest was not recorded")
	}
}

// TestPlainConfigReachesTheStore pins the default: with no tamper_evidence
// config at all, the store still gets a plain chain, matching the behavior
// before TamperEvidence existed.
func TestPlainConfigReachesTheStore(t *testing.T) {
	db := newSQLiteGroveDB(t)

	app := forge.New(forge.WithAppName("t"))
	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}

	ext := extension.New(extension.WithUnauthenticatedAPI())

	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	seedStream(t, db, hash.SchemePlainV4)

	ctx := context.Background()
	event := &audit.Event{
		AppID:    tamperTestAppID,
		Action:   "login",
		Resource: "session",
		Category: "auth",
	}
	if err := ext.Chronicle().Record(ctx, event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	verifyStore := sqlitestore.New(db)
	got, err := verifyStore.Get(ctx, event.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.HashScheme != string(hash.SchemePlainV4) {
		t.Fatalf("HashScheme = %q, want %q; an unconfigured deployment must keep writing a plain chain",
			got.HashScheme, hash.SchemePlainV4)
	}
	if got.HashKeyID != "" {
		t.Errorf("HashKeyID = %q, want empty for a plain digest", got.HashKeyID)
	}
}

// setupHMACExtension builds, registers, and starts an extension configured
// for tamper_evidence.digest: hmac over a fresh sqlite grove.DB, seeds its
// stream, and records one genuine HMAC event. Returns the extension and the
// stream's ID (as a string, for the verify request/form).
func setupHMACExtension(t *testing.T) (*extension.Extension, string) {
	t.Helper()

	db := newSQLiteGroveDB(t)
	app := forge.New(forge.WithAppName("t"))
	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}

	ext := extension.New(
		extension.WithUnauthenticatedAPI(),
		extension.WithDigestScheme("hmac"),
		extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "hmac-1"}),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	seedStream(t, db, hash.SchemeHMACV5)

	event := &audit.Event{
		AppID:    tamperTestAppID,
		Action:   "login",
		Resource: "session",
		Category: "auth",
	}
	if err := ext.Chronicle().Record(context.Background(), event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	st, err := sqlitestore.New(db).GetStreamByScope(context.Background(), tamperTestAppID, "")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	return ext, st.ID.String()
}

// TestHMACDeploymentVerifiesThroughTheAdminAPI closes a gap none of the
// other tests cover: TestHMACConfigReachesTheStore proves e.hashChain is the
// real keyed chain, and handler's TestVerifyChainVerifiesUnderTheConfiguredHMACChain
// proves handler/verify.go recomputes correctly given the right chain -- but
// nothing exercises extension.go's own "HashChain: e.hashChain," literal in
// the handler.Dependencies it builds. Deleting that one line leaves every
// other existing test, including both named above, passing, because they
// each construct handler.New directly rather than going through Register.
// This test goes through the real Register-mounted HTTP path instead.
func TestHMACDeploymentVerifiesThroughTheAdminAPI(t *testing.T) {
	ext, streamID := setupHMACExtension(t)

	body, err := json.Marshal(map[string]any{"stream_id": streamID, "from_seq": 1, "to_seq": 1})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	ctx := forge.WithScope(context.Background(), forge.NewOrgScope(tamperTestAppID, ""))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/verify", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	ext.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var report verify.Report
	if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &report); unmarshalErr != nil {
		t.Fatalf("decode report: %v", unmarshalErr)
	}
	if !report.Valid || len(report.Tampered) != 0 {
		t.Fatalf("report = %+v, want Valid with no Tampered; the admin API never received the configured chain", report)
	}
}

// TestHMACDeploymentVerifiesThroughTheDashboard is
// TestHMACDeploymentVerifiesThroughTheAdminAPI's counterpart for
// extension.go's "HashChain: e.hashChain," literal in the chronicledash.Config
// it builds, exercised through the real Register-wired DashboardContributor.
func TestHMACDeploymentVerifiesThroughTheDashboard(t *testing.T) {
	ext, streamID := setupHMACExtension(t)

	dc := ext.DashboardContributor()
	ctx := scope.WithAppID(context.Background(), tamperTestAppID)

	component, err := dc.RenderPage(ctx, "/verify", contributor.Params{
		FormData: map[string]string{
			"action":    "verify",
			"stream_id": streamID,
			"from_seq":  "1",
			"to_seq":    "1",
		},
	})
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	var buf bytes.Buffer
	if renderErr := component.Render(ctx, &buf); renderErr != nil {
		t.Fatalf("Render: %v", renderErr)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Valid")) || bytes.Contains(buf.Bytes(), []byte("Tampered")) {
		t.Fatalf("rendered page did not report Valid with no Tampered; the dashboard never received the configured chain. Output:\n%s", buf.String())
	}
}
