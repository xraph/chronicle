package extension_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/xraph/forge"
	"github.com/xraph/grove"
	"github.com/xraph/grove/kv"
	"github.com/xraph/grove/kv/drivers/redisdriver"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/keys"
	redisstore "github.com/xraph/chronicle/store/redis"
	sqlitestore "github.com/xraph/chronicle/store/sqlite"
)

// TestCheckpointConfigValidateRejectsEnabledWithoutSigner pins the fail-closed
// posture: a checkpoint nobody can sign asserts nothing, because anyone who
// can write to the store could write a fabricated one.
func TestCheckpointConfigValidateRejectsEnabledWithoutSigner(t *testing.T) {
	cfg := extension.CheckpointConfig{Enabled: true}

	err := cfg.Validate(false)
	if err == nil {
		t.Fatal("Validate accepted checkpoints.enabled: true with no signer, want an error")
	}
	if !errors.Is(err, extension.ErrCheckpointSignerRequired) {
		t.Fatalf("error = %v, want ErrCheckpointSignerRequired", err)
	}
}

// TestCheckpointConfigValidateAcceptsDisabled pins the default: an unconfigured
// (zero-value) CheckpointConfig must not force every deployment to name a
// signing key.
func TestCheckpointConfigValidateAcceptsDisabled(t *testing.T) {
	var cfg extension.CheckpointConfig

	if err := cfg.Validate(false); err != nil {
		t.Fatalf("Validate rejected the zero (disabled) config: %v", err)
	}
}

// TestRegisterRefusesCheckpointsOnRedis is the negative case running
// checkpoints silently without them exists to prevent. store/redis returns
// checkpoint.ErrUnsupported from every checkpoint method (it is positioned as
// a read-through cache, the wrong home for a root of trust); Register must
// refuse to start against it rather than run clean and record nothing.
//
// Builds a real *redisstore.Store over a *kv.Store whose driver was never
// connected: New() only calls redisdriver.UnwrapClient, which reads a struct
// field and never dials out, and every checkpoint method on the resulting
// store returns checkpoint.ErrUnsupported unconditionally without touching
// the driver at all. So the refusal is reachable with no live Redis server.
func TestRegisterRefusesCheckpointsOnRedis(t *testing.T) {
	kvStore, err := kv.Open(redisdriver.New())
	if err != nil {
		t.Fatalf("kv.Open: %v", err)
	}
	t.Cleanup(func() { _ = kvStore.Close() })

	ext := extension.New(
		extension.WithStore(redisstore.New(kvStore)),
		extension.WithUnauthenticatedAPI(),
		// A valid signer, so Register reaches the store probe rather than
		// failing earlier with ErrCheckpointSignerRequired -- that is a
		// different refusal, covered separately above.
		extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "k1"}),
		extension.WithCheckpoints(extension.CheckpointConfig{Enabled: true}),
	)

	err = ext.Register(forge.New(forge.WithAppName("t")))
	if err == nil {
		t.Fatal("Register accepted checkpoints.enabled: true against a redis store, want a refusal")
	}
	if !errors.Is(err, extension.ErrCheckpointsUnsupportedByStore) {
		t.Fatalf("error = %v, want ErrCheckpointsUnsupportedByStore", err)
	}
}

// writeCheckpointKeyset writes a minimal keys.FileProvider keyset containing
// one active ed25519 checkpoint-signing key, and returns its path.
func writeCheckpointKeyset(t *testing.T, priv ed25519.PrivateKey, keyID string) string {
	t.Helper()

	data := `{"keys":[{"id":"` + keyID + `","use":"` + string(keys.UseCheckpointSig) +
		`","active":true,"material":"` + base64.StdEncoding.EncodeToString(priv) + `"}]}`

	path := filepath.Join(t.TempDir(), "checkpoint-keyset.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write keyset: %v", err)
	}
	return path
}

// TestCheckpointsReachTheCheckpointerThroughYAML is the regression test for
// mergeConfigurations dropping a config block nobody added it for -- Axis 1
// found exactly this bug for TamperEvidence (see
// TestYAMLConfigKeepsTheProgrammaticDigestScheme in config_merge_test.go) and
// this is its Checkpoints counterpart.
//
// The YAML here says nothing about checkpoints; it only sets base_path, which
// is what takes loadConfiguration into mergeConfigurations instead of
// mergeWithDefaults -- the merge bug is invisible on the "no YAML at all"
// path every other checkpoint test in this file takes. Checkpoints.Enabled
// and Checkpoints.Signer both come entirely from the programmatic side via
// WithCheckpoints, so if mergeConfigurations does not carry Checkpoints
// through field by field, the returned config reverts to the YAML side's
// zero value (Enabled: false) and POST /v1/checkpoints reports 503 instead of
// actually taking a checkpoint.
func TestCheckpointsReachTheCheckpointerThroughYAML(t *testing.T) {
	db := newSQLiteGroveDB(t)
	app := appWithConfigFile(t, "chronicle:\n  base_path: /audit\n")

	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}

	_, priv, genErr := ed25519.GenerateKey(nil)
	if genErr != nil {
		t.Fatalf("GenerateKey: %v", genErr)
	}
	keysetPath := writeCheckpointKeyset(t, priv, "ckpt-1")

	ext := extension.New(
		extension.WithUnauthenticatedAPI(),
		extension.WithCheckpoints(extension.CheckpointConfig{
			Enabled: true,
			Signer: extension.KeyConfig{
				Provider: "file",
				Path:     keysetPath,
			},
		}),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	seedStream(t, db, hash.SchemePlain)

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

	st, err := sqlitestore.New(db).GetStreamByScope(ctx, tamperTestAppID, "")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}

	body, err := json.Marshal(map[string]any{"stream_id": st.ID.String()})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	reqCtx := forge.WithScope(context.Background(), forge.NewOrgScope(tamperTestAppID, ""))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "/v1/checkpoints", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	ext.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/checkpoints status = %d, want 201; the programmatic checkpoints config "+
			"was dropped by the YAML merge. Body: %s", rec.Code, rec.Body.String())
	}

	var cp checkpoint.Checkpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &cp); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	if len(cp.Signature) == 0 {
		t.Error("checkpoint has no signature; the extension did not build a real Checkpointer")
	}
	if cp.Algorithm != checkpoint.AlgorithmEd25519 {
		t.Errorf("Algorithm = %q, want %q", cp.Algorithm, checkpoint.AlgorithmEd25519)
	}
}

// TestDefaultConfigTakesNoCheckpoints pins that a deployment with no
// checkpoints block records none: Register and Start both succeed (Start in
// particular must not panic building a ticker off a zero EveryInterval), and
// the checkpoint routes report the same 503 an unconfigured Compliance engine
// or CheckpointStore already report for their own routes, rather than
// silently serving an empty (but present) checkpoint API.
func TestDefaultConfigTakesNoCheckpoints(t *testing.T) {
	// A backend that actually supports checkpoints, so a 503 below is
	// unambiguously "checkpoints were never enabled" rather than "this
	// backend can't take them" (that is TestRegisterRefusesCheckpointsOnRedis).
	ext := extension.New(
		extension.WithStore(sqlitestore.New(newSQLiteGroveDB(t))),
		extension.WithUnauthenticatedAPI(),
	)
	if err := ext.Register(forge.New(forge.WithAppName("t"))); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	reqCtx := forge.WithScope(context.Background(), forge.NewOrgScope(tamperTestAppID, ""))
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "/v1/checkpoints", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	rec := httptest.NewRecorder()
	ext.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /v1/checkpoints status = %d, want 503; an unconfigured deployment must not "+
			"record checkpoints. Body: %s", rec.Code, rec.Body.String())
	}
}
