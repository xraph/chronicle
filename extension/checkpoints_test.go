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
	"time"

	"github.com/xraph/forge"
	"github.com/xraph/grove"
	"github.com/xraph/grove/kv"
	"github.com/xraph/grove/kv/drivers/redisdriver"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
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

	_, priv, genErr := ed25519.GenerateKey(nil)
	if genErr != nil {
		t.Fatalf("GenerateKey: %v", genErr)
	}

	ext := extension.New(
		extension.WithStore(redisstore.New(kvStore)),
		extension.WithUnauthenticatedAPI(),
		// A valid, correctly-sized signer, so Register reaches the store
		// probe rather than failing earlier on the signer -- those are
		// different refusals, covered separately elsewhere in this file.
		extension.WithKeyProvider(stubKeyProvider{key: priv, activeID: "k1"}),
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

// writeKeyset writes a minimal keys.FileProvider keyset containing one
// active key of the given use, and returns its path.
func writeKeyset(t *testing.T, use keys.Use, keyID string, material []byte) string {
	t.Helper()

	data := `{"keys":[{"id":"` + keyID + `","use":"` + string(use) +
		`","active":true,"material":"` + base64.StdEncoding.EncodeToString(material) + `"}]}`

	path := filepath.Join(t.TempDir(), string(use)+"-keyset.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write keyset: %v", err)
	}
	return path
}

// multiUseKeyProvider serves different key material per keys.Use, unlike
// stubKeyProvider (tamper_evidence_test.go) which ignores Use entirely.
// Needed to test a provider that can vend one use but not another.
type multiUseKeyProvider struct {
	byUse map[keys.Use][]byte
	idFor map[keys.Use]string
}

func (p multiUseKeyProvider) Current(_ context.Context, use keys.Use) ([]byte, string, error) {
	key, ok := p.byUse[use]
	if !ok {
		return nil, "", keys.ErrNoActiveKey
	}
	return key, p.idFor[use], nil
}

func (p multiUseKeyProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	for use, kid := range p.idFor {
		if kid == keyID {
			return p.byUse[use], nil
		}
	}
	return nil, keys.ErrKeyNotFound
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
	keysetPath := writeKeyset(t, keys.UseCheckpointSig, "ckpt-1", priv)

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

// TestRegisterRefusesUnknownCheckpointSignerProvider is the reproduction for
// review Finding 1: checkpoints.signer.provider naming something this
// extension does not implement -- "kms" here, but the same is true of
// "vault", a typo, or a capitalised "File" -- used to pass
// CheckpointConfig.Validate (which only special-cased "file" and rejected
// empty) and leave buildCheckpointSigner's resolved provider nil, reaching
// checkpoint.NewEd25519Signer(nil). Nothing failed until the scheduler's
// first tick called Sign on it inside its own goroutine and took the whole
// process down. Register must refuse this outright instead.
func TestRegisterRefusesUnknownCheckpointSignerProvider(t *testing.T) {
	ext := extension.New(
		extension.WithStore(sqlitestore.New(newSQLiteGroveDB(t))),
		extension.WithUnauthenticatedAPI(),
		extension.WithCheckpoints(extension.CheckpointConfig{
			Enabled: true,
			Signer:  extension.KeyConfig{Provider: "kms"},
		}),
	)

	err := ext.Register(forge.New(forge.WithAppName("t")))
	if err == nil {
		t.Fatal("Register accepted checkpoints.signer.provider: kms (unimplemented), " +
			"want a refusal at Register rather than a nil signer reaching the scheduler")
	}
}

// TestRegisterRefusesKeyProviderWithoutACheckpointKey is the reproduction for
// review Finding 2: a keys.Provider that resolves cleanly and holds a real
// hmac key for tamper evidence, but no checkpoint-sig key. Before the fix,
// Register succeeded and every scheduler tick then failed silently forever --
// checkpoints.enabled: true recording nothing, the exact gap the Redis
// store-support refusal exists to close, reached through a different door.
func TestRegisterRefusesKeyProviderWithoutACheckpointKey(t *testing.T) {
	provider := multiUseKeyProvider{
		byUse: map[keys.Use][]byte{keys.UseHMAC: make([]byte, keys.HMACKeySize)},
		idFor: map[keys.Use]string{keys.UseHMAC: "hmac-1"},
	}

	ext := extension.New(
		extension.WithStore(sqlitestore.New(newSQLiteGroveDB(t))),
		extension.WithUnauthenticatedAPI(),
		extension.WithKeyProvider(provider),
		extension.WithCheckpoints(extension.CheckpointConfig{Enabled: true}),
	)

	err := ext.Register(forge.New(forge.WithAppName("t")))
	if err == nil {
		t.Fatal("Register accepted a key provider with no checkpoint-sig key, " +
			"want a refusal at Register rather than every scheduler tick failing silently forever")
	}
}

// TestCheckpointSignerPathOverridesInheritedKeyProvider is the reproduction
// for review Finding 3: tamper_evidence.keys.provider: file and
// checkpoints.signer.provider: file naming two different keyset files. Before
// the fix, buildHashChain ran first and left e.keyProvider already non-nil
// (loaded from the tamper-evidence hmac keyset) by the time
// buildCheckpointSigner ran, regardless of whether WithKeyProvider was ever
// called, so the explicit checkpoints.signer.path was never opened.
//
// This also serves as the missing end-to-end signed-checkpoint test Finding
// 2's fix needed: it drives Register, Start, a real Record, and a real
// forced checkpoint through the HTTP API, and inspects the resulting
// checkpoint's SignKeyID to prove the correct (checkpoint) keyset actually
// signed it, not just that Register happened to succeed.
func TestCheckpointSignerPathOverridesInheritedKeyProvider(t *testing.T) {
	db := newSQLiteGroveDB(t)

	hmacPath := writeKeyset(t, keys.UseHMAC, "hmac-1", make([]byte, keys.HMACKeySize))

	_, ckptPriv, genErr := ed25519.GenerateKey(nil)
	if genErr != nil {
		t.Fatalf("GenerateKey: %v", genErr)
	}
	ckptPath := writeKeyset(t, keys.UseCheckpointSig, "ckpt-1", ckptPriv)

	ext := extension.New(
		extension.WithConfig(extension.Config{
			TamperEvidence: extension.TamperEvidenceConfig{
				Digest: "hmac",
				Keys:   extension.KeyConfig{Provider: "file", Path: hmacPath},
			},
			Checkpoints: extension.CheckpointConfig{
				Enabled: true,
				Signer:  extension.KeyConfig{Provider: "file", Path: ckptPath},
			},
		}),
		extension.WithUnauthenticatedAPI(),
		extension.WithStore(sqlitestore.New(db)),
	)

	if err := ext.Register(forge.New(forge.WithAppName("t"))); err != nil {
		t.Fatalf("Register: %v; the checkpoint keyset should open independently of the "+
			"tamper-evidence hmac keyset", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	seedStream(t, db, hash.SchemeHMAC)

	ctx := context.Background()
	event := &audit.Event{AppID: tamperTestAppID, Action: "login", Resource: "session", Category: "auth"}
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
		t.Fatalf("POST /v1/checkpoints status = %d, want 201; the checkpoint keyset was never "+
			"opened. Body: %s", rec.Code, rec.Body.String())
	}

	var cp checkpoint.Checkpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &cp); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	if cp.SignKeyID != "ckpt-1" {
		t.Fatalf("SignKeyID = %q, want ckpt-1 (the checkpoint keyset's key); a different key signed "+
			"this, meaning the wrong provider won", cp.SignKeyID)
	}
}

// TestEveryEventsCheckpointsBeforeEveryIntervalElapses proves Finding 4: the
// scheduler's EveryEvents trigger fires independently of, and well ahead of,
// EveryInterval. EveryInterval is set to 15s specifically so that if
// EveryEvents were not implemented (interval-only, as this scheduler
// originally shipped), the second checkpoint below could not appear before
// this test's own much shorter deadline.
//
// The first checkpoint (after one event) is taken because the stream has
// never been checkpointed before -- that trigger fires regardless of
// EveryEvents, so it is not itself proof of anything. It exists here to
// establish the ToSeq baseline the second checkpoint's event count is
// measured from. Only the second checkpoint, appearing after exactly
// EveryEvents (3) more events and well inside the 6s deadline, proves the
// event-count trigger.
func TestEveryEventsCheckpointsBeforeEveryIntervalElapses(t *testing.T) {
	db := newSQLiteGroveDB(t)

	_, priv, genErr := ed25519.GenerateKey(nil)
	if genErr != nil {
		t.Fatalf("GenerateKey: %v", genErr)
	}
	keysetPath := writeKeyset(t, keys.UseCheckpointSig, "ckpt-1", priv)

	ext := extension.New(
		extension.WithStore(sqlitestore.New(db)),
		extension.WithUnauthenticatedAPI(),
		extension.WithCheckpoints(extension.CheckpointConfig{
			Enabled:       true,
			EveryEvents:   3,
			EveryInterval: 15 * time.Second,
			Signer:        extension.KeyConfig{Provider: "file", Path: keysetPath},
		}),
	)
	if err := ext.Register(forge.New(forge.WithAppName("t"))); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = ext.Stop(context.Background()) })

	seedStream(t, db, hash.SchemePlain)
	ctx := context.Background()
	recordEvent := func() {
		t.Helper()
		event := &audit.Event{AppID: tamperTestAppID, Action: "login", Resource: "session", Category: "auth"}
		if err := ext.Chronicle().Record(ctx, event); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	recordEvent() // HeadSeq=1

	st, err := sqlitestore.New(db).GetStreamByScope(ctx, tamperTestAppID, "")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}

	first := waitForCheckpointCount(t, db, st.ID, 1, 3*time.Second)
	if first[0].ToSeq != 1 {
		t.Fatalf("first checkpoint ToSeq = %d, want 1", first[0].ToSeq)
	}

	recordEvent() // HeadSeq=2
	recordEvent() // HeadSeq=3
	recordEvent() // HeadSeq=4 -- 4-1=3 events since ToSeq=1, meets EveryEvents

	second := waitForCheckpointCount(t, db, st.ID, 2, 6*time.Second)
	if second[0].ToSeq != 4 {
		t.Fatalf("second checkpoint ToSeq = %d, want 4; EveryEvents should have covered the three "+
			"new events well before EveryInterval (15s)", second[0].ToSeq)
	}
}

// waitForCheckpointCount polls the store for streamID's checkpoints, newest
// first (ListCheckpoints' own order), until at least want are present, or
// fails the test once timeout elapses.
func waitForCheckpointCount(
	t *testing.T, db *grove.DB, streamID id.ID, want int, timeout time.Duration,
) []*checkpoint.Checkpoint {
	t.Helper()

	deadline := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			t.Fatalf("timed out after %v waiting for %d checkpoint(s) on stream %s", timeout, want, streamID)
			return nil
		case <-ticker.C:
			cps, err := sqlitestore.New(db).ListCheckpoints(context.Background(), streamID, checkpoint.ListOpts{})
			if err != nil {
				t.Fatalf("ListCheckpoints: %v", err)
			}
			if len(cps) >= want {
				return cps
			}
		}
	}
}
