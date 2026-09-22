package extension_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xraph/forge"
	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

// checkpointE2EAppID is the scope the end-to-end checkpoint tests below
// record, checkpoint and verify under.
const checkpointE2EAppID = "app-checkpoint-e2e"

// setupCheckpointedExtension builds the deployment the README's own YAML
// block describes: checkpoints on, signed from a keyset file, over a plain
// (unkeyed) chain. No tamper_evidence block at all.
//
// That combination is the one that used to verify nothing. The verifier
// derived its checkpoint signer from the digest's key provider, a plain
// deployment has no key provider, so a checkpoint was taken on schedule and
// then never fetched by anything an operator could reach.
//
// It uses store/memory rather than sqlite because the attack below has to
// write relinked rows back under their original sequences, which the SQL
// backends deliberately refuse: they re-derive sequence and prev_hash inside
// Append. memory persists exactly what it is handed, which is what a SQL
// shell against a real deployment does.
func setupCheckpointedExtension(t *testing.T) (*extension.Extension, http.Handler, *memory.Store, id.ID) {
	t.Helper()
	ctx := context.Background()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	mem := memory.New()
	ext := extension.New(
		extension.WithStore(mem),
		extension.WithUnauthenticatedAPI(),
		extension.WithCheckpoints(extension.CheckpointConfig{
			Enabled: true,
			Signer: extension.KeyConfig{
				Provider: "file",
				Path:     writeKeyset(t, keys.UseCheckpointSig, "ckpt-1", priv),
			},
		}),
	)
	if regErr := ext.Register(forge.New(forge.WithAppName("t"))); regErr != nil {
		t.Fatalf("Register: %v", regErr)
	}
	if startErr := ext.Start(ctx); startErr != nil {
		t.Fatalf("Start: %v", startErr)
	}

	for i := range 5 {
		event := &audit.Event{
			AppID:    checkpointE2EAppID,
			Action:   "login",
			Resource: "session",
			Category: "auth",
			UserID:   "user-" + string(rune('a'+i)),
		}
		if recErr := ext.Chronicle().Record(ctx, event); recErr != nil {
			t.Fatalf("Record event %d: %v", i, recErr)
		}
	}

	st, err := mem.GetStreamByScope(ctx, checkpointE2EAppID, "")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}

	// Built once and reused: Handler registers every route into the
	// extension's router, and registering the same path twice panics inside
	// the router rather than returning an error.
	return ext, ext.Handler(), mem, st.ID
}

// takeCheckpointThroughTheAPI signs a checkpoint over the stream's current
// head through POST /v1/checkpoints, the operator-facing route.
func takeCheckpointThroughTheAPI(t *testing.T, h http.Handler, streamID id.ID) *checkpoint.Checkpoint {
	t.Helper()

	rec := callAPI(t, h, "/v1/checkpoints", map[string]any{"stream_id": streamID.String()})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/checkpoints status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	var cp checkpoint.Checkpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &cp); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	if len(cp.Signature) == 0 {
		t.Fatal("checkpoint came back unsigned; the extension never built a real signer")
	}
	return &cp
}

// verifyThroughTheAPI runs POST /v1/verify over the whole stream, genesis to
// head, and returns the report.
func verifyThroughTheAPI(t *testing.T, h http.Handler, streamID id.ID) *verify.Report {
	t.Helper()

	rec := callAPI(t, h, "/v1/verify", map[string]any{"stream_id": streamID.String()})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/verify status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var report verify.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return &report
}

func callAPI(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	ctx := forge.WithScope(context.Background(), forge.NewOrgScope(checkpointE2EAppID, ""))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// rewriteEventAndRelink is the attack: edit one already-checkpointed event,
// recompute every digest from there to the head so the chain still links
// perfectly, and move the stream's own head hash to match.
//
// Every part of that is inside the reach of whoever holds the database. An
// unkeyed digest recomputes from the stored row, so nothing about the chain
// itself is left inconsistent -- this is the same attack
// TestPlainChainDoesNotDetectARewrite pins as undetectable without a
// checkpoint. The signed checkpoint is the one thing here the attacker
// cannot restate.
func rewriteEventAndRelink(t *testing.T, mem *memory.Store, streamID id.ID, seq uint64, newUserID string) {
	t.Helper()
	ctx := context.Background()
	var plain hash.Chain

	events, err := mem.EventRange(ctx, streamID, 1, 5)
	if err != nil {
		t.Fatalf("EventRange: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}

	events[seq-1].UserID = newUserID
	for i := int(seq) - 1; i < len(events); i++ {
		if i > 0 {
			events[i].PrevHash = events[i-1].Hash
		}
		digest, _, computeErr := plain.Compute(ctx, events[i].PrevHash, events[i])
		if computeErr != nil {
			t.Fatalf("relink event %d: %v", events[i].Sequence, computeErr)
		}
		events[i].Hash = digest
		events[i].HashScheme = string(hash.SchemePlain)
	}

	ids := make([]id.ID, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	if _, purgeErr := mem.PurgeEvents(ctx, ids); purgeErr != nil {
		t.Fatalf("PurgeEvents: %v", purgeErr)
	}
	if appendErr := mem.AppendBatch(ctx, events); appendErr != nil {
		t.Fatalf("AppendBatch: %v", appendErr)
	}

	// The head row moves with the events. An attacker who leaves it behind
	// is caught by head anchoring alone, and this test is about what
	// happens when they do not.
	last := events[len(events)-1]
	if headErr := mem.UpdateStreamHead(ctx, streamID, last.Hash, last.Sequence); headErr != nil {
		t.Fatalf("UpdateStreamHead: %v", headErr)
	}
}

// TestVerifyAPIReportsARewriteOfCheckpointedEvents is the end-to-end case the
// whole feature rests on: take a checkpoint through the extension, rewrite an
// event it covers, and have POST /v1/verify say so.
//
// Every checkpoint test before this one built verify.NewVerifierWithCheckpoints
// by hand. That is why nine task reviews passed over a verify route that
// constructed a verifier which never consulted a checkpoint at all: the
// checkpoint machinery was correct, and nothing an operator could reach ran
// it.
//
// The assertions on Tampered and HeadMatch are what make this a checkpoint
// test rather than a chain test. The chain relinks cleanly and the head
// agrees with it; the only evidence that anything happened is the signature
// over what sequence 5 used to hash to.
func TestVerifyAPIReportsARewriteOfCheckpointedEvents(t *testing.T) {
	_, h, mem, streamID := setupCheckpointedExtension(t)

	cp := takeCheckpointThroughTheAPI(t, h, streamID)
	if cp.FromSeq != 1 || cp.ToSeq != 5 {
		t.Fatalf("checkpoint covers %d-%d, want 1-5", cp.FromSeq, cp.ToSeq)
	}

	// Before the attack: the route has to report the checkpoint it just
	// took, or the assertions after the attack would pass just as happily
	// against a verifier that never looked.
	before := verifyThroughTheAPI(t, h, streamID)
	if !before.Valid {
		t.Fatalf("an untouched, checkpointed chain verified as invalid: %+v", before)
	}
	if len(before.Checkpoints) != 1 {
		t.Fatalf("POST /v1/verify reported %d checkpoints on a stream with exactly one, so the route "+
			"never consulted the checkpoint store: %+v", len(before.Checkpoints), before)
	}
	if !before.Checkpoints[0].SignatureValid || !before.Checkpoints[0].HashChecked || !before.Checkpoints[0].HashMatch {
		t.Fatalf("the checkpoint over an untouched chain did not come back fully checked and intact: %+v",
			before.Checkpoints[0])
	}
	var sawSigned bool
	for _, cov := range before.Coverage {
		if cov.Level == verify.LevelSigned {
			sawSigned = true
		}
	}
	if !sawSigned {
		t.Fatalf("coverage never reached %q on a checkpointed range, so the ladder still tops out where "+
			"it did before checkpoints existed: %+v", verify.LevelSigned, before.Coverage)
	}

	rewriteEventAndRelink(t, mem, streamID, 3, "attacker-was-not-here")

	after := verifyThroughTheAPI(t, h, streamID)
	if after.Valid {
		t.Fatalf("a rewrite of checkpointed events verified as Valid through POST /v1/verify: %+v", after)
	}
	if len(after.Tampered) != 0 || len(after.Gaps) != 0 || len(after.Downgrades) != 0 {
		t.Fatalf("the chain itself flagged the rewrite (tampered=%v gaps=%v downgrades=%v), so this test "+
			"no longer proves the checkpoint is what caught it", after.Tampered, after.Gaps, after.Downgrades)
	}
	if !after.HeadChecked || !after.HeadMatch {
		t.Fatalf("head anchoring flagged the rewrite (checked=%v match=%v), so this test no longer proves "+
			"the checkpoint is what caught it", after.HeadChecked, after.HeadMatch)
	}
	if len(after.Checkpoints) != 1 {
		t.Fatalf("got %d checkpoint results, want the one covering 1-5: %+v", len(after.Checkpoints), after.Checkpoints)
	}
	result := after.Checkpoints[0]
	if !result.SignatureValid {
		t.Errorf("the checkpoint's own signature stopped verifying, which is not what this attack does: %+v", result)
	}
	if !result.HashChecked {
		t.Fatalf("the checkpoint's recorded hash was never re-checked, so the report's verdict rests on "+
			"something other than the checkpoint: %+v", result)
	}
	if result.HashMatch {
		t.Errorf("the checkpoint reported HashMatch true after the range it covers was rewritten: %+v", result)
	}
}

// TestDashboardVerifyPageReportsARewriteOfCheckpointedEvents is the
// verify-route test's counterpart for the dashboard, which answers the same
// question through a different set of wiring. The two must not disagree
// about what evidence they consulted: an operator who reads the page and an
// auditor who calls the API are looking at one chain.
func TestDashboardVerifyPageReportsARewriteOfCheckpointedEvents(t *testing.T) {
	ext, h, mem, streamID := setupCheckpointedExtension(t)

	takeCheckpointThroughTheAPI(t, h, streamID)
	rewriteEventAndRelink(t, mem, streamID, 3, "attacker-was-not-here")

	dc := ext.DashboardContributor()
	ctx := scope.WithAppID(context.Background(), checkpointE2EAppID)
	component, err := dc.RenderPage(ctx, "/verify", contributor.Params{
		FormData: map[string]string{
			"action":    "verify",
			"stream_id": streamID.String(),
		},
	})
	if err != nil {
		t.Fatalf("RenderPage: %v", err)
	}

	var buf bytes.Buffer
	if renderErr := component.Render(ctx, &buf); renderErr != nil {
		t.Fatalf("Render: %v", renderErr)
	}
	if !bytes.Contains(buf.Bytes(), []byte("checkpoint failed")) {
		t.Fatalf("the verify page never rendered a failed checkpoint, so the dashboard's verifier was "+
			"built without one. Output:\n%s", buf.String())
	}
}

// TestVerifyAPIWithoutCheckpointsIsUnchanged pins the other half of the
// contract: a deployment that never turned checkpointing on must behave
// exactly as it did before checkpoints existed. No checkpoint results, no
// signed coverage, and a clean chain still verifies clean.
func TestVerifyAPIWithoutCheckpointsIsUnchanged(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	ext := extension.New(
		extension.WithStore(mem),
		extension.WithUnauthenticatedAPI(),
	)
	if err := ext.Register(forge.New(forge.WithAppName("t"))); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for range 3 {
		event := &audit.Event{
			AppID: checkpointE2EAppID, Action: "login", Resource: "session", Category: "auth",
		}
		if err := ext.Chronicle().Record(ctx, event); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	st, err := mem.GetStreamByScope(ctx, checkpointE2EAppID, "")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}

	report := verifyThroughTheAPI(t, ext.Handler(), st.ID)
	if !report.Valid {
		t.Fatalf("an intact chain with no checkpoints configured verified as invalid: %+v", report)
	}
	if len(report.Checkpoints) != 0 {
		t.Errorf("Checkpoints = %+v, want none: nothing here takes them", report.Checkpoints)
	}
	for _, cov := range report.Coverage {
		if cov.Level == verify.LevelSigned || cov.Level == verify.LevelAnchored {
			t.Errorf("coverage claims %q with no checkpoint anywhere: %+v", cov.Level, report.Coverage)
		}
	}
}

// TestHMACChainWithASeparateCheckpointKeysetVerifiesClean is the regression
// test for the third way the old wiring broke: a deployment that digests
// with HMAC from one keyset and signs checkpoints from another.
//
// Both keysets are documented configuration, and buildCheckpointSigner was
// fixed in an earlier task specifically so checkpoints.signer.path wins over
// the inherited tamper_evidence provider. The read side never got the same
// treatment. It rebuilt its signer from the digest's key provider, which has
// never heard of "ckpt-1", so every verification of an intact chain came
// back invalid with "resolve signing key \"ckpt-1\": keys: key not found" --
// a false tamper verdict from an audit tool, on a chain nobody had touched.
func TestHMACChainWithASeparateCheckpointKeysetVerifiesClean(t *testing.T) {
	ctx := context.Background()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	mem := memory.New()
	ext := extension.New(
		extension.WithConfig(extension.Config{
			TamperEvidence: extension.TamperEvidenceConfig{
				Digest: "hmac",
				Keys: extension.KeyConfig{
					Provider: "file",
					Path:     writeKeyset(t, keys.UseHMAC, "hmac-1", make([]byte, keys.HMACKeySize)),
				},
			},
			Checkpoints: extension.CheckpointConfig{
				Enabled: true,
				Signer: extension.KeyConfig{
					Provider: "file",
					Path:     writeKeyset(t, keys.UseCheckpointSig, "ckpt-1", priv),
				},
			},
		}),
		extension.WithStore(mem),
		extension.WithUnauthenticatedAPI(),
	)
	if regErr := ext.Register(forge.New(forge.WithAppName("t"))); regErr != nil {
		t.Fatalf("Register: %v", regErr)
	}
	if startErr := ext.Start(ctx); startErr != nil {
		t.Fatalf("Start: %v", startErr)
	}
	for range 3 {
		event := &audit.Event{
			AppID: checkpointE2EAppID, Action: "login", Resource: "session", Category: "auth",
		}
		if recErr := ext.Chronicle().Record(ctx, event); recErr != nil {
			t.Fatalf("Record: %v", recErr)
		}
	}
	st, err := mem.GetStreamByScope(ctx, checkpointE2EAppID, "")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}

	h := ext.Handler()
	takeCheckpointThroughTheAPI(t, h, st.ID)

	// Nothing has been touched, so both readers have to say so -- and both
	// have to have actually looked, or "valid" here would mean nothing.
	report := verifyThroughTheAPI(t, h, st.ID)
	if len(report.Checkpoints) != 1 {
		t.Fatalf("POST /v1/verify reported %d checkpoints, want the one just taken: %+v",
			len(report.Checkpoints), report)
	}
	if !report.Checkpoints[0].SignatureValid {
		t.Fatalf("the checkpoint's signature did not verify on an untouched chain; the verifier resolved "+
			"the wrong key source: %+v", report.Checkpoints[0])
	}
	if !report.Valid {
		t.Fatalf("an untouched HMAC chain with a separately-keyed checkpoint verified as invalid: %+v", report)
	}

	direct, err := ext.Chronicle().VerifyChain(ctx, &verify.Input{
		StreamID: st.ID, AppID: checkpointE2EAppID,
	})
	if err != nil {
		t.Fatalf("Chronicle.VerifyChain: %v", err)
	}
	if len(direct.Checkpoints) != 1 || !direct.Checkpoints[0].SignatureValid || !direct.Valid {
		t.Fatalf("Chronicle.VerifyChain disagreed with the admin API on an untouched chain: %+v", direct)
	}
}

// TestBoundedVerifyWithNoScopeStillPassesOnAnIntactChain walks the exact
// path an operator takes from the examples: an extension with
// checkpoints.enabled, one checkpoint taken, and a bounded VerifyChain call
// carrying a StreamID and a range but no scope and no head.
//
// The scope-less call skips the head fill in Chronicle.VerifyChain, by
// design: chronicle.go's own doc promises that caller "the old, narrower
// behaviour: no head anchoring, no downgrade detection". What it must not
// get is a hard Valid false because a checkpoint ends past a head it never
// claimed.
func TestBoundedVerifyWithNoScopeStillPassesOnAnIntactChain(t *testing.T) {
	ext, h, _, streamID := setupCheckpointedExtension(t)
	takeCheckpointThroughTheAPI(t, h, streamID)

	report, err := ext.Chronicle().VerifyChain(context.Background(), &verify.Input{
		StreamID: streamID, FromSeq: 2, ToSeq: 4,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("a bounded, scope-less verification of an untouched checkpointed chain reported "+
			"invalid: %+v", report)
	}
	if report.CheckpointHeadChecked {
		t.Errorf("the head comparison ran against a caller that claimed no head: %+v", report)
	}
}
