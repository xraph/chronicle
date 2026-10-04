package compliance_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

const (
	chainApp    = "chain-app"
	chainTenant = "chain-tenant"
)

// testKeys serves an hmac key for event digests and an ed25519 key for
// checkpoint signatures, each under its own ID.
type testKeys struct {
	hmac    []byte
	hmacID  string
	signKey ed25519.PrivateKey
}

func newTestKeys(hmacKey string) testKeys {
	return testKeys{
		hmac:    []byte(hmacKey),
		hmacID:  "hmac-1",
		signKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)),
	}
}

func (k testKeys) Current(_ context.Context, use keys.Use) ([]byte, string, error) {
	if use == keys.UseCheckpointSig {
		return k.signKey, "sign-1", nil
	}
	return k.hmac, k.hmacID, nil
}

func (k testKeys) ByID(_ context.Context, keyID string) ([]byte, error) {
	switch keyID {
	case k.hmacID:
		return k.hmac, nil
	case "sign-1":
		return k.signKey, nil
	}
	return nil, keys.ErrKeyNotFound
}

// chainFixture is a memory store holding a real chain, recorded through
// Chronicle so every digest, link and stream row is what production writes.
type chainFixture struct {
	mem      *memory.Store
	events   []*audit.Event
	streamID id.ID
}

func recordChain(t *testing.T, scheme hash.Scheme, provider keys.Provider, n int) *chainFixture {
	t.Helper()
	ctx := context.Background()

	mem := memory.New()
	opts := []chronicle.Option{
		chronicle.WithStore(store.NewAdapter(mem)),
		chronicle.WithDigestScheme(scheme),
	}
	if provider != nil {
		opts = append(opts, chronicle.WithKeyProvider(provider))
	}
	c, err := chronicle.New(opts...)
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	recCtx := scope.WithTenantID(scope.WithAppID(ctx, chainApp), chainTenant)
	var streamID id.ID
	for i := 1; i <= n; i++ {
		b := c.Info(recCtx, "login", "session", fmt.Sprintf("session-%d", i)).
			Category("auth").
			UserID(fmt.Sprintf("user-%d", i))
		if recordErr := b.Record(); recordErr != nil {
			t.Fatalf("Record %d: %v", i, recordErr)
		}
		streamID = b.Event().StreamID
	}

	events, err := mem.EventRange(ctx, streamID, 1, uint64(n))
	if err != nil || len(events) != n {
		t.Fatalf("EventRange: %d events, %v", len(events), err)
	}
	return &chainFixture{mem: mem, events: events, streamID: streamID}
}

// rewrite replaces a stored event the way a SQL shell would, without touching
// its digest.
func (f *chainFixture) rewrite(t *testing.T, seq uint64, mutate func(*audit.Event)) {
	t.Helper()
	ctx := context.Background()
	ev := f.events[seq-1]
	if _, err := f.mem.PurgeEvents(ctx, []id.ID{ev.ID}); err != nil {
		t.Fatalf("purge: %v", err)
	}
	mutate(ev)
	if err := f.mem.Append(ctx, ev); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func mustChain(t *testing.T, scheme hash.Scheme, provider keys.Provider) *hash.Chain {
	t.Helper()
	c, err := hash.NewChain(scheme, provider)
	if err != nil {
		t.Fatalf("hash.NewChain: %v", err)
	}
	return c
}

func soc2(t *testing.T, e *compliance.Engine, tenantID string) (*compliance.Report, error) {
	t.Helper()
	return e.SOC2(context.Background(), &compliance.SOC2Input{
		Period:      testPeriod(),
		AppID:       chainApp,
		TenantID:    tenantID,
		GeneratedBy: "test-runner",
	})
}

func mustSOC2(t *testing.T, e *compliance.Engine) *compliance.Report {
	t.Helper()
	r, err := soc2(t, e, chainTenant)
	if err != nil {
		t.Fatalf("SOC2: %v", err)
	}
	return r
}

func exportAs(t *testing.T, r *compliance.Report, f compliance.Format) string {
	t.Helper()
	var buf bytes.Buffer
	if err := compliance.NewEngine(nil, nil, nil, nil).Export(context.Background(), r, f, &buf); err != nil {
		t.Fatalf("export %s: %v", f, err)
	}
	return buf.String()
}

// TestReportVerifiesKeyedChainUnderItsKey pins that a report carries a valid
// verification of an intact HMAC chain, and that the chain the engine was
// given is the one it verified under: the same events fail under an unkeyed
// chain and under the wrong key.
func TestReportVerifiesKeyedChainUnderItsKey(t *testing.T) {
	provider := newTestKeys("the-real-key")
	f := recordChain(t, hash.SchemeHMACV5, provider, 5)

	engine := compliance.NewEngine(f.mem, f.mem, f.mem, nil,
		compliance.WithChain(f.mem, mustChain(t, hash.SchemeHMACV5, provider)))
	r := mustSOC2(t, engine)

	v, s := r.Verification, r.VerificationScope
	if v == nil || s == nil {
		t.Fatalf("report carries no verification: %+v / %+v", v, s)
	}
	if !v.Valid || v.Verified != 5 || len(v.Tampered) != 0 {
		t.Fatalf("intact keyed chain: valid=%v verified=%d tampered=%v", v.Valid, v.Verified, v.Tampered)
	}
	if s.Status != compliance.VerificationRan || s.StreamID != f.streamID.String() {
		t.Fatalf("scope = %+v, want verified on stream %s", s, f.streamID)
	}
	if s.FromSeq != 1 || s.ToSeq != 5 || s.Capped || v.Partial {
		t.Fatalf("range = %d..%d capped=%v partial=%v, want whole chain 1..5", s.FromSeq, s.ToSeq, s.Capped, v.Partial)
	}
	if !v.HeadChecked || !v.HeadMatch {
		t.Fatalf("whole-chain report should anchor the head: checked=%v match=%v", v.HeadChecked, v.HeadMatch)
	}
	if s.Scheme != string(hash.SchemeHMACV5) {
		t.Fatalf("scheme = %q, want the stream's pin", s.Scheme)
	}
	for _, c := range v.Coverage {
		if c.Level != verify.LevelKeyed {
			t.Fatalf("coverage %+v, want keyed throughout", c)
		}
	}
	for _, n := range s.Notes {
		if strings.Contains(n, "not tampering") {
			t.Fatalf("keyed report carries the unkeyed caveat: %q", n)
		}
	}

	t.Run("unkeyed chain cannot verify it", func(t *testing.T) {
		unkeyed := compliance.NewEngine(f.mem, f.mem, f.mem, nil, compliance.WithChain(f.mem, &hash.Chain{}))
		if _, err := soc2(t, unkeyed, chainTenant); err == nil {
			t.Fatal("an unkeyed chain verified hmac digests; the engine is not using the chain it was given")
		}
	})

	t.Run("wrong key reports every event tampered", func(t *testing.T) {
		wrong := newTestKeys("some-other-key")
		engine := compliance.NewEngine(f.mem, f.mem, f.mem, nil,
			compliance.WithChain(f.mem, mustChain(t, hash.SchemeHMACV5, wrong)))
		r := mustSOC2(t, engine)
		if r.Verification.Valid || len(r.Verification.Tampered) != 5 {
			t.Fatalf("wrong key: valid=%v tampered=%v, want all 5 tampered",
				r.Verification.Valid, r.Verification.Tampered)
		}
	})
}

// TestReportCarriesTamperedSequences pins that a rewritten event reaches the
// report and every export.
func TestReportCarriesTamperedSequences(t *testing.T) {
	provider := newTestKeys("the-real-key")
	f := recordChain(t, hash.SchemeHMACV5, provider, 5)
	f.rewrite(t, 3, func(e *audit.Event) { e.UserID = "someone-else" })

	engine := compliance.NewEngine(f.mem, f.mem, f.mem, nil,
		compliance.WithChain(f.mem, mustChain(t, hash.SchemeHMACV5, provider)))
	r := mustSOC2(t, engine)

	if r.Verification.Valid {
		t.Fatal("tampered chain verified valid")
	}
	if len(r.Verification.Tampered) != 1 || r.Verification.Tampered[0] != 3 {
		t.Fatalf("tampered = %v, want [3]", r.Verification.Tampered)
	}

	md := exportAs(t, r, compliance.FormatMarkdown)
	if !strings.Contains(md, "| Result | invalid |") || !strings.Contains(md, "| Tampered | 1 | digest or chain link does not match: 3 |") {
		t.Errorf("markdown does not show the tamper:\n%s", md)
	}
	html := exportAs(t, r, compliance.FormatHTML)
	if !strings.Contains(html, "<td>Tampered</td>") || !strings.Contains(html, "does not match: 3") {
		t.Errorf("html does not show the tamper")
	}
	rows := verificationCSV(t, exportAs(t, r, compliance.FormatCSV))
	if got := rows["Tampered"]; got[6] != "1" || !strings.HasSuffix(got[10], ": 3") {
		t.Errorf("csv tampered row = %q", got)
	}
}

// verificationCSV parses a CSV export and returns its verification rows keyed
// by check. It fails if the file is not rectangular.
func verificationCSV(t *testing.T, out string) map[string][]string {
	t.Helper()
	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("csv does not parse: %v", err)
	}
	rows := make(map[string][]string)
	for _, rec := range records[1:] {
		if rec[0] == "Chain verification" {
			rows[rec[2]] = rec
		}
	}
	if len(rows) == 0 {
		t.Fatalf("csv has no verification rows:\n%s", out)
	}
	return rows
}

// TestEveryExportCarriesVerification pins that each format renders the
// verification, including each paired check as one of three states.
func TestEveryExportCarriesVerification(t *testing.T) {
	provider := newTestKeys("the-real-key")
	f := recordChain(t, hash.SchemeHMACV5, provider, 4)
	engine := compliance.NewEngine(f.mem, f.mem, f.mem, nil,
		compliance.WithChain(f.mem, mustChain(t, hash.SchemeHMACV5, provider)))
	r := mustSOC2(t, engine)

	t.Run("json", func(t *testing.T) {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(exportAs(t, r, compliance.FormatJSON)), &decoded); err != nil {
			t.Fatal(err)
		}
		v, _ := decoded["verification"].(map[string]any)
		s, _ := decoded["verification_scope"].(map[string]any)
		if v["valid"] != true || v["head_checked"] != true || s["status"] != "verified" || s["to_seq"] != float64(4) {
			t.Fatalf("json verification = %v / %v", v, s)
		}
	})

	t.Run("csv", func(t *testing.T) {
		rows := verificationCSV(t, exportAs(t, r, compliance.FormatCSV))
		for check, want := range map[string]string{
			"Status":                "verified",
			"Result":                "valid",
			"Range checked":         "1 to 4",
			"Events verified":       "4",
			"Partial":               "no",
			"Head check":            "passed",
			"Checkpoint store":      "not checked",
			"Checkpoint head check": "not checked",
			"Coverage":              "keyed",
		} {
			if got := rows[check]; got == nil || got[6] != want {
				t.Errorf("csv %s = %q, want result %q", check, got, want)
			}
		}
	})

	t.Run("markdown", func(t *testing.T) {
		md := exportAs(t, r, compliance.FormatMarkdown)
		for _, want := range []string{
			"## Chain Verification",
			"| Range checked | 1 to 4 | whole chain, genesis to head 4 |",
			"| Head check | passed |",
			"| Checkpoint head check | not checked |",
			"| Coverage | keyed | sequences 1 to 4;",
		} {
			if !strings.Contains(md, want) {
				t.Errorf("markdown missing %q", want)
			}
		}
	})

	t.Run("html", func(t *testing.T) {
		html := exportAs(t, r, compliance.FormatHTML)
		for _, want := range []string{
			"<h2>Chain Verification</h2>",
			`<td class="result">valid</td>`,
			"<td>Head check</td>",
			"whole chain, genesis to head 4",
		} {
			if !strings.Contains(html, want) {
				t.Errorf("html missing %q", want)
			}
		}
	})
}

// TestReportWindowIsHonouredAndStated pins the bounding rule: a chain longer
// than the window verifies only the newest window sequences, and the report
// says so instead of reading as whole-chain coverage.
func TestReportWindowIsHonouredAndStated(t *testing.T) {
	provider := newTestKeys("the-real-key")
	f := recordChain(t, hash.SchemeHMACV5, provider, 5)
	engine := compliance.NewEngine(f.mem, f.mem, f.mem, nil,
		compliance.WithChain(f.mem, mustChain(t, hash.SchemeHMACV5, provider)),
		compliance.WithVerifyWindow(3))
	r := mustSOC2(t, engine)

	v, s := r.Verification, r.VerificationScope
	if !s.Capped || s.FromSeq != 3 || s.ToSeq != 5 || s.Window != 3 || s.HeadSeq != 5 {
		t.Fatalf("scope = %+v, want capped 3..5 of 5", s)
	}
	if v.Verified != 3 || v.FirstEvent != 3 || !v.Partial {
		t.Fatalf("verified=%d first=%d partial=%v, want 3 events from 3, partial", v.Verified, v.FirstEvent, v.Partial)
	}
	if v.HeadChecked {
		t.Fatal("a partial range claims a head check")
	}
	if !containsNote(s.Notes, "Sequences below 3 were not verified") {
		t.Fatalf("notes do not state the cap: %q", s.Notes)
	}

	md := exportAs(t, r, compliance.FormatMarkdown)
	for _, want := range []string{
		"| Range checked | 3 to 5 | newest 3 sequences of 5; window cap reached |",
		"| Partial | yes |",
		"| Head check | not checked |",
		"Sequences below 3 were not verified",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func containsNote(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// TestReportOnUnkeyedChainSaysCorruptionNotTampering pins the caveat
// LevelUnkeyed carries.
func TestReportOnUnkeyedChainSaysCorruptionNotTampering(t *testing.T) {
	f := recordChain(t, hash.SchemePlainV4, nil, 3)
	engine := compliance.NewEngine(f.mem, f.mem, f.mem, nil,
		compliance.WithChain(f.mem, mustChain(t, hash.SchemePlainV4, nil)))
	r := mustSOC2(t, engine)

	if !r.Verification.Valid {
		t.Fatalf("intact plain chain invalid: %+v", r.Verification)
	}
	if !containsNote(r.VerificationScope.Notes, "detects corruption, not tampering") {
		t.Fatalf("notes = %q", r.VerificationScope.Notes)
	}
	for _, f := range []compliance.Format{compliance.FormatMarkdown, compliance.FormatHTML, compliance.FormatCSV} {
		if !strings.Contains(exportAs(t, r, f), "detects corruption, not tampering") {
			t.Errorf("%s export omits the unkeyed caveat", f)
		}
	}
}

// TestReportGapCarriesRetentionCaveat pins that an unexplained gap tells the
// reader it may be an unrecorded retention purge, and that its successor is
// not reported as tampered.
func TestReportGapCarriesRetentionCaveat(t *testing.T) {
	provider := newTestKeys("the-real-key")
	f := recordChain(t, hash.SchemeHMACV5, provider, 5)
	if _, err := f.mem.PurgeEvents(context.Background(), []id.ID{f.events[1].ID}); err != nil {
		t.Fatal(err)
	}

	engine := compliance.NewEngine(f.mem, f.mem, f.mem, nil,
		compliance.WithChain(f.mem, mustChain(t, hash.SchemeHMACV5, provider)))
	r := mustSOC2(t, engine)

	if r.Verification.Valid || len(r.Verification.Gaps) != 1 || r.Verification.Gaps[0] != 2 {
		t.Fatalf("gaps = %v valid=%v, want [2] invalid", r.Verification.Gaps, r.Verification.Valid)
	}
	if len(r.Verification.Tampered) != 0 {
		t.Fatalf("tampered = %v; a gap's successor is not a tamper", r.Verification.Tampered)
	}
	if !containsNote(r.VerificationScope.Notes, "WithUnrecordedPurge") {
		t.Fatalf("notes = %q", r.VerificationScope.Notes)
	}
}

// TestReportChecksSignedCheckpoints pins that WithCheckpoints reaches the
// verifier: a checkpoint over the chain lifts coverage to signed and its
// result is rendered.
func TestReportChecksSignedCheckpoints(t *testing.T) {
	ctx := context.Background()
	provider := newTestKeys("the-real-key")
	f := recordChain(t, hash.SchemeHMACV5, provider, 4)

	st, err := f.mem.GetStream(ctx, f.streamID)
	if err != nil {
		t.Fatal(err)
	}
	signer := checkpoint.NewEd25519Signer(provider)
	cp, err := checkpoint.NewCheckpointer(f.mem, signer, nil).CheckpointStream(ctx, checkpoint.StreamHead{
		ID: st.ID, AppID: st.AppID, TenantID: st.TenantID, HeadSeq: st.HeadSeq, HeadHash: st.HeadHash,
	})
	if err != nil {
		t.Fatalf("CheckpointStream: %v", err)
	}

	engine := compliance.NewEngine(f.mem, f.mem, f.mem, nil,
		compliance.WithChain(f.mem, mustChain(t, hash.SchemeHMACV5, provider)),
		compliance.WithCheckpoints(f.mem, signer))
	r := mustSOC2(t, engine)

	v := r.Verification
	if !v.Valid || !v.CheckpointsChecked || !v.CheckpointHeadChecked || !v.CheckpointHeadOK {
		t.Fatalf("checkpoint verification = %+v", v)
	}
	if !r.VerificationScope.CheckpointsConfigured {
		t.Fatal("scope does not record checkpoints as configured")
	}
	if len(v.Coverage) != 1 || v.Coverage[0].Level != verify.LevelSigned {
		t.Fatalf("coverage = %+v, want signed", v.Coverage)
	}

	md := exportAs(t, r, compliance.FormatMarkdown)
	want := fmt.Sprintf("| Checkpoint %s | passed | sequences 1 to 4; signature passed; hash passed; continuity passed |", cp.ID)
	for _, w := range []string{want, "| Checkpoint store | consulted |", "| Checkpoint head check | passed |", "| Coverage | signed |"} {
		if !strings.Contains(md, w) {
			t.Errorf("markdown missing %q\n%s", w, md)
		}
	}
}

// TestReportWithoutChainStatesWhy pins the two cases where no verification
// runs: a scope with no stream, and an engine never given a chain. Neither
// is an error and neither may read as a pass.
func TestReportWithoutChainStatesWhy(t *testing.T) {
	provider := newTestKeys("the-real-key")
	f := recordChain(t, hash.SchemeHMACV5, provider, 2)

	t.Run("no stream", func(t *testing.T) {
		engine := compliance.NewEngine(f.mem, f.mem, f.mem, nil,
			compliance.WithChain(f.mem, mustChain(t, hash.SchemeHMACV5, provider)))
		r, err := soc2(t, engine, "tenant-with-no-events")
		if err != nil {
			t.Fatalf("a scope with no stream failed the report: %v", err)
		}
		if r.Verification != nil || r.VerificationScope.Status != compliance.VerificationNoChain {
			t.Fatalf("verification = %+v, scope = %+v", r.Verification, r.VerificationScope)
		}
		if !strings.Contains(exportAs(t, r, compliance.FormatMarkdown), "| Status | no chain |") {
			t.Error("markdown does not say there was no chain")
		}
	})

	t.Run("not configured", func(t *testing.T) {
		r := mustSOC2(t, compliance.NewEngine(f.mem, f.mem, f.mem, nil))
		if r.Verification != nil || r.VerificationScope.Status != compliance.VerificationNotConfigured {
			t.Fatalf("verification = %+v, scope = %+v", r.Verification, r.VerificationScope)
		}
	})

	t.Run("legacy report without either", func(t *testing.T) {
		md := exportAs(t, &compliance.Report{Title: "old"}, compliance.FormatMarkdown)
		if !strings.Contains(md, "| Status | not recorded |") {
			t.Errorf("markdown = %s", md)
		}
	})
}

// TestExportRendersCheckpointStatesSeparately pins that a checkpoint check
// that did not run is rendered as not checked, never folded into passed or
// failed.
func TestExportRendersCheckpointStatesSeparately(t *testing.T) {
	r := &compliance.Report{
		Title:             "states",
		VerificationScope: &compliance.VerificationScope{Status: compliance.VerificationRan, FromSeq: 5, ToSeq: 9, HeadSeq: 9},
		Verification: &verify.Report{
			Valid: false, Verified: 5, FirstEvent: 5, LastEvent: 9, HeadSeq: 9,
			HeadChecked: true, HeadMatch: false,
			CheckpointsChecked: true,
			Checkpoints: []verify.CheckpointResult{
				{ID: "cp-a", FromSeq: 1, ToSeq: 4, SignatureValid: true, ContinuityChecked: true, ContinuityOK: true},
				{ID: "cp-b", FromSeq: 5, ToSeq: 9, SignatureValid: false, HashChecked: true, HashMatch: true},
			},
		},
	}
	md := exportAs(t, r, compliance.FormatMarkdown)
	for _, want := range []string{
		"| Head check | failed |",
		"| Checkpoint head check | not checked |",
		"| Checkpoint cp-a | partly checked | sequences 1 to 4; signature passed; hash not checked; continuity passed |",
		"| Checkpoint cp-b | failed | sequences 5 to 9; signature failed; hash passed; continuity not checked |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n%s", want, md)
		}
	}
}

// TestReportBodyRoundTrips pins the codec every SQL and Mongo backend stores
// a report through, including rows written before it existed.
func TestReportBodyRoundTrips(t *testing.T) {
	in := &compliance.Report{
		Sections:          []compliance.Section{{Title: "s", MatchedEvents: 2}},
		Stats:             &compliance.Stats{TotalEvents: 2},
		Verification:      &verify.Report{Valid: true, Verified: 2, Tampered: []uint64{}},
		VerificationScope: &compliance.VerificationScope{Status: compliance.VerificationRan, ToSeq: 2, Notes: []string{"n"}},
	}
	data, err := compliance.EncodeReportBody(in)
	if err != nil {
		t.Fatal(err)
	}
	var out compliance.Report
	if err := compliance.DecodeReportBody(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Stats.TotalEvents != 2 || !out.Verification.Valid || out.VerificationScope.ToSeq != 2 || out.Sections[0].Title != "s" {
		t.Fatalf("round trip lost fields: %+v", out)
	}

	var legacy compliance.Report
	if err := compliance.DecodeReportBody([]byte(` [{"title":"old","matched_events":1}]`), &legacy); err != nil {
		t.Fatal(err)
	}
	if len(legacy.Sections) != 1 || legacy.Sections[0].Title != "old" || legacy.Verification != nil {
		t.Fatalf("legacy decode = %+v", legacy)
	}
}
