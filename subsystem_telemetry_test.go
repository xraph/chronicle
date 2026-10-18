package chronicle_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/internal/telemetry"
	"github.com/xraph/chronicle/internal/telemetrytest"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/store/sealedstore"
	"github.com/xraph/chronicle/verify"
)

// ckptKeys vends one ed25519 key for checkpoint signing.
type ckptKeys struct{ priv ed25519.PrivateKey }

func (k ckptKeys) Current(context.Context, keys.Use) ([]byte, string, error) {
	return k.priv, "ckpt-1", nil
}

func (k ckptKeys) ByID(context.Context, string) ([]byte, error) { return k.priv, nil }

// leakyKeyStore fails every Delete with an error that quotes the key ID,
// which embeds the subject ID, the way a real key store's error might.
type leakyKeyStore struct{ crypto.KeyStore }

func (s leakyKeyStore) Delete(keyID string) error {
	return fmt.Errorf("key store: cannot delete %q", keyID)
}

// TestSubsystemSpansCarryNoPersonalData drives every traced subsystem with a
// subject's email in every field that can hold one (user, subject,
// resource, session, reason, requester, report author, even the event
// category, plus an IP) and checks
// the spans for it, on the success paths and on a failed erasure whose
// error quotes the subject's key ID.
func TestSubsystemSpansCarryNoPersonalData(t *testing.T) {
	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()

	mem := memory.New()
	keyStore := crypto.NewInMemoryKeyStore()
	sealer := crypto.NewSealer(keyStore)
	sealed := sealedstore.New(mem, sealer)
	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(sealed)),
		chronicle.WithCryptoErasure(true),
		chronicle.WithSealer(sealer),
		chronicle.WithMetrics(sink),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, parent := otel.Tracer("test").Start(t.Context(), "operator session")

	old := time.Now().Add(-48 * time.Hour).UTC()
	for _, ev := range []*audit.Event{
		{Action: "profile.read", Resource: "profile", Category: personal, Timestamp: old},
		{Action: "profile.update", Resource: "profile", Category: "profile"},
	} {
		ev.AppID, ev.TenantID = telApp, telTenant
		ev.UserID, ev.SubjectID, ev.IP, ev.Reason = personal, personal, "203.0.113.7", personal
		ev.ResourceID, ev.SessionID, ev.UserAgent = personal, personal, personal
		ev.Metadata = map[string]any{"email": personal}
		if recErr := c.Record(ctx, ev); recErr != nil {
			t.Fatalf("Record: %v", recErr)
		}
	}

	if _, verErr := c.VerifyChain(ctx, &verify.Input{AppID: telApp, TenantID: telTenant}); verErr != nil {
		t.Fatalf("VerifyChain: %v", verErr)
	}

	st, err := c.Store().GetStreamByScope(ctx, telApp, telTenant)
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cpr := checkpoint.NewCheckpointer(mem, checkpoint.NewEd25519Signer(ckptKeys{priv}), nil, checkpoint.WithMetrics(sink))
	head := checkpoint.StreamHead{ID: st.ID, AppID: st.AppID, TenantID: st.TenantID, HeadSeq: st.HeadSeq, HeadHash: st.HeadHash}
	if _, cpErr := cpr.CheckpointStream(ctx, head); cpErr != nil {
		t.Fatalf("CheckpointStream: %v", cpErr)
	}
	if _, cpErr := cpr.CheckpointStream(ctx, head); !errors.Is(cpErr, checkpoint.ErrNothingToCheckpoint) {
		t.Fatalf("second CheckpointStream: %v, want ErrNothingToCheckpoint", cpErr)
	}

	policy := &retention.Policy{
		ID: id.NewPolicyID(), Category: personal, Duration: 24 * time.Hour,
		AppID: telApp, TenantID: telTenant,
	}
	policy.CreatedAt, policy.UpdatedAt = time.Now(), time.Now()
	if saveErr := mem.SavePolicy(ctx, policy); saveErr != nil {
		t.Fatalf("SavePolicy: %v", saveErr)
	}
	enforcer := retention.NewEnforcer(sealed, nil, nil, retention.WithChainRecorder(c), retention.WithMetrics(sink))
	result, err := enforcer.EnforceScope(ctx, retention.Scope{AppID: telApp, TenantID: telTenant})
	if err != nil {
		t.Fatalf("EnforceScope: %v", err)
	}
	if result.Purged != 1 {
		t.Fatalf("purged = %d, want 1", result.Purged)
	}

	engine := compliance.NewEngine(sealed, sealed, sealed, nil)
	if _, repErr := engine.SOC2(ctx, &compliance.SOC2Input{
		Period:      compliance.DateRange{From: old.Add(-time.Hour), To: time.Now().Add(time.Hour)},
		AppID:       telApp,
		TenantID:    telTenant,
		GeneratedBy: personal,
	}); repErr != nil {
		t.Fatalf("SOC2: %v", repErr)
	}

	input := &erasure.Input{SubjectID: personal, Reason: personal, RequestedBy: personal}
	if _, eraseErr := erasure.NewService(mem, leakyKeyStore{keyStore}).Erase(ctx, input, telApp, telTenant); eraseErr == nil {
		t.Fatal("an erasure whose key store refuses every delete succeeded")
	}
	erased, err := erasure.NewService(mem, keyStore).Erase(ctx, input, telApp, telTenant)
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	parent.End()

	spans := chronicleSpans(t, rec.Ended())
	for name, want := range map[string]int{
		telemetry.SpanRecordEvent:    2,
		telemetry.SpanVerifyChain:    1,
		telemetry.SpanTakeCheckpoint: 2,
		telemetry.SpanEnforcePolicy:  1,
		telemetry.SpanGenerateReport: 1,
		telemetry.SpanEraseSubject:   2,
	} {
		if got := len(spans[name]); got != want {
			t.Errorf("%s spans = %d, want %d", name, got, want)
		}
		for _, s := range spans[name] {
			if s.Parent().SpanID() != parent.SpanContext().SpanID() {
				t.Errorf("%s is not a child of the caller's span", name)
			}
		}
	}

	if got := attr(t, spans[telemetry.SpanRecordEvent][0], telemetry.AttrSealed); got != "true" {
		t.Errorf("sealed = %q for an event with a subject under crypto-erasure", got)
	}
	if v := spans[telemetry.SpanVerifyChain][0]; attr(t, v, telemetry.AttrVerifyValid) != "true" ||
		attr(t, v, telemetry.AttrVerifyVerified) != "2" || attr(t, v, telemetry.AttrStreamID) != st.ID.String() {
		t.Errorf("verify chain attributes = %v", v.Attributes())
	}
	taken, quiet := spans[telemetry.SpanTakeCheckpoint][0], spans[telemetry.SpanTakeCheckpoint][1]
	if attr(t, taken, telemetry.AttrCheckpointResult) != telemetry.ResultOK ||
		attr(t, taken, telemetry.AttrCheckpointAlgorithm) != checkpoint.AlgorithmEd25519 ||
		attr(t, taken, telemetry.AttrCheckpointEvents) != "2" {
		t.Errorf("take checkpoint attributes = %v", taken.Attributes())
	}
	if attr(t, quiet, telemetry.AttrCheckpointResult) != telemetry.ResultNothingNew || quiet.Status().Code != codes.Unset {
		t.Errorf("a stream with nothing new is reported as %v, status %+v", quiet.Attributes(), quiet.Status())
	}
	if p := spans[telemetry.SpanEnforcePolicy][0]; attr(t, p, telemetry.AttrRetentionExpired) != "1" ||
		attr(t, p, telemetry.AttrRetentionPurged) != "1" || attr(t, p, telemetry.AttrRetentionArchive) != "false" {
		t.Errorf("enforce retention policy attributes = %v", p.Attributes())
	}
	if r := spans[telemetry.SpanGenerateReport][0]; attr(t, r, telemetry.AttrReportType) != "soc2" {
		t.Errorf("report type = %v", r.Attributes())
	}
	failedErase, okErase := spans[telemetry.SpanEraseSubject][0], spans[telemetry.SpanEraseSubject][1]
	if failedErase.Status().Code != codes.Error || failedErase.Status().Description != "*errors.errorString" {
		t.Errorf("failed erasure status = %+v, want the key store's error named by its type", failedErase.Status())
	}
	if attr(t, failedErase, telemetry.AttrErasureFailedStep) != "destroy_keys" ||
		attr(t, failedErase, telemetry.AttrErasureKeysDestroyed) != "0" {
		t.Errorf("failed erasure attributes = %v", failedErase.Attributes())
	}
	if okErase.Status().Code != codes.Unset ||
		attr(t, okErase, telemetry.AttrErasureEventsAffected) != fmt.Sprint(erased.EventsAffected) ||
		attr(t, okErase, telemetry.AttrErasureKeysDestroyed) != "1" {
		t.Errorf("erasure attributes = %v, status %+v", okErase.Attributes(), okErase.Status())
	}

	for _, value := range []string{personal, "alice", "203.0.113.7"} {
		if leaks := telemetrytest.Leaks(rec, value); len(leaks) > 0 {
			t.Errorf("%q reached a span: %s", value, strings.Join(leaks, "; "))
		}
	}

	if got := sink.Get(telemetry.MetricEventsPurged).Value(); got != 1 {
		t.Errorf("purged counter = %v, want 1", got)
	}
	if got := sink.Get(telemetry.MetricEventsArchived).Value(); got != 0 {
		t.Errorf("archived counter = %v, want 0 for a policy that does not archive", got)
	}
	for res, want := range map[string]float64{
		telemetry.ResultOK: 1, telemetry.ResultNothingNew: 1, telemetry.ResultLostRace: 0, telemetry.ResultError: 0,
	} {
		if got := sink.Get(telemetry.MetricCheckpointsAttempted, telemetry.LabelResult, res).Value(); got != want {
			t.Errorf("checkpoints attempted{result=%s} = %v, want %v", res, got, want)
		}
	}
}
