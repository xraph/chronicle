package chronicle_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

const (
	retApp    = "ret-app"
	retTenant = "ret-tenant"
)

// retentionChain is one stream and the pieces a retention test drives it with.
type retentionChain struct {
	c        *chronicle.Chronicle
	s        store.Store
	streamID id.ID
}

// newRetentionChain builds a Chronicle over a fresh memory store. provider is
// nil for the plain scheme.
func newRetentionChain(t *testing.T, scheme hash.Scheme, provider keys.Provider) *retentionChain {
	t.Helper()
	s := memory.New()
	return &retentionChain{c: openPinChronicle(t, store.NewAdapter(s), scheme, provider), s: s}
}

// record writes one event through the public pipeline, backdated by age.
func (rc *retentionChain) record(t *testing.T, category string, age time.Duration) {
	t.Helper()
	ctx := scope.WithTenantID(scope.WithAppID(context.Background(), retApp), retTenant)
	e := &audit.Event{
		Action:    "touch",
		Resource:  "doc",
		Category:  category,
		UserID:    fmt.Sprintf("user-%s", category),
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Timestamp: time.Now().Add(-age).UTC(),
	}
	if err := rc.c.Record(ctx, e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	rc.streamID = e.StreamID
}

// savePolicy upserts a retention policy for the test scope.
func (rc *retentionChain) savePolicy(t *testing.T, category string, d time.Duration) {
	t.Helper()
	p := &retention.Policy{
		ID: id.NewPolicyID(), Category: category, Duration: d,
		AppID: retApp, TenantID: retTenant,
	}
	p.CreatedAt, p.UpdatedAt = time.Now(), time.Now()
	if err := rc.s.SavePolicy(context.Background(), p); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}
}

// enforce runs retention the way the extension wires it: with the Chronicle as
// the chain recorder.
func (rc *retentionChain) enforce(t *testing.T) (*retention.EnforceResult, error) {
	t.Helper()
	e := retention.NewEnforcer(rc.s, nil, nil, retention.WithChainRecorder(rc.c))
	return e.EnforceScope(context.Background(), retention.Scope{AppID: retApp, TenantID: retTenant})
}

func (rc *retentionChain) verify(t *testing.T) *verify.Report {
	t.Helper()
	report, err := rc.c.VerifyChain(context.Background(), &verify.Input{AppID: retApp, TenantID: retTenant})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	return report
}

// retainedSeqs flattens a report's retained ranges into sorted sequences.
func retainedSeqs(r *verify.Report) []uint64 {
	var out []uint64
	for _, rr := range r.Retained {
		for s := rr.FromSeq; s <= rr.ToSeq; s++ {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sameSeqs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hmacProvider() *rotatingProvider {
	return &rotatingProvider{
		keys:     map[string][]byte{"k1": []byte("0123456789abcdef0123456789abcdef")},
		activeID: "k1",
	}
}

// seedAlternating records six 90-day-old events alternating auth and billing,
// the shape of the original probe: a per-category policy removes every other
// event, not a prefix.
func seedAlternating(t *testing.T, rc *retentionChain) {
	t.Helper()
	for i := range 6 {
		cat := "auth"
		if i%2 == 1 {
			cat = "billing"
		}
		rc.record(t, cat, 90*24*time.Hour)
	}
}

// TestPerCategoryRetentionKeepsTheChainVerifiable is the probe that found the
// bug. Before the fix it reported valid=false, gaps=[1 3 5], tampered=[4 6]:
// authorised retention was indistinguishable from an attacker deleting events.
func TestPerCategoryRetentionKeepsTheChainVerifiable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		scheme   hash.Scheme
		provider keys.Provider
	}{
		{"plain", hash.SchemePlainV4, nil},
		{"hmac", hash.SchemeHMACV5, hmacProvider()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRetentionChain(t, tc.scheme, tc.provider)
			seedAlternating(t, rc)

			if before := rc.verify(t); !before.Valid || before.Verified != 6 {
				t.Fatalf("before retention: valid=%v verified=%d, want a clean six-event chain", before.Valid, before.Verified)
			}

			rc.savePolicy(t, "auth", 30*24*time.Hour)
			res, err := rc.enforce(t)
			if err != nil {
				t.Fatalf("enforce: %v", err)
			}
			if res.Purged != 3 {
				t.Fatalf("purged %d, want 3", res.Purged)
			}

			report := rc.verify(t)
			if !report.Valid {
				t.Fatalf("after retention: valid=false gaps=%v tampered=%v retained=%v; "+
					"authorised retention must not read as tampering", report.Gaps, report.Tampered, report.Retained)
			}
			if len(report.Gaps) != 0 || len(report.Tampered) != 0 {
				t.Errorf("gaps=%v tampered=%v, want none", report.Gaps, report.Tampered)
			}
			if got := retainedSeqs(report); !sameSeqs(got, []uint64{1, 3, 5}) {
				t.Errorf("retained = %v, want [1 3 5]", got)
			}
			// Three surviving billing events plus the retention record itself.
			if report.Verified != 4 {
				t.Errorf("verified = %d, want 4", report.Verified)
			}
			for _, rr := range report.Retained {
				if rr.RecordSeq != 7 || rr.PolicyID == "" {
					t.Errorf("retained range %+v should name the record at seq 7 and its policy", rr)
				}
			}
			if !report.HeadChecked || !report.HeadMatch {
				t.Errorf("head_checked=%v head_match=%v, want the record to be the anchored head",
					report.HeadChecked, report.HeadMatch)
			}
		})
	}
}

// TestUnauthorisedDeletionBesideRetentionIsStillAGap is the property the fix
// must not trade away: a retention record explains only what it lists, so an
// event an attacker deletes is still a gap.
func TestUnauthorisedDeletionBesideRetentionIsStillAGap(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	rc.savePolicy(t, "auth", 30*24*time.Hour)
	if _, err := rc.enforce(t); err != nil {
		t.Fatalf("enforce: %v", err)
	}

	victim := mustEventAt(t, rc, 4)
	if _, err := rc.s.PurgeEvents(context.Background(), []id.ID{victim.ID}); err != nil {
		t.Fatalf("attacker delete: %v", err)
	}

	report := rc.verify(t)
	if report.Valid {
		t.Fatal("valid=true after deleting an event no policy removed")
	}
	if !sameSeqs(report.Gaps, []uint64{4}) {
		t.Errorf("gaps = %v, want [4]", report.Gaps)
	}
	if got := retainedSeqs(report); !sameSeqs(got, []uint64{1, 3, 5}) {
		t.Errorf("retained = %v, want [1 3 5]; the attacker's deletion must not be folded in", got)
	}
	// Event 5 was not edited, so it is not tampered. The gap before it is
	// the evidence, and it is reported as one.
	if len(report.Tampered) != 0 {
		t.Errorf("tampered = %v, want none: nothing was edited", report.Tampered)
	}
}

// TestForgedRetentionRecordDoesNotExplainADeletion plays an attacker with
// write access to the events table and no HMAC key: delete an event, then
// append a record claiming retention removed it. The record's digest cannot be
// produced without the key, so it is reported as tampered and ignored.
func TestForgedRetentionRecordDoesNotExplainADeletion(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	ctx := context.Background()

	victim := mustEventAt(t, rc, 2)
	if _, err := rc.s.PurgeEvents(ctx, []id.ID{victim.ID}); err != nil {
		t.Fatalf("attacker delete: %v", err)
	}

	head := mustEventAt(t, rc, 6)
	forged := audit.NewRetentionRecord(
		audit.RetentionRef{PolicyID: id.NewPolicyID().String(), Category: "billing"},
		rc.streamID,
		[]audit.RetentionEntry{{Seq: 2, PrevHash: victim.PrevHash, Hash: victim.Hash}},
	)
	forged.ID = id.NewAuditID()
	forged.AppID, forged.TenantID = retApp, retTenant
	forged.StreamID = rc.streamID
	forged.Sequence = 7
	forged.PrevHash = head.Hash
	forged.Timestamp = time.Now().UTC()
	guess, err := hash.NewChain(hash.SchemeHMACV5, &rotatingProvider{
		keys: map[string][]byte{"k1": []byte("not-the-real-key-not-the-real-k")}, activeID: "k1",
	})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	forged.Hash, forged.HashKeyID, err = guess.Compute(ctx, forged.PrevHash, forged)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	forged.HashScheme = string(hash.SchemeHMACV5)
	if err := rc.s.Append(ctx, forged); err != nil {
		t.Fatalf("append forged record: %v", err)
	}
	if err := rc.s.UpdateStreamHead(ctx, rc.streamID, forged.Hash, forged.Sequence); err != nil {
		t.Fatalf("move head: %v", err)
	}

	report := rc.verify(t)
	if report.Valid {
		t.Fatal("valid=true: a forged retention record explained away a deletion")
	}
	if !sameSeqs(report.Gaps, []uint64{2}) {
		t.Errorf("gaps = %v, want [2]", report.Gaps)
	}
	if len(report.Retained) != 0 {
		t.Errorf("retained = %v, want none from a record that does not verify", report.Retained)
	}
	if !sameSeqs(report.Tampered, []uint64{7}) {
		t.Errorf("tampered = %v, want [7] (the forged record)", report.Tampered)
	}
}

// TestWildcardRetentionNeverPurgesItsOwnRecords covers a "*" policy, which
// removes a prefix and, run again later, would select its own earlier record
// if nothing excluded it. Losing a record turns everything it explained back
// into gaps.
func TestWildcardRetentionNeverPurgesItsOwnRecords(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	for range 3 {
		rc.record(t, "auth", 90*24*time.Hour)
	}
	rc.record(t, "billing", time.Minute)
	rc.record(t, "auth", time.Minute)

	rc.savePolicy(t, "*", 30*24*time.Hour)
	res, err := rc.enforce(t)
	if err != nil {
		t.Fatalf("first enforce: %v", err)
	}
	if res.Purged != 3 {
		t.Fatalf("first run purged %d, want 3", res.Purged)
	}

	// Shrink the window so everything, including the first record, is past it.
	time.Sleep(2 * time.Millisecond)
	rc.savePolicy(t, "*", time.Millisecond)
	res, err = rc.enforce(t)
	if err != nil {
		t.Fatalf("second enforce: %v", err)
	}
	if res.Purged != 2 {
		t.Fatalf("second run purged %d, want 2 (events 4 and 5, never the record at 6)", res.Purged)
	}

	report := rc.verify(t)
	if !report.Valid {
		t.Fatalf("valid=false gaps=%v tampered=%v retained=%v", report.Gaps, report.Tampered, report.Retained)
	}
	if got := retainedSeqs(report); !sameSeqs(got, []uint64{1, 2, 3, 4, 5}) {
		t.Errorf("retained = %v, want [1..5]", got)
	}
	if report.Verified != 2 {
		t.Errorf("verified = %d, want 2 (the two records)", report.Verified)
	}
}

// TestRetentionAcrossAPinBoundary purges events on both sides of a scheme pin
// advance: plain events below it, HMAC events above. The plain ones still
// verify under their own recorded scheme before they are purged, and the
// record lands above the pin, keyed.
func TestRetentionAcrossAPinBoundary(t *testing.T) {
	s := memory.New()
	plain := openPinChronicle(t, store.NewAdapter(s), hash.SchemePlainV4, nil)
	rc := &retentionChain{c: plain, s: s}
	rc.record(t, "auth", 90*24*time.Hour)
	rc.record(t, "billing", 90*24*time.Hour)
	rc.record(t, "auth", 90*24*time.Hour)

	rc.c = openPinChronicle(t, store.NewAdapter(s), hash.SchemeHMACV5, hmacProvider())
	rc.record(t, "auth", 90*24*time.Hour)
	rc.record(t, "billing", 90*24*time.Hour)
	if pin := readPin(t, rc.c, rc.streamID); pin.Since != 4 || pin.Scheme != hash.SchemeHMACV5 {
		t.Fatalf("pin = %+v, want hmac from 4", pin)
	}

	rc.savePolicy(t, "auth", 30*24*time.Hour)
	if _, err := rc.enforce(t); err != nil {
		t.Fatalf("enforce: %v", err)
	}

	report := rc.verify(t)
	if !report.Valid {
		t.Fatalf("valid=false gaps=%v tampered=%v downgrades=%v retained=%v",
			report.Gaps, report.Tampered, report.Downgrades, report.Retained)
	}
	if got := retainedSeqs(report); !sameSeqs(got, []uint64{1, 3, 4}) {
		t.Errorf("retained = %v, want [1 3 4]", got)
	}
	rec := mustEventAt(t, rc, 6)
	if rec.Category != audit.CategoryRetention || rec.HashScheme != string(hash.SchemeHMACV5) {
		t.Errorf("record at 6: category=%q scheme=%q, want a keyed retention record", rec.Category, rec.HashScheme)
	}
}

// TestRetentionDoesNotLaunderATamperedEvent: purging an event erases the
// evidence of anything done to it. An event that no longer verifies is kept,
// and the run says so.
func TestRetentionDoesNotLaunderATamperedEvent(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	ctx := context.Background()

	edited := mustEventAt(t, rc, 3)
	edited.UserID = "someone-else"
	if _, err := rc.s.PurgeEvents(ctx, []id.ID{edited.ID}); err != nil {
		t.Fatalf("remove row: %v", err)
	}
	if err := rc.s.Append(ctx, edited); err != nil {
		t.Fatalf("write edited row: %v", err)
	}

	rc.savePolicy(t, "auth", 30*24*time.Hour)
	res, err := rc.enforce(t)
	if !errors.Is(err, chronicle.ErrRetentionWithheld) {
		t.Fatalf("enforce err = %v, want ErrRetentionWithheld", err)
	}
	if res == nil || res.Purged != 2 {
		t.Fatalf("result = %+v, want 2 purged (1 and 5) with 3 withheld", res)
	}

	report := rc.verify(t)
	if !sameSeqs(report.Tampered, []uint64{3}) {
		t.Errorf("tampered = %v, want [3] still on record", report.Tampered)
	}
	if got := retainedSeqs(report); !sameSeqs(got, []uint64{1, 5}) {
		t.Errorf("retained = %v, want [1 5]", got)
	}
}

// TestRetentionRecordIsCheckedAgainstASignedCheckpoint purges the event a
// signed checkpoint ends on. The checkpoint's hash is then compared with the
// retention record's entry for that sequence, rather than being skipped as
// out of reach, which ties the record to a key its own digest did not use.
func TestRetentionRecordIsCheckedAgainstASignedCheckpoint(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	signer := newCheckpointSigner(t)
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)), chronicle.WithCheckpointSigner(signer))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rc := &retentionChain{c: c, s: s}
	for _, cat := range []string{"auth", "billing", "auth", "billing", "auth"} {
		rc.record(t, cat, 90*24*time.Hour)
	}

	info, err := s.GetStreamByScope(ctx, retApp, retTenant)
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	cp, err := checkpoint.NewCheckpointer(s, signer, nil).CheckpointStream(ctx, checkpoint.StreamHead{
		ID: info.ID, AppID: info.AppID, TenantID: info.TenantID, HeadSeq: info.HeadSeq, HeadHash: info.HeadHash,
	})
	if err != nil {
		t.Fatalf("CheckpointStream: %v", err)
	}
	if cp.ToSeq != 5 {
		t.Fatalf("checkpoint ends at %d, want 5 (an auth event the policy will remove)", cp.ToSeq)
	}
	rc.record(t, "billing", 90*24*time.Hour)

	rc.savePolicy(t, "auth", 30*24*time.Hour)
	if _, err := rc.enforce(t); err != nil {
		t.Fatalf("enforce: %v", err)
	}

	report := rc.verify(t)
	if !report.Valid {
		t.Fatalf("valid=false gaps=%v tampered=%v checkpoints=%+v", report.Gaps, report.Tampered, report.Checkpoints)
	}
	if got := retainedSeqs(report); !sameSeqs(got, []uint64{1, 3, 5}) {
		t.Errorf("retained = %v, want [1 3 5]", got)
	}
	if len(report.Checkpoints) != 1 {
		t.Fatalf("checkpoints = %+v, want one", report.Checkpoints)
	}
	if r := report.Checkpoints[0]; !r.SignatureValid || !r.HashChecked || !r.HashMatch {
		t.Errorf("checkpoint result = %+v, want its to_seq hash checked against the retention record and matching", r)
	}
}

func mustEventAt(t *testing.T, rc *retentionChain, seq uint64) *audit.Event {
	t.Helper()
	events, err := rc.s.EventRange(context.Background(), rc.streamID, seq, seq)
	if err != nil || len(events) != 1 {
		t.Fatalf("event at %d: %v (got %d)", seq, err, len(events))
	}
	return events[0]
}
