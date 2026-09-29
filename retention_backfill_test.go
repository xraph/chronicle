package chronicle_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/sink"
	"github.com/xraph/chronicle/store"
)

// archivedPurge runs a policy the way retention ran before retention records
// existed: archive, then delete, with nothing written into the chain. It
// returns a reader over the archive it wrote.
func archivedPurge(t *testing.T, rc *retentionChain, category string) *sink.FileArchive {
	t.Helper()
	dir := t.TempDir()
	fs := sink.NewFileSink(dir, "archive")
	t.Cleanup(func() { _ = fs.Close() })

	p := &retention.Policy{
		ID: id.NewPolicyID(), Category: category, Duration: 30 * 24 * time.Hour, Archive: true,
		AppID: retApp, TenantID: retTenant,
	}
	p.CreatedAt, p.UpdatedAt = time.Now(), time.Now()
	if err := rc.s.SavePolicy(context.Background(), p); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}
	enforcer := retention.NewEnforcer(rc.s, fs, nil, retention.WithUnrecordedPurge())
	if _, err := enforcer.EnforceScope(context.Background(), retention.Scope{AppID: retApp, TenantID: retTenant}); err != nil {
		t.Fatalf("EnforceScope: %v", err)
	}
	return sink.NewFileArchive(dir, "archive")
}

func (rc *retentionChain) backfill(t *testing.T, archive sink.ArchiveReader, dryRun bool) *chronicle.BackfillReport {
	t.Helper()
	report, err := rc.c.BackfillRetention(context.Background(), &chronicle.BackfillInput{
		AppID: retApp, TenantID: retTenant, Archive: archive, DryRun: dryRun,
	})
	if err != nil {
		t.Fatalf("BackfillRetention: %v", err)
	}
	return report
}

func recoveredSeqs(r *chronicle.BackfillReport) []uint64 {
	out := make([]uint64, 0, len(r.Recovered))
	for _, rec := range r.Recovered {
		out = append(out, rec.Seq)
	}
	return out
}

func refusedSeqs(r *chronicle.BackfillReport) []uint64 {
	out := make([]uint64, 0, len(r.Refused))
	for _, rec := range r.Refused {
		out = append(out, rec.Seq)
	}
	return out
}

// sliceArchive is an archive whose contents a test controls exactly.
type sliceArchive struct {
	name   string
	events []*audit.Event
}

func (a *sliceArchive) Name() string { return a.name }

func (a *sliceArchive) ReadEvents(_ context.Context, fn func(*audit.Event, string) error) error {
	for i, e := range a.events {
		cp := *e
		if err := fn(&cp, fmt.Sprintf("%s#%d", a.name, i+1)); err != nil {
			return err
		}
	}
	return nil
}

// TestBackfillRecoversAnArchivedPurge is the case the backfill exists for: a
// per-category purge from before retention records, archived to a file sink.
func TestBackfillRecoversAnArchivedPurge(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	archive := archivedPurge(t, rc, "auth")

	if before := rc.verify(t); before.Valid || !sameSeqs(before.Gaps, []uint64{1, 3, 5}) {
		t.Fatalf("before backfill: valid=%v gaps=%v, want the old unrecorded purge as gaps [1 3 5]", before.Valid, before.Gaps)
	}

	report := rc.backfill(t, archive, false)
	if got := recoveredSeqs(report); !sameSeqs(got, []uint64{1, 3, 5}) {
		t.Fatalf("recovered = %v, want [1 3 5]; refused=%+v rejected=%+v", got, report.Refused, report.Rejected)
	}
	if len(report.Records) != 1 {
		t.Fatalf("records = %v, want one", report.Records)
	}
	if report.After == nil || !report.After.Valid {
		t.Fatalf("after = %+v, want a valid chain", report.After)
	}

	after := rc.verify(t)
	if !after.Valid || len(after.Gaps) != 0 || len(after.Tampered) != 0 {
		t.Fatalf("valid=%v gaps=%v tampered=%v", after.Valid, after.Gaps, after.Tampered)
	}
	if got := retainedSeqs(after); !sameSeqs(got, []uint64{1, 3, 5}) {
		t.Errorf("retained = %v, want [1 3 5]", got)
	}
	for _, r := range after.Retained {
		if r.Backfill != archive.Name() {
			t.Errorf("retained range %+v does not name the archive %q", r, archive.Name())
		}
	}

	// A second run has nothing left to do and writes nothing.
	again := rc.backfill(t, archive, false)
	if len(again.Gaps) != 0 || len(again.Records) != 0 {
		t.Errorf("second run gaps=%v records=%v, want nothing", again.Gaps, again.Records)
	}
}

func TestBackfillDryRunWritesNothing(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	archive := archivedPurge(t, rc, "auth")

	report := rc.backfill(t, archive, true)
	if got := recoveredSeqs(report); !sameSeqs(got, []uint64{1, 3, 5}) {
		t.Fatalf("recovered = %v, want [1 3 5]", got)
	}
	if len(report.Records) != 0 || report.After != nil {
		t.Fatalf("dry run wrote records %v", report.Records)
	}
	if after := rc.verify(t); !sameSeqs(after.Gaps, []uint64{1, 3, 5}) {
		t.Errorf("gaps after dry run = %v, want [1 3 5] untouched", after.Gaps)
	}
}

// TestBackfillRefusesAnUnkeyedChain: under chronicle/v4 anyone who can write
// the store can compute a digest, so an archive proves nothing.
func TestBackfillRefusesAnUnkeyedChain(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemePlainV4, nil)
	seedAlternating(t, rc)
	archive := archivedPurge(t, rc, "auth")

	_, err := rc.c.BackfillRetention(context.Background(), &chronicle.BackfillInput{
		AppID: retApp, TenantID: retTenant, Archive: archive,
	})
	if !errors.Is(err, chronicle.ErrBackfillUnkeyed) {
		t.Fatalf("err = %v, want ErrBackfillUnkeyed", err)
	}
	if after := rc.verify(t); !sameSeqs(after.Gaps, []uint64{1, 3, 5}) {
		t.Errorf("gaps = %v, want [1 3 5] untouched", after.Gaps)
	}
}

// TestBackfillDoesNotExcuseADeletion puts an unarchived deletion next to an
// archived purge. The purge on its own is recovered; the run the deletion
// sits in is not, because it cannot be linked end to end.
func TestBackfillDoesNotExcuseADeletion(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	archive := archivedPurge(t, rc, "auth")

	if _, err := rc.s.PurgeEvents(context.Background(), []id.ID{mustEventAt(t, rc, 4).ID}); err != nil {
		t.Fatalf("delete seq 4: %v", err)
	}

	report := rc.backfill(t, archive, false)
	if got := recoveredSeqs(report); !sameSeqs(got, []uint64{1}) {
		t.Errorf("recovered = %v, want [1]", got)
	}
	if got := refusedSeqs(report); !sameSeqs(got, []uint64{3, 4, 5}) {
		t.Errorf("refused = %v, want [3 4 5]", got)
	}

	after := rc.verify(t)
	if after.Valid || !sameSeqs(after.Gaps, []uint64{3, 4, 5}) {
		t.Errorf("valid=%v gaps=%v, want the deletion's run still reported", after.Valid, after.Gaps)
	}
	if got := retainedSeqs(after); !sameSeqs(got, []uint64{1}) {
		t.Errorf("retained = %v, want [1]", got)
	}
}

// TestBackfillRejectsFabricatedCopies deletes an event and plants copies of it
// in the archive: one with its content edited under the original hash, and
// one re-digested under the unkeyed scheme. Neither is believed.
func TestBackfillRejectsFabricatedCopies(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	ctx := context.Background()

	victim := mustEventAt(t, rc, 4)
	if _, err := rc.s.PurgeEvents(ctx, []id.ID{victim.ID}); err != nil {
		t.Fatalf("delete seq 4: %v", err)
	}

	edited := *victim
	edited.UserID = "someone-else"

	plain := *victim
	plain.UserID = "someone-else"
	plain.HashScheme, plain.HashKeyID = string(hash.SchemePlainV4), ""
	digest, _, err := (&hash.Chain{}).Compute(ctx, plain.PrevHash, &plain)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	plain.Hash = digest

	archive := &sliceArchive{name: "planted", events: []*audit.Event{&edited, &plain}}
	report := rc.backfill(t, archive, false)
	if len(report.Recovered) != 0 {
		t.Fatalf("recovered = %v, want nothing", recoveredSeqs(report))
	}
	if len(report.Rejected) != 2 {
		t.Fatalf("rejected = %+v, want both planted copies", report.Rejected)
	}
	if after := rc.verify(t); !sameSeqs(after.Gaps, []uint64{4}) {
		t.Errorf("gaps = %v, want [4]", after.Gaps)
	}
}

// TestBackfillRefusesConflictingCopies plants a second copy of a purged event
// digested under the real key, as if the key had leaked. Two copies that both
// verify cannot both be the event, so the sequence stays a gap.
func TestBackfillRefusesConflictingCopies(t *testing.T) {
	provider := hmacProvider()
	rc := newRetentionChain(t, hash.SchemeHMACV5, provider)
	seedAlternating(t, rc)
	ctx := context.Background()

	victim := mustEventAt(t, rc, 4)
	if _, err := rc.s.PurgeEvents(ctx, []id.ID{victim.ID}); err != nil {
		t.Fatalf("delete seq 4: %v", err)
	}

	forged := *victim
	forged.UserID = "someone-else"
	chain, err := hash.NewChain(hash.SchemeHMACV5, provider)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	if forged.Hash, forged.HashKeyID, err = chain.Compute(ctx, forged.PrevHash, &forged); err != nil {
		t.Fatalf("Compute: %v", err)
	}

	report := rc.backfill(t, &sliceArchive{name: "two", events: []*audit.Event{victim, &forged}}, false)
	if len(report.Recovered) != 0 || !sameSeqs(refusedSeqs(report), []uint64{4}) {
		t.Fatalf("recovered=%v refused=%+v, want 4 refused", recoveredSeqs(report), report.Refused)
	}
	if !strings.Contains(report.Refused[0].Reason, "different copies") {
		t.Errorf("reason = %q, want it to name the conflict", report.Refused[0].Reason)
	}

	// The forged copy alone verifies under the key, but it does not link to
	// the event after it, so it still does not get in.
	alone := rc.backfill(t, &sliceArchive{name: "forged", events: []*audit.Event{&forged}}, false)
	if len(alone.Recovered) != 0 {
		t.Errorf("recovered = %v from a copy that does not link", recoveredSeqs(alone))
	}
}

// TestBackfillNeverRestoresARetentionRecord: retention never purges a record,
// so an archived copy of one means something else removed it. Excusing that
// sequence would excuse the removal, and with it every gap the record
// explained.
func TestBackfillNeverRestoresARetentionRecord(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	rc.savePolicy(t, "billing", 30*24*time.Hour)
	if _, err := rc.enforce(t); err != nil {
		t.Fatalf("enforce: %v", err)
	}

	record := mustEventAt(t, rc, 7)
	if !audit.IsRetentionRecord(record) {
		t.Fatalf("seq 7 is %s/%s, want the retention record", record.Category, record.Action)
	}
	if _, err := rc.s.PurgeEvents(context.Background(), []id.ID{record.ID}); err != nil {
		t.Fatalf("delete record: %v", err)
	}

	report := rc.backfill(t, &sliceArchive{name: "copied", events: []*audit.Event{record}}, false)
	if len(report.Recovered) != 0 {
		t.Fatalf("recovered = %v, want nothing", recoveredSeqs(report))
	}
	if len(report.Rejected) != 1 || !strings.Contains(report.Rejected[0].Reason, "retention record") {
		t.Errorf("rejected = %+v, want the copied record named", report.Rejected)
	}
	if after := rc.verify(t); !sameSeqs(after.Gaps, []uint64{2, 4, 6, 7}) {
		t.Errorf("gaps = %v, want [2 4 6 7]", after.Gaps)
	}
}

// TestBackfillRefusesBesideATamperedEvent: a hash taken from an event that
// fails verification vouches for nothing, so a copy linking to it is refused.
func TestBackfillRefusesBesideATamperedEvent(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	archive := archivedPurge(t, rc, "auth")
	ctx := context.Background()

	edited := mustEventAt(t, rc, 2)
	edited.UserID = "someone-else"
	if _, err := rc.s.PurgeEvents(ctx, []id.ID{edited.ID}); err != nil {
		t.Fatalf("remove row: %v", err)
	}
	if err := rc.s.Append(ctx, edited); err != nil {
		t.Fatalf("write edited row: %v", err)
	}

	report := rc.backfill(t, archive, false)
	if got := recoveredSeqs(report); !sameSeqs(got, []uint64{5}) {
		t.Errorf("recovered = %v, want [5]: 1 and 3 border the edited event", got)
	}
	if got := refusedSeqs(report); !sameSeqs(got, []uint64{1, 3}) {
		t.Errorf("refused = %v, want [1 3]", got)
	}
}

// TestBackfillRecoversAPurgedHead covers both ends of a stream: a "*" policy
// removed everything, including the head, so the run links from genesis to
// the hash the stream row still holds.
func TestBackfillRecoversAPurgedHead(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemeHMACV5, hmacProvider())
	seedAlternating(t, rc)
	archive := archivedPurge(t, rc, "*")

	report := rc.backfill(t, archive, false)
	if got := recoveredSeqs(report); !sameSeqs(got, []uint64{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("recovered = %v, want 1-6; refused=%+v", got, report.Refused)
	}

	after := rc.verify(t)
	if !after.Valid || len(after.Gaps) != 0 {
		t.Fatalf("valid=%v gaps=%v tampered=%v", after.Valid, after.Gaps, after.Tampered)
	}
	if got := retainedSeqs(after); !sameSeqs(got, []uint64{1, 2, 3, 4, 5, 6}) {
		t.Errorf("retained = %v, want 1-6", got)
	}
}

// TestBackfillRefusesCopiesBelowAKeyedPin: a stream that moved from v4 to v5
// keeps its v4 history, and an archived v4 event proves nothing even though
// the stream is keyed now.
func TestBackfillRefusesCopiesBelowAKeyedPin(t *testing.T) {
	rc := newRetentionChain(t, hash.SchemePlainV4, nil)
	seedAlternating(t, rc)
	archive := archivedPurge(t, rc, "auth")

	upgraded := &retentionChain{c: openPinChronicle(t, store.NewAdapter(rc.s), hash.SchemeHMACV5, hmacProvider()), s: rc.s}
	upgraded.streamID = rc.streamID
	upgraded.record(t, "billing", 0) // Moves the pin to v5 from sequence 7.

	report := upgraded.backfill(t, archive, false)
	if len(report.Recovered) != 0 {
		t.Fatalf("recovered = %v, want nothing below the pin", recoveredSeqs(report))
	}
	if len(report.Rejected) != 3 || !strings.Contains(report.Rejected[0].Reason, "unkeyed") {
		t.Errorf("rejected = %+v, want each v4 copy named unkeyed", report.Rejected)
	}
}

// TestBackfillChecksBothSidesOfAPurgedHead: when the head itself is gone, the
// only hash after it is the one on the stream row, which anyone with write
// access to the store can set. A copy that matches that row but does not
// follow from the event before it is refused. The forger here even holds the
// key, which is the worst case the predecessor check still covers.
func TestBackfillChecksBothSidesOfAPurgedHead(t *testing.T) {
	provider := hmacProvider()
	rc := newRetentionChain(t, hash.SchemeHMACV5, provider)
	seedAlternating(t, rc)
	ctx := context.Background()

	head := mustEventAt(t, rc, 6)
	if _, err := rc.s.PurgeEvents(ctx, []id.ID{head.ID}); err != nil {
		t.Fatalf("delete head: %v", err)
	}

	forged := *head
	forged.PrevHash = strings.Repeat("0", 64)
	chain, err := hash.NewChain(hash.SchemeHMACV5, provider)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	if forged.Hash, forged.HashKeyID, err = chain.Compute(ctx, forged.PrevHash, &forged); err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if err := rc.s.UpdateStreamHead(ctx, rc.streamID, forged.Hash, 6); err != nil {
		t.Fatalf("UpdateStreamHead: %v", err)
	}

	report := rc.backfill(t, &sliceArchive{name: "forged-head", events: []*audit.Event{&forged}}, false)
	if len(report.Recovered) != 0 || !sameSeqs(refusedSeqs(report), []uint64{6}) {
		t.Fatalf("recovered=%v refused=%+v, want 6 refused", recoveredSeqs(report), report.Refused)
	}
	if !strings.Contains(report.Refused[0].Reason, "does not follow from sequence 5") {
		t.Errorf("reason = %q, want the broken link to 5", report.Refused[0].Reason)
	}
}
