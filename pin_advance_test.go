package chronicle_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

// pinApp and pinTenant scope every stream this file creates.
const (
	pinApp    = "pin-app"
	pinTenant = "pin-tenant"
)

// openPinChronicle builds a Chronicle over an already-existing store, which is
// what a restart under a new configuration looks like: the database is the one
// the previous process left behind, only the process config changed.
func openPinChronicle(t *testing.T, s chronicle.Storer, scheme hash.Scheme, provider keys.Provider) *chronicle.Chronicle {
	t.Helper()

	opts := []chronicle.Option{
		chronicle.WithStore(s),
		chronicle.WithDigestScheme(scheme),
	}
	if provider != nil {
		opts = append(opts, chronicle.WithKeyProvider(provider))
	}

	c, err := chronicle.New(opts...)
	if err != nil {
		t.Fatalf("New (%s): %v", scheme, err)
	}
	return c
}

// recordPinEvents writes n events through the public pipeline and returns the
// stream they landed in.
func recordPinEvents(t *testing.T, c *chronicle.Chronicle, prefix string, n int) id.ID {
	t.Helper()

	recCtx := scope.WithTenantID(scope.WithAppID(context.Background(), pinApp), pinTenant)

	var streamID id.ID
	for i := 1; i <= n; i++ {
		b := c.Info(recCtx, "login", "session", fmt.Sprintf("%s-%d", prefix, i)).
			Category("auth").
			UserID(fmt.Sprintf("user-%s-%d", prefix, i))
		if err := b.Record(); err != nil {
			t.Fatalf("Record %s event %d: %v", prefix, i, err)
		}
		streamID = b.Event().StreamID
	}
	return streamID
}

// readPin reads the stream row the way production does, so the assertions can
// never pass on a value the test itself supplied.
func readPin(t *testing.T, c *chronicle.Chronicle, streamID id.ID) hash.Pin {
	t.Helper()

	reader, ok := c.Store().(streamReader)
	if !ok {
		t.Fatalf("store %T cannot read the stream row", c.Store())
	}
	st, err := reader.GetStream(context.Background(), streamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	return hash.Pin{Scheme: hash.Scheme(st.Scheme), Since: st.SchemeSince}
}

// TestTurningHMACOnAdvancesAnExistingStreamsPin is the regression test for the
// finding that nothing ever moved a stream's pin after creation.
//
// The shape is the common upgrade path, not a synthetic one: a stream that
// already exists under the plain scheme (which is also what migration 006
// backfills every pre-existing stream to), a restart with HMAC configured, and
// one more event. It asserts three things in order, and the third is the one
// that matters:
//
//  1. the stream is now pinned to the keyed scheme, from one past the events
//     that were already there;
//  2. the plain events below that boundary still verify, so advancing the pin
//     did not retroactively condemn honest history;
//  3. a wholesale rewrite of every event back to plain, touching nothing in
//     chronicle_streams, is now reported as a downgrade. Before the pin moved,
//     that same attack returned valid=true with an empty Downgrades list.
func TestTurningHMACOnAdvancesAnExistingStreamsPin(t *testing.T) {
	ctx := context.Background()
	backing := store.NewAdapter(memory.New())

	// Era 1: plain.
	plainChron := openPinChronicle(t, backing, hash.SchemePlain, nil)
	streamID := recordPinEvents(t, plainChron, "plain", 5)

	if pin := readPin(t, plainChron, streamID); pin.Scheme != hash.SchemePlain {
		t.Fatalf("pin before the upgrade = %s, want %s", pin.Scheme, hash.SchemePlain)
	}

	// Era 2: same database, HMAC configured.
	key := make([]byte, 32)
	key[0] = 7
	provider := stubProvider{key: key, activeID: "hmac-1"}
	hmacChron := openPinChronicle(t, backing, hash.SchemeHMAC, provider)
	recordPinEvents(t, hmacChron, "keyed", 1)

	pin := readPin(t, hmacChron, streamID)
	if pin.Scheme != hash.SchemeHMAC {
		t.Fatalf("pin after the upgrade = %s, want %s "+
			"(nothing advanced the stream's scheme, so the keyed chain is invisible to verification)",
			pin.Scheme, hash.SchemeHMAC)
	}
	if pin.Since != 6 {
		t.Fatalf("pin applies from sequence %d, want 6 (one past the five plain events)", pin.Since)
	}

	// The keyed event really is keyed, and the plain ones were left alone.
	events, err := hmacChron.Store().EventRange(ctx, streamID, 1, 6)
	if err != nil {
		t.Fatalf("EventRange: %v", err)
	}
	if len(events) != 6 {
		t.Fatalf("read %d events, want 6", len(events))
	}
	for _, e := range events {
		want := string(hash.SchemePlain)
		if e.Sequence == 6 {
			want = string(hash.SchemeHMAC)
		}
		if e.HashScheme != want {
			t.Errorf("event %d HashScheme = %q, want %q", e.Sequence, e.HashScheme, want)
		}
	}

	// (2) The pre-upgrade events still verify under the pin that now sits above
	// them, and so does the keyed one.
	report, err := hmacChron.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: 6, Pin: pin,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("advancing the pin condemned the events written before it: "+
			"gaps=%v tampered=%v downgrades=%v tolerant=%v",
			report.Gaps, report.Tampered, report.Downgrades, report.Tolerant)
	}

	// (3) The attack. Rewrite every event to the plain scheme, recomputing the
	// unkeyed digests (which need no key, only the algorithm in this repo), and
	// write nothing at all to the stream row.
	rewriteAndRelink(t, events, 0, "attacker-rewrote-the-whole-stream")
	persist(t, hmacChron, events)

	after := readPin(t, hmacChron, streamID)
	if after != pin {
		t.Fatalf("the attack changed the stream pin (%+v -> %+v); it is supposed to touch only events", pin, after)
	}

	report, err = hmacChron.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: 6, Pin: after,
	})
	if err != nil {
		t.Fatalf("VerifyChain after the rewrite: %v", err)
	}
	if report.Valid {
		t.Fatal("a wholesale rewrite to plain verified clean; the stream's pin is not being enforced")
	}
	if !hasSeq(report.Downgrades, 6) {
		t.Fatalf("Downgrades = %v, want sequence 6 (the event that claims plain at or above an hmac pin)",
			report.Downgrades)
	}
}

// TestPinDoesNotMoveWhenTheSchemeIsUnchanged pins the equal-rank case: ordinary
// appends must not rewrite the stream's scheme columns, and in particular must
// not keep pushing SchemeSince forward, which would walk the strict window off
// the end of the stream and leave every event resolving tolerantly.
func TestPinDoesNotMoveWhenTheSchemeIsUnchanged(t *testing.T) {
	backing := store.NewAdapter(memory.New())

	c := openPinChronicle(t, backing, hash.SchemePlain, nil)
	streamID := recordPinEvents(t, c, "first", 3)

	before := readPin(t, c, streamID)
	if before.Since != 1 {
		t.Fatalf("a freshly created stream pins from %d, want 1", before.Since)
	}

	recordPinEvents(t, c, "second", 3)

	if after := readPin(t, c, streamID); after != before {
		t.Fatalf("pin moved on an ordinary append: %+v -> %+v", before, after)
	}
}

// TestWeakeningTheSchemeIsRefused covers the other direction of the ruling.
//
// Advancing a pin on its own is safe because it only ever tightens what
// verification will accept. Lowering one is not: the moment the pin drops, every
// event an attacker rewrites to the weaker scheme verifies clean, and the
// operator's report goes green. So a process configured below its stream's pin
// refuses the write instead of quietly relaxing the guarantee.
func TestWeakeningTheSchemeIsRefused(t *testing.T) {
	backing := store.NewAdapter(memory.New())

	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"}
	hmacChron := openPinChronicle(t, backing, hash.SchemeHMAC, provider)
	streamID := recordPinEvents(t, hmacChron, "keyed", 3)

	pinned := readPin(t, hmacChron, streamID)
	if pinned.Scheme != hash.SchemeHMAC {
		t.Fatalf("setup pin = %s, want %s", pinned.Scheme, hash.SchemeHMAC)
	}

	plainChron := openPinChronicle(t, backing, hash.SchemePlain, nil)

	recCtx := scope.WithTenantID(scope.WithAppID(context.Background(), pinApp), pinTenant)
	err := plainChron.Info(recCtx, "login", "session", "after-downgrade").
		Category("auth").
		UserID("user-after-downgrade").
		Record()
	if !errors.Is(err, chronicle.ErrSchemeWeakeningRefused) {
		t.Fatalf("Record under a weaker scheme returned %v, want ErrSchemeWeakeningRefused", err)
	}

	if after := readPin(t, plainChron, streamID); after != pinned {
		t.Fatalf("the refused append still moved the pin: %+v -> %+v", pinned, after)
	}

	// Nothing was written, so the chain is exactly as the keyed era left it.
	events, rangeErr := plainChron.Store().EventRange(context.Background(), streamID, 1, 10)
	if rangeErr != nil {
		t.Fatalf("EventRange: %v", rangeErr)
	}
	if len(events) != 3 {
		t.Fatalf("stream holds %d events, want 3; the refused append was persisted anyway", len(events))
	}
}

// TestPinAdvancesPastEventsHeadSeqDoesNotKnowAbout covers the lagging-head case
// migration 006 already guards against, on the live path this time.
//
// A crash between an event insert and the head update leaves head_seq behind
// MAX(sequence). Pinning from head_seq alone would drop the events in between
// above the new boundary, where their weaker recorded scheme reads as a
// downgrade rather than as the ordinary history it is.
func TestPinAdvancesPastEventsHeadSeqDoesNotKnowAbout(t *testing.T) {
	ctx := context.Background()
	backing := store.NewAdapter(memory.New())

	plainChron := openPinChronicle(t, backing, hash.SchemePlain, nil)
	streamID := recordPinEvents(t, plainChron, "plain", 5)

	// Rewind the head the way a crash after the insert would have left it.
	events, err := plainChron.Store().EventRange(ctx, streamID, 1, 5)
	if err != nil {
		t.Fatalf("EventRange: %v", err)
	}
	if err := backing.UpdateStreamHead(ctx, streamID, events[2].Hash, 3); err != nil {
		t.Fatalf("UpdateStreamHead: %v", err)
	}

	key := make([]byte, 32)
	hmacChron := openPinChronicle(t, backing, hash.SchemeHMAC, stubProvider{key: key, activeID: "hmac-1"})
	recordPinEvents(t, hmacChron, "keyed", 1)

	if pin := readPin(t, hmacChron, streamID); pin.Since != 6 {
		t.Fatalf("pin applies from sequence %d, want 6 (past the highest stored event, not the lagging head)",
			pin.Since)
	}
}

// hasSeq reports whether a report list names a sequence.
func hasSeq(list []uint64, seq uint64) bool {
	for _, v := range list {
		if v == seq {
			return true
		}
	}
	return false
}
