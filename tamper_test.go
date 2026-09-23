package chronicle_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// rewriteAndRelink plays the attacker: change a stored event, then recompute
// every digest from that point on so the chain still links. Under an unkeyed
// scheme this needs nothing but the algorithm, which ships in this repo.
func rewriteAndRelink(t *testing.T, events []*audit.Event, idx int, newUserID string) {
	t.Helper()
	ctx := context.Background()
	var plain hash.Chain

	events[idx].UserID = newUserID
	for i := idx; i < len(events); i++ {
		if i > 0 {
			events[i].PrevHash = events[i-1].Hash
		}
		digest, _, err := plain.Compute(ctx, events[i].PrevHash, events[i])
		if err != nil {
			t.Fatalf("relink: %v", err)
		}
		events[i].Hash = digest
		events[i].HashScheme = string(hash.SchemePlainV4)
		events[i].HashKeyID = ""
	}
}

// This test asserts that the DEFAULT configuration does NOT detect a rewrite.
//
// That is the honest statement of what an unkeyed chain gives you, and it is
// deliberately committed rather than left implicit. If someone later makes the
// plain chain detect this, that is a real change in the product's guarantee and
// this test failing is how they find out.
func TestPlainChainDoesNotDetectARewrite(t *testing.T) {
	ctx := context.Background()
	c, events, streamID := seedChain(t, hash.SchemePlainV4, nil)

	rewriteAndRelink(t, events, 2, "attacker-was-not-here")
	persist(t, c, events)

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemePlainV4, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("plain chain reported the relink invalid: gaps=%v tampered=%v downgrades=%v verified=%d "+
			"(if the plain scheme now genuinely detects rewrites, update this test and the README claim; "+
			"if not, look for a regression in EventRange, Gaps, or the fields hash.Chain covers)",
			report.Gaps, report.Tampered, report.Downgrades, report.Verified)
	}
}

func TestHMACChainDetectsARewrite(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"}
	c, events, streamID := seedChain(t, hash.SchemeHMACV5, provider)

	rewriteAndRelink(t, events, 2, "attacker-was-not-here")
	persist(t, c, events)

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemeHMACV5, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatal("the hmac chain accepted a relinked rewrite")
	}
	if len(report.Downgrades) == 0 {
		t.Error("the relink relabelled events as plain; expected them in Downgrades")
	}
}

// TestRotatedKeyStillVerifiesOldEvents proves that rotating the active HMAC
// key does not strand the events written under the retired one: as long as
// the provider still resolves the old key through ByID, the whole chain --
// old segment and new segment alike -- verifies clean.
//
// This is the legitimate counterpart to the two tests above: rotation is a
// deliberate, authorised change to the signing key, not an attacker rewriting
// rows, so it must NOT show up as a downgrade or a tamper.
func TestRotatedKeyStillVerifiesOldEvents(t *testing.T) {
	ctx := context.Background()

	key1 := make([]byte, 32)
	key1[0] = 1
	provider := &rotatingProvider{
		keys:     map[string][]byte{"hmac-1": key1},
		activeID: "hmac-1",
	}

	c, events, streamID := seedChain(t, hash.SchemeHMACV5, provider)

	// Rotate: hmac-2 becomes the active signing key. hmac-1 stays resolvable
	// through ByID, which is what lets the events already written under it
	// keep verifying.
	key2 := make([]byte, 32)
	key2[0] = 2
	provider.rotate("hmac-2", key2)

	recCtx := scope.WithTenantID(scope.WithAppID(ctx, events[0].AppID), events[0].TenantID)
	for i := 1; i <= 5; i++ {
		err := c.Info(recCtx, "login", "session", fmt.Sprintf("session-post-rotate-%d", i)).
			Category("auth").
			UserID(fmt.Sprintf("user-post-rotate-%d", i)).
			Record()
		if err != nil {
			t.Fatalf("Record post-rotation event %d: %v", i, err)
		}
	}

	total := uint64(len(events) + 5)

	// Valid==true and no Downgrades is necessary but not sufficient: a
	// Chronicle that stopped calling Current per event (resolving the HMAC
	// key once at New instead) would leave every event on hmac-1, rotation
	// would silently stop taking effect, and every event would still verify
	// under a resolvable key -- Valid would stay true and this test would
	// stay green without ever exercising rotation. Reading the key ID back
	// per segment is what catches that: it fails if rotation never happened,
	// independent of whether verification also happens to pass.
	all, err := c.Store().EventRange(ctx, streamID, 1, total)
	if err != nil {
		t.Fatalf("EventRange: %v", err)
	}
	for _, e := range all {
		switch {
		case e.Sequence <= 5 && e.HashKeyID != "hmac-1":
			t.Errorf("event %d HashKeyID = %q, want hmac-1 (written before rotation)", e.Sequence, e.HashKeyID)
		case e.Sequence > 5 && e.HashKeyID != "hmac-2":
			t.Errorf("event %d HashKeyID = %q, want hmac-2 (written after rotation)", e.Sequence, e.HashKeyID)
		}
	}

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: total,
		Pin: hash.Pin{Scheme: hash.SchemeHMACV5, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("rotated-key chain reported invalid: gaps=%v tampered=%v downgrades=%v",
			report.Gaps, report.Tampered, report.Downgrades)
	}
	if len(report.Downgrades) != 0 {
		t.Errorf("Downgrades = %v, want none", report.Downgrades)
	}
}

// TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints names the
// residual risk Axis 1 leaves open: raising the cost of tampering is not the
// same as eliminating it. Per-event forgery without the HMAC key is stopped
// -- see TestHMACChainDetectsARewrite -- because an attacker who rewrites
// events but leaves the stream's pin alone gets caught by the downgrade
// check at hash/chain.go.
//
// But the pin the downgrade check compares against is not outside the
// attacker's reach. It is a row in chronicle_streams, in the same database as
// chronicle_events. An attacker with write access to that database can
// rewrite every event to the plain scheme AND update the stream row's
// scheme to match, the way production reads it at chronicle.go's
// VerifyEvent, handler/verify.go, and dashboard/contributor.go: fetch the
// stream, take st.Scheme and st.SchemeSince as the pin. With both halves
// rewritten consistently, the claimed scheme equals the pinned scheme
// everywhere, the rank comparison never finds a mismatch, and every plain
// digest recomputes correctly. VerifyChain reports Valid: true even when fed
// a pin read fresh from the (now-tampered) stream row, not a literal.
//
// Closing this needs evidence that lives outside the database: a signed
// checkpoint anchored somewhere the attacker's database write access does
// not reach. That is Axis 2, not this one. This test exists so nobody reads
// the three tests above it as a stronger guarantee than they make.
//
// Axis 2 has since landed, in two parts, and only the first is in this repo
// yet. A local checkpoint -- signed, but stored in chronicle_checkpoints,
// the same database as everything else here -- closes part of this gap: if
// one survives covering the tampered range, the rewrite is provable even
// though the events and the pin were rewritten together (see
// checkpoint_tamper_test.go's TestRewriteAfterACheckpointIsProvable), and
// deleting one checkpoint out of several is itself detectable
// (TestDeletingAMiddleCheckpointIsDetected). Truncating the tail and moving
// the head down to hide it is caught too, as long as the covering checkpoint
// is still in the table for VerifyChain to compare against
// (TestTruncationIsDetectedWhileTheCheckpointSurvives). It does not close
// all of it: the same attacker who can rewrite chronicle_events and
// chronicle_streams can also delete the checkpoint that would have caught
// them, or delete every checkpoint a stream has, and VerifyChain alone does
// not notice either (TestTruncationBeyondADeletedCheckpointIsNotDetected,
// TestDeletingEveryCheckpointDropsCoverageNotValidity). What is left is
// exactly the "outside the database" evidence this comment already named:
// external anchoring, still the next piece of work.
func TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"}
	c, events, streamID := seedChain(t, hash.SchemeHMACV5, provider)

	// idx 0, not a tail: a full-stream downgrade needs every claimed scheme
	// to read plain, or a surviving hmac event would still mismatch a
	// plain-pinned stream and get caught on its own.
	rewriteAndRelink(t, events, 0, "attacker-was-not-here")
	persist(t, c, events)

	// Rewrite the stream's own pin, the second half of the attack a SQL shell
	// can run in the same transaction. There is no exported method for this:
	// production never updates a stream's scheme after creation, only an
	// attacker would. The closest available read path is stream.Store's
	// GetStream, promoted onto store.Adapter; for the memory backend it
	// returns the live *stream.Stream (see UpdateStreamHead in
	// store/memory/store.go, which mutates a stream the same way, by finding
	// it and setting fields directly -- streams are not cloned on read or
	// write the way events are). Setting fields on it is, for this backend,
	// the persisted state, which is the closest analogue available to the
	// UPDATE chronicle_streams a real attacker would run.
	reader, ok := c.Store().(streamReader)
	if !ok {
		t.Fatalf("store %T cannot read the stream row directly", c.Store())
	}
	st, err := reader.GetStream(ctx, streamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	st.Scheme = string(hash.SchemePlainV4)

	// Derive the pin the way production does, from the stream row, not a
	// literal, so this test cannot pass just because the test author typed
	// the wrong scheme by hand.
	pin := hash.Pin{Scheme: hash.Scheme(st.Scheme), Since: st.SchemeSince}

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: pin,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("a full-stream downgrade (events and pin rewritten together) was detected; "+
			"that would mean Axis 1 closes this gap on its own, which it does not -- "+
			"gaps=%v tampered=%v downgrades=%v verified=%d",
			report.Gaps, report.Tampered, report.Downgrades, report.Verified)
	}
}

// streamReader is satisfied by the store this suite always builds: its
// embedded store.Store interface promotes stream.Store's GetStream.
// TestFullStreamDowngradeIsNotDetectedWithoutSignedCheckpoints uses it to
// read, and for the memory backend mutate through the same pointer, the
// stream row that carries the pin.
type streamReader interface {
	GetStream(ctx context.Context, streamID id.ID) (*stream.Stream, error)
}

// seedChain builds a memory-backed Chronicle under the given scheme, records
// five events through Info(...).Record() under a fixed app/tenant scope, and
// reads them back in sequence order. The returned events carry exactly what
// the store persisted -- sequence, hash, scheme and key ID included -- which
// is what rewriteAndRelink and persist need to operate on.
func seedChain(t *testing.T, scheme hash.Scheme, provider keys.Provider) (*chronicle.Chronicle, []*audit.Event, id.ID) {
	t.Helper()
	ctx := context.Background()

	opts := []chronicle.Option{
		chronicle.WithStore(store.NewAdapter(memory.New())),
		chronicle.WithDigestScheme(scheme),
	}
	if provider != nil {
		opts = append(opts, chronicle.WithKeyProvider(provider))
	}

	c, err := chronicle.New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	recCtx := scope.WithTenantID(scope.WithAppID(ctx, "tamper-app"), "tamper-tenant")

	var streamID id.ID
	for i := 1; i <= 5; i++ {
		b := c.Info(recCtx, "login", "session", fmt.Sprintf("session-%d", i)).
			Category("auth").
			UserID(fmt.Sprintf("user-%d", i))
		if recErr := b.Record(); recErr != nil {
			t.Fatalf("Record event %d: %v", i, recErr)
		}
		streamID = b.Event().StreamID
	}

	events, err := c.Store().EventRange(ctx, streamID, 1, 5)
	if err != nil {
		t.Fatalf("EventRange: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("seeded %d events, want 5", len(events))
	}

	return c, events, streamID
}

// eventPurger is satisfied by the store this suite always builds
// (store.NewAdapter(memory.New())): its embedded store.Store interface
// promotes retention.Store's PurgeEvents. persist uses it to remove the stale
// rows before writing the relinked ones back under the same IDs -- a delete
// plus an insert, which is what an UPDATE through a SQL shell does to the
// underlying table.
type eventPurger interface {
	PurgeEvents(ctx context.Context, eventIDs []id.ID) (int64, error)
}

// persist writes the (already mutated) events straight into the store,
// bypassing Record entirely: no scope application, no fresh hash computation,
// no stream head update. That is deliberate. It is what an attacker with a SQL
// shell and no HMAC key can do, and it is the scenario rewriteAndRelink sets up.
func persist(t *testing.T, c *chronicle.Chronicle, events []*audit.Event) {
	t.Helper()
	ctx := context.Background()

	purger, ok := c.Store().(eventPurger)
	if !ok {
		t.Fatalf("persist: store %T cannot purge events for a raw rewrite", c.Store())
	}

	ids := make([]id.ID, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	if _, err := purger.PurgeEvents(ctx, ids); err != nil {
		t.Fatalf("persist: remove stale rows: %v", err)
	}
	if err := c.Store().AppendBatch(ctx, events); err != nil {
		t.Fatalf("persist: write relinked rows: %v", err)
	}
}

// rotatingProvider is a two-key keys.Provider that lets a test simulate
// rotation: Current always resolves whichever key is currently marked active,
// while ByID resolves any key it has ever held. That difference is what makes
// rotation safe: new digests move to the new key while everything written
// under the old one stays verifiable.
type rotatingProvider struct {
	keys     map[string][]byte
	activeID string
}

// rotate makes newID the active signing key, adding it if it is not already
// known. Existing keys stay resolvable through ByID, which is the property
// TestRotatedKeyStillVerifiesOldEvents exists to prove.
func (p *rotatingProvider) rotate(newID string, key []byte) {
	p.keys[newID] = key
	p.activeID = newID
}

func (p *rotatingProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	key, ok := p.keys[p.activeID]
	if !ok {
		return nil, "", keys.ErrNoActiveKey
	}
	return key, p.activeID, nil
}

func (p *rotatingProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, keys.ErrKeyNotFound
	}
	return key, nil
}

// Compile-time check.
var _ keys.Provider = (*rotatingProvider)(nil)
