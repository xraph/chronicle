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
		events[i].HashScheme = string(hash.SchemePlain)
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
	c, events, streamID := seedChain(t, hash.SchemePlain, nil)

	rewriteAndRelink(t, events, 2, "attacker-was-not-here")
	persist(t, c, events)

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatal("the plain chain detected a full relink; update this test and the README claim")
	}
}

func TestHMACChainDetectsARewrite(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"}
	c, events, streamID := seedChain(t, hash.SchemeHMAC, provider)

	rewriteAndRelink(t, events, 2, "attacker-was-not-here")
	persist(t, c, events)

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemeHMAC, Since: 1},
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

	c, events, streamID := seedChain(t, hash.SchemeHMAC, provider)

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
	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: total,
		Pin: hash.Pin{Scheme: hash.SchemeHMAC, Since: 1},
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
