package hash_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/keys"
)

// stubProvider is a Provider backed by a fixed key.
type stubProvider struct {
	key      []byte
	activeID string
}

func (s stubProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return s.key, s.activeID, nil
}

func (s stubProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != s.activeID {
		return nil, keys.ErrKeyNotFound
	}
	return s.key, nil
}

func newEvent() *audit.Event {
	return &audit.Event{
		Timestamp: time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Sequence:  5,
		Action:    "login",
		Resource:  "session",
		Category:  "auth",
		UserID:    "user-42",
		IP:        "10.0.0.1",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
	}
}

func hmacChain(t *testing.T) *hash.Chain {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c, err := hash.NewChain(hash.SchemeHMAC, stubProvider{key: key, activeID: "hmac-1"})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	return c
}

// A zero Chain is constructed in three places in this repo and must keep
// behaving exactly as it did before schemes existed.
func TestZeroChainIsPlain(t *testing.T) {
	var c hash.Chain
	digest, keyID, err := c.Compute(context.Background(), "", newEvent())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if keyID != "" {
		t.Errorf("keyID = %q, want empty for the plain scheme", keyID)
	}
	if len(digest) != 64 {
		t.Errorf("digest length = %d, want 64", len(digest))
	}
}

// The point of the whole exercise: without the key you cannot produce the
// digest, so recomputing the chain from the stored row is not enough.
func TestHMACDigestDiffersFromPlain(t *testing.T) {
	ctx := context.Background()
	event := newEvent()

	var plain hash.Chain
	plainDigest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("plain Compute: %v", err)
	}

	hmacDigest, keyID, err := hmacChain(t).Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("hmac Compute: %v", err)
	}

	if hmacDigest == plainDigest {
		t.Error("hmac digest equals the plain digest; the key is not being used")
	}
	if keyID != "hmac-1" {
		t.Errorf("keyID = %q, want hmac-1", keyID)
	}
}

func TestHMACRoundTripVerifies(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()

	digest, keyID, err := c.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme, event.HashKeyID = digest, string(hash.SchemeHMAC), keyID

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMAC, Since: 1})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.OK {
		t.Error("a freshly computed hmac event failed verification")
	}
	if res.Downgrade {
		t.Error("a matching scheme was reported as a downgrade")
	}
}

// The strict path (claimed scheme matches or exceeds the pin) has to actually
// reject a mismatch, not just accept a match. A downgrade check that always
// runs before it would let a strict-branch implementation that returns
// OK: true unconditionally pass every other test in this file.
func TestHMACStrictVerificationRejectsTamperedEvent(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()

	digest, keyID, err := c.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme, event.HashKeyID = digest, string(hash.SchemeHMAC), keyID

	// Tamper after the digest is stored: same scheme, same key, wrong content.
	event.UserID = "attacker"

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMAC, Since: 1})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if res.OK {
		t.Error("a tampered event verified OK under the strict path")
	}
	if res.Downgrade {
		t.Error("a same-scheme mismatch must not be reported as a downgrade")
	}
	if res.Scheme != hash.SchemeHMAC {
		t.Errorf("Scheme = %q, want %q", res.Scheme, hash.SchemeHMAC)
	}
}

// A HashKeyID that resolves to nothing is not a verification failure to
// report as OK: false; it is a lookup the chain cannot even perform, so it
// must surface as an error rather than silently reporting tampering.
func TestVerifyWithPinErrorsOnUnresolvableKeyID(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()

	digest, _, err := c.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme, event.HashKeyID = digest, string(hash.SchemeHMAC), "no-such-key"

	if _, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMAC, Since: 1}); err == nil {
		t.Fatal("VerifyWithPin accepted an event whose HashKeyID does not resolve, want an error")
	}
}

// The failure scenario this guards: a row edited to claim a scheme this
// package does not implement, with a digest recomputed under plain SHA-256.
// Falling through to the plain algorithm because the label is unrecognized
// would let that pass as an ordinary plain-scheme event. A zero Pin is the
// case that matters most, since it is what the deprecated Verify shim passes
// and so what every call site not yet rewired to VerifyWithPin uses today;
// with a zero Pin the downgrade check at rank() never runs, so only
// computeUnder itself stands between an unrecognized scheme and a false OK.
func TestVerifyWithPinRejectsUnrecognizedScheme(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()

	var plain hash.Chain
	digest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("plain Compute: %v", err)
	}
	event.Hash, event.HashScheme = digest, "chronicle/v4"

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{})
	if err == nil {
		t.Fatalf("VerifyWithPin accepted scheme %q by falling back to another algorithm, want an error; got %+v",
			event.HashScheme, res)
	}
}

// The attack this design exists to stop: rewrite the event, recompute the
// digest under the weaker scheme, and relabel it.
func TestDowngradeToPlainIsDetected(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()

	var plain hash.Chain
	plainDigest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("plain Compute: %v", err)
	}
	event.Hash, event.HashScheme, event.HashKeyID = plainDigest, string(hash.SchemePlain), ""

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMAC, Since: 1})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.Downgrade {
		t.Error("an event claiming the plain scheme above the pin was not flagged as a downgrade")
	}
	if res.OK {
		t.Error("a downgraded event verified OK")
	}
}

// Blanking the column must not buy the tolerant path.
func TestBlankSchemeAboveThePinIsADowngrade(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()

	var plain hash.Chain
	plainDigest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("plain Compute: %v", err)
	}
	event.Hash, event.HashScheme = plainDigest, ""

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMAC, Since: 1})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.Downgrade {
		t.Error("a blank scheme above the pin was not flagged as a downgrade")
	}
}

// Pre-migration rows carry no scheme and sit below the pin. They keep verifying.
func TestPreMigrationEventVerifiesTolerantly(t *testing.T) {
	ctx := context.Background()
	event := newEvent()

	var plain hash.Chain
	digest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme = digest, ""

	res, err := hmacChain(t).VerifyWithPin(ctx, "prev", event,
		hash.Pin{Scheme: hash.SchemeHMAC, Since: 100})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.OK {
		t.Error("a pre-migration event below the pin failed verification")
	}
	if !res.Tolerant {
		t.Error("resolution below the pin should be reported as tolerant")
	}
	if res.Downgrade {
		t.Error("an event below the pin must not be flagged as a downgrade")
	}
}

// Plain events written before a switch to HMAC sit below the new pin, and are
// still verified strictly because they carry a scheme.
func TestPlainEventBelowPinVerifiesStrictly(t *testing.T) {
	ctx := context.Background()
	event := newEvent()

	var plain hash.Chain
	digest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme = digest, string(hash.SchemePlain)

	res, err := hmacChain(t).VerifyWithPin(ctx, "prev", event,
		hash.Pin{Scheme: hash.SchemeHMAC, Since: 100})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.OK || res.Tolerant || res.Downgrade {
		t.Errorf("got %+v, want a strict plain verification below the pin", res)
	}
}

func TestNewChainRequiresProviderForHMAC(t *testing.T) {
	if _, err := hash.NewChain(hash.SchemeHMAC, nil); err == nil {
		t.Fatal("NewChain accepted SchemeHMAC with no key provider, want an error")
	}
}

func TestNewChainRejectsLegacyForWriting(t *testing.T) {
	if _, err := hash.NewChain(hash.SchemeLegacy, nil); err == nil {
		t.Fatal("NewChain accepted SchemeLegacy, which is verify-only, want an error")
	}
}
