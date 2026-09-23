package hash_test

import (
	"context"
	"strings"
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
	c, err := hash.NewChain(hash.SchemeHMACV5, stubProvider{key: key, activeID: "hmac-1"})
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
	event.Hash, event.HashScheme, event.HashKeyID = digest, string(hash.SchemeHMACV5), keyID

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMACV5, Since: 1})
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
	event.Hash, event.HashScheme, event.HashKeyID = digest, string(hash.SchemeHMACV5), keyID

	// Tamper after the digest is stored: same scheme, same key, wrong content.
	event.UserID = "attacker"

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMACV5, Since: 1})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if res.OK {
		t.Error("a tampered event verified OK under the strict path")
	}
	if res.Downgrade {
		t.Error("a same-scheme mismatch must not be reported as a downgrade")
	}
	if res.Scheme != hash.SchemeHMACV5 {
		t.Errorf("Scheme = %q, want %q", res.Scheme, hash.SchemeHMACV5)
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
	event.Hash, event.HashScheme, event.HashKeyID = digest, string(hash.SchemeHMACV5), "no-such-key"

	if _, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMACV5, Since: 1}); err == nil {
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
	// Deliberately a version number no scheme will plausibly reach. This test
	// previously used "chronicle/v4" and started passing for the wrong reason
	// the day v4 shipped.
	event.Hash, event.HashScheme = digest, "chronicle/v99"

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
	event.Hash, event.HashScheme, event.HashKeyID = plainDigest, string(hash.SchemePlainV4), ""

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMACV5, Since: 1})
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

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMACV5, Since: 1})
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

	event.Hash, event.HashScheme = hash.ComputeV2ForTest("prev", event), ""

	res, err := hmacChain(t).VerifyWithPin(ctx, "prev", event,
		hash.Pin{Scheme: hash.SchemeHMACV5, Since: 100})
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

	event.Hash, event.HashScheme = hash.ComputeV2ForTest("prev", event), string(hash.SchemePlain)

	res, err := hmacChain(t).VerifyWithPin(ctx, "prev", event,
		hash.Pin{Scheme: hash.SchemeHMACV5, Since: 100})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.OK || res.Tolerant || res.Downgrade {
		t.Errorf("got %+v, want a strict plain verification below the pin", res)
	}
}

func TestNewChainRequiresProviderForHMAC(t *testing.T) {
	if _, err := hash.NewChain(hash.SchemeHMACV5, nil); err == nil {
		t.Fatal("NewChain accepted SchemeHMACV5 with no key provider, want an error")
	}
}

func TestNewChainRejectsLegacyForWriting(t *testing.T) {
	if _, err := hash.NewChain(hash.SchemeLegacy, nil); err == nil {
		t.Fatal("NewChain accepted SchemeLegacy, which is verify-only, want an error")
	}
}

// The ordering reconcileStreamPin leans on. Framing breaks ties inside a pair,
// but a keyed scheme always outranks an unkeyed one.
//
// The row that matters is SchemeHMAC above SchemePlainV4. Rank them the other
// way round and a move from the keyed-but-ambiguous scheme to the unkeyed-but-
// framed one reads as strengthening, so the pin advances while the deployment
// stops using its key and nothing anywhere says so.
func TestKeyingOutranksFraming(t *testing.T) {
	ascending := []hash.Scheme{
		hash.SchemeLegacy,
		hash.SchemePlain,
		hash.SchemePlainV4,
		hash.SchemeHMAC,
		hash.SchemeHMACV5,
	}

	for i := 1; i < len(ascending); i++ {
		lower, higher := ascending[i-1], ascending[i]
		if hash.Rank(lower) >= hash.Rank(higher) {
			t.Errorf("Rank(%s) = %d is not below Rank(%s) = %d",
				lower, hash.Rank(lower), higher, hash.Rank(higher))
		}
	}

	if hash.Rank(hash.SchemePlainV4) >= hash.Rank(hash.SchemeHMAC) {
		t.Error("dropping the key to gain the framing fix reads as strengthening; " +
			"a stream pinned to hmac could be moved to an unkeyed scheme")
	}

	// An unknown scheme has to sit below every named one, or an attacker
	// invents a label and outranks the pin.
	if hash.Rank("chronicle/v99") != 0 {
		t.Errorf("Rank of an unknown scheme = %d, want 0", hash.Rank("chronicle/v99"))
	}
}

func TestKeyedNamesTheSchemesThatUseAKey(t *testing.T) {
	for scheme, want := range map[hash.Scheme]bool{
		hash.SchemeLegacy:  false,
		hash.SchemePlain:   false,
		hash.SchemePlainV4: false,
		hash.SchemeHMAC:    true,
		hash.SchemeHMACV5:  true,
		"":                 false,
		"chronicle/v99":    false,
	} {
		if got := hash.Keyed(scheme); got != want {
			t.Errorf("Keyed(%q) = %v, want %v", scheme, got, want)
		}
	}
}

// Both ambiguous schemes have to be refused for writing, and the error has to
// name the replacement -- an operator hitting this at startup needs to know
// what to set, not just that what they set is wrong.
func TestNewChainRefusesToWriteTheAmbiguousSchemes(t *testing.T) {
	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"}

	for scheme, replacement := range map[hash.Scheme]hash.Scheme{
		hash.SchemePlain: hash.SchemePlainV4,
		hash.SchemeHMAC:  hash.SchemeHMACV5,
	} {
		_, err := hash.NewChain(scheme, provider)
		if err == nil {
			t.Errorf("NewChain(%s) succeeded; it writes an ambiguous content encoding", scheme)
			continue
		}
		if !strings.Contains(err.Error(), string(replacement)) {
			t.Errorf("NewChain(%s) error %q does not name %s", scheme, err, replacement)
		}
	}
}

// An event claiming the keyed-but-ambiguous scheme above a v5 pin is a
// downgrade, even though it is keyed. This is the rollback an attacker reaches
// for once plain is off the table: keep the key, lose the framing.
func TestFramingDowngradeAboveThePinIsDetected(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()
	event.Hash, event.HashScheme, event.HashKeyID = "whatever", string(hash.SchemeHMAC), "hmac-1"

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMACV5, Since: 1})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.Downgrade {
		t.Error("an event claiming chronicle/v3 above a chronicle/v5 pin was not flagged as a downgrade")
	}
	if res.OK {
		t.Error("a downgraded event verified OK")
	}
}
