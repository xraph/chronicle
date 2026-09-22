package extension_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xraph/forge"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/store/memory"
	sqlitestore "github.com/xraph/chronicle/store/sqlite"
)

// hasherStore wraps memory.Store to implement the optional
// interface{ SetHasher(*hash.Chain) } Register type-asserts for, standing in
// for pgstore.Store/sqlitestore.Store without the overhead of a real
// database connection. hasher is unused beyond recording that SetHasher was
// called with something non-nil -- these tests only exercise Register's
// wiring, not a real Append.
type hasherStore struct {
	*memory.Store
	hasher *hash.Chain
}

func (s *hasherStore) SetHasher(h *hash.Chain) { s.hasher = h }

// TestAuthValidateFailsClosed pins the default posture: mounting the admin API
// with no authentication has to be an explicit choice.
//
// The API can permanently destroy audit data, and Chronicle's per-request scope
// check only keeps tenants out of each other's data — it does not gate these
// operations at all. So an unconfigured extension must refuse to start rather
// than quietly serving a destructive API to any caller.
func TestAuthValidateFailsClosed(t *testing.T) {
	var cfg extension.AuthConfig

	err := cfg.Validate(true)
	if err == nil {
		t.Fatal("an unconfigured API with routes enabled must not validate")
	}
	if !errors.Is(err, extension.ErrAuthNotConfigured) {
		t.Fatalf("error = %v, want ErrAuthNotConfigured", err)
	}
}

func TestAuthValidateAcceptsAConfiguredProvider(t *testing.T) {
	cfg := extension.AuthConfig{
		Provider:    "jwt",
		AdminScopes: []string{"chronicle:admin"},
	}

	if err := cfg.Validate(true); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !cfg.Configured() {
		t.Fatal("Configured() should report true when a provider is named")
	}
}

// TestAuthValidateAcceptsExplicitOptOut is the escape hatch for deployments that
// authenticate upstream.
func TestAuthValidateAcceptsExplicitOptOut(t *testing.T) {
	cfg := extension.AuthConfig{AllowUnauthenticated: true}

	if err := cfg.Validate(true); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Configured() {
		t.Fatal("Configured() should report false with no provider")
	}
}

// TestAuthValidateSkipsWhenRoutesDisabled: nothing is exposed, nothing to guard.
func TestAuthValidateSkipsWhenRoutesDisabled(t *testing.T) {
	var cfg extension.AuthConfig

	if err := cfg.Validate(false); err != nil {
		t.Fatalf("Validate with routes disabled: %v", err)
	}
}

// TestAuthNotConfiguredErrorNamesTheWayOut keeps the message actionable: an
// operator hitting this at startup needs to know their three options.
func TestAuthNotConfiguredErrorNamesTheWayOut(t *testing.T) {
	msg := extension.ErrAuthNotConfigured.Error()

	for _, want := range []string{
		"auth.provider",
		"auth.allow_unauthenticated",
		"disable_routes",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message should mention %q, got: %s", want, msg)
		}
	}
}

// TestCryptoErasureNeedsAKeyStore pins that enabling encryption without
// somewhere durable to keep the keys is refused rather than silently degrading.
//
// A defaulted in-memory key store would lose every key on restart, which reads as
// having erased every subject — indistinguishable from data loss.
func TestCryptoErasureNeedsAKeyStore(t *testing.T) {
	ext := extension.New(
		extension.WithStore(memory.New()),
		extension.WithCryptoErasure(true),
		extension.WithUnauthenticatedAPI(),
	)

	err := ext.Register(forge.New(forge.WithAppName("t")))
	if err == nil {
		t.Fatal("crypto-erasure without a key store must fail")
	}
	if !errors.Is(err, extension.ErrKeyStoreRequired) {
		t.Fatalf("error = %v, want ErrKeyStoreRequired", err)
	}
}

// TestCryptoErasureWithKeyStoreStarts is the happy path.
func TestCryptoErasureWithKeyStoreStarts(t *testing.T) {
	ext := extension.New(
		extension.WithStore(memory.New()),
		extension.WithCryptoErasure(true),
		extension.WithKeyStore(crypto.NewInMemoryKeyStore()),
		extension.WithUnauthenticatedAPI(),
	)

	if err := ext.Register(forge.New(forge.WithAppName("t"))); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if ext.Chronicle() == nil {
		t.Fatal("expected a Chronicle instance")
	}
}

func TestTamperEvidenceValidateRejectsHMACWithoutKeys(t *testing.T) {
	cfg := extension.TamperEvidenceConfig{Digest: "hmac"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted digest: hmac with no key source, want an error")
	}
}

func TestTamperEvidenceValidateAcceptsPlain(t *testing.T) {
	cfg := extension.TamperEvidenceConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected the default plain config: %v", err)
	}
}

func TestTamperEvidenceValidateRejectsUnknownDigest(t *testing.T) {
	cfg := extension.TamperEvidenceConfig{Digest: "sha1"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted an unknown digest, want an error")
	}
}

// TestExtensionAcceptsKeyProviderSuppliedDirectly pins a case
// TamperEvidenceConfig.Validate cannot see by itself: KeyConfig.Provider's doc
// comment says empty means "take a keys.Provider from WithKeyProvider", but
// Validate only inspects the Keys config fields, so on its own it would reject
// this deployment with ErrKeyProviderRequired even though a real provider is
// in hand. The extension has to recognize that case at Register rather than
// force every HMAC deployment through a file-backed keyset.
//
// Uses hasherStore rather than a bare memory.Store: under digest: hmac,
// Register now also requires an operator-supplied WithStore to be able to
// receive the chain (see TestWithStoreRefusesHMACWhenStoreCannotReceiveTheChain),
// and a bare memory.Store can't, which is orthogonal to what this test pins.
func TestExtensionAcceptsKeyProviderSuppliedDirectly(t *testing.T) {
	ext := extension.New(
		extension.WithStore(&hasherStore{Store: memory.New()}),
		extension.WithUnauthenticatedAPI(),
		extension.WithDigestScheme("hmac"),
		extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "k1"}),
	)

	if err := ext.Register(forge.New(forge.WithAppName("t"))); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

// TestWithStoreRefusesHMACWhenStoreCannotReceiveTheChain is FINDING 1's
// negative case: extension.WithStore bypasses buildStoreFromGroveDB, which is
// the only place a pg/sqlite store otherwise gets WithHasher. A store that
// can't be given the chain after construction either (no SetHasher) must not
// be allowed to start under an HMAC config: it would keep re-linking every
// event under its own default plain chain while Chronicle writes HMAC
// digests, silently, since the writes still succeed.
func TestWithStoreRefusesHMACWhenStoreCannotReceiveTheChain(t *testing.T) {
	ext := extension.New(
		extension.WithStore(memory.New()), // does not implement SetHasher
		extension.WithUnauthenticatedAPI(),
		extension.WithDigestScheme("hmac"),
		extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "k1"}),
	)

	err := ext.Register(forge.New(forge.WithAppName("t")))
	if err == nil {
		t.Fatal("Register accepted an HMAC config with a WithStore store that cannot receive the chain")
	}
	if !errors.Is(err, extension.ErrStoreCannotReceiveHasher) {
		t.Fatalf("error = %v, want ErrStoreCannotReceiveHasher", err)
	}
}

// TestWithStoreInjectsTheChainWhenTheStoreCanReceiveIt is FINDING 1's
// positive case, and the literal repro the finding cited:
//
//	extension.New(
//	    extension.WithStore(pgstore.New(db)),
//	    extension.WithDigestScheme("hmac"),
//	    extension.WithKeyProvider(p),
//	)
//
// Uses sqlitestore in place of pgstore (no server dependency; both back
// SetHasher identically), and proves the injection actually took effect --
// not just that Register returned no error -- by recording a real event and
// reading the persisted hash_scheme back.
func TestWithStoreInjectsTheChainWhenTheStoreCanReceiveIt(t *testing.T) {
	db := newSQLiteGroveDB(t)

	app := forge.New(forge.WithAppName("t"))
	ext := extension.New(
		extension.WithStore(sqlitestore.New(db)),
		extension.WithUnauthenticatedAPI(),
		extension.WithDigestScheme("hmac"),
		extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "hmac-1"}),
	)

	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	ctx := context.Background()
	if err := ext.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	seedStream(t, db, hash.SchemeHMAC)

	event := &audit.Event{
		AppID:    tamperTestAppID,
		Action:   "login",
		Resource: "session",
		Category: "auth",
	}
	if err := ext.Chronicle().Record(ctx, event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := sqlitestore.New(db).Get(ctx, event.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HashScheme != string(hash.SchemeHMAC) {
		t.Fatalf("HashScheme = %q, want %q; the store passed to WithStore never received the chain",
			got.HashScheme, hash.SchemeHMAC)
	}
}

// TestExtensionRejectsHMACWithoutKeyProviderAtRegister pins the headline
// fail-closed promise through the actual entry point an operator hits:
// Register, not just TamperEvidenceConfig.Validate in isolation. digest: hmac
// with no key source at all -- no Keys.Provider/Path, no WithKeyProvider --
// must refuse to start rather than quietly write unkeyed digests an operator
// believes are keyed.
func TestExtensionRejectsHMACWithoutKeyProviderAtRegister(t *testing.T) {
	ext := extension.New(
		extension.WithStore(memory.New()),
		extension.WithUnauthenticatedAPI(),
		extension.WithDigestScheme("hmac"),
	)

	err := ext.Register(forge.New(forge.WithAppName("t")))
	if err == nil {
		t.Fatal("Register accepted digest: hmac with no key source at all, want an error")
	}
	if !errors.Is(err, extension.ErrKeyProviderRequired) {
		t.Fatalf("error = %v, want ErrKeyProviderRequired", err)
	}
}

// TestPlainConfigIgnoresStaleFileProviderConfig pins that a plain (or
// unconfigured) deployment never touches Keys.Provider/Path at all. Before
// buildHashChain gated the file-provider branch on Digest == "hmac", a
// leftover tamper_evidence.keys.provider: file block -- e.g. from a
// deployment that turned HMAC back off but forgot to clear its key config --
// would fail Register trying to read a keyset nothing is ever going to use.
func TestPlainConfigIgnoresStaleFileProviderConfig(t *testing.T) {
	ext := extension.New(
		extension.WithStore(memory.New()),
		extension.WithConfig(extension.Config{
			TamperEvidence: extension.TamperEvidenceConfig{
				// Digest left at "" (plain) deliberately.
				Keys: extension.KeyConfig{
					Provider: "file",
					Path:     "/does/not/exist/keyset.json",
				},
			},
		}),
		extension.WithUnauthenticatedAPI(),
	)

	if err := ext.Register(forge.New(forge.WithAppName("t"))); err != nil {
		t.Fatalf("Register: %v; a plain deployment must not read the stale file provider config", err)
	}
}
