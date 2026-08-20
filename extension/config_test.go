package extension_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/xraph/forge"

	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/store/memory"
)

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
