package contract

import (
	"bytes"
	"context"
	"errors"
	"testing"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
)

// settingsStaticProvider is a keys.Provider with one active hmac key.
type settingsStaticProvider struct{}

func (settingsStaticProvider) Current(context.Context, keys.Use) ([]byte, string, error) {
	return make([]byte, keys.HMACKeySize), "hmac-1", nil
}
func (settingsStaticProvider) ByID(context.Context, string) ([]byte, error) {
	return make([]byte, keys.HMACKeySize), nil
}

// settingsProbeStore answers the checkpoint capability probe with a fixed
// result and embeds the stub store for everything else.
type settingsProbeStore struct {
	*stubStore
	err error
}

func (s settingsProbeStore) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, s.err
}

func settingsCall(t *testing.T, deps Deps) SettingsDetail {
	t.Helper()
	out, err := settingsDetailHandler(deps)(context.Background(), struct{}{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("settings.detail: %v", err)
	}
	return out
}

// The default deployment: plain digest, no checkpoints. The settings panel
// is where an operator finds out, and it must not describe that state with
// a word stronger than it earns.
func TestSettingsReportsADefaultDeploymentHonestly(t *testing.T) {
	out := settingsCall(t, Deps{Store: newStubStore(), Config: SurfaceConfig{BackendName: "sqlite"}})

	if out.DigestScheme != string(hash.SchemePlainV4) {
		t.Errorf("DigestScheme = %q, want %q", out.DigestScheme, hash.SchemePlainV4)
	}
	if out.Keyed {
		t.Error("a nil HashChain was reported as keyed")
	}
	if out.CheckpointingConfigured {
		t.Error("reported checkpointing as configured when no store or signer was supplied")
	}
}

func TestSettingsReportsAKeyedChainAsKeyed(t *testing.T) {
	chain, err := hash.NewChain(hash.SchemeHMACV5, settingsStaticProvider{})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	out := settingsCall(t, Deps{Store: newStubStore(), HashChain: chain})

	if out.DigestScheme != string(hash.SchemeHMACV5) {
		t.Errorf("DigestScheme = %q, want %q", out.DigestScheme, hash.SchemeHMACV5)
	}
	if !out.Keyed {
		t.Error("a chain writing under chronicle/v5 was not reported as keyed")
	}
}

// An explicit plain chain and a nil one are the same deployment.
func TestSettingsReportsAnExplicitPlainChainAsUnkeyed(t *testing.T) {
	chain, err := hash.NewChain(hash.SchemePlainV4, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	out := settingsCall(t, Deps{Store: newStubStore(), HashChain: chain})
	if out.DigestScheme != string(hash.SchemePlainV4) || out.Keyed {
		t.Errorf("got scheme %q keyed=%v, want chronicle/v4 unkeyed", out.DigestScheme, out.Keyed)
	}
}

func TestSettingsReportsCheckpointingOnlyWhenBothStoreAndSignerExist(t *testing.T) {
	cases := []struct {
		name string
		deps Deps
		want bool
	}{
		{"neither", Deps{}, false},
		// A store without a signer proves nothing: whoever could write the
		// checkpoint row could write a fabricated one.
		{"store only", Deps{CheckpointStore: stubCheckpointStore{}}, false},
		{"signer only", Deps{CheckpointSigner: stubSigner{}}, false},
		{"both", Deps{CheckpointStore: stubCheckpointStore{}, CheckpointSigner: stubSigner{}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.deps.Store = newStubStore()
			if got := settingsCall(t, tc.deps).CheckpointingConfigured; got != tc.want {
				t.Errorf("CheckpointingConfigured = %v, want %v", got, tc.want)
			}
		})
	}
}

// The backend determines what a verification result is worth. Redis neither
// recomputes the chain under a lock nor holds checkpoints, so an operator
// reading a result there deserves to know it means less than the same result
// on postgres.
func TestSettingsReportsTheBackendAndWhetherItHoldsCheckpoints(t *testing.T) {
	out := settingsCall(t, Deps{
		Store:  settingsProbeStore{stubStore: &stubStore{}, err: checkpoint.ErrUnsupported},
		Config: SurfaceConfig{BackendName: "redis"},
	})
	if out.BackendName != "redis" {
		t.Errorf("BackendName = %q, want redis", out.BackendName)
	}
	if out.BackendHoldsCheckpoints {
		t.Error("a store answering ErrUnsupported was reported as holding checkpoints")
	}
}

func TestSettingsProbeOutcomes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"unsupported", checkpoint.ErrUnsupported, false},
		{"wrapped unsupported", errors.Join(errors.New("redis"), checkpoint.ErrUnsupported), false},
		// The backend can hold checkpoints and simply has none for the nil ID.
		{"not found", checkpoint.ErrNotFound, true},
		{"no error", nil, true},
		// The probe failing says nothing about capability.
		{"other error", errors.New("connection refused"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := settingsCall(t, Deps{Store: settingsProbeStore{stubStore: &stubStore{}, err: tc.err}})
			if out.BackendHoldsCheckpoints != tc.want {
				t.Errorf("BackendHoldsCheckpoints = %v, want %v", out.BackendHoldsCheckpoints, tc.want)
			}
		})
	}
}

// A failed probe must not fail the intent, but it must leave a trace.
func TestSettingsLogsAProbeFailureAndStillAnswers(t *testing.T) {
	logger := log.NewTestLogger()
	out := settingsCall(t, Deps{
		Store:  settingsProbeStore{stubStore: &stubStore{}, err: errors.New("connection refused")},
		Logger: logger,
	})
	if !out.BackendHoldsCheckpoints {
		t.Error("a failed probe was reported as unsupported")
	}
	if n := logger.(*log.TestLogger).CountLogs("ERROR"); n != 1 {
		t.Errorf("logged %d errors, want 1", n)
	}
}

func TestSettingsPassesConfigurationThrough(t *testing.T) {
	out := settingsCall(t, Deps{Store: newStubStore(), Config: SurfaceConfig{
		BatchSize:           250,
		FlushInterval:       "5s",
		RetentionInterval:   "1h0m0s",
		EnableCryptoErasure: true,
		BackendName:         "postgres",
	}})
	if out.BatchSize != 250 || out.FlushInterval != "5s" || out.RetentionInterval != "1h0m0s" ||
		!out.EnableCryptoErasure || out.BackendName != "postgres" {
		t.Errorf("configuration not carried through: %+v", out)
	}
}

func TestSettingsRefusesAPrincipalWithNoAppBeforeTouchingTheStore(t *testing.T) {
	store := &settingsCountingStore{stubStore: &stubStore{}}
	_, err := settingsDetailHandler(Deps{Store: store})(context.Background(), struct{}{}, principalWith(nil))

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodePermissionDenied {
		t.Fatalf("settings.detail for a principal with no app = %v, want PERMISSION_DENIED", err)
	}
	if store.probes != 0 {
		t.Errorf("the store was probed %d times before the scope was refused", store.probes)
	}
}

type settingsCountingStore struct {
	*stubStore
	probes int
}

func (s *settingsCountingStore) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	s.probes++
	return nil, checkpoint.ErrNotFound
}

// Every camelCase name here is what the React client reads. A rename that
// leaves the Go field alone would compile and break the page silently.
func TestSettingsWireNames(t *testing.T) {
	d := newTestDispatcher(t)
	if err := Register(d, fcontract.NewRegistry(), fcontract.NewWardenRegistry(), Deps{Store: newStubStore()}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	data, _, err := d.Dispatch(context.Background(), fcontract.Request{
		Kind: fcontract.KindQuery, Contributor: "chronicle", Intent: "settings.detail", IntentVersion: 1,
	}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("dispatch settings.detail: %v", err)
	}
	for _, name := range []string{
		"batchSize", "flushInterval", "retentionInterval", "enableCryptoErasure",
		"digestScheme", "keyed", "checkpointingConfigured", "backendName", "backendHoldsCheckpoints",
	} {
		if !bytes.Contains(data, []byte(`"`+name+`"`)) {
			t.Errorf("response %s carries no %q field", data, name)
		}
	}
}
