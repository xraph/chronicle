package extension_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/extension"
)

// contractPrincipal builds a dashboard principal carrying the given claims.
func contractPrincipal(claims map[string]any) fcontract.Principal {
	return fcontract.Principal{
		User:   &dashauth.UserInfo{Subject: "operator-1", Claims: claims},
		Claims: claims,
	}
}

// dispatchQuery sends one query intent through the dispatcher, the way the
// dashboard's HTTP layer does, and returns the raw response data.
func dispatchQuery(d *dispatcher.Dispatcher, intent string, p fcontract.Principal) ([]byte, error) {
	data, _, err := d.Dispatch(context.Background(), fcontract.Request{
		Kind:          fcontract.KindQuery,
		Contributor:   "chronicle",
		Intent:        intent,
		IntentVersion: 1,
	}, p)
	return data, err
}

// TestContractContributorServesAnHMACDeployment drives the extension's own
// RegisterContractContributor wiring over a real HMAC deployment and
// dispatches through the dispatcher.
//
// The contract package's tests build Deps by hand, so none of them can notice
// a field the extension forgot to pass. The one that matters most is
// Deps.HashChain: with it missing the verifier is unkeyed and reports every
// keyed event as tampered or downgraded, while everything else in the
// package stays green. That is the same hole
// TestHMACDeploymentVerifiesThroughTheDashboard closes for the templ path.
func TestContractContributorServesAnHMACDeployment(t *testing.T) {
	ext, _ := setupHMACExtension(t)
	ctx := context.Background()
	for range 2 {
		if err := ext.Chronicle().Record(ctx, &audit.Event{
			AppID:    tamperTestAppID,
			Action:   "logout",
			Resource: "session",
			Category: "auth",
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	d := dispatcher.New(dispatcher.NoopMetricsEmitter{})
	reg := fcontract.NewRegistry()
	if err := ext.RegisterContractContributor(d, reg, fcontract.NewWardenRegistry()); err != nil {
		t.Fatalf("RegisterContractContributor: %v", err)
	}
	if _, ok := reg.Contributor("chronicle"); !ok {
		t.Fatal("the chronicle contributor was not registered")
	}

	scoped := contractPrincipal(map[string]any{"app_id": tamperTestAppID})

	t.Run("streams.mine answers with a keyed chain", func(t *testing.T) {
		data, err := dispatchQuery(d, "streams.mine", scoped)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		var out struct {
			Stream *struct {
				HeadSeq         uint64 `json:"headSeq"`
				Scheme          string `json:"scheme"`
				CoverageCeiling string `json:"coverageCeiling"`
			} `json:"stream"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
		if out.Stream == nil {
			t.Fatalf("no chain in %s", data)
		}
		if out.Stream.HeadSeq != 3 {
			t.Errorf("headSeq = %d, want 3", out.Stream.HeadSeq)
		}
		if out.Stream.CoverageCeiling != "keyed" {
			t.Errorf("coverageCeiling = %q, want keyed", out.Stream.CoverageCeiling)
		}
	})

	t.Run("verify.run is valid under the configured chain", func(t *testing.T) {
		data, err := dispatchQuery(d, "verify.run", scoped)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		var out struct {
			NoChain bool `json:"noChain"`
			Report  *struct {
				Valid      bool     `json:"valid"`
				Verified   int64    `json:"verified"`
				Tampered   []uint64 `json:"tampered"`
				Downgrades []uint64 `json:"downgrades"`
			} `json:"report"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
		if out.NoChain || out.Report == nil {
			t.Fatalf("no report in %s", data)
		}
		if !out.Report.Valid || len(out.Report.Tampered) != 0 || len(out.Report.Downgrades) != 0 {
			t.Fatalf("report = %s, want valid with nothing tampered or downgraded; "+
				"the contract path never received the keyed hash chain", data)
		}
		if out.Report.Verified != 3 {
			t.Errorf("verified = %d, want 3", out.Report.Verified)
		}
	})

	t.Run("a principal with no app is refused", func(t *testing.T) {
		_, err := dispatchQuery(d, "streams.mine", contractPrincipal(nil))
		if !errors.Is(err, fcontract.ErrPermissionDenied) {
			t.Fatalf("err = %v, want PERMISSION_DENIED", err)
		}
	})

	t.Run("settings.detail reports the keyed scheme and the backend", func(t *testing.T) {
		data, err := dispatchQuery(d, "settings.detail", scoped)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		var out struct {
			DigestScheme string `json:"digestScheme"`
			Keyed        bool   `json:"keyed"`
			BackendName  string `json:"backendName"`
			BatchSize    int    `json:"batchSize"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
		if out.DigestScheme != "chronicle/v5" || !out.Keyed {
			t.Errorf("digestScheme = %q keyed = %v, want chronicle/v5 and keyed", out.DigestScheme, out.Keyed)
		}
		if out.BackendName != "sqlite" {
			t.Errorf("backendName = %q, want sqlite", out.BackendName)
		}
		if out.BatchSize == 0 {
			t.Error("batchSize = 0; SurfaceConfig was not filled from the extension config")
		}
	})
}

// An extension that has not been through Register has no store to serve from.
// The dashboard calls this for every contributor it finds, so failing here
// would take the whole dashboard down with one unstarted extension.
func TestContractContributorSkipsAnExtensionThatIsNotRegistered(t *testing.T) {
	ext := extension.New()
	d := dispatcher.New(dispatcher.NoopMetricsEmitter{})
	reg := fcontract.NewRegistry()

	if err := ext.RegisterContractContributor(d, reg, fcontract.NewWardenRegistry()); err != nil {
		t.Fatalf("RegisterContractContributor = %v, want nil", err)
	}
	if _, ok := reg.Contributor("chronicle"); ok {
		t.Fatal("a contributor was registered for an extension with no store")
	}
	if _, err := dispatchQuery(d, "streams.mine", contractPrincipal(map[string]any{"app_id": "a"})); err == nil {
		t.Fatal("streams.mine dispatched with nothing registered")
	}
}
