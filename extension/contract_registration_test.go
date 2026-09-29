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
	return dispatchIntent(d, fcontract.KindQuery, intent, nil, p)
}

// dispatchIntent is dispatchQuery for either kind, with an optional payload.
func dispatchIntent(d *dispatcher.Dispatcher, kind fcontract.Kind, intent string, payload any, p fcontract.Principal) ([]byte, error) {
	req := fcontract.Request{
		Kind:          kind,
		Contributor:   "chronicle",
		Intent:        intent,
		IntentVersion: 1,
	}
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		req.Payload = raw
	}
	data, _, err := d.Dispatch(context.Background(), req, p)
	return data, err
}

// registerContract wires ext into a fresh dispatcher and registry the way the
// dashboard does.
func registerContract(t *testing.T, ext *extension.Extension) *dispatcher.Dispatcher {
	t.Helper()
	d := dispatcher.New(dispatcher.NoopMetricsEmitter{})
	if err := ext.RegisterContractContributor(d, fcontract.NewRegistry(), fcontract.NewWardenRegistry()); err != nil {
		t.Fatalf("RegisterContractContributor: %v", err)
	}
	return d
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
	last := &audit.Event{AppID: tamperTestAppID, Action: "logout", Resource: "session", Category: "auth"}
	for _, e := range []*audit.Event{
		{AppID: tamperTestAppID, Action: "logout", Resource: "session", Category: "auth"},
		last,
	} {
		if err := ext.Chronicle().Record(ctx, e); err != nil {
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

	// verify.event goes through Chronicle.VerifyEvent, so it is what notices
	// the Chronicle instance missing from Deps.
	t.Run("verify.event verifies one event through the chronicle instance", func(t *testing.T) {
		data, err := dispatchIntent(d, fcontract.KindQuery, "verify.event", map[string]any{"eventId": last.ID.String()}, scoped)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		var out struct {
			Valid bool `json:"valid"`
			Keyed bool `json:"keyed"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("decode %s: %v", data, err)
		}
		if !out.Valid || !out.Keyed {
			t.Fatalf("verify.event = %s, want valid and keyed", data)
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

// TestContractContributorServesACheckpointedDeployment covers the other half
// of the wiring: the checkpoint store, signer and checkpointer travel as a
// set, and each one is only noticed by a different intent. Without the
// signer or the store the chain never reaches the "signed" ceiling; without
// the checkpointer checkpoints.take answers UNAVAILABLE. The compliance
// engine and retention enforcer are reached only by the last two commands,
// so a dropped field shows up as UNAVAILABLE there and nowhere else.
//
// It runs on the memory store, not sqlite: the compliance engine hands the
// store a []string filter that the sqlite driver cannot bind, so
// reports.generate fails on sqlite for reasons that have nothing to do with
// this wiring.
func TestContractContributorServesACheckpointedDeployment(t *testing.T) {
	ext, _, _, _ := setupCheckpointedExtension(t)
	d := registerContract(t, ext)
	scoped := contractPrincipal(map[string]any{"app_id": checkpointE2EAppID})

	data, err := dispatchIntent(d, fcontract.KindCommand, "checkpoints.take", nil, scoped)
	if err != nil {
		t.Fatalf("checkpoints.take: %v", err)
	}
	var taken struct {
		Checkpoint *struct {
			ToSeq uint64 `json:"toSeq"`
		} `json:"checkpoint"`
	}
	if err := json.Unmarshal(data, &taken); err != nil || taken.Checkpoint == nil {
		t.Fatalf("checkpoints.take = %s (%v), want a checkpoint", data, err)
	}

	data, err = dispatchQuery(d, "streams.mine", scoped)
	if err != nil {
		t.Fatalf("streams.mine: %v", err)
	}
	var mine struct {
		Stream struct {
			CoverageCeiling         string `json:"coverageCeiling"`
			CheckpointingConfigured bool   `json:"checkpointingConfigured"`
		} `json:"stream"`
	}
	if err := json.Unmarshal(data, &mine); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	if mine.Stream.CoverageCeiling != "signed" || !mine.Stream.CheckpointingConfigured {
		t.Fatalf("streams.mine = %s, want a signed ceiling with checkpointing configured", data)
	}

	data, err = dispatchQuery(d, "verify.run", scoped)
	if err != nil {
		t.Fatalf("verify.run: %v", err)
	}
	var run struct {
		Report struct {
			Valid              bool `json:"valid"`
			CheckpointsChecked bool `json:"checkpointsChecked"`
		} `json:"report"`
	}
	if err := json.Unmarshal(data, &run); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	if !run.Report.Valid || !run.Report.CheckpointsChecked {
		t.Fatalf("verify.run = %s, want valid with checkpoints checked", data)
	}

	data, err = dispatchIntent(d, fcontract.KindCommand, "reports.generate", map[string]any{"type": "soc2"}, scoped)
	if err != nil {
		t.Fatalf("reports.generate: %v", err)
	}
	var report struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &report); err != nil || report.ID == "" {
		t.Fatalf("reports.generate = %s (%v), want a report id", data, err)
	}

	if _, err := dispatchIntent(d, fcontract.KindCommand, "retention.enforce", nil, scoped); err != nil {
		t.Fatalf("retention.enforce: %v", err)
	}
}
