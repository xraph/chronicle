package extension_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/xraph/forge"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/extension"
)

// startErasureExtension starts an extension over sqlite with the dashboard
// pointed at dashScopeApp, with crypto-erasure on or off, and records two
// events for one subject in that app and one in another.
func startErasureExtension(t *testing.T, cryptoErasure bool) *extension.Extension {
	t.Helper()

	app := forge.New(forge.WithAppName("t"))
	db := newSQLiteGroveDB(t)
	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}
	opts := []extension.Option{
		extension.WithConfig(extension.Config{
			Auth:      extension.AuthConfig{AllowUnauthenticated: true},
			Dashboard: extension.DashboardConfig{AppID: dashScopeApp},
		}),
		extension.WithUnauthenticatedAPI(),
	}
	if cryptoErasure {
		opts = append(opts,
			extension.WithCryptoErasure(true),
			extension.WithKeyStore(crypto.NewInMemoryKeyStore()),
		)
	}
	ext := extension.New(opts...)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	for _, appID := range []string{dashScopeApp, dashScopeApp, "someone-else"} {
		if err := ext.Chronicle().Record(context.Background(), &audit.Event{
			AppID: appID, Action: "export", Resource: "user", Category: "data",
			SubjectID: "user-42", Reason: "subject access request",
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	return ext
}

var erasePayload = map[string]any{"subjectId": "user-42", "reason": "gdpr article 17"}

// The contract package's tests build Deps by hand, so none of them can notice
// that the extension forgot to hand over the erasure service. With
// crypto-erasure on, the command must reach it and erase inside the
// dashboard's own app only.
func TestContractContributorServesErasuresRequestWhenCryptoErasureIsOn(t *testing.T) {
	ext := startErasureExtension(t, true)
	d := registerContract(t, ext)

	data, err := dispatchIntent(d, fcontract.KindCommand, "erasures.request", erasePayload, subjectOnly())
	if err != nil {
		t.Fatalf("erasures.request: %v", err)
	}
	var out struct {
		EventsAffected    int64 `json:"eventsAffected"`
		KeyDestroyed      bool  `json:"keyDestroyed"`
		LegacyKeyRetained bool  `json:"legacyKeyRetained"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	if out.EventsAffected != 2 || !out.KeyDestroyed || out.LegacyKeyRetained {
		t.Fatalf("result = %s, want 2 events erased with the key destroyed", data)
	}

	// The other app's event for the same subject ID is untouched.
	other, err := ext.Chronicle().Query(context.Background(), &audit.Query{AppID: "someone-else", Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(other.Events) != 1 || other.Events[0].Erased || other.Events[0].Reason != "subject access request" {
		t.Fatalf("another app's event after this app's erasure = %+v", other.Events)
	}
}

// Without crypto-erasure there is no service and no key to destroy, so the
// command says how to turn it on instead of pretending.
func TestContractContributorAnswersErasuresRequestUnavailableWithoutCryptoErasure(t *testing.T) {
	ext := startErasureExtension(t, false)
	d := registerContract(t, ext)

	_, err := dispatchIntent(d, fcontract.KindCommand, "erasures.request", erasePayload, subjectOnly())
	if !errors.Is(err, fcontract.ErrUnavailable) {
		t.Fatalf("err = %v, want UNAVAILABLE", err)
	}
}
