package contract

import (
	"context"
	"strings"
	"testing"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
)

// Every intent has to reach the configured default, not only the ones a test
// happens to name. A handler that resolved its scope without Deps would keep
// refusing every subject-only session while the rest of the dashboard worked,
// and nothing else would notice.
//
// Each intent is dispatched with an empty payload. Some refuse that input, and
// that is fine: what matters is that none of them refuses for want of a scope
// when the deployment names one, and that every one of them does refuse for it
// when it does not. The second half is what proves the first half could fail.
func TestEveryIntentResolvesItsScopeThroughTheConfiguredDefault(t *testing.T) {
	subjectOnly := fcontract.Principal{User: &dashauth.UserInfo{Subject: "operator-1"}}

	newDispatcher := func(t *testing.T, deps Deps) *dispatcher.Dispatcher {
		t.Helper()
		disp := newTestDispatcher(t)
		deps.Store = newSQLiteStore(t)
		if err := Register(disp, fcontract.NewRegistry(), fcontract.NewWardenRegistry(), deps); err != nil {
			t.Fatalf("Register: %v", err)
		}
		return disp
	}

	refusedForScope := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "no app scope")
	}

	withDefault := newDispatcher(t, Deps{DefaultAppID: "app-1"})
	without := newDispatcher(t, Deps{})

	for _, r := range registrations() {
		kind := fcontract.KindQuery
		if r.kind == kindCommand {
			kind = fcontract.KindCommand
		}
		req := fcontract.Request{Kind: kind, Contributor: contributorName, Intent: r.name, IntentVersion: intentVersion}

		t.Run(r.name, func(t *testing.T) {
			_, _, err := withDefault.Dispatch(context.Background(), req, subjectOnly)
			if refusedForScope(err) {
				t.Errorf("refused for want of a scope although the deployment names an app: %v", err)
			}
			_, _, err = without.Dispatch(context.Background(), req, subjectOnly)
			if !refusedForScope(err) {
				t.Errorf("did not refuse a subject-only session in a deployment with no app: %v", err)
			}
		})
	}
}
