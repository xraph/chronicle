package extension_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/forge"
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	sqlitestore "github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/verify"
)

// TestExtensionRetentionKeepsTheChainVerifiable runs the original probe
// through a real deployment: an HMAC extension over sqlite, whose enforcer
// must have been wired with the Chronicle as its chain recorder. Without that
// one option the enforcer refuses to purge, and before this fix it purged and
// left the chain reporting gaps=[1 3 5] tampered=[4 6].
//
// It also exercises the SQL path end to end: the retention record's metadata
// goes through a JSON column and comes back through Query, and its digest
// still has to verify afterwards.
func TestExtensionRetentionKeepsTheChainVerifiable(t *testing.T) {
	ctx := context.Background()
	db := newSQLiteGroveDB(t)
	app := forge.New(forge.WithAppName("t"))
	if err := vessel.Provide(app.Container(), func() (*grove.DB, error) { return db, nil }); err != nil {
		t.Fatalf("provide grove.DB: %v", err)
	}
	ext := extension.New(
		extension.WithUnauthenticatedAPI(),
		extension.WithDigestScheme("hmac"),
		extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "hmac-1"}),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ext.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	old := time.Now().Add(-90 * 24 * time.Hour).UTC()
	for i := range 6 {
		cat := "auth"
		if i%2 == 1 {
			cat = "billing"
		}
		e := &audit.Event{
			AppID: tamperTestAppID, Action: "touch", Resource: "doc", Category: cat,
			UserID: "u", Timestamp: old.Add(time.Duration(i) * time.Second),
		}
		if err := ext.Chronicle().Record(ctx, e); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	st := sqlitestore.New(db)
	p := &retention.Policy{ID: id.NewPolicyID(), Category: "auth", Duration: 30 * 24 * time.Hour, AppID: tamperTestAppID}
	p.CreatedAt, p.UpdatedAt = time.Now(), time.Now()
	if err := st.SavePolicy(ctx, p); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	res, err := ext.RetentionEnforcer().EnforceScope(ctx, retention.Scope{AppID: tamperTestAppID})
	if err != nil {
		t.Fatalf("EnforceScope: %v", err)
	}
	if res.Purged != 3 {
		t.Fatalf("purged %d, want 3", res.Purged)
	}

	report, err := ext.Chronicle().VerifyChain(ctx, &verify.Input{AppID: tamperTestAppID})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid || len(report.Gaps) != 0 || len(report.Tampered) != 0 {
		t.Fatalf("valid=%v gaps=%v tampered=%v retained=%v, want a valid chain with 1, 3 and 5 retained",
			report.Valid, report.Gaps, report.Tampered, report.Retained)
	}
	var retainedCount uint64
	for _, rr := range report.Retained {
		retainedCount += rr.ToSeq - rr.FromSeq + 1
	}
	if retainedCount != 3 {
		t.Errorf("retained = %v, want 3 sequences", report.Retained)
	}
}
