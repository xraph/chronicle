package mongo

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/verify"
)

// nestedMetadata returns metadata whose nested keys are out of sorted order,
// so a reader that hands them back in stored order changes the JSON the
// digest covers.
func nestedMetadata() map[string]any {
	return map[string]any{
		"top": "level",
		"nested": map[string]any{
			"s":      "x",
			"n":      1,
			"deeper": map[string]any{"z": true, "a": 2.5},
		},
		"list": []any{
			map[string]any{"y": "b", "x": "a"},
			[]any{"inner", map[string]any{"q": 1, "p": 2}},
			"plain",
		},
	}
}

// TestMetadataRoundTripsThroughBSON covers the model conversion without a
// database. The driver decodes embedded documents inside a map[string]any as
// bson.D, which keeps stored order, and json.Marshal writes a bson.D in that
// order. The digest was computed over sorted keys, so toEvent has to hand back
// plain maps.
func TestMetadataRoundTripsThroughBSON(t *testing.T) {
	want := nestedMetadata()

	raw, err := bson.Marshal(EventModel{Metadata: want})
	if err != nil {
		t.Fatalf("bson.Marshal: %v", err)
	}
	var decoded EventModel
	if err := bson.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("bson.Unmarshal: %v", err)
	}

	got := normalizeMetadata(decoded.Metadata)

	wantJSON, _ := json.Marshal(want)
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("metadata JSON changed across a BSON round trip:\n got %s\nwant %s", gotJSON, wantJSON)
	}

	// Callers type-assert nested values the way they do on every other store.
	if _, ok := got["nested"].(map[string]any); !ok {
		t.Errorf("nested is %T, want map[string]any", got["nested"])
	}
	list, ok := got["list"].([]any)
	if !ok {
		t.Fatalf("list is %T, want []any", got["list"])
	}
	if _, ok := list[0].(map[string]any); !ok {
		t.Errorf("list[0] is %T, want map[string]any", list[0])
	}
	if _, ok := list[1].([]any); !ok {
		t.Errorf("list[1] is %T, want []any", list[1])
	}
}

func TestNormalizeMetadataLeavesEmptyAlone(t *testing.T) {
	if got := normalizeMetadata(nil); got != nil {
		t.Fatalf("normalizeMetadata(nil) = %v, want nil", got)
	}
}

// TestChainWithNestedMetadataVerifiesOnMongo is the regression test for
// nested metadata reporting tampered. Top-level keys were always fine; the
// nested ones came back in stored order.
func TestChainWithNestedMetadataVerifiesOnMongo(t *testing.T) {
	s, _ := openLiveStore(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(s)),
		chronicle.WithDigestScheme(hash.SchemePlainV4),
	)
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	app := "nested-" + id.NewAuditID().String()
	recCtx := scope.WithAppID(ctx, app)

	for i := range 3 {
		if recErr := c.Record(recCtx, &audit.Event{
			Action: "touch", Resource: "doc", Category: "auth", UserID: "u",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			Timestamp: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Metadata:  nestedMetadata(),
		}); recErr != nil {
			t.Fatalf("Record %d: %v", i, recErr)
		}
	}

	report, err := c.VerifyChain(ctx, &verify.Input{AppID: app})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid || len(report.Tampered) != 0 || len(report.Gaps) != 0 {
		t.Fatalf("valid=%v tampered=%v gaps=%v; nested metadata must verify",
			report.Valid, report.Tampered, report.Gaps)
	}

	res, err := s.Query(ctx, &audit.Query{AppID: app, Order: "asc"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	wantJSON, _ := json.Marshal(nestedMetadata())
	for i, e := range res.Events {
		gotJSON, _ := json.Marshal(e.Metadata)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("event %d metadata = %s, want %s", i, gotJSON, wantJSON)
		}
	}
}

// TestMetadataUint64AboveInt64IsRefused pins what mongo does with an integer
// BSON cannot hold. BSON has no unsigned 64-bit type, so the driver refuses
// the insert. That is the behaviour we want: the event is not recorded, the
// caller gets the error, and the stream head never moves, so the chain stays
// whole. Storing the value as anything else would read back as a different
// type and fail verification later instead.
func TestMetadataUint64AboveInt64IsRefused(t *testing.T) {
	s, _ := openLiveStore(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(s)),
		chronicle.WithDigestScheme(hash.SchemePlainV4),
	)
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	app := "uint64-" + id.NewAuditID().String()
	recCtx := scope.WithAppID(ctx, app)
	event := func(md map[string]any) *audit.Event {
		return &audit.Event{
			Action: "touch", Resource: "doc", Category: "auth", UserID: "u",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			Metadata: md,
		}
	}

	if err := c.Record(recCtx, event(map[string]any{"n": uint64(math.MaxInt64)})); err != nil {
		t.Fatalf("Record MaxInt64 as uint64: %v", err)
	}
	if err := c.Record(recCtx, event(map[string]any{"n": uint64(math.MaxUint64)})); err == nil {
		t.Fatal("Record MaxUint64: want an error, BSON cannot hold it")
	}
	if err := c.Record(recCtx, event(map[string]any{"n": 1})); err != nil {
		t.Fatalf("Record after the refused event: %v", err)
	}

	report, err := c.VerifyChain(ctx, &verify.Input{AppID: app})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid || len(report.Tampered) != 0 || len(report.Gaps) != 0 || report.Verified != 2 {
		t.Fatalf("valid=%v verified=%d tampered=%v gaps=%v; a refused event must leave the chain whole",
			report.Valid, report.Verified, report.Tampered, report.Gaps)
	}
}
