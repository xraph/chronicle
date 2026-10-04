package postgres

import (
	"context"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/verify"
)

// An integer in metadata that float64 can't hold has to verify as recorded.
//
// pgx decoded the jsonb column into map[string]any with json.Unmarshal,
// which reads every number as float64. 2^53+1 came back as 2^53, the
// metadata encoded differently from what Record hashed, and VerifyChain
// reported the event as tampered straight after it was written.
//
// jsonb also rewrites some floats in its own notation. Those verified before
// only because they went back through float64, so they are here to keep the
// fix from trading one break for another.
func TestLargeIntegerMetadataVerifies(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	const appID = "large-int-metadata"
	event := &audit.Event{
		AppID:    appID,
		Action:   "transfer",
		Resource: "ledger",
		Category: "billing",
		Metadata: map[string]any{
			"big":    int64(9007199254740993), // 2^53 + 1
			"nested": map[string]any{"id": uint64(18446744073709551615)},
			"small":  7,
			"frac":   1.5,
			"tiny":   1e-7, // jsonb hands this back as 0.0000001
			"huge":   1e21, // and this as 1000000000000000000000
			"tags":   []any{"a", "b"},
		},
	}
	if err = c.Record(ctx, event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	report, err := c.VerifyChain(ctx, &verify.Input{AppID: appID})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid || len(report.Tampered) != 0 {
		t.Fatalf("report = valid %v, tampered %v; want a clean chain", report.Valid, report.Tampered)
	}

	got, err := s.Get(ctx, event.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Metadata["big"] != int64(9007199254740993) {
		t.Errorf("big = %#v, want int64(9007199254740993)", got.Metadata["big"])
	}
	if got.Metadata["small"] != float64(7) {
		t.Errorf("small = %#v, want float64(7), the type small numbers have always come back as", got.Metadata["small"])
	}
}
