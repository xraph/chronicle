package sqlite

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
// The digest covers the JSON encoding of the metadata. Record hashes the
// caller's int64, which encodes as 9007199254740993. toEvent used to decode
// the stored TEXT with plain json.Unmarshal, so every number came back as
// float64, and 2^53+1 rounds to 2^53 on the way. Re-encoded, that is
// 9007199254740992: a different digest, and VerifyChain reported the event as
// tampered the moment it was written. Nothing had touched the row.
func TestLargeIntegerMetadataVerifies(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

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
	if report.Verified != 1 {
		t.Errorf("Verified = %d, want 1", report.Verified)
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
