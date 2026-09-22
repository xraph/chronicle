package store_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
)

func TestAdapterCarriesTheSchemePinBothWays(t *testing.T) {
	ctx := context.Background()
	a := store.NewAdapter(memory.New())

	if err := a.CreateStreamInfo(ctx, &chronicle.StreamInfo{
		ID:          id.NewStreamID(),
		AppID:       "app",
		TenantID:    "tenant",
		Scheme:      "chronicle/v3",
		SchemeSince: 7,
	}); err != nil {
		t.Fatalf("CreateStreamInfo: %v", err)
	}

	got, err := a.GetStreamByScope(ctx, "app", "tenant")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	if got.Scheme != "chronicle/v3" {
		t.Errorf("Scheme = %q, want chronicle/v3; the adapter dropped the pin", got.Scheme)
	}
	if got.SchemeSince != 7 {
		t.Errorf("SchemeSince = %d, want 7; the adapter dropped the pin", got.SchemeSince)
	}
}

// The adapter is the only thing standing between chronicle.Storer and a
// backend, so a pin advance that stops here is indistinguishable from one that
// never happened.
func TestAdapterForwardsAPinAdvance(t *testing.T) {
	ctx := context.Background()
	a := store.NewAdapter(memory.New())

	streamID := id.NewStreamID()
	if err := a.CreateStreamInfo(ctx, &chronicle.StreamInfo{
		ID:          streamID,
		AppID:       "app",
		TenantID:    "tenant",
		Scheme:      "chronicle/v2",
		SchemeSince: 1,
	}); err != nil {
		t.Fatalf("CreateStreamInfo: %v", err)
	}

	if err := a.UpdateStreamScheme(ctx, streamID, "chronicle/v3", 9); err != nil {
		t.Fatalf("UpdateStreamScheme: %v", err)
	}

	got, err := a.GetStreamByScope(ctx, "app", "tenant")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	if got.Scheme != "chronicle/v3" || got.SchemeSince != 9 {
		t.Errorf("pin = %s from %d, want chronicle/v3 from 9", got.Scheme, got.SchemeSince)
	}
}
