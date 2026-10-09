package chronicle_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/stream"
)

// corruptStream replaces the fixture database with a snapshot containing an
// explicitly altered stream row. Production head updates cannot rewind it.
// These attack fixtures contain events and streams only; checkpoint stores
// are independent. No production mutation API is weakened for the simulation.
func corruptStream(t *testing.T, c *chronicle.Chronicle, streamID id.ID, mutate func(*stream.Stream)) {
	t.Helper()
	adapter, ok := c.Store().(*store.Adapter)
	if !ok {
		t.Fatalf("unexpected fixture store %T", c.Store())
	}
	ctx := context.Background()
	streams, err := adapter.ListStreams(ctx, stream.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	replacement := memory.New()
	for _, st := range streams {
		events, err := adapter.EventRange(ctx, st.ID, 1, st.HeadSeq)
		if err != nil {
			t.Fatal(err)
		}
		if st.ID == streamID {
			mutate(st)
		}
		if err = replacement.CreateStream(ctx, st); err != nil {
			t.Fatal(err)
		}
		if err = replacement.AppendBatch(ctx, events); err != nil {
			t.Fatal(err)
		}
	}
	adapter.Store = replacement
}
