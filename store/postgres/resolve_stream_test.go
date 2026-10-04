package postgres

import (
	"context"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/store"
)

// Recording the first event for an app scope has to create the stream row.
//
// Record resolves the stream before it hashes anything, and resolveStream only
// takes its create-it-if-missing branch when GetStreamByScope comes back
// wrapping chronicle.ErrStreamNotFound. That makes the store-level mapping
// only half of what a caller depends on; the other half is resolveStream
// asking errors.Is about the answer, and TestMissingRowsReturnTheNotFoundSentinels
// covers the first half without ever touching the second. So drive Record.
//
// On sqlite this branch was unreachable until the fix in 7f1bdf5, and standing
// up a fresh app+tenant scope failed on the very first event. Nothing said the
// postgres path was any different except a reading of pgx's source. Now a real
// database says so.
func TestRecordCreatesTheStreamForAFreshScope(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	const appID = "a-scope-that-has-never-been-written-to"
	event := &audit.Event{
		AppID:    appID,
		Action:   "login",
		Resource: "session",
		Category: "auth",
	}
	if err = c.Record(ctx, event); err != nil {
		t.Fatalf("Record on a scope with no stream row yet: %v", err)
	}

	st, err := s.GetStreamByScope(ctx, appID, "")
	if err != nil {
		t.Fatalf("GetStreamByScope after Record: %v", err)
	}
	if st.HeadSeq != 1 {
		t.Errorf("HeadSeq = %d, want 1", st.HeadSeq)
	}

	got, err := s.Get(ctx, event.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.StreamID.String() != st.ID.String() {
		t.Errorf("event landed in stream %s, want the one Record created, %s",
			got.StreamID, st.ID)
	}
	if got.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1 for the first event in a new stream", got.Sequence)
	}
}
