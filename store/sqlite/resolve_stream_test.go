package sqlite

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
// wrapping chronicle.ErrStreamNotFound. groveError used to compare err.Error()
// against the exact string "no rows in result set", which is pgx's wording.
// sqlite reaches grove through database/sql, which says "sql: no rows in
// result set". The equality failed, the raw driver error went back to
// resolveStream, and errors.Is said no. So the branch that creates the stream
// could not be reached on this backend at all. Stand up a new app+tenant scope
// on sqlite and the very first event you recorded failed, which looked for all
// the world like something you had misconfigured.
//
// This drives Record rather than calling GetStreamByScope directly because the
// store-level mapping is only half the bug. The other half is resolveStream
// asking errors.Is about the answer, and TestMissingRowsReturnTheNotFoundSentinels
// covers the first half without ever touching the second.
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
