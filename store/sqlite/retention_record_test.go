package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/retention"
)

// TestEventsOlderThanNeverSelectsRetentionRecords: a "*" policy selects every
// category, and must still never select a retention record, or the next run
// purges the record and everything it explained becomes a gap.
func TestEventsOlderThanNeverSelectsRetentionRecords(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	streamID := seedStream(t, s, "app-1", "")
	old := time.Now().Add(-48 * time.Hour).UTC()

	for i, cat := range []string{"auth", audit.CategoryRetention, "billing"} {
		ev := testEvent(streamID, "app-1", "", "u1", cat, old.Add(time.Duration(i)*time.Second))
		if err := s.Append(ctx, ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	for _, category := range []string{"*", audit.CategoryRetention} {
		got, err := s.EventsOlderThan(ctx, retention.PurgeQuery{
			Scope: retention.Scope{AppID: "app-1"}, Category: category, Before: time.Now(),
		})
		if err != nil {
			t.Fatalf("EventsOlderThan(%q): %v", category, err)
		}
		for _, e := range got {
			if e.Category == audit.CategoryRetention {
				t.Errorf("EventsOlderThan(%q) selected a retention record", category)
			}
		}
	}
}
