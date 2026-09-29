package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
)

// TestQueryFiltersByCategoryList pins the IN-clause fix. sqlitedriver binds a
// slice as one argument, so "category IN (?)" with a []string failed every
// filtered query with "unsupported type []string". Verification looks up
// retention records this way, so on sqlite it could never find one.
func TestQueryFiltersByCategoryList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	streamID := seedStream(t, s, "app-1", "")
	now := time.Now().UTC()

	for i, cat := range []string{"auth", "billing", "admin", "auth"} {
		ev := testEvent(streamID, "app-1", "", "u1", cat, now.Add(time.Duration(i)*time.Second))
		if err := s.Append(ctx, ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	res, err := s.Query(ctx, &audit.Query{Categories: []string{"auth", "admin"}, Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Total != 3 || len(res.Events) != 3 {
		t.Fatalf("total=%d events=%d, want 3 (two auth, one admin)", res.Total, len(res.Events))
	}
	for _, e := range res.Events {
		if e.Category != "auth" && e.Category != "admin" {
			t.Errorf("category %q leaked through the filter", e.Category)
		}
	}
}
