package redis

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// TestCountHonoursEveryFilter seeds events across two apps, two tenants and two
// categories, then checks every combination of CountQuery filters against a
// count taken straight from the seed. Count picks one sorted-set index and may
// return its length without reading events back, which is only right when that
// index already narrows by every filter the query sets. A category index spans
// all tenants, so {TenantID, Category} counted other tenants' events.
func TestCountHonoursEveryFilter(t *testing.T) {
	s, _ := openTestStore(t, true)
	ctx := context.Background()

	run := runSuffix(t)
	apps := []string{"app-a-" + run, "app-b-" + run}
	tenants := []string{"tenant-1-" + run, "tenant-2-" + run}
	categories := []string{"auth-" + run, "data-" + run}

	base := time.Now().UTC().Truncate(time.Second)
	var seeded []*audit.Event
	for ai, app := range apps {
		for ti, tenant := range tenants {
			for ci, category := range categories {
				// Uneven counts per cell, so a count from the wrong slice of the
				// seed cannot land on the right number by accident.
				for n := 0; n <= ai+2*ti+4*ci; n++ {
					e := &audit.Event{
						ID:        id.NewAuditID(),
						StreamID:  id.NewStreamID(),
						Timestamp: base.Add(time.Duration(len(seeded)) * time.Second),
						AppID:     app,
						TenantID:  tenant,
						Category:  category,
						Action:    "test",
						Resource:  "count",
						Outcome:   "success",
						Severity:  "info",
					}
					if err := s.Append(ctx, e); err != nil {
						t.Fatalf("append: %v", err)
					}
					seeded = append(seeded, e)
				}
			}
		}
	}

	want := func(q *audit.CountQuery) int64 {
		var n int64
		for _, e := range seeded {
			if q.AppID != "" && e.AppID != q.AppID {
				continue
			}
			if q.TenantID != "" && e.TenantID != q.TenantID {
				continue
			}
			if q.Category != "" && e.Category != q.Category {
				continue
			}
			n++
		}
		return n
	}

	// Every combination of set and unset filters, each set one pinned to the
	// first value.
	for mask := 0; mask < 8; mask++ {
		q := &audit.CountQuery{}
		if mask&1 != 0 {
			q.AppID = apps[0]
		}
		if mask&2 != 0 {
			q.TenantID = tenants[0]
		}
		if mask&4 != 0 {
			q.Category = categories[0]
		}

		name := "app=" + boolName(q.AppID != "") +
			"/tenant=" + boolName(q.TenantID != "") +
			"/category=" + boolName(q.Category != "")
		t.Run(name, func(t *testing.T) {
			got, err := s.Count(ctx, q)
			if err != nil {
				t.Fatalf("count: %v", err)
			}
			if w := want(q); got != w {
				t.Errorf("Count(%+v) = %d, want %d", *q, got, w)
			}
		})
	}
}

func boolName(set bool) string {
	if set {
		return "set"
	}
	return "unset"
}
