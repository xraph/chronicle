package dashboard_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/chronicle/erasure"
)

// renderHTML renders one dashboard route as the viewer and returns the HTML.
func renderHTML(t *testing.T, ts *dashSetup, route string, params contributor.Params) string {
	t.Helper()

	c, err := ts.contributor.RenderPage(viewerCtx(), route, params)
	if err != nil {
		t.Fatalf("RenderPage(%s): %v", route, err)
	}
	var buf bytes.Buffer
	if err := c.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render %s: %v", route, err)
	}
	return buf.String()
}

// TestDashboardShowsErasureStatusAndKeyOutcome checks the list and the detail
// page tell a pending erasure, a retained legacy key and a finished erasure
// apart. A pending erasure must not claim the key is intact, since some of its
// keys may already be gone.
func TestDashboardShowsErasureStatusAndKeyOutcome(t *testing.T) {
	cases := []struct {
		name     string
		rec      erasure.Erasure
		badges   []string
		note     string
		notBadge string
	}{
		{
			name:     "pending",
			rec:      erasure.Erasure{Status: erasure.StatusPending},
			badges:   []string{"Pending", "Not Confirmed"},
			note:     "Run the erasure again for this subject to finish it.",
			notBadge: "Key Intact",
		},
		{
			name:     "legacy key retained",
			rec:      erasure.Erasure{Status: erasure.StatusCompleted, LegacyKeyRetained: true},
			badges:   []string{"Completed", "Legacy Key Retained"},
			note:     "this erasure is not yet cryptographic",
			notBadge: "Key Destroyed",
		},
		{
			name:     "completed",
			rec:      erasure.Erasure{Status: erasure.StatusCompleted, KeyDestroyed: true},
			badges:   []string{"Completed", "Key Destroyed"},
			notBadge: "Pending",
		},
		{
			name:     "before statuses",
			rec:      erasure.Erasure{KeyDestroyed: true},
			badges:   []string{"Completed", "Key Destroyed"},
			notBadge: "Pending",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newDashSetup(t, false)
			rec := tc.rec
			rec.AppID, rec.TenantID = viewerApp, viewerTenant
			e := seedErasure(t, ts, &rec)

			list := renderHTML(t, ts, "/erasures", contributor.Params{})
			detail := renderHTML(t, ts, "/erasures/detail", contributor.Params{
				QueryParams: map[string]string{"id": e.ID.String()},
			})

			for page, html := range map[string]string{"list": list, "detail": detail} {
				for _, want := range tc.badges {
					if !strings.Contains(html, want) {
						t.Errorf("%s page has no %q", page, want)
					}
				}
				if strings.Contains(html, tc.notBadge) {
					t.Errorf("%s page shows %q", page, tc.notBadge)
				}
			}
			if tc.note != "" && !strings.Contains(detail, tc.note) {
				t.Errorf("detail page has no note %q", tc.note)
			}
		})
	}
}
