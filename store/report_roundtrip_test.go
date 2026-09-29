package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// TestReportKeepsVerificationThroughTheStore pins that a saved report comes
// back with its stats and chain verification on every backend.
//
// Every backend used to store sections alone, so a report read back through
// GetReport, which is what the export route does, lost its verification, and
// an auditor's download said nothing about integrity.
func TestReportKeepsVerificationThroughTheStore(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			s, _ := open(t)
			ctx := context.Background()

			in := &compliance.Report{
				Entity: chronicle.Entity{CreatedAt: time.Now().UTC().Truncate(time.Millisecond)},
				ID:     id.NewReportID(),
				Title:  "roundtrip",
				Type:   "soc2",
				Period: compliance.DateRange{
					From: time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond),
					To:   time.Now().UTC().Truncate(time.Millisecond),
				},
				AppID:    "roundtrip-app-" + id.NewReportID().String(),
				TenantID: "t",
				Sections: []compliance.Section{{Title: "CC6.1", MatchedEvents: 3}},
				Stats:    &compliance.Stats{TotalEvents: 3, FailedEvents: 1},
				Verification: &verify.Report{
					Valid: false, Verified: 3, Tampered: []uint64{2}, Gaps: []uint64{},
					HeadChecked: true, HeadMatch: true, HeadSeq: 3,
					Coverage: []verify.Coverage{{FromSeq: 1, ToSeq: 3, Level: verify.LevelKeyed}},
				},
				VerificationScope: &compliance.VerificationScope{
					Status: compliance.VerificationRan, StreamID: "stream_x",
					FromSeq: 1, ToSeq: 3, HeadSeq: 3, Window: compliance.DefaultVerifyWindow,
					Notes: []string{"a caveat"},
				},
				GeneratedBy: "test",
				Format:      compliance.FormatJSON,
			}
			if err := s.SaveReport(ctx, in); err != nil {
				t.Fatalf("SaveReport: %v", err)
			}
			t.Cleanup(func() { _ = s.DeleteReport(context.Background(), in.ID) })

			out, err := s.GetReport(ctx, in.ID)
			if err != nil {
				t.Fatalf("GetReport: %v", err)
			}

			if out.Stats == nil || out.Stats.TotalEvents != 3 || out.Stats.FailedEvents != 1 {
				t.Errorf("stats = %+v", out.Stats)
			}
			v := out.Verification
			if v == nil || v.Valid || v.Verified != 3 || len(v.Tampered) != 1 || v.Tampered[0] != 2 ||
				!v.HeadChecked || len(v.Coverage) != 1 || v.Coverage[0].Level != verify.LevelKeyed {
				t.Errorf("verification = %+v", v)
			}
			sc := out.VerificationScope
			if sc == nil || sc.Status != compliance.VerificationRan || sc.ToSeq != 3 || len(sc.Notes) != 1 {
				t.Errorf("verification scope = %+v", sc)
			}
			if len(out.Sections) != 1 || out.Sections[0].Title != "CC6.1" {
				t.Errorf("sections = %+v", out.Sections)
			}
		})
	}
}
