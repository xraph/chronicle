package pages

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/xraph/chronicle/verify"
)

// renderVerify renders the verification page to a string.
func renderVerify(t *testing.T, data VerifyPageData) string {
	t.Helper()

	var buf bytes.Buffer
	if err := VerifyPage(data).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render VerifyPage: %v", err)
	}
	return buf.String()
}

// TestVerifyPageShowsDowngrades is the regression test for a downgraded chain
// reading as a clean one on screen.
//
// verify.Report has carried Downgrades since this branch landed, and the page
// rendered only Gaps and Tampered. So an operator looking at the dashboard saw
// a result with nothing in it, which is indistinguishable from a chain that
// verified. The sequences have to appear, and the copy around them has to say
// what a downgrade means, because "6" on its own tells nobody anything.
func TestVerifyPageShowsDowngrades(t *testing.T) {
	out := renderVerify(t, VerifyPageData{
		Report: &verify.Report{
			Valid:      false,
			Verified:   6,
			FirstEvent: 1,
			LastEvent:  6,
			Downgrades: []uint64{6},
		},
	})

	if !strings.Contains(out, "Scheme Downgrades") {
		t.Error("the page does not name downgrades at all")
	}
	if !strings.Contains(out, "tampering") {
		t.Error("the downgrade copy does not say a downgrade is tampering")
	}
	if !strings.Contains(out, "text-destructive") {
		t.Error("the downgrade block is not styled as a failure")
	}
	if !strings.Contains(out, ">6</code>") {
		t.Error("the downgraded sequence number is not rendered")
	}
}

// A downgrade has to reach the headline number too. A report whose only finding
// is a downgrade would otherwise show Issues: 0 beside a red status badge.
func TestVerifyPageCountsDowngradesAsIssues(t *testing.T) {
	report := &verify.Report{
		Valid:      false,
		Downgrades: []uint64{6, 7},
	}

	if got := issueCount(report); got != 2 {
		t.Errorf("issueCount = %d, want 2", got)
	}

	report.Gaps = []uint64{3}
	report.Tampered = []uint64{4}
	if got := issueCount(report); got != 4 {
		t.Errorf("issueCount with gaps and tampered = %d, want 4", got)
	}
}

// TestVerifyPageShowsTolerantAsACaveat covers the other invisible field.
//
// A tolerant resolution is not a failure, and the page must not dress it up as
// one: those events verified, just under a guessed scheme rather than a
// declared one. It still has to be visible, because a report that silently
// omits how it reached its answer is not a report an auditor can rely on.
func TestVerifyPageShowsTolerantAsACaveat(t *testing.T) {
	out := renderVerify(t, VerifyPageData{
		Report: &verify.Report{
			Valid:      true,
			Verified:   4,
			FirstEvent: 1,
			LastEvent:  4,
			Tolerant:   []uint64{1, 2},
		},
	})

	if !strings.Contains(out, "Resolved Tolerantly") {
		t.Error("the page does not mention that events were resolved tolerantly")
	}
	if !strings.Contains(out, ">1</code>") || !strings.Contains(out, ">2</code>") {
		t.Error("the tolerantly resolved sequence numbers are not rendered")
	}
	if strings.Contains(out, "Tampered Events") {
		t.Error("a tolerant resolution is being presented as tampering")
	}

	// Tolerant events are a caveat, not a finding, so the Issues tile stays at
	// zero. A number no action can ever clear is worse than no number.
	if got := issueCount(&verify.Report{Tolerant: []uint64{1, 2}}); got != 0 {
		t.Errorf("issueCount for a tolerant-only report = %d, want 0", got)
	}
}

// A clean report must stay clean: neither block appears when there is nothing
// to say.
func TestVerifyPageStaysQuietOnACleanReport(t *testing.T) {
	out := renderVerify(t, VerifyPageData{
		Report: &verify.Report{Valid: true, Verified: 3, FirstEvent: 1, LastEvent: 3},
	})

	for _, unwanted := range []string{"Scheme Downgrades", "Resolved Tolerantly", "Tampered Events", "Sequence Gaps"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("a clean report rendered the %q block", unwanted)
		}
	}
}
