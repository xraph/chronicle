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

	for _, unwanted := range []string{
		"Scheme Downgrades", "Resolved Tolerantly", "Tampered Events", "Sequence Gaps",
		"Coverage", "Checkpoints",
	} {
		if strings.Contains(out, unwanted) {
			t.Errorf("a clean report rendered the %q block", unwanted)
		}
	}
}

// TestVerifyPageRendersCoverageSpans covers Task 7's addition of the coverage
// ladder to the page: each span has to show its range, its level, and its
// note when one is present.
func TestVerifyPageRendersCoverageSpans(t *testing.T) {
	out := renderVerify(t, VerifyPageData{
		Report: &verify.Report{
			Valid: true, Verified: 10, FirstEvent: 1, LastEvent: 10,
			Coverage: []verify.Coverage{
				{FromSeq: 1, ToSeq: 4, Level: verify.LevelUnkeyed, Note: "below the scheme pin; resolved tolerantly"},
				{FromSeq: 5, ToSeq: 10, Level: verify.LevelSigned},
			},
		},
	})

	if !strings.Contains(out, "Coverage") {
		t.Error("the page does not have a Coverage section")
	}
	if !strings.Contains(out, "1-4: unkeyed") {
		t.Error("the first span's range and level are not rendered")
	}
	if !strings.Contains(out, "below the scheme pin; resolved tolerantly") {
		t.Error("the first span's note is not rendered")
	}
	if !strings.Contains(out, "5-10: signed") {
		t.Error("the second span's range and level are not rendered")
	}
}

// TestVerifyPageMarksAFailedCheckpointAsDestructive is the positive case: a
// checkpoint whose signature or hash actually failed is real tampering
// evidence and must read like the Downgrades block does.
func TestVerifyPageMarksAFailedCheckpointAsDestructive(t *testing.T) {
	out := renderVerify(t, VerifyPageData{
		Report: &verify.Report{
			Valid: false, Verified: 10, FirstEvent: 1, LastEvent: 10,
			Checkpoints: []verify.CheckpointResult{
				{
					ID: "ckpt_1", FromSeq: 1, ToSeq: 10,
					SignatureValid: true, HashChecked: true, HashMatch: false,
					ContinuityChecked: true, ContinuityOK: true,
					Note: "chain hash at to_seq no longer matches what the checkpoint recorded",
				},
			},
		},
	})

	if !strings.Contains(out, "checkpoint failed") {
		t.Error("a checkpoint whose hash check failed does not say so")
	}
	// The generic Tailwind utility classes on every input and button already
	// contain the substring "border-destructive" (aria-invalid:border-destructive),
	// so the assertion has to name the failed-checkpoint block's own class
	// combination, not that substring alone.
	if !strings.Contains(out, "border-destructive bg-destructive/5 p-3") {
		t.Error("a failed checkpoint is not styled as a failure")
	}
	if !strings.Contains(out, "chain hash at to_seq no longer matches what the checkpoint recorded") {
		t.Error("the failure note is not rendered")
	}
}

// TestVerifyPageDoesNotTreatAnUncheckedCheckpointAsFailed is the regression
// test for the bug HashChecked and ContinuityChecked exist to prevent: a
// checkpoint whose to_seq or predecessor simply fell outside a bounded
// sub-range must not read as tampering just because the field defaults to
// false. It reads as inconclusive, with no destructive styling anywhere on
// the page.
func TestVerifyPageDoesNotTreatAnUncheckedCheckpointAsFailed(t *testing.T) {
	out := renderVerify(t, VerifyPageData{
		Report: &verify.Report{
			Valid: true, Verified: 5, FirstEvent: 6, LastEvent: 10, Partial: true,
			Checkpoints: []verify.CheckpointResult{
				{
					ID: "ckpt_1", FromSeq: 1, ToSeq: 10,
					SignatureValid: true,
					// HashChecked and ContinuityChecked both left false: to_seq
					// and the predecessor fell outside this bounded range.
					Note: "to_seq falls outside the verified range; hash not re-checked",
				},
			},
		},
	})

	if !strings.Contains(out, "not fully checked") {
		t.Error("an unchecked checkpoint does not say it was not fully checked")
	}
	if strings.Contains(out, "checkpoint failed") {
		t.Error("an unchecked checkpoint is being reported as a failed one")
	}
	// Same reasoning as the failed-checkpoint test: check the block's actual
	// class combination, not a substring the page's ordinary form chrome
	// (aria-invalid:border-destructive, etc.) already contains everywhere.
	if strings.Contains(out, "border-destructive bg-destructive/5") {
		t.Error("an unchecked checkpoint is styled as a failure; HashChecked/ContinuityChecked exist to prevent exactly this")
	}
}

// A checkpoint that is fully checked and intact should read as unremarkable,
// not draw the eye the way a failure or an inconclusive result does.
func TestVerifyPageRendersAnIntactCheckpointAsUnremarkable(t *testing.T) {
	out := renderVerify(t, VerifyPageData{
		Report: &verify.Report{
			Valid: true, Verified: 10, FirstEvent: 1, LastEvent: 10,
			Checkpoints: []verify.CheckpointResult{
				{
					ID: "ckpt_1", FromSeq: 1, ToSeq: 10,
					SignatureValid: true, HashChecked: true, HashMatch: true,
					ContinuityChecked: true, ContinuityOK: true,
				},
			},
		},
	})

	if !strings.Contains(out, "signed and intact") {
		t.Error("an intact checkpoint does not say so")
	}
	if strings.Contains(out, "border-destructive bg-destructive/5") {
		t.Error("an intact checkpoint is styled as a failure")
	}
	if strings.Contains(out, "not fully checked") {
		t.Error("an intact, fully-checked checkpoint is being reported as inconclusive")
	}
}

// TestVerifyPageExplainsATruncatedTail covers the finding that has no
// sequence numbers to show.
//
// A truncation caught by the latest checkpoint leaves Gaps, Tampered and
// Downgrades all empty, so the Issues tile reads zero and every other block
// on the page stays hidden. Without copy of its own, an operator sees a
// result that says "Tampered" and offers no reason at all.
func TestVerifyPageExplainsATruncatedTail(t *testing.T) {
	out := renderVerify(t, VerifyPageData{
		Report: &verify.Report{
			Valid:                 false,
			Verified:              10,
			FirstEvent:            1,
			LastEvent:             10,
			HeadSeq:               10,
			HeadChecked:           true,
			HeadMatch:             true,
			CheckpointHeadChecked: true,
			CheckpointHeadOK:      false,
		},
	})

	if !strings.Contains(out, "Truncated Tail") {
		t.Error("the page does not name the truncation at all")
	}
	if !strings.Contains(out, "signed checkpoint") {
		t.Error("the copy does not say what the finding rests on")
	}
	if !strings.Contains(out, "text-destructive") {
		t.Error("the truncation block is not styled as a failure")
	}
}

// TestVerifyPageStaysQuietWhenTheHeadComparisonAgrees pins the other side:
// a clean comparison, and one that never ran, must both render nothing.
// CheckpointHeadOK's false zero value on an unchecked report would otherwise
// accuse every deployment that takes no checkpoints.
func TestVerifyPageStaysQuietWhenTheHeadComparisonAgrees(t *testing.T) {
	for _, tc := range []struct {
		name    string
		checked bool
		ok      bool
	}{
		{name: "compared and consistent", checked: true, ok: true},
		{name: "never compared", checked: false, ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := renderVerify(t, VerifyPageData{
				Report: &verify.Report{
					Valid: true, Verified: 10, FirstEvent: 1, LastEvent: 10,
					CheckpointHeadChecked: tc.checked, CheckpointHeadOK: tc.ok,
				},
			})
			if strings.Contains(out, "Truncated Tail") {
				t.Errorf("the page reported a truncation on a report that found none:\n%s", out)
			}
		})
	}
}
