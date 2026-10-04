package compliance

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xraph/chronicle/verify"
)

// verificationListLimit is how many sequences a list in a human-readable
// export shows before summarising the rest. The JSON export lists them all.
const verificationListLimit = 50

// verificationRow is one line of a report's chain verification as the CSV,
// Markdown and HTML exports render it. Every one of them renders the same
// rows, so no format can show an auditor less than another.
type verificationRow struct {
	Check  string
	Result string
	Detail string
}

// Three states for every paired *Checked / *OK flag in verify.Report. A false
// OK beside a false Checked means nothing ran, and collapsing it into
// "failed" or "passed" would both be wrong.
const (
	statePassed     = "passed"
	stateFailed     = "failed"
	stateNotChecked = "not checked"
)

func threeState(checked, ok bool) string {
	switch {
	case !checked:
		return stateNotChecked
	case ok:
		return statePassed
	default:
		return stateFailed
	}
}

// verificationRows projects a report's verification into rows.
func verificationRows(r *Report) []verificationRow {
	s, v := r.VerificationScope, r.Verification

	if s == nil && v == nil {
		return []verificationRow{{
			Check:  "Status",
			Result: "not recorded",
			Detail: "This report carries no chain verification. Nothing here says the chain is intact.",
		}}
	}

	var rows []verificationRow
	if s != nil {
		rows = append(rows, verificationRow{Check: "Status", Result: statusLabel(s.Status), Detail: streamDetail(s)})
	}
	if v != nil {
		rows = append(rows, resultRows(v, s)...)
	}
	if s != nil {
		for _, n := range s.Notes {
			rows = append(rows, verificationRow{Check: "Note", Detail: n})
		}
	}
	return rows
}

func statusLabel(s VerificationStatus) string {
	switch s {
	case VerificationRan:
		return "verified"
	case VerificationNoChain:
		return "no chain"
	case VerificationNotConfigured:
		return "not configured"
	default:
		return string(s)
	}
}

func streamDetail(s *VerificationScope) string {
	if s.StreamID == "" {
		return ""
	}
	detail := "stream " + s.StreamID
	if s.Scheme != "" {
		detail += fmt.Sprintf(", pinned to %s from sequence %d", s.Scheme, s.SchemeSince)
	}
	return detail
}

func resultRows(v *verify.Report, s *VerificationScope) []verificationRow {
	valid := "invalid"
	if v.Valid {
		valid = "valid"
	}

	// Twelve fixed rows, then one per coverage span and one per checkpoint.
	rows := make([]verificationRow, 0, 12+len(v.Coverage)+len(v.Checkpoints))
	rows = append(rows,
		verificationRow{Check: "Result", Result: valid},
		rangeRow(s),
		verificationRow{
			Check:  "Events verified",
			Result: strconv.FormatInt(v.Verified, 10),
			Detail: eventSpan(v),
		},
		verificationRow{Check: "Partial", Result: yesNo(v.Partial), Detail: partialDetail(v)},
		seqListRow("Gaps", v.Gaps, "missing sequences nothing accounts for"),
		seqListRow("Tampered", v.Tampered, "digest or chain link does not match"),
		seqListRow("Downgrades", v.Downgrades, "claim a weaker digest scheme than the stream pins"),
		retainedRow(v.Retained),
		seqListRow("Tolerant", v.Tolerant, "resolved through the pre-migration fallback, scheme guessed"),
		verificationRow{
			Check:  "Head check",
			Result: threeState(v.HeadChecked, v.HeadMatch),
			Detail: fmt.Sprintf("last verified event against the stream head at sequence %d", v.HeadSeq),
		},
		verificationRow{
			Check:  "Checkpoint store",
			Result: consulted(v.CheckpointsChecked),
			Detail: fmt.Sprintf("%d covering checkpoints", len(v.Checkpoints)),
		},
		verificationRow{
			Check:  "Checkpoint head check",
			Result: threeState(v.CheckpointHeadChecked, v.CheckpointHeadOK),
			Detail: "latest signed checkpoint against the stream head",
		},
	)

	for _, c := range v.Coverage {
		rows = append(rows, verificationRow{
			Check:  "Coverage",
			Result: string(c.Level),
			Detail: coverageDetail(c),
		})
	}
	for _, cp := range v.Checkpoints {
		rows = append(rows, checkpointRow(cp))
	}
	return rows
}

func rangeRow(s *VerificationScope) verificationRow {
	row := verificationRow{Check: "Range checked"}
	if s == nil {
		row.Result = "unknown"
		row.Detail = "the report does not record which sequences were asked for"
		return row
	}
	if s.HeadSeq == 0 {
		row.Result = "empty chain"
		row.Detail = "the stream has no events"
		return row
	}
	row.Result = fmt.Sprintf("%d to %d", s.FromSeq, s.ToSeq)
	if s.Capped {
		row.Detail = fmt.Sprintf("newest %d sequences of %d; window cap reached", s.Window, s.HeadSeq)
	} else {
		row.Detail = fmt.Sprintf("whole chain, genesis to head %d", s.HeadSeq)
	}
	return row
}

func eventSpan(v *verify.Report) string {
	if v.Verified == 0 {
		return "no events found in range"
	}
	return fmt.Sprintf("first %d, last %d", v.FirstEvent, v.LastEvent)
}

func partialDetail(v *verify.Report) string {
	if v.Partial {
		return "range bounded short of genesis or head; tail not anchored"
	}
	return "genesis to head"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func consulted(b bool) string {
	if b {
		return "consulted"
	}
	return stateNotChecked
}

func seqListRow(check string, seqs []uint64, meaning string) verificationRow {
	row := verificationRow{Check: check, Result: strconv.Itoa(len(seqs))}
	if len(seqs) == 0 {
		return row
	}
	row.Detail = meaning + ": " + seqList(seqs)
	return row
}

func seqList(seqs []uint64) string {
	shown := seqs
	if len(shown) > verificationListLimit {
		shown = shown[:verificationListLimit]
	}
	parts := make([]string, len(shown))
	for i, s := range shown {
		parts[i] = strconv.FormatUint(s, 10)
	}
	out := strings.Join(parts, ", ")
	if len(seqs) > len(shown) {
		out += fmt.Sprintf(" and %d more (the JSON export lists all)", len(seqs)-len(shown))
	}
	return out
}

func retainedRow(ranges []verify.RetainedRange) verificationRow {
	row := verificationRow{Check: "Retained", Result: strconv.Itoa(len(ranges))}
	if len(ranges) == 0 {
		return row
	}
	shown := ranges
	if len(shown) > verificationListLimit {
		shown = shown[:verificationListLimit]
	}
	parts := make([]string, len(shown))
	for i, rr := range shown {
		p := fmt.Sprintf("%d to %d (record %d", rr.FromSeq, rr.ToSeq, rr.RecordSeq)
		if rr.PolicyID != "" {
			p += ", policy " + rr.PolicyID
		}
		if rr.Backfill != "" {
			p += ", backfilled from " + rr.Backfill
		}
		parts[i] = p + ")"
	}
	row.Detail = "removed by retention and linked across by an authentic record: " + strings.Join(parts, "; ")
	if len(ranges) > len(shown) {
		row.Detail += fmt.Sprintf(" and %d more ranges (the JSON export lists all)", len(ranges)-len(shown))
	}
	return row
}

// levelMeaning says what each assurance level lets a reader conclude.
func levelMeaning(l verify.Level) string {
	switch l {
	case verify.LevelUnkeyed:
		return "detects corruption, not tampering: anyone who can write the store can recompute these digests"
	case verify.LevelKeyed:
		return "digests need key material the store does not hold"
	case verify.LevelSigned:
		return "a signed checkpoint covers these, so a later rewrite is provable"
	case verify.LevelAnchored:
		return "a covering checkpoint was confirmed from an external publisher"
	default:
		return ""
	}
}

func coverageDetail(c verify.Coverage) string {
	d := fmt.Sprintf("sequences %d to %d; %s", c.FromSeq, c.ToSeq, levelMeaning(c.Level))
	if c.Note != "" {
		d += "; " + c.Note
	}
	return d
}

func checkpointRow(cp verify.CheckpointResult) verificationRow {
	hash := threeState(cp.HashChecked, cp.HashMatch)
	continuity := threeState(cp.ContinuityChecked, cp.ContinuityOK)
	signature := stateFailed
	if cp.SignatureValid {
		signature = statePassed
	}

	result := statePassed
	switch {
	case signature == stateFailed || hash == stateFailed || continuity == stateFailed:
		result = stateFailed
	case hash == stateNotChecked || continuity == stateNotChecked:
		result = "partly checked"
	}

	detail := fmt.Sprintf("sequences %d to %d; signature %s; hash %s; continuity %s",
		cp.FromSeq, cp.ToSeq, signature, hash, continuity)
	if cp.Note != "" {
		detail += "; " + cp.Note
	}
	return verificationRow{Check: "Checkpoint " + cp.ID, Result: result, Detail: detail}
}
