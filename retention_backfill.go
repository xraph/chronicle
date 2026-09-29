package chronicle

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/sink"
	"github.com/xraph/chronicle/verify"
)

// BackfillInput says which stream to backfill and where its purged events
// were archived.
type BackfillInput struct {
	// AppID and TenantID select the stream. AppID is required.
	AppID    string
	TenantID string

	// Archive is where the policy that purged the events archived them.
	Archive sink.ArchiveReader

	// DryRun reports what would be recovered and writes nothing.
	DryRun bool
}

// BackfillReport is what a backfill found and did.
type BackfillReport struct {
	StreamID id.ID `json:"stream_id"`
	DryRun   bool  `json:"dry_run,omitempty"`

	// Gaps are the sequences verification could not account for before the
	// backfill ran.
	Gaps []uint64 `json:"gaps"`

	// Recovered are the gaps an archived copy proved, in sequence order. On a
	// dry run nothing was written for them.
	Recovered []BackfillRecovered `json:"recovered,omitempty"`

	// Refused are the gaps left as gaps, each with the reason.
	Refused []BackfillRefused `json:"refused,omitempty"`

	// Rejected are archived copies that failed a check. A copy that claims to
	// be a purged event of this stream and does not verify under its key is
	// worth looking at on its own account: nothing the chain writer produced
	// looks like that.
	Rejected []BackfillRejected `json:"rejected,omitempty"`

	// Records are the sequences of the retention records written.
	Records []uint64 `json:"records,omitempty"`

	// After is the stream's verification once the records were written. Nil
	// on a dry run or when nothing was recovered.
	After *verify.Report `json:"after,omitempty"`
}

// BackfillRecovered is one gap an archived copy accounts for.
type BackfillRecovered struct {
	Seq      uint64 `json:"seq"`
	Hash     string `json:"hash"`
	Location string `json:"location"`
}

// BackfillRefused is one gap the backfill left alone.
type BackfillRefused struct {
	Seq    uint64 `json:"seq"`
	Reason string `json:"reason"`
}

// BackfillRejected is one archived copy that failed a check.
type BackfillRejected struct {
	Seq      uint64 `json:"seq"`
	Location string `json:"location"`
	Reason   string `json:"reason"`
}

// archivedCopy is one candidate read from the archive.
type archivedCopy struct {
	event *audit.Event
	loc   string
}

// BackfillRetention writes retention records for gaps left by purges that ran
// before retention records existed, where the purged events survive in an
// archive and can be proven to be the events that were removed.
//
// It is an operator tool, run once per stream after an upgrade. Nothing calls
// it automatically, and there is deliberately no way to tell it to accept a
// gap without evidence: a tool that marks gaps as authorised on someone's say
// so cannot be told apart from one covering up a deletion.
//
// A gap is recovered only when all of this holds:
//
//   - The stream is pinned to chronicle/v5 and this process writes it.
//     Anything else returns ErrBackfillUnkeyed before reading the archive.
//   - The archive holds a copy of the event at that sequence, for this stream
//     and scope, that is not itself a retention record.
//   - The copy's digest recomputes under the stream's pin with the HMAC key it
//     names, and it claims chronicle/v5. That is what shows the chain writer
//     produced it and nobody has edited it since. Copies below the pin under
//     an unkeyed scheme are refused, whatever the rest of the stream is.
//   - Every sequence in the same run of consecutive gaps has such a copy, and
//     the run links end to end: the first copy's PrevHash is the hash of the
//     event before the run, each copy's PrevHash is the one before's Hash, and
//     the last copy's Hash is the PrevHash of the event after the run. The
//     neighbours can be present events that verify cleanly, sequences an
//     existing record already accounts for, genesis, or the stream head.
//
// A run is recovered whole or not at all, so the verifier can always link
// across what a backfilled record lists. One sequence nothing can prove
// leaves its whole run as gaps, and a sequence deleted by anything other than
// retention stays exactly what it is.
//
// The records are written the same way RecordRetention writes them, marked
// with the archive's name, and verification reports those sequences as
// retained with RetainedRange.Backfill set. Verification never re-reads the
// archive. What it relies on afterwards is the record, which is as hard to
// forge as any other v5 event.
//
// What this proves, and what it does not: a recovered sequence held an event
// the chain writer wrote, whose complete content is in the archive. It does
// not prove a retention policy removed it rather than someone who copied the
// row into the archive first. Either way nothing was hidden, since the content
// is still there to read, and that is the property a gap exists to protect.
// Keep the archive.
func (c *Chronicle) BackfillRetention(ctx context.Context, in *BackfillInput) (*BackfillReport, error) {
	if c.store == nil {
		return nil, ErrNoStore
	}
	if in == nil || in.Archive == nil {
		return nil, errors.New("chronicle: retention backfill needs an archive to read")
	}
	if in.AppID == "" {
		return nil, errors.New("chronicle: retention backfill needs an app ID")
	}

	s, err := c.store.GetStreamByScope(ctx, in.AppID, in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("chronicle: resolve stream for backfill: %w", err)
	}
	if hash.Scheme(s.Scheme) != hash.SchemeHMACV5 || c.hasher.Scheme() != hash.SchemeHMACV5 {
		return nil, fmt.Errorf("%w (stream %s is pinned to %q, this process writes %q)",
			ErrBackfillUnkeyed, s.ID, s.Scheme, c.hasher.Scheme())
	}
	pin := hash.Pin{Scheme: hash.Scheme(s.Scheme), Since: s.SchemeSince}

	input := &verify.Input{
		StreamID: s.ID, AppID: s.AppID, TenantID: s.TenantID,
		Pin: pin, HeadSeq: s.HeadSeq, HeadHash: s.HeadHash,
	}
	verifier := c.newVerifier()
	before, err := verifier.VerifyChain(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("chronicle: verify before backfill: %w", err)
	}

	report := &BackfillReport{StreamID: s.ID, DryRun: in.DryRun, Gaps: before.Gaps}
	if len(before.Gaps) == 0 {
		return report, nil
	}

	retained, err := verifier.RetainedEntries(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("chronicle: read retention records: %w", err)
	}

	candidates, err := readArchived(ctx, in.Archive, s.ID, before.Gaps)
	if err != nil {
		return nil, fmt.Errorf("chronicle: read archive %s: %w", in.Archive.Name(), err)
	}

	// Pick one proven copy per gap, or the reason there is none.
	proven := make(map[uint64]archivedCopy, len(before.Gaps))
	unproven := make(map[uint64]string)
	for _, seq := range before.Gaps {
		cp, reason := c.proveArchived(ctx, s, pin, seq, candidates[seq], report)
		if reason != "" {
			unproven[seq] = reason
			continue
		}
		proven[seq] = cp
	}

	suspect := make(map[uint64]bool, len(before.Tampered)+len(before.Downgrades))
	for _, seq := range append(slices.Clone(before.Tampered), before.Downgrades...) {
		suspect[seq] = true
	}

	var entries []audit.RetentionEntry
	for _, run := range consecutiveRuns(before.Gaps) {
		if reason := c.linkRun(ctx, s, run, proven, unproven, retained, suspect); reason != "" {
			for _, seq := range run {
				r := reason
				if own, ok := unproven[seq]; ok {
					r = own
				}
				report.Refused = append(report.Refused, BackfillRefused{Seq: seq, Reason: r})
			}
			continue
		}
		for _, seq := range run {
			e := proven[seq].event
			entries = append(entries, audit.RetentionEntry{Seq: seq, PrevHash: e.PrevHash, Hash: e.Hash})
			report.Recovered = append(report.Recovered, BackfillRecovered{Seq: seq, Hash: e.Hash, Location: proven[seq].loc})
		}
	}

	if in.DryRun || len(entries) == 0 {
		return report, nil
	}

	like := &audit.Event{StreamID: s.ID, AppID: s.AppID, TenantID: s.TenantID}
	ref := audit.RetentionRef{Backfill: in.Archive.Name()}
	for start := 0; start < len(entries); start += audit.MaxRetentionEntries {
		end := min(start+audit.MaxRetentionEntries, len(entries))
		seq, appendErr := c.appendRetentionRecord(ctx, ref, like, entries[start:end])
		if appendErr != nil {
			return report, appendErr
		}
		report.Records = append(report.Records, seq)
	}

	after, err := c.VerifyChain(ctx, &verify.Input{AppID: s.AppID, TenantID: s.TenantID})
	if err != nil {
		return report, fmt.Errorf("chronicle: verify after backfill: %w", err)
	}
	report.After = after

	// Belt and braces. Every check above mirrors one the verifier makes, so a
	// recovered sequence still reported as a gap means they disagree, and the
	// operator needs to hear about it rather than read a clean report.
	var still []string
	for _, r := range report.Recovered {
		if slices.Contains(after.Gaps, r.Seq) {
			still = append(still, fmt.Sprint(r.Seq))
		}
	}
	if len(still) > 0 {
		return report, fmt.Errorf("chronicle: backfill recorded sequences verification still reports as gaps: %s",
			strings.Join(still, ", "))
	}
	return report, nil
}

// readArchived collects every archived copy that claims to be one of the gaps
// in this stream. Everything else in the archive is ignored.
func readArchived(
	ctx context.Context, archive sink.ArchiveReader, streamID id.ID, gaps []uint64,
) (map[uint64][]archivedCopy, error) {
	want := make(map[uint64]bool, len(gaps))
	for _, seq := range gaps {
		want[seq] = true
	}
	out := make(map[uint64][]archivedCopy)
	err := archive.ReadEvents(ctx, func(e *audit.Event, loc string) error {
		if e.StreamID == streamID && want[e.Sequence] {
			out[e.Sequence] = append(out[e.Sequence], archivedCopy{event: e, loc: loc})
		}
		return nil
	})
	return out, err
}

// proveArchived picks the one archived copy of seq that proves itself, or says
// why there is none. Copies that fail are added to report.Rejected.
//
// Identical copies are what a retried archive write leaves behind and count as
// one. Two different copies that both verify would mean the writer produced
// two events at one sequence, and neither can be believed over the other.
func (c *Chronicle) proveArchived(
	ctx context.Context, s *StreamInfo, pin hash.Pin, seq uint64, copies []archivedCopy, report *BackfillReport,
) (chosen archivedCopy, reason string) {
	if len(copies) == 0 {
		return archivedCopy{}, "no archived copy"
	}

	var good []archivedCopy
	for _, cp := range copies {
		if why := c.checkArchived(ctx, s, pin, cp.event); why != "" {
			report.Rejected = append(report.Rejected, BackfillRejected{Seq: seq, Location: cp.loc, Reason: why})
			continue
		}
		if !slices.ContainsFunc(good, func(g archivedCopy) bool { return g.event.Hash == cp.event.Hash }) {
			good = append(good, cp)
		}
	}

	switch len(good) {
	case 0:
		return archivedCopy{}, "no archived copy verifies"
	case 1:
		return good[0], ""
	default:
		return archivedCopy{}, fmt.Sprintf("the archive holds %d different copies that all verify", len(good))
	}
}

// checkArchived returns why an archived copy cannot be believed, or "".
func (c *Chronicle) checkArchived(ctx context.Context, s *StreamInfo, pin hash.Pin, e *audit.Event) string {
	switch scheme := hash.Scheme(e.HashScheme); {
	case e.AppID != s.AppID || e.TenantID != s.TenantID:
		return fmt.Sprintf("scope %q/%q is not the stream's", e.AppID, e.TenantID)
	case e.Category == audit.CategoryRetention:
		// Retention never purges a record, so an archived one was removed by
		// something else. Excusing its sequence would excuse that removal.
		return "it is a retention record, and retention never removes those"
	case scheme == hash.SchemeHMAC:
		return "digested under chronicle/v3, whose field encoding lets content be rewritten without the key"
	case scheme != hash.SchemeHMACV5:
		return fmt.Sprintf("digested under %q, which is unkeyed, so anyone who can write the store could have produced it",
			e.HashScheme)
	}

	res, err := c.hasher.VerifyWithPin(ctx, e.PrevHash, e, pin)
	switch {
	case err != nil:
		return fmt.Sprintf("cannot be verified: %v", err)
	case res.Downgrade:
		return "claims a weaker scheme than the stream pins"
	case !res.OK:
		return "digest does not match its content"
	}
	return ""
}

// linkRun checks that one run of consecutive gaps links end to end through
// the proven copies, and returns why not, or "".
func (c *Chronicle) linkRun(
	ctx context.Context, s *StreamInfo, run []uint64,
	proven map[uint64]archivedCopy, unproven map[uint64]string,
	retained map[uint64]audit.RetentionEntry, suspect map[uint64]bool,
) string {
	for _, seq := range run {
		if _, ok := unproven[seq]; ok {
			if len(run) == 1 {
				return unproven[seq]
			}
			return fmt.Sprintf("sequence %d in the same run of gaps has no proven copy, so the run cannot be linked end to end", seq)
		}
	}

	first, last := run[0], run[len(run)-1]

	want, reason := c.hashBefore(ctx, s, first, retained, suspect)
	if reason != "" {
		return reason
	}
	for _, seq := range run {
		e := proven[seq].event
		if e.PrevHash != want {
			return fmt.Sprintf("archived copy of %d does not follow from sequence %d", seq, seq-1)
		}
		want = e.Hash
	}

	next, reason := c.hashAfter(ctx, s, last, retained, suspect)
	if reason != "" {
		return reason
	}
	if want != next {
		return fmt.Sprintf("sequence %d does not follow from the archived copy of %d", last+1, last)
	}
	return ""
}

// hashBefore returns the hash the event at seq must name as its predecessor,
// or why it cannot be established.
func (c *Chronicle) hashBefore(
	ctx context.Context, s *StreamInfo, seq uint64,
	retained map[uint64]audit.RetentionEntry, suspect map[uint64]bool,
) (prevHash, reason string) {
	prev := seq - 1
	if prev == 0 {
		return "", "" // Genesis.
	}
	if e, ok := retained[prev]; ok {
		return e.Hash, ""
	}
	e, reason := c.neighbour(ctx, s, prev, suspect)
	if reason != "" {
		return "", reason
	}
	return e.Hash, ""
}

// hashAfter returns the hash the event after seq names as its predecessor, or
// why it cannot be established.
func (c *Chronicle) hashAfter(
	ctx context.Context, s *StreamInfo, seq uint64,
	retained map[uint64]audit.RetentionEntry, suspect map[uint64]bool,
) (nextPrevHash, reason string) {
	next := seq + 1
	if e, ok := retained[next]; ok {
		return e.PrevHash, ""
	}
	e, reason := c.neighbour(ctx, s, next, suspect)
	switch {
	case reason == "":
		return e.PrevHash, ""
	case seq == s.HeadSeq:
		// The purged event was the head. The stream row still carries its
		// hash, and the archived copy's keyed digest is what makes matching
		// it mean something.
		return s.HeadHash, ""
	default:
		return "", reason
	}
}

// neighbour fetches the present event at seq, refusing one verification
// already found tampered: linking to a hash nobody can vouch for proves
// nothing.
func (c *Chronicle) neighbour(ctx context.Context, s *StreamInfo, seq uint64, suspect map[uint64]bool) (event *audit.Event, reason string) {
	if suspect[seq] {
		return nil, fmt.Sprintf("neighbouring sequence %d fails verification", seq)
	}
	events, err := c.store.EventRange(ctx, s.ID, seq, seq)
	if err != nil {
		return nil, fmt.Sprintf("cannot read neighbouring sequence %d: %v", seq, err)
	}
	if len(events) == 0 {
		return nil, fmt.Sprintf("neighbouring sequence %d is missing", seq)
	}
	return events[0], ""
}

// consecutiveRuns splits sorted sequences into runs of consecutive values.
func consecutiveRuns(seqs []uint64) [][]uint64 {
	sorted := slices.Clone(seqs)
	slices.Sort(sorted)
	var runs [][]uint64
	for i, seq := range sorted {
		if i > 0 && seq == sorted[i-1]+1 {
			runs[len(runs)-1] = append(runs[len(runs)-1], seq)
			continue
		}
		runs = append(runs, []uint64{seq})
	}
	return runs
}
