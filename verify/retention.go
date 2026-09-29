package verify

import (
	"context"
	"fmt"
	"sort"

	"github.com/xraph/chronicle/audit"
)

// RetainedRange is a run of sequences that retention removed, all explained
// by the same retention record.
type RetainedRange struct {
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`

	// RecordSeq is the sequence of the retention record that lists them.
	RecordSeq uint64 `json:"record_seq"`

	// PolicyID is the retention policy the record says it acted under.
	PolicyID string `json:"policy_id,omitempty"`

	// Backfill names the archive the record was recovered from, when the
	// record was backfilled for a purge that predates retention records. It
	// is empty for a record the enforcer wrote at purge time.
	Backfill string `json:"backfill,omitempty"`
}

// retainedEntry is one removed event as an authenticated record lists it.
type retainedEntry struct {
	audit.RetentionEntry
	recordSeq uint64
	policyID  string
	backfill  string
}

// RetainedEntries returns every removed sequence the stream's authentic
// retention records account for, keyed by sequence, with the hashes either
// side of each one.
//
// It applies exactly the rules VerifyChain does: a record counts only if its
// own digest verifies under input.Pin, an entry at or after its record's
// sequence is dropped, and a sequence two records disagree about is left out.
// input needs StreamID, AppID, TenantID and Pin.
func (v *Verifier) RetainedEntries(ctx context.Context, input *Input) (map[uint64]audit.RetentionEntry, error) {
	entries, err := v.retentionEntries(ctx, input, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[uint64]audit.RetentionEntry, len(entries))
	for seq, e := range entries {
		out[seq] = e.RetentionEntry
	}
	return out, nil
}

// eventQuerier is how the verifier finds a stream's retention records. Every
// backend's audit.Store has it; a verify.Store that does not simply gets no
// retention accounting, and every missing sequence is a gap as before.
type eventQuerier interface {
	Query(ctx context.Context, q *audit.Query) (*audit.QueryResult, error)
}

// retentionPageSize bounds each page of the record lookup.
const retentionPageSize = 500

// retentionEntries returns every removed sequence this stream's authentic
// retention records account for.
//
// A record is authentic when its own digest verifies under the stream's pin.
// That is the whole of its protection, and it is the same protection every
// event has: under a keyed scheme nobody without the key can write one, and a
// forged row fails here and is reported as tampered by the chain walk when it
// falls in range. Under an unkeyed scheme anyone who can write the store can
// forge a record, exactly as they can rewrite any event; Coverage already says
// unkeyed for that range.
//
// Nothing is taken on trust from a record that fails, and an entry is dropped
// when it could not be genuine: one at or after its own record's sequence
// (a record is always written after the events it lists), or one two records
// disagree about.
func (v *Verifier) retentionEntries(
	ctx context.Context, input *Input, events []*audit.Event,
) (map[uint64]retainedEntry, error) {
	querier, ok := v.store.(eventQuerier)
	if !ok {
		return nil, nil
	}

	appID, tenantID := input.AppID, input.TenantID
	if appID == "" && len(events) > 0 {
		appID, tenantID = events[0].AppID, events[0].TenantID
	}

	entries := make(map[uint64]retainedEntry)
	conflicted := make(map[uint64]bool)

	for offset := 0; ; offset += retentionPageSize {
		page, err := querier.Query(ctx, &audit.Query{
			AppID:      appID,
			TenantID:   tenantID,
			Categories: []string{audit.CategoryRetention},
			Limit:      retentionPageSize,
			Offset:     offset,
			Order:      "asc",
		})
		if err != nil {
			return nil, fmt.Errorf("verify: find retention records: %w", err)
		}
		for _, rec := range page.Events {
			v.collectRetention(ctx, input, rec, entries, conflicted)
		}
		if !page.HasMore || len(page.Events) == 0 {
			break
		}
	}

	for seq := range conflicted {
		delete(entries, seq)
	}
	return entries, nil
}

// collectRetention adds one record's entries, if the record is authentic.
func (v *Verifier) collectRetention(
	ctx context.Context, input *Input, rec *audit.Event,
	entries map[uint64]retainedEntry, conflicted map[uint64]bool,
) {
	if rec.StreamID != input.StreamID || !audit.IsRetentionRecord(rec) {
		return
	}
	res, err := v.chain.VerifyWithPin(ctx, rec.PrevHash, rec, input.Pin)
	if err != nil || !res.OK || res.Downgrade {
		// A key that cannot be resolved is no opinion, and no opinion is not
		// authority to excuse a gap.
		return
	}
	parsed, err := audit.ParseRetentionRecord(rec)
	if err != nil || parsed.StreamID != input.StreamID.String() {
		return
	}

	for _, e := range parsed.Entries {
		if e.Seq >= rec.Sequence {
			continue
		}
		next := retainedEntry{
			RetentionEntry: e, recordSeq: rec.Sequence,
			policyID: parsed.Ref.PolicyID, backfill: parsed.Ref.Backfill,
		}
		prev, seen := entries[e.Seq]
		switch {
		case !seen:
			entries[e.Seq] = next
		case prev.PrevHash != e.PrevHash || prev.Hash != e.Hash:
			// Two authentic records disagree about one event. Neither can
			// be believed over the other, so the sequence stays a gap.
			conflicted[e.Seq] = true
		}
		// An identical duplicate is what a retried purge leaves behind; the
		// first record to list it keeps the credit.
	}
}

// linkAcross carries the chain hash across the missing sequences from..to,
// starting from cur, the hash the chain held just before from.
//
// linked is true when retention accounts for every missing sequence and each
// entry continues from the one before it; next is then the hash the event
// after the run must name as its PrevHash. accounted is false when at least
// one sequence is simply missing, in which case there is nothing to link
// across and the caller falls back to the event's own declared PrevHash.
func linkAcross(cur string, from, to uint64, retained map[uint64]retainedEntry) (next string, linked, accounted bool) {
	linked = true
	for seq := from; seq <= to; seq++ {
		e, ok := retained[seq]
		if !ok {
			return "", false, false
		}
		if e.PrevHash != cur {
			linked = false
		}
		cur = e.Hash
	}
	return cur, linked, true
}

// splitGaps separates missing sequences retention accounts for from the ones
// nothing explains, and groups the former into ranges by record.
func splitGaps(gaps []uint64, retained map[uint64]retainedEntry) (unexplained []uint64, ranges []RetainedRange) {
	sorted := append([]uint64(nil), gaps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	for _, seq := range sorted {
		e, ok := retained[seq]
		if !ok {
			unexplained = append(unexplained, seq)
			continue
		}
		if n := len(ranges); n > 0 && ranges[n-1].ToSeq+1 == seq && ranges[n-1].RecordSeq == e.recordSeq {
			ranges[n-1].ToSeq = seq
			continue
		}
		ranges = append(ranges, RetainedRange{
			FromSeq: seq, ToSeq: seq, RecordSeq: e.recordSeq,
			PolicyID: e.policyID, Backfill: e.backfill,
		})
	}
	return unexplained, ranges
}
