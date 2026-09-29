package audit

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/xraph/chronicle/id"
)

// CategoryRetention is the reserved category of retention records.
//
// A retention record is an ordinary event in the stream whose events a policy
// removed. It lists what was removed, so verification can tell a sequence
// retention deleted from one an attacker deleted. Because it is hashed into the
// chain like every other event, it is exactly as hard to forge as the chain it
// explains: keyed when the chain is keyed, and covered by a signed checkpoint
// when checkpoints are on.
//
// Retention never selects an event in this category. A record that could be
// purged would turn everything it explains back into unexplained gaps.
const CategoryRetention = "chronicle.retention"

// ActionRetentionPurge is the action of a retention record.
const ActionRetentionPurge = "retention.purge"

// retentionFormat versions the record's metadata layout.
const retentionFormat = "chronicle-retention/v1"

// MaxRetentionEntries bounds how many removed events one record lists, so a
// large purge becomes several modest events rather than one enormous one.
const MaxRetentionEntries = 256

// Metadata keys of a retention record.
const (
	retentionKeyFormat   = "format"
	retentionKeyPolicy   = "policy_id"
	retentionKeyCategory = "policy_category"
	retentionKeyStream   = "stream_id"
	retentionKeyEntries  = "entries"
	retentionKeyBackfill = "backfill_source"
)

// ErrNotRetentionRecord is returned by ParseRetentionRecord for an event that
// is not a well-formed retention record.
var ErrNotRetentionRecord = errors.New("audit: not a retention record")

// RetentionRef identifies the policy a retention record acted under.
type RetentionRef struct {
	PolicyID string `json:"policy_id"`
	Category string `json:"category"`

	// Backfill names the archive a backfilled record was recovered from, and
	// is empty on a record the enforcer wrote at purge time. A backfilled
	// record explains a purge that happened before retention records existed:
	// every entry in it was checked against an archived copy of the event,
	// whose keyed digest was recomputed and whose hashes link to the events
	// either side of it. See Chronicle.BackfillRetention.
	Backfill string `json:"backfill,omitempty"`
}

// RetentionEntry is one removed event, reduced to exactly what the chain needs
// to link across it: its position and the two hashes either side of it.
//
// The event's own digest cannot be recomputed once its content is gone, since
// the digest covers nearly every field. What survives is linkage: the
// predecessor's Hash must equal PrevHash, and the successor's PrevHash must
// equal Hash. The retention record's own digest is what vouches for these
// values.
type RetentionEntry struct {
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// RetentionRecord is a parsed retention record.
type RetentionRecord struct {
	Ref      RetentionRef
	StreamID string
	Entries  []RetentionEntry
}

// NewRetentionRecord builds the event that records a retention purge. The
// caller appends it through the chain writer, which assigns its identity,
// sequence and digest.
//
// Entries are encoded as "seq:prev_hash:hash" strings rather than objects.
// Metadata is hashed after a round trip through whatever the backend stores it
// as, and a JSON number can come back as a float64 where it went in as a
// uint64. A string comes back as the same string.
func NewRetentionRecord(ref RetentionRef, streamID id.ID, entries []RetentionEntry) *Event {
	encoded := make([]any, len(entries))
	for i, e := range entries {
		encoded[i] = strconv.FormatUint(e.Seq, 10) + ":" + e.PrevHash + ":" + e.Hash
	}
	meta := map[string]any{
		retentionKeyFormat:   retentionFormat,
		retentionKeyPolicy:   ref.PolicyID,
		retentionKeyCategory: ref.Category,
		retentionKeyStream:   streamID.String(),
		retentionKeyEntries:  encoded,
	}
	reason := fmt.Sprintf("retention policy %s (%s)", ref.PolicyID, ref.Category)
	if ref.Backfill != "" {
		// Only set when present, so a record the enforcer writes hashes
		// exactly as it did before backfills existed.
		meta[retentionKeyBackfill] = ref.Backfill
		reason = "retention backfill from archive " + ref.Backfill
	}
	return &Event{
		Action:     ActionRetentionPurge,
		Resource:   "stream",
		ResourceID: streamID.String(),
		Category:   CategoryRetention,
		Outcome:    OutcomeSuccess,
		Severity:   SeverityInfo,
		Reason:     reason,
		Metadata:   meta,
	}
}

// IsRetentionRecord reports whether an event claims to be a retention record.
// It says nothing about whether the claim is genuine; only verifying the
// event's digest does that.
func IsRetentionRecord(e *Event) bool {
	return e != nil && e.Category == CategoryRetention && e.Action == ActionRetentionPurge
}

// ParseRetentionRecord decodes a retention record's metadata.
func ParseRetentionRecord(e *Event) (*RetentionRecord, error) {
	if !IsRetentionRecord(e) {
		return nil, ErrNotRetentionRecord
	}
	if f := metaString(e, retentionKeyFormat); f != retentionFormat {
		return nil, fmt.Errorf("%w: format %q", ErrNotRetentionRecord, f)
	}

	rec := &RetentionRecord{
		Ref: RetentionRef{
			PolicyID: metaString(e, retentionKeyPolicy),
			Category: metaString(e, retentionKeyCategory),
			Backfill: metaString(e, retentionKeyBackfill),
		},
		StreamID: metaString(e, retentionKeyStream),
	}

	raw, err := stringList(e.Metadata[retentionKeyEntries])
	if err != nil {
		return nil, fmt.Errorf("%w: entries: %w", ErrNotRetentionRecord, err)
	}
	rec.Entries = make([]RetentionEntry, 0, len(raw))
	for _, s := range raw {
		parts := strings.SplitN(s, ":", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("%w: entry %q", ErrNotRetentionRecord, s)
		}
		seq, perr := strconv.ParseUint(parts[0], 10, 64)
		if perr != nil || seq == 0 {
			return nil, fmt.Errorf("%w: entry %q", ErrNotRetentionRecord, s)
		}
		rec.Entries = append(rec.Entries, RetentionEntry{Seq: seq, PrevHash: parts[1], Hash: parts[2]})
	}
	return rec, nil
}

// metaString returns a string metadata value, or "" when it is absent or not a
// string.
func metaString(e *Event, key string) string {
	s, ok := e.Metadata[key].(string)
	if !ok {
		return ""
	}
	return s
}

// stringList accepts the shapes a list of strings comes back from a backend
// in: a []string from the memory store, the []any every JSON decoder produces,
// and the named slice types some drivers use for arrays.
func stringList(v any) ([]string, error) {
	switch l := v.(type) {
	case []string:
		return l, nil
	case nil:
		return nil, errors.New("missing")
	}

	// []any, and a driver's named array type such as mongo's bson.A, which is
	// a []any underneath but would not match a []any case.
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice {
		return nil, fmt.Errorf("unsupported type %T", v)
	}
	out := make([]string, rv.Len())
	for i := range out {
		s, ok := rv.Index(i).Interface().(string)
		if !ok {
			return nil, fmt.Errorf("element %d is %T, not a string", i, rv.Index(i).Interface())
		}
		out[i] = s
	}
	return out, nil
}
