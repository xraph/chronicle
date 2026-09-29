package audit_test

import (
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// TestRetentionRecordCarriesItsBackfillSource round-trips the archive name a
// backfilled record names, and checks that a record the enforcer writes has
// no such key at all. Adding one, even empty, would change the metadata every
// enforcer record is hashed over.
func TestRetentionRecordCarriesItsBackfillSource(t *testing.T) {
	stream := id.NewStreamID()
	entries := []audit.RetentionEntry{{Seq: 3, PrevHash: "a", Hash: "b"}}

	plain := audit.NewRetentionRecord(audit.RetentionRef{PolicyID: "p", Category: "auth"}, stream, entries)
	if _, ok := plain.Metadata["backfill_source"]; ok {
		t.Errorf("enforcer record has a backfill_source key: %v", plain.Metadata)
	}

	backfilled := audit.NewRetentionRecord(audit.RetentionRef{Backfill: "s3://b/p"}, stream, entries)
	parsed, err := audit.ParseRetentionRecord(backfilled)
	if err != nil {
		t.Fatalf("ParseRetentionRecord: %v", err)
	}
	if parsed.Ref.Backfill != "s3://b/p" {
		t.Errorf("backfill = %q, want s3://b/p", parsed.Ref.Backfill)
	}
	if len(parsed.Entries) != 1 || parsed.Entries[0] != entries[0] {
		t.Errorf("entries = %+v, want %+v", parsed.Entries, entries)
	}
}
