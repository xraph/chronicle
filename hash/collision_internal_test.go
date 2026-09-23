package hash

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
)

// collidingPair returns two events that differ in their field values but whose
// delimiter-joined content is byte-identical.
//
// UserID and IP sit next to each other in the hashed field order, so moving the
// separator between them moves content from one field into the other while the
// joined string stays the same. Everything else about the two events matches,
// including sequence and timestamp, so the only difference is which field the
// address lives in -- which is to say, who the record says acted and from where.
func collidingPair() (a, b *audit.Event) {
	base := func() *audit.Event {
		return &audit.Event{
			Timestamp: time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC),
			Sequence:  7,
			AppID:     "app-1",
			TenantID:  "tenant-1",
			Action:    "delete",
			Resource:  "record",
			Category:  "data",
			Outcome:   audit.OutcomeSuccess,
			Severity:  audit.SeverityInfo,
		}
	}

	a = base()
	a.UserID = "alice"
	a.IP = "10.0.0.9|attacker-note"

	b = base()
	b.UserID = "alice|10.0.0.9"
	b.IP = "attacker-note"

	return a, b
}

// The defect this package's v4 schemes exist to fix. Kept as a live assertion
// rather than a comment: if someone ever "tidies" contentV2, this test says out
// loud that the old digests depend on its exact broken shape and must not move.
func TestDelimiterJoinedContentCollides(t *testing.T) {
	a, b := collidingPair()

	if a.UserID == b.UserID || a.IP == b.IP {
		t.Fatal("the two events are supposed to differ in both fields")
	}

	if contentV2("prev", a) != contentV2("prev", b) {
		t.Fatalf("expected a collision under the delimiter-joined content:\n a: %s\n b: %s",
			contentV2("prev", a), contentV2("prev", b))
	}
}

// Length prefixes are what close it: the reader of the canonical form can tell
// where each field ends without trusting its contents.
func TestLengthPrefixedContentDoesNotCollide(t *testing.T) {
	a, b := collidingPair()

	if contentV4(SchemePlainV4, "prev", a) == contentV4(SchemePlainV4, "prev", b) {
		t.Fatalf("expected distinct content, got %s for both", contentV4(SchemePlainV4, "prev", a))
	}
}

// A v4 content string must never be readable as a v5 one. Tagging each scheme's
// content with its own name is what stops a digest computed for one being
// presented as the other's.
func TestContentIsTaggedWithItsOwnScheme(t *testing.T) {
	a, _ := collidingPair()

	if contentV4(SchemePlainV4, "prev", a) == contentV4(SchemeHMACV5, "prev", a) {
		t.Fatal("v4 and v5 content are identical; the scheme tag is not being covered")
	}
}

// The end of the attack, spelled out: plant event A's stored digest on the
// doctored event B and ask the verifier whether the record is intact.
//
// Under the old schemes it says yes, which is the whole problem -- the audit
// trail now reads that alice acted from a different address, and the hash chain
// agrees. Under v4 it says no.
func TestTheSwapIsAcceptedUnderV2AndRejectedUnderV4(t *testing.T) {
	ctx := context.Background()
	a, b := collidingPair()
	c := &Chain{}

	for _, tc := range []struct {
		scheme     Scheme
		wantVerify bool
	}{
		{SchemePlain, true},
		{SchemePlainV4, false},
	} {
		digestOfA, err := c.computeUnder(ctx, tc.scheme, "", "prev", a)
		if err != nil {
			t.Fatalf("computeUnder(%s) for a: %v", tc.scheme, err)
		}

		// b is what an attacker leaves behind: different field values,
		// carrying the digest that was computed for a.
		doctored := *b
		doctored.Hash = digestOfA
		doctored.HashScheme = string(tc.scheme)

		res, err := c.VerifyWithPin(ctx, "prev", &doctored, Pin{})
		if err != nil {
			t.Fatalf("VerifyWithPin(%s): %v", tc.scheme, err)
		}
		if res.OK != tc.wantVerify {
			t.Errorf("%s: verified = %v, want %v", tc.scheme, res.OK, tc.wantVerify)
		}
	}
}
