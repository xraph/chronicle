package hash

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/keys"
)

func requestEvent() *audit.Event {
	return &audit.Event{
		Sequence:  7,
		Timestamp: time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC),
		AppID:     "app_1",
		TenantID:  "org_1",
		UserID:    "user_1",
		IP:        "203.0.113.9",
		UserAgent: "curl/8.0",
		RequestID: "req_1",
		SessionID: "sess_1",
		Action:    "signin",
		Resource:  "session",
		Category:  "auth",
		Outcome:   "success",
		Severity:  "info",
	}
}

func withoutRequestContext(e *audit.Event) *audit.Event {
	cp := *e
	cp.UserAgent, cp.RequestID, cp.SessionID = "", "", ""
	return &cp
}

// TestContentV4IsUnchangedWithoutRequestContext freezes the bytes every v4 and
// v5 event written before the request fields existed was digested over. If
// this string changes, every one of those events reads as tampered.
func TestContentV4IsUnchangedWithoutRequestContext(t *testing.T) {
	got := contentV4(SchemePlainV4, "prev", withoutRequestContext(requestEvent()))
	want := "12:chronicle/v4|4:prev|1:7|20:2026-09-22T10:00:00Z|5:app_1|5:org_1|6:user_1|11:203.0.113.9|" +
		"6:signin|7:session|4:auth|0:|7:success|4:info|0:|0:|2:{}"
	if got != want {
		t.Fatalf("contentV4 without request fields changed:\n got %s\nwant %s", got, want)
	}
}

// TestRequestContextIsCovered checks each field changes the digest under both
// writable schemes.
func TestRequestContextIsCovered(t *testing.T) {
	ctx := context.Background()
	for _, scheme := range []Scheme{SchemePlainV4, SchemeHMACV5} {
		c := testChain(t, scheme)
		base, _, err := c.Compute(ctx, "prev", requestEvent())
		if err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*audit.Event){
			"user agent": func(e *audit.Event) { e.UserAgent = "other" },
			"request id": func(e *audit.Event) { e.RequestID = "other" },
			"session id": func(e *audit.Event) { e.SessionID = "other" },
		} {
			ev := requestEvent()
			mutate(ev)
			if got, _, _ := c.Compute(ctx, "prev", ev); got == base {
				t.Errorf("%s: changing the %s did not change the digest", scheme, name)
			}
		}
	}
}

// TestRequestContextCannotBeStrippedOrAdded: removing the fields from an event
// that had them, or adding them to one that did not, both break the digest.
// This is what makes covering them only when present safe.
func TestRequestContextCannotBeStrippedOrAdded(t *testing.T) {
	ctx := context.Background()
	for _, scheme := range []Scheme{SchemePlainV4, SchemeHMACV5} {
		c := testChain(t, scheme)

		with := requestEvent()
		stamp(t, c, with)
		stripped := withoutRequestContext(with)
		if res, _ := c.VerifyWithPin(ctx, "prev", stripped, Pin{}); res.OK {
			t.Errorf("%s: an event verified with its request fields stripped", scheme)
		}

		without := withoutRequestContext(requestEvent())
		stamp(t, c, without)
		if res, _ := c.VerifyWithPin(ctx, "prev", without, Pin{}); !res.OK {
			t.Fatalf("%s: an event with no request fields does not verify", scheme)
		}
		added := *without
		added.RequestID = "req_forged"
		if res, _ := c.VerifyWithPin(ctx, "prev", &added, Pin{}); res.OK {
			t.Errorf("%s: an event verified with a request id added after the fact", scheme)
		}
	}
}

// TestOlderSchemesRejectRequestContext: v1, v2 and v3 never covered the
// request fields and were retired before they existed, so a row under one of
// them that carries a request field had it added later. Its digest still
// matches, because the digest never looked at that field, and it must fail
// anyway. The same goes for a row with no scheme at all.
func TestOlderSchemesRejectRequestContext(t *testing.T) {
	ctx := context.Background()
	c := &Chain{}

	plain := withoutRequestContext(requestEvent())
	sum := sha256.Sum256([]byte(contentV2("prev", plain)))
	plain.Hash = hex.EncodeToString(sum[:])

	legacy := withoutRequestContext(requestEvent())
	legacy.Hash = ComputeLegacy("prev", legacy)

	for _, tc := range []struct {
		name   string
		event  *audit.Event
		scheme Scheme
	}{
		{"chronicle/v2", plain, SchemePlain},
		{"chronicle/v1", legacy, SchemeLegacy},
		{"no scheme", plain, ""},
	} {
		ev := *tc.event
		ev.HashScheme = string(tc.scheme)
		if res, err := c.VerifyWithPin(ctx, "prev", &ev, Pin{}); err != nil || !res.OK {
			t.Fatalf("%s: untouched row does not verify (ok=%v err=%v)", tc.name, res.OK, err)
		}
		ev.SessionID = "sess_added"
		if res, _ := c.VerifyWithPin(ctx, "prev", &ev, Pin{}); res.OK {
			t.Errorf("%s: row verified with a session id its scheme never covered", tc.name)
		}
	}
}

// stamp digests e under c as the writer would.
func stamp(t *testing.T, c *Chain, e *audit.Event) {
	t.Helper()
	digest, keyID, err := c.Compute(context.Background(), "prev", e)
	if err != nil {
		t.Fatal(err)
	}
	e.Hash, e.HashKeyID, e.HashScheme = digest, keyID, string(c.Scheme())
}

// fixedKey is a one-key provider for the internal tests.
type fixedKey struct{}

func (fixedKey) Current(context.Context, keys.Use) ([]byte, string, error) {
	return []byte("0123456789abcdef0123456789abcdef"), "k1", nil
}

func (fixedKey) ByID(context.Context, string) ([]byte, error) {
	return []byte("0123456789abcdef0123456789abcdef"), nil
}

func testChain(t *testing.T, scheme Scheme) *Chain {
	t.Helper()
	var provider keys.Provider
	if Keyed(scheme) {
		provider = fixedKey{}
	}
	c, err := NewChain(scheme, provider)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
