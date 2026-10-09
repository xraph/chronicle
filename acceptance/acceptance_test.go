package acceptance

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
)

func request() Request {
	return Request{Producer: "p", Installation: "i", SourceKey: "k", SourceFingerprint: "s", Event: &audit.Event{AppID: "a", Action: "act", Resource: "r", Category: "c", Timestamp: time.Date(2026, 10, 9, 1, 2, 3, 999, time.UTC)}}
}

func TestCanonicalFingerprint(t *testing.T) {
	a := request()
	a.Event.Metadata = map[string]any{"n": json.Number("9007199254740993"), "decimal": json.Number("10e-1"), "raw": json.RawMessage(`{"z":2,"a":1}`)}
	b := request()
	b.Event.Timestamp = a.Event.Timestamp.In(time.FixedZone("offset", 3600))
	b.Event.Metadata = map[string]any{"raw": map[string]any{"a": 1, "z": 2}, "decimal": json.Number("1.00"), "n": json.Number("9007199254740993.0")}
	af, err := Fingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	bf, err := Fingerprint(b)
	if err != nil || af != bf {
		t.Fatalf("not equivalent: %s %s %v", af, bf, err)
	}
	b.Event.Metadata["n"] = json.Number("9007199254740992")
	bf, err = Fingerprint(b)
	if err != nil || af == bf {
		t.Fatal("large integer rounded")
	}
	c, _, err := Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	c.Event.Metadata["raw"].(map[string]any)["z"] = "changed"
	if string(a.Event.Metadata["raw"].(json.RawMessage)) != `{"z":2,"a":1}` {
		t.Fatal("caller mutated")
	}
	for _, bad := range []any{math.Inf(1), math.NaN(), json.RawMessage(`{"a":1,"a":2}`), json.Number("1e999999")} {
		r := request()
		r.Event.Metadata = map[string]any{"bad": bad}
		if _, err := Fingerprint(r); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	r := request()
	r.Event.Timestamp = time.Time{}
	if _, err := Fingerprint(r); err == nil {
		t.Fatal("accepted absent timestamp")
	}
}
