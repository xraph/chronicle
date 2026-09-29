package metajson

import (
	"encoding/json"
	"math"
	"testing"
)

// Decode has to hand back values that encode to the bytes Go wrote, because
// that encoding is what the digest covers. Each case is a value a caller could
// put in metadata, written the way Record writes it.
func TestDecodeReencodesToTheSameBytes(t *testing.T) {
	cases := map[string]any{
		"above 2^53":      int64(9007199254740993),
		"below -2^53":     int64(-9007199254740993),
		"int64 max":       int64(math.MaxInt64),
		"uint64 max":      uint64(math.MaxUint64),
		"small int":       7,
		"fraction":        1.5,
		"whole float":     3.0,
		"negative zero":   math.Copysign(0, -1),
		"tiny float":      1e-7,
		"big float":       1e21,
		"float past 2^53": 1e17,
		"strings":         []any{"a", "b"},
		"nested":          map[string]any{"n": int64(9007199254740993), "xs": []any{uint64(math.MaxUint64)}},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			want, err := json.Marshal(map[string]any{"v": v})
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(want)
			if err != nil {
				t.Fatalf("Decode(%s): %v", want, err)
			}
			again, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(want) {
				t.Errorf("re-encoded %s, want %s", again, want)
			}
		})
	}
}

// jsonb hands numbers back in its own notation, not Go's. Those have to come
// out as the float64 Go started from, the same as plain json.Unmarshal gives.
func TestDecodeFloatsJSONBRewrote(t *testing.T) {
	cases := map[string]string{
		`{"v":0.0000001}`:              `{"v":1e-7}`,
		`{"v":1000000000000000000000}`: `{"v":1e21}`,
	}
	for stored, written := range cases {
		got, err := Decode([]byte(stored))
		if err != nil {
			t.Fatalf("Decode(%s): %v", stored, err)
		}
		var want map[string]any
		if err := json.Unmarshal([]byte(written), &want); err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		if string(a) != string(b) {
			t.Errorf("Decode(%s) encodes as %s, want %s", stored, a, b)
		}
	}
}

// Callers read small numbers as float64 today. That stays true.
func TestDecodeKeepsSmallNumbersFloat64(t *testing.T) {
	got, err := Decode([]byte(`{"rows":7,"big":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if got["rows"] != float64(7) {
		t.Errorf("rows = %#v, want float64(7)", got["rows"])
	}
	if got["big"] != int64(9007199254740993) {
		t.Errorf("big = %#v, want int64(9007199254740993)", got["big"])
	}
}

func TestDecodeEdges(t *testing.T) {
	for _, in := range []string{"", "  ", "null"} {
		got, err := Decode([]byte(in))
		if err != nil || got != nil {
			t.Errorf("Decode(%q) = %v, %v; want nil, nil", in, got, err)
		}
	}
	if _, err := Decode([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Error("Decode accepted trailing data")
	}
	if _, err := Decode([]byte(`[1]`)); err == nil {
		t.Error("Decode accepted a non-object")
	}
}
