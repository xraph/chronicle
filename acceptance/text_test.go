package acceptance

import (
	"encoding/json"
	"errors"
	"testing"
)

type rawJSON string

func (r rawJSON) MarshalJSON() ([]byte, error) { return []byte(r), nil }

type countedJSON struct {
	calls *int
	raw   string
}

func (r countedJSON) MarshalJSON() ([]byte, error) { *r.calls++; return []byte(r.raw), nil }

type textOnly string

func (r textOnly) MarshalText() ([]byte, error) { return []byte(r), nil }

func TestMetadataTextBoundary(t *testing.T) {
	bad := string([]byte{0xff})
	for name, v := range map[string]any{
		"value":            bad,
		"key":              map[string]any{bad: 1},
		"typed nested":     []map[string][]string{{"items": {bad}}},
		"struct":           struct{ Value string }{bad},
		"raw bytes":        json.RawMessage("\"" + bad + "\""),
		"custom bytes":     rawJSON("\"" + bad + "\""),
		"raw surrogate":    json.RawMessage(`"\ud800"`),
		"custom surrogate": rawJSON(`{"\udfff":1}`),
		"nul":              "\x00",
		"raw nul":          json.RawMessage(`"\u0000"`),
		"text-only":        textOnly(bad),
		"valid text-only":  textOnly("valid"),
		"valid text key":   map[textOnly]int{"valid": 1},
		"text key":         map[textOnly]int{textOnly(bad): 1},
	} {
		t.Run(name, func(t *testing.T) {
			r := request()
			r.Event.Metadata = map[string]any{"v": v}
			if _, _, err := Normalize(r); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted invalid metadata: %v", err)
			}
		})
	}
	for _, raw := range []string{`"�"`, `"\ufffd"`, `"\ud83d\ude00"`, `"\\ud800"`, `{"number":9007199254740993}`} {
		calls := 0
		r := request()
		r.Event.Metadata = map[string]any{"v": countedJSON{&calls, raw}}
		if _, _, err := Normalize(r); err != nil || calls != 1 {
			t.Fatalf("raw=%s err=%v calls=%d", raw, err, calls)
		}
	}
}
