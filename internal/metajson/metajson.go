// Package metajson decodes stored event metadata without losing numbers.
//
// The event digest covers the JSON encoding of Metadata, so whatever a store
// reads back has to encode to the same bytes Record hashed. encoding/json turns
// every number into float64 by default, and float64 holds integers exactly only
// up to 2^53. Past that, 9007199254740993 comes back as 9007199254740992 and
// the event fails verification the moment it is read.
//
// Decoding with UseNumber alone is not the answer either. PostgreSQL's jsonb
// rewrites numbers on the way in (1e-07 is returned as 0.0000001), and those
// only round-trip today because float64 formats them back the way Go first
// wrote them. So a number stays float64 whenever float64 holds it exactly,
// which also keeps the type callers already get for small values, and only an
// integer float64 would round becomes int64 or uint64.
package metajson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
)

// Decode parses a JSON object into metadata. Empty input and JSON null both
// decode to a nil map.
func Decode(data []byte) (map[string]any, error) {
	m, err := DecodeExact(data)
	if err != nil {
		return nil, err
	}

	for k, v := range m {
		m[k] = normalize(v)
	}
	return m, nil
}

// DecodeExact retains every JSON number without floating point conversion.
// Reliable ingestion normalizes number spelling before hashing; encrypted
// payloads and archive restores keep that exact representation.
func DecodeExact(data []byte) (map[string]any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	// json.Unmarshal rejects trailing data and the decoder does not, so ask.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("metajson: unexpected data after metadata object")
	}

	return m, nil
}

// Map is metadata that decodes through Decode. Stores use it as the model
// field type where a driver or encoding/json does the unmarshalling for them.
type Map map[string]any

// UnmarshalJSON implements json.Unmarshaler.
func (m *Map) UnmarshalJSON(data []byte) error {
	decoded, err := Decode(data)
	if err != nil {
		return err
	}
	*m = decoded
	return nil
}

// Scan implements sql.Scanner, for drivers that hand over the raw column.
func (m *Map) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*m = nil
		return nil
	case []byte:
		return m.UnmarshalJSON(v)
	case string:
		return m.UnmarshalJSON([]byte(v))
	default:
		return errors.New("metajson: cannot scan metadata from a non-text column")
	}
}

func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = normalize(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = normalize(e)
		}
		return x
	case json.Number:
		return number(x)
	default:
		return v
	}
}

// maxExact is 2^53. Every integer of at most this magnitude is exact in float64.
const maxExact = 1 << 53

func number(n json.Number) any {
	s := string(n)

	// Only a plain integer literal can be one float64 would round. A literal
	// with a fraction or exponent came from a float (Go writes integers
	// without either), so float64 is what it was.
	// Anything inside ±2^53 falls through to Float64 below, which also keeps
	// "-0" negative.
	if !strings.ContainsAny(s, ".eE") {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			if i > maxExact || i < -maxExact {
				return i
			}
		} else if u, err := strconv.ParseUint(s, 10, 64); err == nil {
			return u
		}
		// Too wide for any Go integer, so it was a float64 Go chose to write
		// in full (it does up to 1e21). float64 formats it back the same way.
	}

	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) {
		// Nothing Go encodes lands here. Keep the literal rather than guess.
		return n
	}
	return f
}
