package acceptance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func normalizeMetadata(raw []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	budget := 1048576
	v, err := decodeValue(d, 0, &budget)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing JSON")
	}
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metadata must be an object")
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

func decodeValue(d *json.Decoder, depth int, budget *int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("JSON nesting exceeds 64")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := t.(type) {
	case json.Number:
		number, numberErr := decimal(v.String())
		*budget -= len(number)
		if *budget < 0 {
			return nil, fmt.Errorf("expanded JSON numbers exceed limit")
		}
		return number, numberErr
	case json.Delim:
		switch v {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if !ok {
					return nil, fmt.Errorf("invalid object key")
				}
				if _, ok = m[key]; ok {
					return nil, fmt.Errorf("duplicate JSON key")
				}
				value, e := decodeValue(d, depth+1, budget)
				if e != nil {
					return nil, e
				}
				m[key] = value
			}
			_, err = d.Token()
			return m, err
		case '[':
			a := []any{}
			for d.More() {
				v, e := decodeValue(d, depth+1, budget)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, err = d.Token()
			return a, err
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter")
		}
	default:
		return v, nil
	}
}

// decimal emits bounded fixed-point JSON so PostgreSQL jsonb preserves the
// exact bytes hashed by the chain, including integers above 2^53.
func decimal(s string) (json.Number, error) {
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	exponent := 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil || n > 4096 || n < -4096 {
			return "", fmt.Errorf("JSON exponent out of range")
		}
		exponent = n
		s = s[:i]
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		exponent -= len(s) - i - 1
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0", nil
	}
	for strings.HasSuffix(s, "0") {
		s = strings.TrimSuffix(s, "0")
		exponent++
	}
	if len(s)+exponent > 4096 || exponent < -4096 {
		return "", fmt.Errorf("JSON number out of range")
	}
	if exponent >= 0 {
		s += strings.Repeat("0", exponent)
	} else {
		pos := len(s) + exponent
		if pos > 0 {
			s = s[:pos] + "." + s[pos:]
		} else {
			s = "0." + strings.Repeat("0", -pos) + s
		}
	}
	if negative {
		s = "-" + s
	}
	return json.Number(s), nil
}
