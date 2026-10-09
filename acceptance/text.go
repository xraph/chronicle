package acceptance

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	jsonMarshalerType = reflect.TypeFor[json.Marshaler]()
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
)

func validText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }

// validateMetadataText runs before encoding/json can replace invalid Go strings.
// MarshalJSON owns its representation, which is checked in validateJSONText after
// its single invocation. TextMarshaler cannot expose its bytes at that boundary.
func validateMetadataText(v reflect.Value, depth int) error {
	if depth > 64 {
		return fmt.Errorf("metadata nesting exceeds 64")
	}
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		return validateMetadataText(v.Elem(), depth)
	}
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil
	}
	if implements(v, jsonMarshalerType) {
		return nil
	}
	if implements(v, textMarshalerType) {
		return fmt.Errorf("TextMarshaler-only metadata is unsupported; use JSON values or MarshalJSON")
	}
	switch v.Kind() {
	case reflect.String:
		if !validText(v.String()) {
			return fmt.Errorf("invalid metadata text")
		}
	case reflect.Pointer:
		return validateMetadataText(v.Elem(), depth+1)
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			key := iter.Key()
			// Map keys use strings first, then MarshalText, never MarshalJSON.
			if key.Type().Implements(textMarshalerType) {
				return fmt.Errorf("TextMarshaler metadata keys are unsupported; use string keys")
			}
			if key.Kind() == reflect.String && !validText(key.String()) {
				return fmt.Errorf("invalid metadata key")
			}
			if err := validateMetadataText(iter.Value(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		// encoding/json treats []byte as binary, unless an element has an encoder.
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 && !reflect.PointerTo(v.Type().Elem()).Implements(jsonMarshalerType) && !reflect.PointerTo(v.Type().Elem()).Implements(textMarshalerType) {
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := validateMetadataText(v.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if (!field.IsExported() && !field.Anonymous) || field.Tag.Get("json") == "-" {
				continue
			}
			if err := validateMetadataText(v.Field(i), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func implements(v reflect.Value, typ reflect.Type) bool {
	return v.Type().Implements(typ) || (v.CanAddr() && v.Addr().Type().Implements(typ))
}

// validateJSONText checks raw custom encodings before the decoder can replace
// invalid UTF-8 or unpaired UTF-16 escapes. NUL is not representable in jsonb.
func validateJSONText(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("invalid JSON UTF-8")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		r, err := jsonEscape(raw, i)
		if err != nil {
			return err
		}
		i += 4
		switch {
		case r == 0:
			return fmt.Errorf("JSON NUL is unsupported")
		case r >= 0xdc00 && r <= 0xdfff:
			return fmt.Errorf("unpaired JSON surrogate")
		case r >= 0xd800 && r <= 0xdbff:
			if i+2 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return fmt.Errorf("unpaired JSON surrogate")
			}
			low, err := jsonEscape(raw, i+2)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return fmt.Errorf("unpaired JSON surrogate")
			}
			i += 6
		}
	}
	return nil
}

func jsonEscape(raw []byte, u int) (uint64, error) {
	if u+5 > len(raw) {
		return 0, fmt.Errorf("short JSON escape")
	}
	return strconv.ParseUint(string(raw[u+1:u+5]), 16, 16)
}
