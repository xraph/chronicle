package id_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xraph/chronicle/id"
)

// ──────────────────────────────────────────────────
// New
// ──────────────────────────────────────────────────

func TestNew_IsValid(t *testing.T) {
	got := id.New(id.PrefixAudit)
	if got.IsNil() {
		t.Error("New() returned a nil ID")
	}
}

func TestNew_HasCorrectPrefix(t *testing.T) {
	got := id.New(id.PrefixStream)
	if got.IDPrefix() != id.PrefixStream {
		t.Errorf("IDPrefix() = %q, want %q", got.IDPrefix(), id.PrefixStream)
	}
}

func TestNew_StringContainsPrefix(t *testing.T) {
	got := id.New(id.PrefixAudit)
	s := got.String()
	if !strings.HasPrefix(s, "audit_") {
		t.Errorf("String() = %q, expected prefix %q", s, "audit_")
	}
}

func TestNew_Uniqueness(t *testing.T) {
	a := id.New(id.PrefixAudit)
	b := id.New(id.PrefixAudit)
	if a.String() == b.String() {
		t.Error("two consecutive New() calls produced the same ID")
	}
}

func TestNew_KSortable(t *testing.T) {
	a := id.New(id.PrefixAudit)
	b := id.New(id.PrefixAudit)
	// K-sortable: string of a should sort before string of b.
	if a.String() >= b.String() {
		t.Errorf("IDs are not K-sortable: %q >= %q", a.String(), b.String())
	}
}

// ──────────────────────────────────────────────────
// Parse
// ──────────────────────────────────────────────────

func TestParse_EmptyString(t *testing.T) {
	got, err := id.Parse("")
	if err != nil {
		t.Fatalf("Parse(\"\") returned unexpected error: %v", err)
	}
	if !got.IsNil() {
		t.Error("Parse(\"\") should return a nil ID")
	}
}

func TestParse_ValidString(t *testing.T) {
	original := id.New(id.PrefixReport)
	s := original.String()

	got, err := id.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	if got.String() != s {
		t.Errorf("Parse() roundtrip: got %q, want %q", got.String(), s)
	}
}

func TestParse_InvalidString(t *testing.T) {
	_, err := id.Parse("not-a-valid-typeid!!!")
	if err == nil {
		t.Error("Parse(invalid) expected error, got nil")
	}
}

// ──────────────────────────────────────────────────
// ParseWithPrefix
// ──────────────────────────────────────────────────

func TestParseWithPrefix_Correct(t *testing.T) {
	original := id.New(id.PrefixErasure)
	got, err := id.ParseWithPrefix(original.String(), id.PrefixErasure)
	if err != nil {
		t.Fatalf("ParseWithPrefix: %v", err)
	}
	if got.String() != original.String() {
		t.Errorf("got %q, want %q", got.String(), original.String())
	}
}

func TestParseWithPrefix_WrongPrefix(t *testing.T) {
	auditID := id.New(id.PrefixAudit)
	_, err := id.ParseWithPrefix(auditID.String(), id.PrefixStream)
	if err == nil {
		t.Error("ParseWithPrefix with wrong prefix should fail")
	}
}

func TestParseWithPrefix_EmptyString(t *testing.T) {
	_, err := id.ParseWithPrefix("", id.PrefixAudit)
	if err == nil {
		t.Error("ParseWithPrefix(\"\", ...) should return error")
	}
}

func TestParseWithPrefix_InvalidString(t *testing.T) {
	_, err := id.ParseWithPrefix("garbage", id.PrefixAudit)
	if err == nil {
		t.Error("ParseWithPrefix(invalid, ...) should return error")
	}
}

// ──────────────────────────────────────────────────
// ID methods
// ──────────────────────────────────────────────────

func TestID_String_NilReturnsEmpty(t *testing.T) {
	var zero id.ID
	if zero.String() != "" {
		t.Errorf("zero ID String() = %q, want %q", zero.String(), "")
	}
}

func TestID_IDPrefix_NilReturnsEmpty(t *testing.T) {
	var zero id.ID
	if zero.IDPrefix() != "" {
		t.Errorf("zero ID IDPrefix() = %q, want empty", zero.IDPrefix())
	}
}

func TestID_IsNil_ZeroValue(t *testing.T) {
	var zero id.ID
	if !zero.IsNil() {
		t.Error("zero value ID should be nil")
	}
}

func TestID_IsNil_ValidID(t *testing.T) {
	got := id.New(id.PrefixPolicy)
	if got.IsNil() {
		t.Error("New() ID should not be nil")
	}
}

// ──────────────────────────────────────────────────
// MarshalText / UnmarshalText
// ──────────────────────────────────────────────────

func TestMarshalText_ValidID(t *testing.T) {
	original := id.New(id.PrefixAudit)
	b, err := original.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(b) != original.String() {
		t.Errorf("MarshalText = %q, want %q", b, original.String())
	}
}

func TestMarshalText_NilID(t *testing.T) {
	var zero id.ID
	b, err := zero.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText nil: %v", err)
	}
	if string(b) != "" {
		t.Errorf("MarshalText nil = %q, want empty", b)
	}
}

func TestUnmarshalText_RoundTrip(t *testing.T) {
	original := id.New(id.PrefixStream)
	b, _ := original.MarshalText()

	var got id.ID
	if err := got.UnmarshalText(b); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if got.String() != original.String() {
		t.Errorf("UnmarshalText roundtrip: got %q, want %q", got.String(), original.String())
	}
}

func TestUnmarshalText_EmptyBytes(t *testing.T) {
	var got id.ID
	if err := got.UnmarshalText([]byte("")); err != nil {
		t.Fatalf("UnmarshalText empty: %v", err)
	}
	if !got.IsNil() {
		t.Error("UnmarshalText empty should yield nil ID")
	}
}

func TestUnmarshalText_InvalidBytes(t *testing.T) {
	var got id.ID
	if err := got.UnmarshalText([]byte("bad!data")); err == nil {
		t.Error("UnmarshalText invalid should return error")
	}
}

// ──────────────────────────────────────────────────
// MarshalJSON / UnmarshalJSON
// ──────────────────────────────────────────────────

func TestMarshalJSON_ValidID(t *testing.T) {
	original := id.New(id.PrefixAudit)
	b, err := original.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	want := `"` + original.String() + `"`
	if string(b) != want {
		t.Errorf("MarshalJSON = %s, want %s", b, want)
	}
}

func TestMarshalJSON_NilID(t *testing.T) {
	var zero id.ID
	b, err := zero.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON nil: %v", err)
	}
	if string(b) != `""` {
		t.Errorf("MarshalJSON nil = %s, want %q", b, `""`)
	}
}

func TestUnmarshalJSON_RoundTrip(t *testing.T) {
	original := id.New(id.PrefixReport)
	b, _ := original.MarshalJSON()

	var got id.ID
	if err := got.UnmarshalJSON(b); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if got.String() != original.String() {
		t.Errorf("UnmarshalJSON roundtrip: got %q, want %q", got.String(), original.String())
	}
}

func TestUnmarshalJSON_Null(t *testing.T) {
	var got id.ID
	if err := got.UnmarshalJSON([]byte("null")); err != nil {
		t.Fatalf("UnmarshalJSON null: %v", err)
	}
	if !got.IsNil() {
		t.Error("UnmarshalJSON null should yield nil ID")
	}
}

func TestUnmarshalJSON_EmptyString(t *testing.T) {
	var got id.ID
	if err := got.UnmarshalJSON([]byte(`""`)); err != nil {
		t.Fatalf("UnmarshalJSON empty string: %v", err)
	}
	if !got.IsNil() {
		t.Error(`UnmarshalJSON "" should yield nil ID`)
	}
}

func TestUnmarshalJSON_Invalid(t *testing.T) {
	var got id.ID
	if err := got.UnmarshalJSON([]byte(`"not_valid!!!"`)); err == nil {
		t.Error("UnmarshalJSON invalid should return error")
	}
}

func TestJSONMarshalUnmarshal_InStruct(t *testing.T) {
	type record struct {
		ID id.ID `json:"id"`
	}

	original := record{ID: id.New(id.PrefixArchive)}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got record
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got.ID.String() != original.ID.String() {
		t.Errorf("struct JSON roundtrip: got %q, want %q", got.ID.String(), original.ID.String())
	}
}

// ──────────────────────────────────────────────────
// Value / Scan (database/sql)
// ──────────────────────────────────────────────────

func TestValue_ValidID(t *testing.T) {
	original := id.New(id.PrefixAudit)
	v, err := original.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if v != original.String() {
		t.Errorf("Value() = %v, want %q", v, original.String())
	}
}

func TestValue_NilID(t *testing.T) {
	var zero id.ID
	v, err := zero.Value()
	if err != nil {
		t.Fatalf("Value nil: %v", err)
	}
	if v != nil {
		t.Errorf("Value nil = %v, want nil", v)
	}
}

func TestScan_String(t *testing.T) {
	original := id.New(id.PrefixStream)
	var got id.ID
	if err := got.Scan(original.String()); err != nil {
		t.Fatalf("Scan string: %v", err)
	}
	if got.String() != original.String() {
		t.Errorf("Scan string: got %q, want %q", got.String(), original.String())
	}
}

func TestScan_Bytes(t *testing.T) {
	original := id.New(id.PrefixErasure)
	var got id.ID
	if err := got.Scan([]byte(original.String())); err != nil {
		t.Fatalf("Scan []byte: %v", err)
	}
	if got.String() != original.String() {
		t.Errorf("Scan []byte: got %q, want %q", got.String(), original.String())
	}
}

func TestScan_Nil(t *testing.T) {
	var got id.ID
	if err := got.Scan(nil); err != nil {
		t.Fatalf("Scan nil: %v", err)
	}
	if !got.IsNil() {
		t.Error("Scan nil should yield nil ID")
	}
}

func TestScan_UnsupportedType(t *testing.T) {
	var got id.ID
	if err := got.Scan(12345); err == nil {
		t.Error("Scan unsupported type should return error")
	}
}

func TestScan_InvalidString(t *testing.T) {
	var got id.ID
	if err := got.Scan("not-valid!!!"); err == nil {
		t.Error("Scan invalid string should return error")
	}
}

func TestValue_Scan_RoundTrip(t *testing.T) {
	original := id.New(id.PrefixPolicy)
	v, err := original.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}

	var got id.ID
	if err := got.Scan(v); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.String() != original.String() {
		t.Errorf("Value/Scan roundtrip: got %q, want %q", got.String(), original.String())
	}
}

// ──────────────────────────────────────────────────
// Convenience constructors
// ──────────────────────────────────────────────────

func TestConvenienceConstructors(t *testing.T) {
	tests := []struct {
		name   string
		fn     func() id.ID
		prefix id.Prefix
	}{
		{"NewAuditID", id.NewAuditID, id.PrefixAudit},
		{"NewStreamID", id.NewStreamID, id.PrefixStream},
		{"NewErasureID", id.NewErasureID, id.PrefixErasure},
		{"NewReportID", id.NewReportID, id.PrefixReport},
		{"NewPolicyID", id.NewPolicyID, id.PrefixPolicy},
		{"NewArchiveID", id.NewArchiveID, id.PrefixArchive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn()
			if got.IsNil() {
				t.Errorf("%s() returned nil ID", tt.name)
			}
			if got.IDPrefix() != tt.prefix {
				t.Errorf("%s() prefix = %q, want %q", tt.name, got.IDPrefix(), tt.prefix)
			}
		})
	}
}

// ──────────────────────────────────────────────────
// Convenience parsers
// ──────────────────────────────────────────────────

func TestConvenienceParsers_Valid(t *testing.T) {
	tests := []struct {
		name string
		id   id.ID
		fn   func(string) (id.ID, error)
	}{
		{"ParseAuditID", id.NewAuditID(), id.ParseAuditID},
		{"ParseStreamID", id.NewStreamID(), id.ParseStreamID},
		{"ParseErasureID", id.NewErasureID(), id.ParseErasureID},
		{"ParseReportID", id.NewReportID(), id.ParseReportID},
		{"ParsePolicyID", id.NewPolicyID(), id.ParsePolicyID},
		{"ParseArchiveID", id.NewArchiveID(), id.ParseArchiveID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fn(tt.id.String())
			if err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			if got.String() != tt.id.String() {
				t.Errorf("%s: got %q, want %q", tt.name, got.String(), tt.id.String())
			}
		})
	}
}

func TestConvenienceParsers_WrongPrefix(t *testing.T) {
	auditID := id.NewAuditID()
	tests := []struct {
		name string
		fn   func(string) (id.ID, error)
	}{
		{"ParseStreamID", id.ParseStreamID},
		{"ParseErasureID", id.ParseErasureID},
		{"ParseReportID", id.ParseReportID},
		{"ParsePolicyID", id.ParsePolicyID},
		{"ParseArchiveID", id.ParseArchiveID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn(auditID.String())
			if err == nil {
				t.Errorf("%s with audit ID should fail", tt.name)
			}
		})
	}
}

// ──────────────────────────────────────────────────
// ParseAny
// ──────────────────────────────────────────────────

func TestParseAny_ValidID(t *testing.T) {
	original := id.New(id.PrefixAudit)
	got, err := id.ParseAny(original.String())
	if err != nil {
		t.Fatalf("ParseAny: %v", err)
	}
	if got.String() != original.String() {
		t.Errorf("ParseAny: got %q, want %q", got.String(), original.String())
	}
}

func TestParseAny_EmptyString(t *testing.T) {
	got, err := id.ParseAny("")
	if err != nil {
		t.Fatalf("ParseAny empty: %v", err)
	}
	if !got.IsNil() {
		t.Error("ParseAny empty should yield nil ID")
	}
}

func TestParseAny_AnyPrefix(t *testing.T) {
	prefixes := []id.Prefix{
		id.PrefixAudit, id.PrefixStream, id.PrefixErasure,
		id.PrefixReport, id.PrefixPolicy, id.PrefixArchive, id.PrefixPlugin,
	}
	for _, p := range prefixes {
		original := id.New(p)
		got, err := id.ParseAny(original.String())
		if err != nil {
			t.Errorf("ParseAny(%q): %v", p, err)
			continue
		}
		if got.IDPrefix() != p {
			t.Errorf("ParseAny(%q) prefix = %q", p, got.IDPrefix())
		}
	}
}
