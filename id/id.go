// Package id defines type-safe, K-sortable entity IDs for Chronicle.
// All IDs use TypeID (go.jetify.com/typeid) with entity-specific prefixes.
// A single ID struct is used for all entity types with convenience constructors
// and parsers per entity type.
package id

import (
	"database/sql/driver"
	"fmt"

	"go.jetify.com/typeid"
)

// Prefix defines the entity type prefix for a TypeID.
type Prefix string

// Known prefixes for Chronicle entities.
const (
	PrefixAudit   Prefix = "audit"
	PrefixStream  Prefix = "stream"
	PrefixErasure Prefix = "erasure"
	PrefixReport  Prefix = "report"
	PrefixPolicy  Prefix = "retpol"
	PrefixArchive Prefix = "archive"
	PrefixPlugin  Prefix = "plugin"
)

// ID is a type-safe, K-sortable identifier for any Chronicle entity.
// It wraps a typeid.AnyID with a known prefix. The zero value is a nil/invalid ID.
type ID struct {
	inner typeid.AnyID
	valid bool
}

// New creates a new unique ID with the given prefix.
func New(prefix Prefix) ID {
	tid, err := typeid.WithPrefix(string(prefix))
	if err != nil {
		panic(fmt.Sprintf("id: failed to create TypeID with prefix %q: %v", prefix, err))
	}
	return ID{inner: tid, valid: true}
}

// Parse parses a TypeID string (e.g. "audit_01h2xcejqtf2nbrexx3vqjhp41") into an ID.
// Returns an error if the string is not a valid TypeID.
func Parse(s string) (ID, error) {
	if s == "" {
		return ID{}, nil
	}
	tid, err := typeid.FromString(s)
	if err != nil {
		return ID{}, fmt.Errorf("id: parse %q: %w", s, err)
	}
	return ID{inner: tid, valid: true}, nil
}

// ParseWithPrefix parses a TypeID string and validates that its prefix matches the expected prefix.
func ParseWithPrefix(s string, expected Prefix) (ID, error) {
	parsed, err := Parse(s)
	if err != nil {
		return ID{}, err
	}
	if !parsed.valid {
		return ID{}, fmt.Errorf("id: empty id for prefix %q", expected)
	}
	if Prefix(parsed.inner.Prefix()) != expected {
		return ID{}, fmt.Errorf("id: expected prefix %q, got %q", expected, parsed.inner.Prefix())
	}
	return parsed, nil
}

// String returns the TypeID string representation (e.g. "audit_01h2xcejqtf2nbrexx3vqjhp41").
// Returns an empty string for a nil/invalid ID.
func (i ID) String() string {
	if !i.valid {
		return ""
	}
	return i.inner.String()
}

// IDPrefix returns the entity type prefix of this ID.
func (i ID) IDPrefix() Prefix {
	if !i.valid {
		return ""
	}
	return Prefix(i.inner.Prefix())
}

// IsNil returns true if this ID is the zero value (not set).
func (i ID) IsNil() bool {
	return !i.valid
}

// MarshalText implements encoding.TextMarshaler.
func (i ID) MarshalText() ([]byte, error) {
	return []byte(i.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (i *ID) UnmarshalText(data []byte) error {
	s := string(data)
	if s == "" {
		*i = ID{}
		return nil
	}
	parsed, err := Parse(s)
	if err != nil {
		return err
	}
	*i = parsed
	return nil
}

// Value implements driver.Valuer for database storage.
func (i ID) Value() (driver.Value, error) {
	if !i.valid {
		return nil, nil
	}
	return i.String(), nil
}

// Scan implements sql.Scanner for database retrieval.
func (i *ID) Scan(src any) error {
	if src == nil {
		*i = ID{}
		return nil
	}
	switch v := src.(type) {
	case string:
		parsed, err := Parse(v)
		if err != nil {
			return err
		}
		*i = parsed
	case []byte:
		parsed, err := Parse(string(v))
		if err != nil {
			return err
		}
		*i = parsed
	default:
		return fmt.Errorf("id: unsupported scan source type %T", src)
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (i ID) MarshalJSON() ([]byte, error) {
	if !i.valid {
		return []byte(`""`), nil
	}
	return []byte(`"` + i.String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (i *ID) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "null" || s == `""` {
		*i = ID{}
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return i.UnmarshalText([]byte(s))
}

// ──────────────────────────────────────────────────
// Convenience constructors
// ──────────────────────────────────────────────────

// NewAuditID creates a new unique audit event ID.
func NewAuditID() ID { return New(PrefixAudit) }

// NewStreamID creates a new unique stream ID.
func NewStreamID() ID { return New(PrefixStream) }

// NewErasureID creates a new unique erasure ID.
func NewErasureID() ID { return New(PrefixErasure) }

// NewReportID creates a new unique report ID.
func NewReportID() ID { return New(PrefixReport) }

// NewPolicyID creates a new unique retention policy ID.
func NewPolicyID() ID { return New(PrefixPolicy) }

// NewArchiveID creates a new unique archive ID.
func NewArchiveID() ID { return New(PrefixArchive) }

// ──────────────────────────────────────────────────
// Convenience parsers (type-safe: ParseAuditID("stream_01h...") fails)
// ──────────────────────────────────────────────────

// ParseAuditID parses a string into an audit ID, returning an error if the prefix doesn't match.
func ParseAuditID(s string) (ID, error) { return ParseWithPrefix(s, PrefixAudit) }

// ParseStreamID parses a string into a stream ID.
func ParseStreamID(s string) (ID, error) { return ParseWithPrefix(s, PrefixStream) }

// ParseErasureID parses a string into an erasure ID.
func ParseErasureID(s string) (ID, error) { return ParseWithPrefix(s, PrefixErasure) }

// ParseReportID parses a string into a report ID.
func ParseReportID(s string) (ID, error) { return ParseWithPrefix(s, PrefixReport) }

// ParsePolicyID parses a string into a retention policy ID.
func ParsePolicyID(s string) (ID, error) { return ParseWithPrefix(s, PrefixPolicy) }

// ParseArchiveID parses a string into an archive ID.
func ParseArchiveID(s string) (ID, error) { return ParseWithPrefix(s, PrefixArchive) }

// ParseAny parses a TypeID string with any prefix.
func ParseAny(s string) (ID, error) { return Parse(s) }
