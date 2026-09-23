package crypto

import (
	"strconv"
	"strings"
)

// scopedKeyIDPrefix leads every scoped key ID. The version lets the encoding
// change later without misreading IDs already recorded on events.
const scopedKeyIDPrefix = "ck1|"

// ScopedKeyID returns the key store identifier for a subject's key within one
// app and tenant. [Sealer.Seal] asks the key store for this ID and records it
// in Event.EncryptionKeyID, and erasure destroys it.
//
// The scope is part of the identity because subject IDs are not unique across
// apps and tenants. "user-42" in one tenant is usually a different person from
// "user-42" in the next, and when the key was addressed by subject alone,
// erasing one of them destroyed the other's data too.
//
// Each field is length-prefixed ("<byte-length>:<value>"), the same way
// checkpoint.CanonicalPayload renders its fields. AppID and TenantID are free
// text, so a bare join lets a separator inside one value move the boundary:
// joined with ":", app "a:b" with tenant "c" and app "a" with tenant "b:c"
// would name the same key. With a length in front of each field, a reader finds
// where it ends without trusting what is inside it.
//
// The result contains ":" and "|" and whatever bytes the IDs themselves hold.
// A key store that maps IDs onto paths or resource names has to escape or hash
// them, and treat the ID as opaque.
func ScopedKeyID(appID, tenantID, subjectID string) string {
	var b strings.Builder
	b.Grow(len(scopedKeyIDPrefix) + len(appID) + len(tenantID) + len(subjectID) + 16)
	b.WriteString(scopedKeyIDPrefix)
	writeLengthPrefixed(&b, appID)
	b.WriteByte('|')
	writeLengthPrefixed(&b, tenantID)
	b.WriteByte('|')
	writeLengthPrefixed(&b, subjectID)
	return b.String()
}

// ParseScopedKeyID reverses [ScopedKeyID]. ok is false for any string
// ScopedKeyID could not have produced, which includes every legacy key ID: the
// bare subject IDs that events were sealed under before keys were scoped.
func ParseScopedKeyID(keyID string) (appID, tenantID, subjectID string, ok bool) {
	rest, found := strings.CutPrefix(keyID, scopedKeyIDPrefix)
	if !found {
		return "", "", "", false
	}

	var fields [3]string
	for i := range fields {
		if i > 0 {
			if rest, found = strings.CutPrefix(rest, "|"); !found {
				return "", "", "", false
			}
		}
		if fields[i], rest, found = readLengthPrefixed(rest); !found {
			return "", "", "", false
		}
	}
	if rest != "" {
		return "", "", "", false
	}

	// Only the canonical spelling counts, so "03:abc" is not a second name for
	// "3:abc". Without this, one key could be reached through two IDs.
	if ScopedKeyID(fields[0], fields[1], fields[2]) != keyID {
		return "", "", "", false
	}
	return fields[0], fields[1], fields[2], true
}

func writeLengthPrefixed(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
}

// readLengthPrefixed takes one "<byte-length>:<value>" field off the front of s.
func readLengthPrefixed(s string) (value, rest string, ok bool) {
	lenText, after, found := strings.Cut(s, ":")
	if !found || lenText == "" {
		return "", "", false
	}
	n, err := strconv.Atoi(lenText)
	if err != nil || n < 0 || n > len(after) {
		return "", "", false
	}
	return after[:n], after[n:], true
}
