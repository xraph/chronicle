package redis

import (
	"strings"
	"testing"
)

// Different tuples must render differently: the ones a bare ":" join rendered
// the same, and ones built to look like this encoding from the inside.
func TestScopeSuffixSeparatesDistinctTuples(t *testing.T) {
	for _, tc := range []struct {
		name         string
		a, b         []string
		oldJoinClash bool // the pre-v2 key format gave both the same key
	}{
		{"separator moves between app and tenant", []string{"a:b", "c"}, []string{"a", "b:c"}, true},
		{"separator moves into category", []string{"a", "b:c", "d"}, []string{"a", "b", "c:d"}, true},
		{"encoded shape inside a value", []string{"1:a|1:b", ""}, []string{"1:a", "1:b|0:"}, false},
		{"empty parts", []string{"", "x"}, []string{"x", ""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if clash := strings.Join(tc.a, ":") == strings.Join(tc.b, ":"); clash != tc.oldJoinClash {
				t.Fatalf("old join clash = %v, case says %v", clash, tc.oldJoinClash)
			}
			if got, other := scopeSuffix(tc.a...), scopeSuffix(tc.b...); got == other {
				t.Errorf("scopeSuffix(%q) == scopeSuffix(%q) == %q", tc.a, tc.b, got)
			}
		})
	}
}

// Migrate deletes old keys with SCAN MATCH legacy+"*". If a v2 key started with
// a legacy prefix, that delete would take the new index with it.
func TestV2ScopeKeysAreOutsideLegacyPrefixes(t *testing.T) {
	v2 := []string{
		streamScopeKey("a", "b"),
		eventScopeKey("a", "b"),
		policyScopeKey("a", "b", "c"),
	}
	for _, key := range v2 {
		for _, legacy := range []string{legacyStreamScope, legacyEventScope, legacyPolicyScope} {
			if strings.HasPrefix(key, legacy) {
				t.Errorf("v2 key %q is under legacy prefix %q", key, legacy)
			}
		}
	}
}
