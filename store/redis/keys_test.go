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
	s := &Store{prefix: DefaultKeyPrefix}
	v2 := []string{
		s.streamScopeKey("a", "b"),
		s.eventScopeKey("a", "b"),
		s.policyScopeKey("a", "b", "c"),
	}
	for _, key := range v2 {
		for _, legacy := range []string{s.key(legacyStreamScope), s.key(legacyEventScope), s.key(legacyPolicyScope)} {
			if strings.HasPrefix(key, legacy) {
				t.Errorf("v2 key %q is under legacy prefix %q", key, legacy)
			}
		}
	}
}

// Data written before WithKeyPrefix existed has to stay where the store looks
// for it. A change to the default layout orphans every key already in redis.
func TestDefaultKeyLayoutIsUnchanged(t *testing.T) {
	s := &Store{prefix: DefaultKeyPrefix}
	for got, want := range map[string]string{
		entityKey(s.key(prefixEvent), "e1"):  "chronicle:evt:e1",
		entityKey(s.key(prefixStream), "s1"): "chronicle:str:s1",
		s.key(zEventAll):                     "chronicle:z:evt:all",
		s.key(zEventApp) + "app":             "chronicle:z:evt:app:app",
		s.eventScopeKey("a", "t"):            "chronicle:z:evt:scopev2:1:a|1:t",
		s.streamScopeKey("a", "t"):           "chronicle:u:str:scopev2:1:a|1:t",
		s.policyScopeKey("a", "t", "c"):      "chronicle:u:pol:scopev2:1:a|1:t|1:c",
		s.key(legacyEventScope):              "chronicle:z:evt:scope:",
		s.key(scopeKeyFormatMarker):          "chronicle:meta:scope-key-format",
	} {
		if got != want {
			t.Errorf("key = %q, want %q", got, want)
		}
	}
}

// WithKeyPrefix moves every key, including the ones built from scope parts.
func TestKeyPrefixAppliesToEveryKey(t *testing.T) {
	s := &Store{prefix: "tenant-a:"}
	for _, key := range []string{
		s.key(zEventAll),
		s.eventScopeKey("a", "t"),
		s.streamScopeKey("a", "t"),
		s.policyScopeKey("a", "t", "c"),
		s.key(scopeCollisionsKey),
	} {
		if !strings.HasPrefix(key, "tenant-a:") || strings.HasPrefix(key, DefaultKeyPrefix) {
			t.Errorf("key %q is not under the configured prefix", key)
		}
	}
}

// A prefix is matched literally when Migrate scans for it, so one holding a
// glob character cannot reach another store's keys.
func TestGlobEscapeMatchesOnlyTheLiteralPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"chronicle:":  "chronicle:",
		"t[1]:":       `t\[1\]:`,
		"a*b?:":       `a\*b\?:`,
		`back\slash:`: `back\\slash:`,
	} {
		if got := globEscape(in); got != want {
			t.Errorf("globEscape(%q) = %q, want %q", in, got, want)
		}
	}
}
