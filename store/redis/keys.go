package redis

import (
	"strconv"
	"strings"
)

// DefaultKeyPrefix is what every key starts with unless New is given
// WithKeyPrefix. The names below are relative to it: with the default, the
// event index zEventAll is the key "chronicle:z:evt:all".
const DefaultKeyPrefix = "chronicle:"

// key puts the store's prefix in front of one of the names below.
func (s *Store) key(name string) string {
	return s.prefix + name
}

// Key prefixes for primary entity storage.
const (
	prefixEvent   = "evt:"
	prefixStream  = "str:"
	prefixErasure = "era:"
	prefixPolicy  = "pol:"
	prefixArchive = "arc:"
	prefixReport  = "rpt:"
)

// Key prefixes for sorted set indexes.
//
// A key that appends one caller-supplied value to a prefix of its own (app,
// category, user, subject) needs no encoding: the prefix names the index and
// the whole remainder is the value. Only a key built from two or more values
// has boundaries to get wrong, and those go through scopeSuffix.
const (
	// Events
	zEventAll      = "z:evt:all"
	zEventStream   = "z:evt:stream:"   // + stream ID
	zEventScope    = "z:evt:scopev2:"  // + scopeSuffix(appID, tenantID)
	zEventApp      = "z:evt:app:"      // + appID
	zEventCategory = "z:evt:category:" // + category
	zEventUser     = "z:evt:user:"     // + user ID
	zEventSubject  = "z:evt:subject:"  // + subject ID

	// Streams
	zStreamAll = "z:str:all"

	// Erasures
	zErasureAll = "z:era:all"

	// Policies
	zPolicyAll = "z:pol:all"

	// Archives
	zArchiveAll = "z:arc:all"

	// Reports
	zReportAll = "z:rpt:all"
)

// Key prefixes for unique indexes.
const (
	uniqueStreamScope = "u:str:scopev2:" // + scopeSuffix(appID, tenantID)
	// uniquePolicyScope keys a policy by its owner, not by category alone: a
	// category-only key let one app evict another app's policy.
	uniquePolicyScope = "u:pol:scopev2:" // + scopeSuffix(appID, tenantID, category)
)

// Scope keys written before scopeSuffix existed. They joined the parts with a
// bare ":", so app "a:b" with tenant "c" and app "a" with tenant "b:c" shared
// one key. Only Migrate reads them, to rebuild the v2 indexes and then delete
// them.
//
// The v2 prefixes differ from these at the character after "scope", so a SCAN
// for legacy+"*" never matches a v2 key. They could not share a prefix: an old
// key's suffix is arbitrary text, so every v2 suffix is also a valid old one.
const (
	legacyEventScope  = "z:evt:scope:"
	legacyStreamScope = "u:str:scope:"
	legacyPolicyScope = "u:pol:scope:"
)

// Keys Migrate keeps its own state in.
const (
	// scopeKeyFormatMarker exists once every scope index is in the v2 format.
	// GetStreamByScope will not report a miss until it does.
	scopeKeyFormatMarker = "meta:scope-key-format"

	// scopeCollisionsKey is a set of the stream IDs Migrate found holding
	// events from more than one scope. See ErrScopeCollision.
	scopeCollisionsKey = "meta:scope-collisions"
)

// scopeSuffix renders caller-supplied scope parts as one key suffix: each part
// as "<byte-length>:<value>", joined with "|". AppID, TenantID and Category are
// free text, so with a bare join a separator inside one value moves the
// boundary between two. The length pins where each part ends, so two different
// tuples of the same arity never render the same. checkpoint.CanonicalPayload
// encodes its scope fields this way for the same reason.
func scopeSuffix(parts ...string) string {
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	return b.String()
}

// streamScopeKey is the unique index from an app+tenant scope to its stream.
func (s *Store) streamScopeKey(appID, tenantID string) string {
	return s.key(uniqueStreamScope) + scopeSuffix(appID, tenantID)
}

// eventScopeKey is the sorted set holding an app+tenant scope's events.
func (s *Store) eventScopeKey(appID, tenantID string) string {
	return s.key(zEventScope) + scopeSuffix(appID, tenantID)
}

// policyScopeKey is the unique index from (app, tenant, category) to the policy
// that scope holds for that category.
func (s *Store) policyScopeKey(appID, tenantID, category string) string {
	return s.key(uniquePolicyScope) + scopeSuffix(appID, tenantID, category)
}

// entityKey returns the primary key for an entity.
func entityKey(prefix, id string) string {
	return prefix + id
}
