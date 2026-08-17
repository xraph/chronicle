// Package hash provides SHA-256 hash chain computation for audit events.
package hash

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/xraph/chronicle/audit"
)

// versionTag prefixes the hashed content so the scheme a digest was produced
// under is unambiguous, and so a digest from one scheme can never collide with
// the other's.
const versionTag = "chronicle/v2"

// Chain computes SHA-256 hashes linking events into a tamper-evident chain.
type Chain struct{}

// Compute generates the SHA-256 hash for an event, linking it to the previous
// hash.
//
// The digest covers every field that carries accountability: who acted
// (UserID), from where (IP), under which tenant (AppID, TenantID), why
// (Reason), about whom (SubjectID), and the event's position in the stream
// (Sequence) — as well as what happened. An earlier scheme covered only
// timestamp, action, resource, category, resource ID, outcome, severity and
// metadata, which meant the actor and source address could be rewritten and the
// chain would still verify. See [ComputeLegacy].
//
// Content is versionTag|prevHash|sequence|timestamp|appID|tenantID|userID|ip|
// action|resource|category|resourceID|outcome|severity|reason|subjectID|
// metadata_json.
func (c *Chain) Compute(prevHash string, event *audit.Event) string {
	content := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		versionTag,
		prevHash,
		event.Sequence,
		event.Timestamp.UTC().Format(time.RFC3339Nano),
		event.AppID,
		event.TenantID,
		event.UserID,
		event.IP,
		event.Action,
		event.Resource,
		event.Category,
		event.ResourceID,
		event.Outcome,
		event.Severity,
		event.Reason,
		event.SubjectID,
		marshalMetadata(event.Metadata),
	)
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// ComputeLegacy reproduces the original hash scheme, which covered only
// timestamp, action, resource, category, resource ID, outcome, severity and
// metadata.
//
// It exists so events written before the coverage was extended still verify;
// without it, upgrading would report every historical event as tampered. Never
// use it to write a new hash.
//
// Falling back to it does not weaken current events: a digest written under the
// current scheme includes versionTag, so recomputing a tampered event under
// either scheme yields a different digest than the one stored.
func ComputeLegacy(prevHash string, event *audit.Event) string {
	content := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
		prevHash,
		event.Timestamp.UTC().Format(time.RFC3339Nano),
		event.Action,
		event.Resource,
		event.Category,
		event.ResourceID,
		event.Outcome,
		event.Severity,
		marshalMetadata(event.Metadata),
	)
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// Verify reports whether the event's stored Hash matches a recomputation from
// prevHash, accepting either the current or the legacy scheme.
//
// Comparison is constant-time so verification does not leak digest bytes
// through timing.
func (c *Chain) Verify(prevHash string, event *audit.Event) bool {
	if hashesEqual(event.Hash, c.Compute(prevHash, event)) {
		return true
	}
	// Pre-extension events carry a legacy digest.
	return hashesEqual(event.Hash, ComputeLegacy(prevHash, event))
}

// hashesEqual compares two hex digests in constant time.
func hashesEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// marshalMetadata produces deterministic JSON for metadata (sorted keys).
func marshalMetadata(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make([]orderedEntry, 0, len(keys))
	for _, k := range keys {
		ordered = append(ordered, orderedEntry{Key: k, Value: m[k]})
	}

	data, err := json.Marshal(orderedMapFromEntries(ordered))
	if err != nil {
		return "{}"
	}
	return string(data)
}

// orderedEntry is a key-value pair for ordered JSON marshaling.
type orderedEntry struct {
	Key   string
	Value any
}

// orderedMapFromEntries converts sorted entries to a map for JSON marshaling.
// Since Go 1.12+ json.Marshal uses sorted keys for maps, we can use a regular map.
func orderedMapFromEntries(entries []orderedEntry) map[string]any {
	m := make(map[string]any, len(entries))
	for _, e := range entries {
		m[e.Key] = e.Value
	}
	return m
}
