// Package hash provides SHA-256 hash chain computation for audit events.
package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/xraph/chronicle/audit"
)

// Chain computes SHA-256 hashes linking events into a tamper-evident chain.
type Chain struct{}

// Compute generates the SHA-256 hash for an event, linking it to the previous hash.
// Content = prevHash|timestamp|action|resource|category|resourceID|outcome|severity|metadata_json
func (c *Chain) Compute(prevHash string, event *audit.Event) string {
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
