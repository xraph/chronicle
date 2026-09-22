// Package hash provides SHA-256 hash chain computation for audit events.
package hash

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/keys"
)

// versionTag prefixes the hashed content so the scheme a digest was produced
// under is unambiguous, and so a digest from one scheme can never collide with
// the other's.
const versionTag = "chronicle/v2"

// Scheme names how a digest was produced. It is recorded on every event so
// verification never has to guess, and so a weaker scheme cannot be substituted
// for a stronger one without the substitution being visible.
type Scheme string

const (
	// SchemeLegacy is the original digest, covering neither the actor nor the
	// source address. Verify-only; never write one.
	SchemeLegacy Scheme = "chronicle/v1"

	// SchemePlain is the unkeyed SHA-256 digest. Anyone who can write to the
	// store can reproduce it, so it detects corruption and not tampering.
	SchemePlain Scheme = "chronicle/v2"

	// SchemeHMAC is HMAC-SHA256 over identical content, under a key the store
	// does not hold.
	SchemeHMAC Scheme = "chronicle/v3"
)

// Rank orders schemes by strength, so a stream pinned to one scheme can detect
// an event claiming anything weaker. Ranking rather than requiring equality is
// what lets a stream change scheme more than once without an epoch table.
//
// It is exported because the same ordering decides two different questions, and
// they must never disagree: verification asks whether an event claims less than
// its stream pins, and the writer asks whether a newly configured scheme is
// strong enough to move that pin forward. An unknown or empty scheme ranks
// below every named one.
func Rank(s Scheme) int {
	switch s {
	case SchemeHMAC:
		return 2
	case SchemePlain:
		return 1
	default:
		return 0
	}
}

// Pin is a stream's declared scheme and the sequence from which it applies.
// Events below Since predate the pin and are resolved tolerantly.
type Pin struct {
	Scheme Scheme
	Since  uint64
}

// Result reports what a verification concluded.
type Result struct {
	// OK is whether the stored digest matched a recomputation.
	OK bool

	// Scheme is the scheme the digest was actually verified under.
	Scheme Scheme

	// Downgrade is true when the event claims a weaker scheme than its stream
	// pins at that sequence. Treat it as tampering, not as an old event.
	Downgrade bool

	// Tolerant is true when the event carried no scheme and was resolved by
	// trying the historical schemes in turn.
	Tolerant bool
}

// Chain computes SHA-256 or HMAC-SHA256 hashes linking events into a chain.
//
// The zero value is a plain, unkeyed chain, which is what this type was before
// schemes existed and what several call sites still construct.
type Chain struct {
	scheme Scheme
	keys   keys.Provider
}

// NewChain returns a Chain writing under the given scheme.
//
// SchemeHMAC needs a provider, because accepting one without is how a
// deployment ends up believing its chain is keyed while writing plain digests.
// SchemeLegacy is rejected outright: it exists to verify old rows, and writing
// a new one would deliberately drop the actor and source address from coverage.
//
// Under SchemeHMAC the active key is resolved here, once, and construction
// fails if there is not one. A provider that loads cleanly is not the same as a
// provider that can sign: a keyset whose use is misspelled, or whose only hmac
// key is active: false, parses and validates perfectly and then has no active
// key for hmac. Without this check the process boots green and every single
// Record fails at runtime, which is the worst possible place to find out.
//
// The key resolved here is deliberately discarded. Compute re-resolves per
// event so a rotation takes effect without a restart of the writer; this is a
// readiness check, not a cache.
func NewChain(scheme Scheme, provider keys.Provider) (*Chain, error) {
	switch scheme {
	case SchemeLegacy:
		return nil, fmt.Errorf("hash: %s is verify-only and cannot be used for writing", scheme)
	case SchemeHMAC:
		if provider == nil {
			return nil, fmt.Errorf("hash: %s requires a key provider", scheme)
		}
		key, keyID, err := provider.Current(context.Background(), keys.UseHMAC)
		if err != nil {
			return nil, fmt.Errorf(
				"hash: %s is configured but no active %s key could be resolved: %w",
				scheme, keys.UseHMAC, err)
		}
		if len(key) == 0 {
			return nil, fmt.Errorf(
				"hash: %s key %q resolved to no material; a keyed digest over an empty key "+
					"is an unkeyed digest with extra steps", scheme, keyID)
		}
	case SchemePlain, "":
		scheme = SchemePlain
	default:
		return nil, fmt.Errorf("hash: unknown scheme %q", scheme)
	}
	return &Chain{scheme: scheme, keys: provider}, nil
}

// Scheme reports the scheme this chain writes under.
func (c *Chain) Scheme() Scheme {
	if c.scheme == "" {
		return SchemePlain
	}
	return c.scheme
}

// content assembles the bytes a digest covers. Both schemes hash exactly this,
// so the field coverage documented above holds either way.
func content(prevHash string, event *audit.Event) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
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
}

// Compute generates the digest for an event, linking it to the previous hash,
// and returns the ID of the key used. The key ID is empty for unkeyed schemes.
//
// The digest covers every field that carries accountability: who acted
// (UserID), from where (IP), under which tenant (AppID, TenantID), why
// (Reason), about whom (SubjectID), and the event's position in the stream
// (Sequence), as well as what happened.
func (c *Chain) Compute(ctx context.Context, prevHash string, event *audit.Event) (digest, keyID string, err error) {
	body := []byte(content(prevHash, event))

	if c.Scheme() != SchemeHMAC {
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:]), "", nil
	}

	key, resolvedKeyID, err := c.keys.Current(ctx, keys.UseHMAC)
	if err != nil {
		return "", "", fmt.Errorf("hash: resolve hmac key: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), resolvedKeyID, nil
}

// computeUnder recomputes a digest under an explicit scheme and key ID, which
// is what verification needs: it must reproduce what was written, not what this
// chain would write now.
//
// The switch is exhaustive on purpose. Verification must check a claimed
// scheme against exactly that scheme's algorithm, never a different one: an
// event whose HashScheme names something this package does not recognize is
// evidence of tampering or a version skew, not a plain digest waiting to be
// found by falling through.
func (c *Chain) computeUnder(ctx context.Context, scheme Scheme, keyID, prevHash string, event *audit.Event) (string, error) {
	switch scheme {
	case SchemeLegacy:
		return ComputeLegacy(prevHash, event), nil

	case SchemePlain, "":
		sum := sha256.Sum256([]byte(content(prevHash, event)))
		return hex.EncodeToString(sum[:]), nil

	case SchemeHMAC:
		if c.keys == nil {
			return "", fmt.Errorf("hash: cannot verify an %s digest without a key provider", scheme)
		}
		key, err := c.keys.ByID(ctx, keyID)
		if err != nil {
			return "", fmt.Errorf("hash: resolve key %q: %w", keyID, err)
		}

		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(content(prevHash, event)))
		return hex.EncodeToString(mac.Sum(nil)), nil

	default:
		return "", fmt.Errorf("hash: unknown scheme %q", scheme)
	}
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

// VerifyWithPin checks an event's stored digest against a recomputation,
// resolving the scheme from what the event records and cross-checking it
// against what its stream pins.
//
// Recording the scheme in both places is what makes a downgrade visible.
// Per-event alone is forgeable, since an attacker relabels the event and
// recomputes under the weaker scheme. Per-stream alone is forgeable too, since
// one row update covers the whole chain. Together, an event claiming less than
// its stream promises at that sequence is evidence rather than history.
func (c *Chain) VerifyWithPin(ctx context.Context, prevHash string, event *audit.Event, pin Pin) (Result, error) {
	claimed := Scheme(event.HashScheme)
	atOrAbovePin := pin.Scheme != "" && event.Sequence >= pin.Since

	if claimed == "" {
		// A pre-migration row. Above the pin, a blank scheme means the column
		// was cleared to buy the tolerant path, so it is not history.
		if atOrAbovePin {
			return Result{Downgrade: true}, nil
		}
		for _, scheme := range []Scheme{SchemePlain, SchemeLegacy} {
			digest, err := c.computeUnder(ctx, scheme, "", prevHash, event)
			if err != nil {
				return Result{}, err
			}
			if hashesEqual(event.Hash, digest) {
				return Result{OK: true, Scheme: scheme, Tolerant: true}, nil
			}
		}
		return Result{Tolerant: true}, nil
	}

	if atOrAbovePin && Rank(claimed) < Rank(pin.Scheme) {
		return Result{Scheme: claimed, Downgrade: true}, nil
	}

	digest, err := c.computeUnder(ctx, claimed, event.HashKeyID, prevHash, event)
	if err != nil {
		return Result{}, err
	}
	return Result{OK: hashesEqual(event.Hash, digest), Scheme: claimed}, nil
}

// Verify reports whether the event's stored Hash matches a recomputation,
// accepting either the current or the legacy unkeyed scheme.
//
// Deprecated: it cannot see a stream's pin, so it cannot detect a downgrade.
// Use VerifyWithPin. This remains for callers that have no stream in hand.
func (c *Chain) Verify(prevHash string, event *audit.Event) bool {
	res, err := c.VerifyWithPin(context.Background(), prevHash, event, Pin{})
	return err == nil && res.OK
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

	mapKeys := make([]string, 0, len(m))
	for k := range m {
		mapKeys = append(mapKeys, k)
	}
	sort.Strings(mapKeys)

	ordered := make([]orderedEntry, 0, len(mapKeys))
	for _, k := range mapKeys {
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
