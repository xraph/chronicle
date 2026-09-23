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
	"strconv"
	"strings"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/keys"
)

// contentV2Tag prefixes the content the v2 and v3 schemes hash.
//
// It is frozen. Every digest ever written under those schemes covers exactly
// these bytes, so changing the tag, the field order, or the separator would
// report the entire history as tampered.
const contentV2Tag = "chronicle/v2"

// Scheme names how a digest was produced. It is recorded on every event so
// verification never has to guess, and so a weaker scheme cannot be substituted
// for a stronger one without the substitution being visible.
type Scheme string

const (
	// SchemeLegacy is the original digest, covering neither the actor nor the
	// source address. Verify-only; never write one.
	SchemeLegacy Scheme = "chronicle/v1"

	// SchemePlain is the unkeyed SHA-256 digest over delimiter-joined content.
	//
	// Verify-only; never write one. Its content encoding is ambiguous, which
	// lets an attacker move content across a field boundary without changing
	// the digest. See contentV4. Use SchemePlainV4 instead.
	SchemePlain Scheme = "chronicle/v2"

	// SchemeHMAC is HMAC-SHA256 over the same delimiter-joined content, under a
	// key the store does not hold.
	//
	// Verify-only; never write one. The key does not close the encoding hole:
	// the MAC covers the same ambiguous bytes, so the swap described in
	// contentV4 works without ever resolving the key. Use SchemeHMACV5.
	SchemeHMAC Scheme = "chronicle/v3"

	// SchemePlainV4 is the unkeyed SHA-256 digest over length-prefixed content.
	// Unkeyed still means reproducible by anyone who can write to the store, so
	// it detects corruption and not tampering.
	SchemePlainV4 Scheme = "chronicle/v4"

	// SchemeHMACV5 is HMAC-SHA256 over that same length-prefixed content, under
	// a key the store does not hold. This is the strongest digest on offer.
	SchemeHMACV5 Scheme = "chronicle/v5"
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
// The ordering puts keying ahead of content framing, and that is deliberate.
// Ranking the framing fix above SchemeHMAC would make a move from SchemeHMAC to
// SchemePlainV4 read as strengthening, so reconcileStreamPin would advance the
// pin while the deployment quietly stopped using its key. Losing the key is the
// larger loss, so every keyed scheme outranks every unkeyed one and the framing
// fix breaks the tie within each pair.
func Rank(s Scheme) int {
	switch s {
	case SchemeHMACV5:
		return 4
	case SchemeHMAC:
		return 3
	case SchemePlainV4:
		return 2
	case SchemePlain:
		return 1
	default:
		return 0
	}
}

// Keyed reports whether a scheme's digest depends on key material the store
// does not hold. It is the question callers actually mean when they reach for
// an equality check against SchemeHMAC, and unlike that check it keeps giving
// the right answer as schemes are added.
func Keyed(s Scheme) bool {
	return s == SchemeHMAC || s == SchemeHMACV5
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
	case SchemePlain:
		return nil, fmt.Errorf(
			"hash: %s is verify-only and cannot be used for writing; its content encoding is "+
				"ambiguous, so use %s", scheme, SchemePlainV4)
	case SchemeHMAC:
		return nil, fmt.Errorf(
			"hash: %s is verify-only and cannot be used for writing; its content encoding is "+
				"ambiguous and the key does not close that hole, so use %s", scheme, SchemeHMACV5)
	case SchemeHMACV5:
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
	case SchemePlainV4, "":
		scheme = SchemePlainV4
	default:
		return nil, fmt.Errorf("hash: unknown scheme %q", scheme)
	}
	return &Chain{scheme: scheme, keys: provider}, nil
}

// Scheme reports the scheme this chain writes under.
func (c *Chain) Scheme() Scheme {
	if c.scheme == "" {
		return SchemePlainV4
	}
	return c.scheme
}

// contentV2 assembles the bytes a v2 or v3 digest covers.
//
// Frozen, and ambiguous by construction: see contentV4 for what that costs and
// contentV2Tag for why it cannot be corrected in place.
func contentV2(prevHash string, event *audit.Event) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		contentV2Tag,
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

// contentV4 assembles the bytes a v4 or v5 digest covers, with every field
// length-prefixed.
//
// contentV2 joins its fields with a bare "|" and escapes nothing, so content can
// move across a separator without changing the joined string. A user ID of
// "alice" beside an address of "10.0.0.9|note" produces the same bytes as a user
// ID of "alice|10.0.0.9" beside an address of "note". The two events say
// different things about who acted and from where, and they hash identically.
// HMAC does not help: the MAC covers those same bytes, so rewriting the actor
// never needed the key at all.
//
// Prefixing each value with its byte length closes it. A reader can find where
// every field ends without trusting what is inside it, so no arrangement of
// field contents can imitate another. The scheme's own name leads the content
// rather than a shared tag, so v4 bytes can never be read as v5 bytes.
func contentV4(scheme Scheme, prevHash string, event *audit.Event) string {
	fields := [...]string{
		string(scheme),
		prevHash,
		strconv.FormatUint(event.Sequence, 10),
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
	}

	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return b.String()
}

// Compute generates the digest for an event, linking it to the previous hash,
// and returns the ID of the key used. The key ID is empty for unkeyed schemes.
//
// The digest covers every field that carries accountability: who acted
// (UserID), from where (IP), under which tenant (AppID, TenantID), why
// (Reason), about whom (SubjectID), and the event's position in the stream
// (Sequence), as well as what happened.
func (c *Chain) Compute(ctx context.Context, prevHash string, event *audit.Event) (digest, keyID string, err error) {
	scheme := c.Scheme()
	body := []byte(contentV4(scheme, prevHash, event))

	if !Keyed(scheme) {
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
		sum := sha256.Sum256([]byte(contentV2(prevHash, event)))
		return hex.EncodeToString(sum[:]), nil

	case SchemeHMAC:
		return c.keyedDigest(ctx, scheme, keyID, contentV2(prevHash, event))

	case SchemePlainV4:
		sum := sha256.Sum256([]byte(contentV4(scheme, prevHash, event)))
		return hex.EncodeToString(sum[:]), nil

	case SchemeHMACV5:
		return c.keyedDigest(ctx, scheme, keyID, contentV4(scheme, prevHash, event))

	default:
		return "", fmt.Errorf("hash: unknown scheme %q", scheme)
	}
}

// keyedDigest is the MAC half of computeUnder, shared by both keyed schemes so
// that resolving the key and applying it happens in exactly one place.
func (c *Chain) keyedDigest(ctx context.Context, scheme Scheme, keyID, body string) (string, error) {
	if c.keys == nil {
		return "", fmt.Errorf("hash: cannot verify an %s digest without a key provider", scheme)
	}
	key, err := c.keys.ByID(ctx, keyID)
	if err != nil {
		return "", fmt.Errorf("hash: resolve key %q: %w", keyID, err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ComputeLegacy reproduces the original hash scheme, which covered only
// timestamp, action, resource, category, resource ID, outcome, severity and
// metadata.
//
// It exists so events written before the coverage was extended still verify;
// without it, upgrading would report every historical event as tampered. Never
// use it to write a new hash.
//
// Falling back to it does not weaken current events: every later scheme covers
// its own name, so recomputing a tampered event under any of them yields a
// different digest than the one stored.
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
