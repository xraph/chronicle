# Keyed digests and scheme recording (Axis 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the hash chain forgeable only by someone holding a key the database does not contain, and record which scheme each event was written under so a downgrade is detectable.

**Architecture:** A new `keys` package supplies rotatable key material by use. `hash.Chain` gains a scheme and a key provider, and `Compute` returns the key ID alongside the digest. Events record `hash_scheme` and `hash_key_id`; streams record the scheme they are pinned to and the sequence that pin took effect. Verification resolves strictly from the recorded scheme and reports any event claiming a weaker scheme than its stream promises.

**Tech Stack:** Go 1.26, grove ORM for Postgres/SQLite, stdlib `testing` (no testify), stdlib `crypto/hmac`.

**Spec:** `specs/2026-09-22-tamper-evidence-design.md`

## Global Constraints

- Go 1.26.0, module `github.com/xraph/chronicle`.
- No new third-party dependencies. `keys` and `hash` use stdlib only.
- Tests are external test packages (`package hash_test`), stdlib `testing`, no testify. Follow `hash/chain_test.go`.
- `&hash.Chain{}` is constructed as a zero value in `chronicle.go`, `verify/verifier.go`, and `store/postgres/audit.go`. A zero `Chain` MUST keep behaving as `SchemePlain` with no key provider.
- Never write a digest under `SchemeLegacy`. It is verify-only.
- `golangci-lint` runs in CI and the repo is currently clean. Keep it clean.
- Run `go build ./... && go vet ./...` before every commit.

## Deviation from the spec

The spec writes `Compute(prevHash string, event *audit.Event) (digest, keyID string, err error)`. `keys.Provider` takes a `context.Context`, so `Compute` takes one too:

```go
Compute(ctx context.Context, prevHash string, event *audit.Event) (digest, keyID string, err error)
```

Both existing call sites (`Chronicle.Record`, `postgres.Store.Append`) already have a ctx in scope.

## How scheme resolution actually works

Worth reading before Task 2, because it is the one non-obvious part.

Each event carries `HashScheme`. Each stream carries `Scheme` plus `SchemeSince`. Resolution:

- `HashScheme == ""` means a pre-migration row. Verify tolerantly: try `SchemePlain`, then `SchemeLegacy`. If such an event sits at or above `SchemeSince`, that is a downgrade, because someone blanked the column.
- `HashScheme != ""` means verify strictly under exactly that scheme, never trying another.
- Separately, if the event is at or above `SchemeSince` and its scheme ranks below the stream's pinned scheme, that is a downgrade.

Ranks: legacy 0, plain 1, hmac 2.

Ranking rather than equality is what makes multiple epochs work without an epoch table. Switch a stream to HMAC at sequence 84,301 and the older plain events still verify strictly under plain, because they sit below the new `SchemeSince`, while anything from 84,301 on must rank at least as high as HMAC.

Migration 006 sets `scheme_since = head_seq + 1` on every existing stream. That puts all pre-existing events in the tolerant window and makes everything written afterwards strict, which is the "freeze the ambiguity" behaviour the spec calls for.

---

### Task 1: The `keys` package

**Files:**
- Create: `keys/keys.go`
- Create: `keys/file.go`
- Test: `keys/keys_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `keys.Use`, `keys.UseHMAC`, `keys.UseCheckpointSig`, `keys.Provider` (with `Current(ctx, Use) ([]byte, string, error)` and `ByID(ctx, string) ([]byte, error)`), `keys.NewFileProvider(path string) (*keys.FileProvider, error)`, `keys.ErrKeyNotFound`, `keys.ErrNoActiveKey`.

- [ ] **Step 1: Write the failing test**

Create `keys/keys_test.go`:

```go
package keys_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xraph/chronicle/keys"
)

// writeKeyset writes a keyset file and returns its path.
func writeKeyset(t *testing.T, entries []map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.json")
	data, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatalf("marshal keyset: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write keyset: %v", err)
	}
	return path
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestFileProviderCurrentReturnsActiveKey(t *testing.T) {
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i)
	}
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-2026-09", "use": "hmac", "active": true, "material": b64(material)},
	})

	p, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	key, keyID, err := p.Current(context.Background(), keys.UseHMAC)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if keyID != "hmac-2026-09" {
		t.Errorf("keyID = %q, want %q", keyID, "hmac-2026-09")
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

// Rotation is the whole reason ByID exists: a retired key must still resolve so
// events written under it stay verifiable.
func TestFileProviderByIDResolvesRetiredKey(t *testing.T) {
	old, cur := make([]byte, 32), make([]byte, 32)
	old[0], cur[0] = 1, 2
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-old", "use": "hmac", "active": false, "material": b64(old)},
		{"id": "hmac-new", "use": "hmac", "active": true, "material": b64(cur)},
	})

	p, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	_, keyID, err := p.Current(context.Background(), keys.UseHMAC)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if keyID != "hmac-new" {
		t.Errorf("active keyID = %q, want hmac-new", keyID)
	}

	got, err := p.ByID(context.Background(), "hmac-old")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got[0] != 1 {
		t.Errorf("ByID returned the wrong key material")
	}
}

func TestFileProviderUnknownKeyID(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-1", "use": "hmac", "active": true, "material": b64(make([]byte, 32))},
	})
	p, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	if _, err := p.ByID(context.Background(), "nope"); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("ByID error = %v, want ErrKeyNotFound", err)
	}
}

func TestFileProviderNoActiveKeyForUse(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-1", "use": "hmac", "active": false, "material": b64(make([]byte, 32))},
	})
	p, err := keys.NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}

	if _, _, err := p.Current(context.Background(), keys.UseHMAC); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Errorf("Current error = %v, want ErrNoActiveKey", err)
	}
}

// A short HMAC key silently weakens every digest, so it is rejected at load
// time rather than at the first write.
func TestFileProviderRejectsShortHMACKey(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "hmac-1", "use": "hmac", "active": true, "material": b64(make([]byte, 16))},
	})
	if _, err := keys.NewFileProvider(path); err == nil {
		t.Fatal("NewFileProvider accepted a 16-byte HMAC key, want an error")
	}
}

func TestFileProviderRejectsTwoActiveKeysForOneUse(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "a", "use": "hmac", "active": true, "material": b64(make([]byte, 32))},
		{"id": "b", "use": "hmac", "active": true, "material": b64(make([]byte, 32))},
	})
	if _, err := keys.NewFileProvider(path); err == nil {
		t.Fatal("NewFileProvider accepted two active hmac keys, want an error")
	}
}

func TestFileProviderRejectsDuplicateKeyID(t *testing.T) {
	path := writeKeyset(t, []map[string]any{
		{"id": "dup", "use": "hmac", "active": true, "material": b64(make([]byte, 32))},
		{"id": "dup", "use": "checkpoint-sig", "active": true, "material": b64(make([]byte, 32))},
	})
	if _, err := keys.NewFileProvider(path); err == nil {
		t.Fatal("NewFileProvider accepted a duplicate key ID across uses, want an error")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./keys/ -v`
Expected: build failure, `no required module provides package github.com/xraph/chronicle/keys`.

- [ ] **Step 3: Write the implementation**

Create `keys/keys.go`:

```go
// Package keys supplies the key material that keyed digests and signed
// checkpoints depend on.
//
// It is deliberately separate from crypto.KeyStore. That store holds
// per-subject erasure keys, which exist to be destroyed; these keys are per
// deployment and exist to be retained and rotated. Sharing one store would mean
// a subject exercising their right to erasure could take out the key needed to
// verify a five-year-old event.
package keys

import (
	"context"
	"errors"
)

// Use identifies what a key is for. Key IDs are unique across all uses, so
// ByID does not need one.
type Use string

const (
	// UseHMAC is the 32-byte symmetric key behind hash.SchemeHMAC.
	UseHMAC Use = "hmac"

	// UseCheckpointSig is the ed25519 private key that signs checkpoints.
	UseCheckpointSig Use = "checkpoint-sig"
)

// HMACKeySize is the required length of a UseHMAC key.
const HMACKeySize = 32

// Sentinel errors.
var (
	// ErrKeyNotFound is returned when no key carries the requested ID.
	ErrKeyNotFound = errors.New("keys: key not found")

	// ErrNoActiveKey is returned when no key is marked active for a use.
	ErrNoActiveKey = errors.New("keys: no active key for use")
)

// Provider supplies key material.
//
// Current is for writing and ByID is for verifying artifacts written under an
// earlier key. Having both is what makes rotation possible: retiring a key
// stops it being used for new digests without making old ones unverifiable.
type Provider interface {
	// Current returns the active key for a use, and its ID.
	Current(ctx context.Context, use Use) (key []byte, keyID string, err error)

	// ByID returns the key with the given ID, active or retired.
	ByID(ctx context.Context, keyID string) (key []byte, err error)
}
```

Create `keys/file.go`:

```go
package keys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// FileProvider reads a keyset from a JSON file at construction time.
//
// The file holds every key the deployment has used, with exactly one marked
// active per use. Rotating is adding a key and moving the active flag; the
// retired entry stays so its events keep verifying.
//
//	{
//	  "keys": [
//	    {"id": "hmac-2026-09", "use": "hmac", "active": true,  "material": "<base64>"},
//	    {"id": "hmac-2026-03", "use": "hmac", "active": false, "material": "<base64>"}
//	  ]
//	}
//
// It is read once and held in memory. Rotating requires a restart, which is a
// deliberate limit: reloading under a running chain would let a digest be
// written under a key that verification later cannot find.
type FileProvider struct {
	byID     map[string][]byte
	activeID map[Use]string
}

type keysetFile struct {
	Keys []keysetEntry `json:"keys"`
}

type keysetEntry struct {
	ID       string `json:"id"`
	Use      Use    `json:"use"`
	Active   bool   `json:"active"`
	Material string `json:"material"`
}

// NewFileProvider loads and validates a keyset file.
//
// Validation happens here rather than at first use so a malformed keyset stops
// the process at startup instead of at the first audit event.
func NewFileProvider(path string) (*FileProvider, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("keys: read keyset %q: %w", path, err)
	}

	var file keysetFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("keys: parse keyset %q: %w", path, err)
	}
	if len(file.Keys) == 0 {
		return nil, fmt.Errorf("keys: keyset %q contains no keys", path)
	}

	p := &FileProvider{
		byID:     make(map[string][]byte, len(file.Keys)),
		activeID: make(map[Use]string),
	}

	for _, entry := range file.Keys {
		if entry.ID == "" {
			return nil, fmt.Errorf("keys: keyset %q has a key with no id", path)
		}
		if _, dup := p.byID[entry.ID]; dup {
			return nil, fmt.Errorf("keys: keyset %q repeats key id %q", path, entry.ID)
		}

		material, decErr := base64.StdEncoding.DecodeString(entry.Material)
		if decErr != nil {
			return nil, fmt.Errorf("keys: key %q material is not base64: %w", entry.ID, decErr)
		}
		if entry.Use == UseHMAC && len(material) != HMACKeySize {
			return nil, fmt.Errorf(
				"keys: key %q is %d bytes; a %s key must be %d",
				entry.ID, len(material), UseHMAC, HMACKeySize)
		}

		p.byID[entry.ID] = material

		if entry.Active {
			if existing, ok := p.activeID[entry.Use]; ok {
				return nil, fmt.Errorf(
					"keys: keyset %q marks both %q and %q active for use %q",
					path, existing, entry.ID, entry.Use)
			}
			p.activeID[entry.Use] = entry.ID
		}
	}

	return p, nil
}

// Current returns the active key for a use.
func (p *FileProvider) Current(_ context.Context, use Use) ([]byte, string, error) {
	keyID, ok := p.activeID[use]
	if !ok {
		return nil, "", fmt.Errorf("%w: %s", ErrNoActiveKey, use)
	}
	return p.byID[keyID], keyID, nil
}

// ByID returns a key by ID, whether or not it is still active.
func (p *FileProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	key, ok := p.byID[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return key, nil
}

// Compile-time check.
var _ Provider = (*FileProvider)(nil)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./keys/ -v`
Expected: all seven tests PASS.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./...
git add keys/
git commit -m "feat(keys): key provider with rotation and a file-backed keyset"
```

---

### Task 2: Scheme-aware `hash.Chain`

**Files:**
- Modify: `hash/chain.go`
- Test: `hash/scheme_test.go`

**Interfaces:**
- Consumes: `keys.Provider`, `keys.UseHMAC`, `keys.ErrKeyNotFound` from Task 1.
- Produces: `hash.Scheme`, `hash.SchemeLegacy`, `hash.SchemePlain`, `hash.SchemeHMAC`, `hash.Pin{Scheme, Since}`, `hash.Result{OK, Scheme, Downgrade, Tolerant}`, `hash.NewChain(Scheme, keys.Provider) (*Chain, error)`, `(*Chain).Compute(ctx, prevHash, event) (string, string, error)`, `(*Chain).VerifyWithPin(ctx, prevHash, event, Pin) (Result, error)`. The existing `(*Chain).Verify(prevHash, event) bool` stays as a tolerant-mode shim.

- [ ] **Step 1: Write the failing test**

Create `hash/scheme_test.go`:

```go
package hash_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/keys"
)

// stubProvider is a Provider backed by a fixed key.
type stubProvider struct {
	key      []byte
	activeID string
}

func (s stubProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return s.key, s.activeID, nil
}

func (s stubProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != s.activeID {
		return nil, keys.ErrKeyNotFound
	}
	return s.key, nil
}

func newEvent() *audit.Event {
	return &audit.Event{
		Timestamp: time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Sequence:  5,
		Action:    "login",
		Resource:  "session",
		Category:  "auth",
		UserID:    "user-42",
		IP:        "10.0.0.1",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
	}
}

func hmacChain(t *testing.T) *hash.Chain {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c, err := hash.NewChain(hash.SchemeHMAC, stubProvider{key: key, activeID: "hmac-1"})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	return c
}

// A zero Chain is constructed in three places in this repo and must keep
// behaving exactly as it did before schemes existed.
func TestZeroChainIsPlain(t *testing.T) {
	var c hash.Chain
	digest, keyID, err := c.Compute(context.Background(), "", newEvent())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if keyID != "" {
		t.Errorf("keyID = %q, want empty for the plain scheme", keyID)
	}
	if len(digest) != 64 {
		t.Errorf("digest length = %d, want 64", len(digest))
	}
}

// The point of the whole exercise: without the key you cannot produce the
// digest, so recomputing the chain from the stored row is not enough.
func TestHMACDigestDiffersFromPlain(t *testing.T) {
	ctx := context.Background()
	event := newEvent()

	var plain hash.Chain
	plainDigest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("plain Compute: %v", err)
	}

	hmacDigest, keyID, err := hmacChain(t).Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("hmac Compute: %v", err)
	}

	if hmacDigest == plainDigest {
		t.Error("hmac digest equals the plain digest; the key is not being used")
	}
	if keyID != "hmac-1" {
		t.Errorf("keyID = %q, want hmac-1", keyID)
	}
}

func TestHMACRoundTripVerifies(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()

	digest, keyID, err := c.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme, event.HashKeyID = digest, string(hash.SchemeHMAC), keyID

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMAC, Since: 1})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.OK {
		t.Error("a freshly computed hmac event failed verification")
	}
	if res.Downgrade {
		t.Error("a matching scheme was reported as a downgrade")
	}
}

// The attack this design exists to stop: rewrite the event, recompute the
// digest under the weaker scheme, and relabel it.
func TestDowngradeToPlainIsDetected(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()

	var plain hash.Chain
	plainDigest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("plain Compute: %v", err)
	}
	event.Hash, event.HashScheme, event.HashKeyID = plainDigest, string(hash.SchemePlain), ""

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMAC, Since: 1})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.Downgrade {
		t.Error("an event claiming the plain scheme above the pin was not flagged as a downgrade")
	}
	if res.OK {
		t.Error("a downgraded event verified OK")
	}
}

// Blanking the column must not buy the tolerant path.
func TestBlankSchemeAboveThePinIsADowngrade(t *testing.T) {
	ctx := context.Background()
	c := hmacChain(t)
	event := newEvent()

	var plain hash.Chain
	plainDigest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("plain Compute: %v", err)
	}
	event.Hash, event.HashScheme = plainDigest, ""

	res, err := c.VerifyWithPin(ctx, "prev", event, hash.Pin{Scheme: hash.SchemeHMAC, Since: 1})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.Downgrade {
		t.Error("a blank scheme above the pin was not flagged as a downgrade")
	}
}

// Pre-migration rows carry no scheme and sit below the pin. They keep verifying.
func TestPreMigrationEventVerifiesTolerantly(t *testing.T) {
	ctx := context.Background()
	event := newEvent()

	var plain hash.Chain
	digest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme = digest, ""

	res, err := hmacChain(t).VerifyWithPin(ctx, "prev", event,
		hash.Pin{Scheme: hash.SchemeHMAC, Since: 100})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.OK {
		t.Error("a pre-migration event below the pin failed verification")
	}
	if !res.Tolerant {
		t.Error("resolution below the pin should be reported as tolerant")
	}
	if res.Downgrade {
		t.Error("an event below the pin must not be flagged as a downgrade")
	}
}

// Plain events written before a switch to HMAC sit below the new pin, and are
// still verified strictly because they carry a scheme.
func TestPlainEventBelowPinVerifiesStrictly(t *testing.T) {
	ctx := context.Background()
	event := newEvent()

	var plain hash.Chain
	digest, _, err := plain.Compute(ctx, "prev", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme = digest, string(hash.SchemePlain)

	res, err := hmacChain(t).VerifyWithPin(ctx, "prev", event,
		hash.Pin{Scheme: hash.SchemeHMAC, Since: 100})
	if err != nil {
		t.Fatalf("VerifyWithPin: %v", err)
	}
	if !res.OK || res.Tolerant || res.Downgrade {
		t.Errorf("got %+v, want a strict plain verification below the pin", res)
	}
}

func TestNewChainRequiresProviderForHMAC(t *testing.T) {
	if _, err := hash.NewChain(hash.SchemeHMAC, nil); err == nil {
		t.Fatal("NewChain accepted SchemeHMAC with no key provider, want an error")
	}
}

func TestNewChainRejectsLegacyForWriting(t *testing.T) {
	if _, err := hash.NewChain(hash.SchemeLegacy, nil); err == nil {
		t.Fatal("NewChain accepted SchemeLegacy, which is verify-only, want an error")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./hash/ -run 'Scheme|HMAC|Downgrade|Pin|ZeroChain|Blank|PreMigration' -v`
Expected: build failure, `undefined: hash.NewChain`.

- [ ] **Step 3: Write the implementation**

In `hash/chain.go`, add the imports `context`, `crypto/hmac`, and `github.com/xraph/chronicle/keys`. Add above the `Chain` type:

```go
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

// rank orders schemes by strength, so a stream pinned to one scheme can detect
// an event claiming anything weaker. Ranking rather than requiring equality is
// what lets a stream change scheme more than once without an epoch table.
func rank(s Scheme) int {
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
```

Replace `type Chain struct{}` with:

```go
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
func NewChain(scheme Scheme, provider keys.Provider) (*Chain, error) {
	switch scheme {
	case SchemeLegacy:
		return nil, fmt.Errorf("hash: %s is verify-only and cannot be used for writing", scheme)
	case SchemeHMAC:
		if provider == nil {
			return nil, fmt.Errorf("hash: %s requires a key provider", scheme)
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
```

Replace the body of `Compute` with a content builder plus a scheme-aware digest:

```go
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
func (c *Chain) Compute(ctx context.Context, prevHash string, event *audit.Event) (string, string, error) {
	body := []byte(content(prevHash, event))

	if c.Scheme() != SchemeHMAC {
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:]), "", nil
	}

	key, keyID, err := c.keys.Current(ctx, keys.UseHMAC)
	if err != nil {
		return "", "", fmt.Errorf("hash: resolve hmac key: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), keyID, nil
}

// computeUnder recomputes a digest under an explicit scheme and key ID, which
// is what verification needs: it must reproduce what was written, not what this
// chain would write now.
func (c *Chain) computeUnder(ctx context.Context, scheme Scheme, keyID, prevHash string, event *audit.Event) (string, error) {
	if scheme == SchemeLegacy {
		return ComputeLegacy(prevHash, event), nil
	}

	body := []byte(content(prevHash, event))

	if scheme != SchemeHMAC {
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:]), nil
	}

	if c.keys == nil {
		return "", fmt.Errorf("hash: cannot verify an %s digest without a key provider", scheme)
	}
	key, err := c.keys.ByID(ctx, keyID)
	if err != nil {
		return "", fmt.Errorf("hash: resolve key %q: %w", keyID, err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
```

Add `VerifyWithPin` and rewrite `Verify` as a shim:

```go
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

	if atOrAbovePin && rank(claimed) < rank(pin.Scheme) {
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./hash/ -v`
Expected: the new tests PASS and every pre-existing test in `hash/chain_test.go` still PASSES, except calls to `c.Compute(...)` which now need updating for the new signature. Fix those call sites in `hash/chain_test.go` to `digest, _, _ := c.Compute(context.Background(), ...)`.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./...
git add hash/ audit/event.go chronicle.go store/postgres/audit.go
git commit -m "feat(hash): scheme-aware chain with HMAC digests and downgrade detection"
```

`Compute` now returns three values, so `go build ./...` fails in `chronicle.go` and `store/postgres/audit.go` until both call sites are updated. Both need somewhere to put the scheme and key ID, so add the two fields to `audit/event.go` in this same commit, immediately after `EncryptionKeyID`:

```go
	// Hash scheme provenance. HashScheme names the digest scheme this event was
	// written under and HashKeyID the key generation, so verification
	// reproduces what was written rather than what the current config would
	// write. Both empty means a row written before schemes were recorded.
	HashScheme string `json:"hash_scheme,omitempty"`
	HashKeyID  string `json:"hash_key_id,omitempty"`
```

Then update `chronicle.go` in `Record`, replacing `event.Hash = c.hasher.Compute(event.PrevHash, event)`:

```go
	digest, keyID, hErr := c.hasher.Compute(ctx, event.PrevHash, event)
	if hErr != nil {
		return fmt.Errorf("chronicle: compute hash: %w", hErr)
	}
	event.Hash = digest
	event.HashScheme = string(c.hasher.Scheme())
	event.HashKeyID = keyID
```

And `store/postgres/audit.go` in `Append`, replacing `event.Hash = hasher.Compute(event.PrevHash, event)`:

```go
	digest, keyID, hErr := hasher.Compute(ctx, event.PrevHash, event)
	if hErr != nil {
		return fmt.Errorf("compute hash for event %s: %w", event.ID, hErr)
	}
	event.Hash = digest
	event.HashScheme = string(hasher.Scheme())
	event.HashKeyID = keyID
```

The columns backing these fields arrive in Task 4. Until then the values round-trip through the memory store only, which is what Task 3 tests.

---

### Task 3: Scheme fields on Event, Stream, and StreamInfo

**Files:**
- Modify: `stream/stream.go` (the `Stream` struct)
- Modify: `chronicle.go` (the `StreamInfo` struct, and the `Record` and `resolveStream` bodies)
- Modify: `store/memory/store.go`
- Test: `store/memory/scheme_test.go`

**Interfaces:**
- Consumes: `hash.Scheme`, `hash.Pin` from Task 2.
- Consumes also: `audit.Event.HashScheme` and `audit.Event.HashKeyID`, added in Task 2.
- Produces: `stream.Stream.Scheme string`, `stream.Stream.SchemeSince uint64`, `chronicle.StreamInfo.Scheme string`, `chronicle.StreamInfo.SchemeSince uint64`.

- [ ] **Step 1: Write the failing test**

Create `store/memory/scheme_test.go`:

```go
package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store/memory"
)

func TestEventSchemeFieldsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	eventID := id.NewAuditID()
	if err := s.Append(ctx, &audit.Event{
		ID:         eventID,
		Timestamp:  time.Now().UTC(),
		Sequence:   1,
		Hash:       "abc",
		AppID:      "app",
		Action:     "login",
		Resource:   "session",
		Category:   "auth",
		Outcome:    audit.OutcomeSuccess,
		Severity:   audit.SeverityInfo,
		HashScheme: "chronicle/v3",
		HashKeyID:  "hmac-1",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := s.Get(ctx, eventID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HashScheme != "chronicle/v3" {
		t.Errorf("HashScheme = %q, want chronicle/v3", got.HashScheme)
	}
	if got.HashKeyID != "hmac-1" {
		t.Errorf("HashKeyID = %q, want hmac-1", got.HashKeyID)
	}
}

func TestStreamSchemePinRoundTrips(t *testing.T) {
	ctx := context.Background()
	s := memory.New()

	info := &chronicle.StreamInfo{
		ID:          id.NewStreamID(),
		AppID:       "app",
		TenantID:    "tenant",
		Scheme:      "chronicle/v3",
		SchemeSince: 84301,
	}
	if err := s.CreateStreamInfo(ctx, info); err != nil {
		t.Fatalf("CreateStreamInfo: %v", err)
	}

	got, err := s.GetStreamByScope(ctx, "app", "tenant")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	if got.Scheme != "chronicle/v3" {
		t.Errorf("Scheme = %q, want chronicle/v3", got.Scheme)
	}
	if got.SchemeSince != 84301 {
		t.Errorf("SchemeSince = %d, want 84301", got.SchemeSince)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./store/memory/ -run 'Scheme' -v`
Expected: build failure, `unknown field HashScheme in struct literal`.

- [ ] **Step 3: Write the implementation**

In `stream/stream.go`, add to `Stream`:

```go
	// Scheme is the digest scheme this stream is pinned to, and SchemeSince the
	// first sequence it applies from. Events below SchemeSince predate the pin.
	Scheme      string `json:"scheme"`
	SchemeSince uint64 `json:"scheme_since"`
```

In `chronicle.go`, add the same two fields to `StreamInfo`:

```go
	Scheme      string
	SchemeSince uint64
```

In `chronicle.go`, `resolveStream` pins a newly created stream to the chain's scheme from its first event:

```go
	// A new stream is pinned from sequence 1, so every event it will ever hold
	// is covered by the pin and none of them fall into the tolerant window.
	s = &StreamInfo{
		ID:          id.NewStreamID(),
		AppID:       appID,
		TenantID:    tenantID,
		Scheme:      string(c.hasher.Scheme()),
		SchemeSince: 1,
	}
```

In `store/memory/store.go`, carry the two new stream fields through `CreateStreamInfo`, `GetStreamByScope`, and any `StreamInfo` to `stream.Stream` conversion. Events are stored as whole `*audit.Event` values, so the event fields need no change beyond confirming `cloneEvents` copies the struct (it does; it is a value copy).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./store/memory/ ./audit/ ./stream/ ./... -count=1`
Expected: PASS across the module.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./...
git add stream/stream.go chronicle.go store/memory/
git commit -m "feat(audit): record the digest scheme and key on events and streams"
```

---

### Task 4: Postgres and SQLite migration 006

**Files:**
- Modify: `store/postgres/migrations.go`
- Modify: `store/postgres/models.go`
- Modify: `store/sqlite/migrations.go`
- Modify: `store/sqlite/models.go`
- Delete: `store/postgres/migrations/*.sql`
- Test: `store/sqlite/scheme_test.go`

**Interfaces:**
- Consumes: the struct fields from Task 3.
- Produces: `chronicle_events.hash_scheme`, `chronicle_events.hash_key_id`, `chronicle_streams.scheme`, `chronicle_streams.scheme_since` on both backends.

- [ ] **Step 1: Write the failing test**

Create `store/sqlite/scheme_test.go`, following the setup helper already used in `store/sqlite/audit_test.go` (read that file first and reuse its store constructor):

```go
package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// Existing streams must land in the tolerant window, so every row written
// before the migration keeps verifying and everything after it is strict.
func TestMigrationPinsExistingStreamsAboveTheirHead(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t) // the helper from audit_test.go

	info := &chronicle.StreamInfo{ID: id.NewStreamID(), AppID: "app", TenantID: "t"}
	if err := s.CreateStreamInfo(ctx, info); err != nil {
		t.Fatalf("CreateStreamInfo: %v", err)
	}

	got, err := s.GetStreamByScope(ctx, "app", "t")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	if got.Scheme == "" {
		t.Error("Scheme is empty; the migration default did not apply")
	}
}

func TestEventSchemeColumnsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	info := &chronicle.StreamInfo{ID: id.NewStreamID(), AppID: "app", SchemeSince: 1, Scheme: "chronicle/v3"}
	if err := s.CreateStreamInfo(ctx, info); err != nil {
		t.Fatalf("CreateStreamInfo: %v", err)
	}

	eventID := id.NewAuditID()
	if err := s.Append(ctx, &audit.Event{
		ID: eventID, StreamID: info.ID, Timestamp: time.Now().UTC(),
		AppID: "app", Action: "login", Resource: "session", Category: "auth",
		Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
		HashScheme: "chronicle/v3", HashKeyID: "hmac-1",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := s.Get(ctx, eventID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HashScheme != "chronicle/v3" || got.HashKeyID != "hmac-1" {
		t.Errorf("scheme columns = (%q, %q), want (chronicle/v3, hmac-1)", got.HashScheme, got.HashKeyID)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./store/sqlite/ -run 'Scheme|Migration' -v`
Expected: FAIL, the columns do not exist.

- [ ] **Step 3: Write the implementation**

Append to the `Migrations.MustRegister(...)` list in `store/postgres/migrations.go`:

```go
		&migrate.Migration{
			Name:    "record_hash_scheme",
			Version: "20240101000006",
			Comment: "Record the digest scheme per event and pin it per stream",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				// Non-volatile defaults, so Postgres 11+ takes the metadata-only
				// path and does not rewrite the events table.
				_, err := exec.Exec(ctx, `
ALTER TABLE chronicle_events
    ADD COLUMN IF NOT EXISTS hash_scheme TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS hash_key_id TEXT NOT NULL DEFAULT '';

ALTER TABLE chronicle_streams
    ADD COLUMN IF NOT EXISTS scheme       TEXT   NOT NULL DEFAULT 'chronicle/v2',
    ADD COLUMN IF NOT EXISTS scheme_since BIGINT NOT NULL DEFAULT 0;

-- Every event that already exists predates the pin, so put the pin just past
-- the current head. Those rows keep verifying under the tolerant path and
-- everything written from now on is resolved strictly.
UPDATE chronicle_streams SET scheme_since = head_seq + 1 WHERE scheme_since = 0;
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE chronicle_streams DROP COLUMN IF EXISTS scheme_since;
ALTER TABLE chronicle_streams DROP COLUMN IF EXISTS scheme;
ALTER TABLE chronicle_events DROP COLUMN IF EXISTS hash_key_id;
ALTER TABLE chronicle_events DROP COLUMN IF EXISTS hash_scheme;
`)
				return err
			},
		},
```

Add the same migration to `store/sqlite/migrations.go`, with SQLite's one-column-per-statement form:

```go
		&migrate.Migration{
			Name:    "record_hash_scheme",
			Version: "20240101000006",
			Comment: "Record the digest scheme per event and pin it per stream",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				// chronicle_events and chronicle_streams are never rebuilt by an
				// earlier migration, so plain ADD COLUMN is safe here. Note the
				// rebuild of chronicle_retention_policies above: anything added
				// to a rebuilt table has to go in its CREATE, not its copy list.
				_, err := exec.Exec(ctx, `
ALTER TABLE chronicle_events  ADD COLUMN hash_scheme  TEXT NOT NULL DEFAULT '';
ALTER TABLE chronicle_events  ADD COLUMN hash_key_id  TEXT NOT NULL DEFAULT '';
ALTER TABLE chronicle_streams ADD COLUMN scheme       TEXT NOT NULL DEFAULT 'chronicle/v2';
ALTER TABLE chronicle_streams ADD COLUMN scheme_since INTEGER NOT NULL DEFAULT 0;
UPDATE chronicle_streams SET scheme_since = head_seq + 1 WHERE scheme_since = 0;
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
ALTER TABLE chronicle_streams DROP COLUMN scheme_since;
ALTER TABLE chronicle_streams DROP COLUMN scheme;
ALTER TABLE chronicle_events  DROP COLUMN hash_key_id;
ALTER TABLE chronicle_events  DROP COLUMN hash_scheme;
`)
				return err
			},
		},
```

In `store/postgres/models.go` add to `EventModel`:

```go
	HashScheme string `grove:"hash_scheme"`
	HashKeyID  string `grove:"hash_key_id"`
```

and to `StreamModel`:

```go
	Scheme      string `grove:"scheme"`
	SchemeSince int64  `grove:"scheme_since"`
```

Carry all four through `toEvent`, `fromEvent`, `toStream`, and `fromStream`, using `safeUint64` for `SchemeSince` the way `HeadSeq` already does. Mirror every one of these changes in `store/sqlite/models.go`.

Delete the stale checked-in SQL, which stopped at migration 005 and now describes a schema the code has not used for two migrations:

```bash
git rm -r store/postgres/migrations
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./store/... -count=1`
Expected: PASS.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./...
git add store/
git commit -m "feat(store): migration 006 for hash scheme columns and stream pins

Also drops store/postgres/migrations/*.sql. Those files stopped at 005 while
migrations.go went to 006, so anyone provisioning from them or reading them
during a schema review got a schema the code has not used since the retention
scoping fix."
```

---

### Task 5: Root options and fail-closed validation

**Files:**
- Modify: `options.go`
- Modify: `config.go`
- Modify: `errors.go`
- Modify: `chronicle.go` (the `New` function)
- Test: `options_scheme_test.go`

**Interfaces:**
- Consumes: `hash.NewChain`, `hash.Scheme`, `keys.Provider`.
- Produces: `chronicle.WithDigestScheme(hash.Scheme) Option`, `chronicle.WithKeyProvider(keys.Provider) Option`, `chronicle.ErrHMACKeyUnavailable`.

- [ ] **Step 1: Write the failing test**

Create `options_scheme_test.go`:

```go
package chronicle_test

import (
	"errors"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/hash"
)

// Accepting the flag without a provider is how a deployment ends up believing
// its chain is keyed while writing plain digests.
func TestNewRefusesHMACWithoutKeyProvider(t *testing.T) {
	_, err := chronicle.New(
		chronicle.WithStore(newTestStore(t)), // the helper already in chronicle_test.go
		chronicle.WithDigestScheme(hash.SchemeHMAC),
	)
	if !errors.Is(err, chronicle.ErrHMACKeyUnavailable) {
		t.Fatalf("New error = %v, want ErrHMACKeyUnavailable", err)
	}
}

func TestNewAcceptsHMACWithKeyProvider(t *testing.T) {
	key := make([]byte, 32)
	c, err := chronicle.New(
		chronicle.WithStore(newTestStore(t)),
		chronicle.WithDigestScheme(hash.SchemeHMAC),
		chronicle.WithKeyProvider(stubProvider{key: key, activeID: "hmac-1"}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("New returned a nil Chronicle")
	}
}

func TestDefaultSchemeIsPlain(t *testing.T) {
	c, err := chronicle.New(chronicle.WithStore(newTestStore(t)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("New returned a nil Chronicle")
	}
}
```

Add a `stubProvider` to `chronicle_test.go` mirroring the one in `hash/scheme_test.go`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test . -run 'Scheme|HMAC' -v`
Expected: build failure, `undefined: chronicle.WithDigestScheme`.

- [ ] **Step 3: Write the implementation**

In `config.go` add to `Config`:

```go
	// DigestScheme selects how each event's digest is computed. The default,
	// hash.SchemePlain, is unkeyed and reproducible by anyone who can read the
	// store, so it detects corruption rather than tampering.
	//
	// hash.SchemeHMAC requires a key provider; see [ErrHMACKeyUnavailable].
	DigestScheme hash.Scheme
```

and set `DigestScheme: hash.SchemePlain` in `DefaultConfig()`.

In `errors.go`:

```go
	// ErrHMACKeyUnavailable is returned when a keyed digest scheme is selected
	// without a key provider to supply the key.
	//
	// The reasoning matches ErrCryptoErasureUnavailable: an operator who set
	// digest: hmac believes their chain cannot be recomputed from the stored
	// rows alone. Writing unkeyed digests under that belief is worse than
	// refusing to start.
	ErrHMACKeyUnavailable = errors.New(
		"chronicle: digest scheme hmac is selected but no key provider was given; " +
			"pass chronicle.WithKeyProvider(keys.NewFileProvider(path)) so digests " +
			"are keyed, or leave the digest scheme unset",
	)
```

In `options.go`:

```go
// WithDigestScheme selects how event digests are computed.
//
// hash.SchemeHMAC requires [WithKeyProvider]; without one, New returns
// [ErrHMACKeyUnavailable] rather than accepting a flag that promises a
// guarantee nothing implements. The two options may be given in either order.
func WithDigestScheme(s hash.Scheme) Option {
	return func(c *Chronicle) error {
		c.config.DigestScheme = s
		return nil
	}
}

// WithKeyProvider supplies the key material for keyed digest schemes.
//
// Rotation lives in the provider: retiring a key stops new digests using it
// while keeping old events verifiable through Provider.ByID.
func WithKeyProvider(p keys.Provider) Option {
	return func(c *Chronicle) error {
		c.keys = p
		return nil
	}
}
```

In `chronicle.go`, add a `keys keys.Provider` field to the `Chronicle` struct, and in `New`, after the options loop and beside the existing crypto-erasure check:

```go
	// Checked after every option has run, because the scheme and the provider
	// can be supplied in either order.
	if c.config.DigestScheme == hash.SchemeHMAC && c.keys == nil {
		return nil, ErrHMACKeyUnavailable
	}

	hasher, err := hash.NewChain(c.config.DigestScheme, c.keys)
	if err != nil {
		return nil, fmt.Errorf("chronicle: %w", err)
	}
	c.hasher = hasher
```

Remove `hasher: &hash.Chain{}` from the `Chronicle` literal in `New`, since `NewChain` now supplies it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test . -count=1 -v`
Expected: PASS, including the existing `chronicle_test.go` suite.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./...
git add options.go config.go errors.go chronicle.go options_scheme_test.go
git commit -m "feat: select the digest scheme, and refuse hmac without a key"
```

---

### Task 6: Postgres and SQLite append records provenance

**Files:**
- Modify: `store/postgres/audit.go` (the `Append` function, the re-link block)
- Modify: `store/postgres/store.go` (wherever the package-level `hasher` is declared)
- Modify: `store/sqlite/audit.go` if it re-links the same way
- Test: `store/sqlite/scheme_test.go` (extend)

**Interfaces:**
- Consumes: `hash.NewChain`, `keys.Provider`, the columns from Task 4.
- Produces: `postgres.WithHasher(*hash.Chain)` (or an equivalent constructor argument) so the backend re-links under the configured scheme rather than a hardcoded plain chain.

- [ ] **Step 1: Write the failing test**

Add to `store/sqlite/scheme_test.go`:

```go
// Append re-derives the sequence and prev_hash under a row lock, and therefore
// recomputes the digest. If it recomputes under a plain chain while Chronicle
// is configured for HMAC, every event silently reverts to an unkeyed digest.
func TestAppendRecomputesUnderTheConfiguredScheme(t *testing.T) {
	ctx := context.Background()
	s := newHMACTestStore(t) // wraps newTestStore with an HMAC chain; see step 3

	info := &chronicle.StreamInfo{ID: id.NewStreamID(), AppID: "app", Scheme: "chronicle/v3", SchemeSince: 1}
	if err := s.CreateStreamInfo(ctx, info); err != nil {
		t.Fatalf("CreateStreamInfo: %v", err)
	}

	eventID := id.NewAuditID()
	if err := s.Append(ctx, &audit.Event{
		ID: eventID, StreamID: info.ID, Timestamp: time.Now().UTC(),
		AppID: "app", Action: "login", Resource: "session", Category: "auth",
		Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := s.Get(ctx, eventID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HashScheme != "chronicle/v3" {
		t.Errorf("HashScheme = %q, want chronicle/v3; Append reverted to an unkeyed digest", got.HashScheme)
	}
	if got.HashKeyID == "" {
		t.Error("HashKeyID is empty; the key used for the digest was not recorded")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./store/sqlite/ -run 'AppendRecomputes' -v`
Expected: FAIL, `HashScheme = ""`.

- [ ] **Step 3: Write the implementation**

Find the package-level `hasher` in `store/postgres` (used by `Append`). Replace it with a field on `Store`, defaulting to a zero `hash.Chain`, plus an option:

```go
// WithHasher sets the chain the store re-links with.
//
// Append re-derives the sequence and prev_hash while holding the stream's row
// lock, which means it must also recompute the digest. That recomputation has
// to use the same scheme Chronicle was configured with; a store left on the
// default plain chain would quietly downgrade every event it re-linked.
func WithHasher(h *hash.Chain) Option {
	return func(s *Store) { s.hasher = h }
}
```

In `Append`, replace the re-link block with:

```go
	event.PrevHash = headHash
	digest, keyID, hErr := s.hasher.Compute(ctx, event.PrevHash, event)
	if hErr != nil {
		return fmt.Errorf("compute hash for event %s: %w", event.ID, hErr)
	}
	event.Hash = digest
	event.HashScheme = string(s.hasher.Scheme())
	event.HashKeyID = keyID
```

Make the same change in `store/sqlite/audit.go` if it re-links; if it does not, leave it and note so in the commit message. Add a `newHMACTestStore` helper to the sqlite test file that builds a store with `WithHasher(h)` where `h` comes from `hash.NewChain(hash.SchemeHMAC, stubProvider{...})`.

Wire it up where the extension constructs the store, so the configured scheme reaches the backend.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./store/... . -count=1`
Expected: PASS.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./...
git add store/
git commit -m "fix(store): re-link under the configured digest scheme, not a plain chain"
```

---

### Task 7: Verification reports downgrades

**Files:**
- Modify: `verify/verify.go` (the `Input` and `Report` types)
- Modify: `verify/verifier.go`
- Modify: `verify/store.go`
- Modify: `chronicle.go` (`VerifyEvent`, `VerifyChain`)
- Test: `verify/downgrade_test.go`

**Interfaces:**
- Consumes: `hash.Pin`, `hash.Result`, `(*hash.Chain).VerifyWithPin`.
- Produces: `verify.Report.Downgrades []uint64`, `verify.Report.Tolerant []uint64`, `verify.Input.Pin hash.Pin`, `verify.NewVerifierWithChain(Store, *hash.Chain) *Verifier`.

- [ ] **Step 1: Write the failing test**

Create `verify/downgrade_test.go`:

```go
package verify_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// fakeStore returns a fixed range of events.
type fakeStore struct{ events []*audit.Event }

func (f fakeStore) EventRange(_ context.Context, _ id.ID, _, _ uint64) ([]*audit.Event, error) {
	return f.events, nil
}
func (f fakeStore) Gaps(_ context.Context, _ id.ID, _, _ uint64) ([]uint64, error) {
	return nil, nil
}

func TestVerifyChainReportsDowngrade(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"} // mirror hash/scheme_test.go
	chain, err := hash.NewChain(hash.SchemeHMAC, provider)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	event := &audit.Event{
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Sequence:  10, Action: "login", Resource: "session", Category: "auth",
		Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
	}

	// The attacker recomputes under the weaker scheme and relabels the row.
	var plain hash.Chain
	digest, _, err := plain.Compute(ctx, "", event)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	event.Hash, event.HashScheme = digest, string(hash.SchemePlain)

	v := verify.NewVerifierWithChain(fakeStore{events: []*audit.Event{event}}, chain)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: id.NewStreamID(),
		FromSeq:  1, ToSeq: 20,
		Pin:      hash.Pin{Scheme: hash.SchemeHMAC, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if report.Valid {
		t.Error("a downgraded chain reported Valid")
	}
	if len(report.Downgrades) != 1 || report.Downgrades[0] != 10 {
		t.Errorf("Downgrades = %v, want [10]", report.Downgrades)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./verify/ -run 'Downgrade' -v`
Expected: build failure, `undefined: verify.NewVerifierWithChain`.

- [ ] **Step 3: Write the implementation**

In `verify/verify.go`, add to `Input`:

```go
	// Pin is the stream's declared scheme and the sequence it applies from.
	// A zero Pin disables downgrade detection, which is only correct for
	// callers that genuinely have no stream in hand.
	Pin hash.Pin
```

and to `Report`:

```go
	// Downgrades are sequences whose event claims a weaker digest scheme than
	// its stream pins at that point. These are tampering, not old events.
	Downgrades []uint64 `json:"downgrades,omitempty"`

	// Tolerant are sequences resolved through the pre-migration fallback,
	// where the scheme was not recorded and had to be guessed.
	Tolerant []uint64 `json:"tolerant,omitempty"`
```

In `verify/verifier.go`, add the constructor and thread the pin through:

```go
// NewVerifierWithChain creates a Verifier that verifies under a specific chain.
//
// A keyed chain needs its key provider to recompute a digest, so a verifier
// built with NewVerifier (which uses a plain chain) cannot check HMAC events.
func NewVerifierWithChain(store Store, chain *hash.Chain) *Verifier {
	return &Verifier{store: store, chain: chain}
}
```

Replace the per-event verification block inside `VerifyChain` with:

```go
		res, err := v.chain.VerifyWithPin(ctx, expectedPrevHash, event, input.Pin)
		if err != nil {
			return nil, fmt.Errorf("verify event %d: %w", event.Sequence, err)
		}
		if res.Downgrade {
			report.Valid = false
			report.Downgrades = append(report.Downgrades, event.Sequence)
		}
		if res.Tolerant {
			report.Tolerant = append(report.Tolerant, event.Sequence)
		}
		if !res.OK {
			report.Valid = false
			if !containsSeq(report.Tampered, event.Sequence) {
				report.Tampered = append(report.Tampered, event.Sequence)
			}
		}
```

In `chronicle.go`, have `VerifyChain` build the verifier with the configured chain and fill the pin from the stream:

```go
func (c *Chronicle) VerifyChain(ctx context.Context, input *verify.Input) (*verify.Report, error) {
	if c.store == nil {
		return nil, ErrNoStore
	}

	verifier := verify.NewVerifierWithChain(c.store, c.hasher)
	return verifier.VerifyChain(ctx, input)
}
```

and have `VerifyEvent` resolve the event's stream so it can pass a pin:

```go
	s, err := c.store.GetStreamByScope(ctx, event.AppID, event.TenantID)
	if err != nil {
		return false, fmt.Errorf("chronicle: resolve stream for verification: %w", err)
	}
	res, err := c.hasher.VerifyWithPin(ctx, event.PrevHash, event,
		hash.Pin{Scheme: hash.Scheme(s.Scheme), Since: s.SchemeSince})
	if err != nil {
		return false, err
	}
	return res.OK, nil
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./verify/ . -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./...
git add verify/ chronicle.go
git commit -m "feat(verify): report scheme downgrades and tolerant resolutions"
```

---

### Task 8: Extension config

**Files:**
- Modify: `extension/config.go`
- Modify: `extension/options.go`
- Modify: `extension/errors.go`
- Modify: `extension/extension.go`
- Test: `extension/config_test.go` (extend the existing file)

**Interfaces:**
- Consumes: `chronicle.WithDigestScheme`, `chronicle.WithKeyProvider`, `keys.NewFileProvider`.
- Produces: `extension.TamperEvidenceConfig{Digest string, Keys KeyConfig}`, `extension.WithDigestScheme(string) Option`, `extension.WithKeyProvider(keys.Provider) Option`, `extension.ErrKeyProviderRequired`.

- [ ] **Step 1: Write the failing test**

Add to `extension/config_test.go`:

```go
func TestTamperEvidenceValidateRejectsHMACWithoutKeys(t *testing.T) {
	cfg := extension.TamperEvidenceConfig{Digest: "hmac"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted digest: hmac with no key source, want an error")
	}
}

func TestTamperEvidenceValidateAcceptsPlain(t *testing.T) {
	cfg := extension.TamperEvidenceConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected the default plain config: %v", err)
	}
}

func TestTamperEvidenceValidateRejectsUnknownDigest(t *testing.T) {
	cfg := extension.TamperEvidenceConfig{Digest: "sha1"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted an unknown digest, want an error")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./extension/ -run 'TamperEvidence' -v`
Expected: build failure, `undefined: extension.TamperEvidenceConfig`.

- [ ] **Step 3: Write the implementation**

In `extension/config.go`:

```go
// TamperEvidenceConfig selects how the hash chain resists rewriting.
//
// The default leaves the chain unkeyed, which is reproducible by anyone who can
// write to the store. Setting digest to hmac makes a digest depend on key
// material the database does not hold.
type TamperEvidenceConfig struct {
	// Digest is "plain" (default) or "hmac".
	Digest string `json:"digest" mapstructure:"digest" yaml:"digest"`

	// Keys configures where the HMAC key comes from.
	Keys KeyConfig `json:"keys" mapstructure:"keys" yaml:"keys"`
}

// KeyConfig points at key material.
type KeyConfig struct {
	// Provider is "file", or empty to take a keys.Provider from [WithKeyProvider].
	Provider string `json:"provider" mapstructure:"provider" yaml:"provider"`

	// Path is the keyset file, for the file provider.
	Path string `json:"path" mapstructure:"path" yaml:"path"`
}

// Validate checks that a keyed digest has somewhere to get its key.
//
// Refusing here rather than at the first event means a misconfigured deployment
// fails at startup instead of writing unkeyed digests an operator believes are
// keyed.
func (c TamperEvidenceConfig) Validate() error {
	switch c.Digest {
	case "", "plain":
		return nil
	case "hmac":
		if c.Keys.Provider == "" && c.Keys.Path == "" {
			return ErrKeyProviderRequired
		}
		if c.Keys.Provider == "file" && c.Keys.Path == "" {
			return fmt.Errorf("chronicle: tamper_evidence.keys.provider is file but no path was given")
		}
		return nil
	default:
		return fmt.Errorf("chronicle: unknown tamper_evidence.digest %q; want plain or hmac", c.Digest)
	}
}
```

Add `TamperEvidence TamperEvidenceConfig` to `Config`, with the mapstructure tag `tamper_evidence`.

In `extension/errors.go`:

```go
	// ErrKeyProviderRequired is returned when a keyed digest is configured with
	// no key source.
	ErrKeyProviderRequired = errors.New(
		"chronicle: tamper_evidence.digest is hmac but no key source was configured; " +
			"set tamper_evidence.keys.provider and path, or pass extension.WithKeyProvider",
	)
```

In `extension/options.go`:

```go
// WithDigestScheme sets the digest scheme, "plain" or "hmac".
func WithDigestScheme(scheme string) Option {
	return func(e *Extension) { e.config.TamperEvidence.Digest = scheme }
}

// WithKeyProvider supplies key material directly, for deployments resolving
// keys from a KMS rather than a file.
func WithKeyProvider(p keys.Provider) Option {
	return func(e *Extension) { e.keyProvider = p }
}
```

In `extension/extension.go`, add a `keyProvider keys.Provider` field, call `Validate()` alongside the existing `Auth.Validate` call, build the provider from config when one was not supplied, and append the chronicle options:

```go
	if err := e.config.TamperEvidence.Validate(); err != nil {
		return err
	}

	if e.keyProvider == nil && e.config.TamperEvidence.Keys.Provider == "file" {
		p, err := keys.NewFileProvider(e.config.TamperEvidence.Keys.Path)
		if err != nil {
			return err
		}
		e.keyProvider = p
	}

	if e.config.TamperEvidence.Digest == "hmac" {
		chronicleOpts = append(chronicleOpts,
			chronicle.WithDigestScheme(hash.SchemeHMAC),
			chronicle.WithKeyProvider(e.keyProvider),
		)
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./extension/ -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./...
git add extension/
git commit -m "feat(extension): tamper_evidence config with startup validation"
```

---

### Task 9: The adversarial suite

**Files:**
- Create: `tamper_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1 through 8.
- Produces: nothing; this is the evidence that the controls work.

- [ ] **Step 1: Write the failing test**

Create `tamper_test.go`:

```go
package chronicle_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/verify"
)

// rewriteAndRelink plays the attacker: change a stored event, then recompute
// every digest from that point on so the chain still links. Under an unkeyed
// scheme this needs nothing but the algorithm, which ships in this repo.
func rewriteAndRelink(t *testing.T, events []*audit.Event, idx int, newUserID string) {
	t.Helper()
	ctx := context.Background()
	var plain hash.Chain

	events[idx].UserID = newUserID
	for i := idx; i < len(events); i++ {
		if i > 0 {
			events[i].PrevHash = events[i-1].Hash
		}
		digest, _, err := plain.Compute(ctx, events[i].PrevHash, events[i])
		if err != nil {
			t.Fatalf("relink: %v", err)
		}
		events[i].Hash = digest
		events[i].HashScheme = string(hash.SchemePlain)
		events[i].HashKeyID = ""
	}
}

// This test asserts that the DEFAULT configuration does NOT detect a rewrite.
//
// That is the honest statement of what an unkeyed chain gives you, and it is
// deliberately committed rather than left implicit. If someone later makes the
// plain chain detect this, that is a real change in the product's guarantee and
// this test failing is how they find out.
func TestPlainChainDoesNotDetectARewrite(t *testing.T) {
	ctx := context.Background()
	c, events, streamID := seedChain(t, hash.SchemePlain, nil)

	rewriteAndRelink(t, events, 2, "attacker-was-not-here")
	persist(t, c, events)

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatal("the plain chain detected a full relink; update this test and the README claim")
	}
}

func TestHMACChainDetectsARewrite(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	provider := stubProvider{key: key, activeID: "hmac-1"}
	c, events, streamID := seedChain(t, hash.SchemeHMAC, provider)

	rewriteAndRelink(t, events, 2, "attacker-was-not-here")
	persist(t, c, events)

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 1, ToSeq: uint64(len(events)),
		Pin: hash.Pin{Scheme: hash.SchemeHMAC, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatal("the hmac chain accepted a relinked rewrite")
	}
	if len(report.Downgrades) == 0 {
		t.Error("the relink relabelled events as plain; expected them in Downgrades")
	}
}

func TestRotatedKeyStillVerifiesOldEvents(t *testing.T) {
	ctx := context.Background()
	_ = ctx
	// Write under hmac-1, rotate the provider so hmac-2 is active while hmac-1
	// remains resolvable through ByID, then verify the whole chain.
	// Assert report.Valid is true and Downgrades is empty.
	t.Skip("implement alongside the multi-key stub provider")
}
```

Write `seedChain(t, scheme, provider) (*chronicle.Chronicle, []*audit.Event, id.ID)` and `persist(t, c, events)` helpers in the same file. `seedChain` builds a memory-backed Chronicle under the given scheme, records five events through `c.Info(...).Record()` with `scope.WithAppID`/`WithTenantID` on the context, then reads them back. `persist` writes the mutated events straight into the memory store, bypassing `Record`, which is what a SQL shell does.

Replace the `t.Skip` in `TestRotatedKeyStillVerifiesOldEvents` with a real body once the two-key stub is written. A skipped test is a placeholder and must not survive this task.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test . -run 'Tamper|Rewrite|Rotated' -v`
Expected: build failure, `undefined: seedChain`.

- [ ] **Step 3: Write the helpers and the rotation test**

Implement `seedChain`, `persist`, and a two-key `rotatingProvider` whose `Current` returns `hmac-2` and whose `ByID` resolves both `hmac-1` and `hmac-2`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test . -count=1 -race -v`
Expected: PASS, with no skipped tests.

- [ ] **Step 5: Build, vet, lint, and commit**

```bash
go build ./... && go vet ./... && golangci-lint run
go test ./... -count=1 -race
git add tamper_test.go
git commit -m "test: adversarial suite for chain rewriting and scheme downgrades

Includes a test asserting the unkeyed default does not detect a relink. That is
what the plain scheme actually gives you, and committing it stops the README's
tamper-detection claim drifting away from the code."
```

---

## Self-review

**Spec coverage for Axis 1.** Scheme constants and HMAC digests, Task 2. `keys.Provider` with `Use` and rotation, Task 1. `keys.FileProvider`, Task 1. Per-event `hash_scheme` and `hash_key_id`, Tasks 3 and 4. Per-stream `scheme` and `scheme_since`, Tasks 3 and 4. Freezing the tolerant window at `head_seq + 1`, Task 4. Downgrade detection through rank comparison, Tasks 2 and 7. Root options and `ErrHMACKeyUnavailable`, Task 5. Extension YAML and startup validation, Task 8. The adversarial table's HMAC and downgrade rows, Task 9. Deleting the stale `.sql` files, Task 4.

**Deferred to Plan B (Axis 2), all checkpoint and anchor work:** the `checkpoint` package, `Signer`, `Publisher` with `Fetch`, the checkpoints and anchors tables, the `Coverage` ladder and `HeadMatch`, verifying from genesis by default, the API routes, the compliance verification block, `fail_closed` and the lag bound, the `Checkpointer` scheduler, backend coverage with `ErrCheckpointsUnsupported`, and the `storetest` conformance suite. The adversarial table's truncation and anchor rows go there too, since they need checkpoints to exist.

**Type consistency.** `Compute` returns `(digest, keyID string, err error)` in Tasks 2, 3, 5, 6, and 9. `VerifyWithPin` returns `(hash.Result, error)` in Tasks 2 and 7. `Pin{Scheme, Since}` is spelled identically in Tasks 2, 7, and 9. `keys.Provider.Current` returns `([]byte, string, error)` in Tasks 1, 2, 5, and 9. `stubProvider` appears in `hash/scheme_test.go` (Task 2) and is copied into `chronicle_test.go` (Task 5) and `verify/downgrade_test.go` (Task 7); it is duplicated on purpose, since Go test helpers do not cross package boundaries without an exported testing package.

**Ordering.** Task 2 changes `Compute`'s signature and therefore carries the two `audit.Event` fields and both call-site updates in its own commit, so the tree builds and every suite is green at each commit boundary. Tasks run in order 1 through 9 with no exceptions.
