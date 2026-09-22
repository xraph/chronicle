# Signed checkpoints (Axis 2, part 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a rewrite of already-checkpointed events provable, by signing periodic statements about where a stream's chain stood and verifying events against them.

**Architecture:** A new `checkpoint` package holds an entity, a `Store`, a `Signer`, and a `Checkpointer` that takes a signed statement over a sequence range on a schedule. Verification gains a coverage ladder, anchors to genesis and the stream head by default, and checks each covering checkpoint's signature, its continuity with the one before it, and whether the event now at `to_seq` still hashes to the recorded value.

**Tech Stack:** Go 1.26, stdlib `crypto/ed25519`, grove ORM for Postgres/SQLite, stdlib `testing` (no testify).

**Spec:** `specs/2026-09-22-tamper-evidence-design.md`

**Predecessor:** `plans/2026-09-22-tamper-evidence-axis1.md`, complete and merged into this branch. Axis 1 built `keys`, scheme-aware `hash.Chain`, per-event and per-stream scheme recording, downgrade detection, and the config wiring. This plan consumes all of it.

## Global Constraints

- Go 1.26.0, module `github.com/xraph/chronicle`.
- No new third-party dependencies. Signing is stdlib `crypto/ed25519`.
- Tests use stdlib `testing`, no testify. Test files match their directory's package: `store/sqlite/*_test.go` is `package sqlite`, `store/memory/*_test.go` is `package memory`, most others are `package X_test`.
- `golangci-lint` runs in CI and the repo is clean. Keep it clean.
- Run `go build ./... && go vet ./...` before every commit, and `-race` on touched packages.
- `_examples/` is NOT reached by `./...` because of the leading underscore. Vet those directories individually if you touch anything they use.
- Default behaviour must not change. A deployment with no `checkpoints` config records no checkpoints, and every existing test stays green.

## What Axis 1 left you, and what it cost

These are load-bearing and already exist. Do not rebuild them.

```go
// keys
const UseCheckpointSig Use = "checkpoint-sig"   // declared in Axis 1, still unconsumed. This plan consumes it.
type Provider interface {
    Current(ctx context.Context, use Use) (key []byte, keyID string, err error)
    ByID(ctx context.Context, keyID string) (key []byte, err error)
}
var ErrKeyNotFound, ErrNoActiveKey, ErrKeyRevoked error

// hash
func Rank(s Scheme) int                          // exported in Axis 1's final fix wave
type Pin struct { Scheme Scheme; Since uint64 }
func (c *Chain) VerifyWithPin(ctx, prevHash string, event *audit.Event, pin Pin) (Result, error)

// stream.Store  (the precedent for threading a new store method through six implementations)
UpdateStreamScheme(ctx context.Context, streamID id.ID, scheme string, since uint64) error
```

Three hard-won lessons from Axis 1 that apply directly here:

**Thread new store methods through every implementation.** `stream.Store` gained `UpdateStreamScheme` and it had to land in memory, postgres, sqlite, mongo, redis and `store.Adapter`. A field or method missing from one mapper is silently dropped and every test still passes. Axis 1 lost a whole review round to exactly that in `store/adapter.go`.

**Never use the read-then-reslice flush pattern.** `batcher.Flush` and `sink.S3Sink.Flush` both read a buffer under a lock, released it, did slow work, then unconditionally re-sliced. Two concurrent calls duplicate every item and then panic on the slice bound. The `Checkpointer` has the same shape (background ticker plus an HTTP handler) so make the invariant structural: `UNIQUE(stream_id, to_seq)` is the backstop, not lock discipline.

**There is a live SQLite bug that will bite your tests.** `store/sqlite/store.go`'s `groveError` compares against `"no rows in result set"` but the driver returns `sql.ErrNoRows`, whose message carries a `sql: ` prefix. So `GetStreamByScope` never returns `chronicle.ErrStreamNotFound` and `resolveStream` cannot auto-create a stream: the first event for a brand-new scope fails on SQLite. It is unrelated to this work and is being fixed separately. Build tests on the memory store, or pre-seed the stream, and do not try to fix it here.

## What this plan does NOT build

External anchoring is part 2. That means `Publisher`, `Fetch`, the file and S3 publishers, the `chronicle_anchors` table and its retry queue, `fail_closed` with its lag bound, and the `anchored` coverage level. The `Level` type below declares `LevelAnchored` so part 2 does not have to change it, but nothing in this plan ever emits it.

Also not here: the `storetest` conformance suite, and the compliance report's verification block. Both are specced; both are separable.

## The honest limit of part 1, which you will write a test for

A checkpoint is a signed statement, so it cannot be forged without the key. But it is stored in the same database as the events. An attacker with database write access can:

- rewrite an event covered by a surviving checkpoint: **detected**, the recorded `to_hash` no longer matches
- delete a checkpoint from the middle: **detected**, continuity against `prev_checkpoint` breaks
- delete the newest checkpoints and every event after the last surviving one: **not detected**, this is truncation and needs an external anchor
- delete every checkpoint: **not detected as tampering**, but coverage drops from `signed` to `keyed`, which an operator who expects checkpoints can see

Task 9 commits tests for all four, including the two that fail to detect. Axis 1 established that pattern and it is why the limits of that work are now legible.

---

### Task 1: The `checkpoint` entity and its signer

**Files:**
- Create: `checkpoint/checkpoint.go`
- Create: `checkpoint/signer.go`
- Modify: `keys/file.go` (validate `UseCheckpointSig` material length)
- Modify: `keys/keys.go` (add `Ed25519KeySize`)
- Test: `checkpoint/signer_test.go`

**Interfaces:**
- Consumes: `keys.Provider`, `keys.UseCheckpointSig`, `keys.ErrKeyRevoked`, `id.ID`.
- Produces: `checkpoint.Checkpoint`, `checkpoint.CanonicalPayload(*Checkpoint) string`, `checkpoint.Digest(payload string) string`, `checkpoint.Signer` interface, `checkpoint.NewEd25519Signer(keys.Provider) *Ed25519Signer`, `checkpoint.AlgorithmEd25519`, `keys.Ed25519KeySize`.

- [ ] **Step 1: Write the failing test**

Create `checkpoint/signer_test.go`:

```go
package checkpoint_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
)

// stubProvider serves one ed25519 private key.
type stubProvider struct {
	key      ed25519.PrivateKey
	activeID string
	revoked  bool
}

func (s stubProvider) Current(_ context.Context, _ keys.Use) ([]byte, string, error) {
	return s.key, s.activeID, nil
}

func (s stubProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != s.activeID {
		return nil, keys.ErrKeyNotFound
	}
	if s.revoked {
		return nil, keys.ErrKeyRevoked
	}
	return s.key, nil
}

func newSigner(t *testing.T, revoked bool) (*checkpoint.Ed25519Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return checkpoint.NewEd25519Signer(stubProvider{key: priv, activeID: "cp-1", revoked: revoked}), priv
}

func newCheckpoint() *checkpoint.Checkpoint {
	return &checkpoint.Checkpoint{
		ID:             id.NewCheckpointID(),
		StreamID:       id.NewStreamID(),
		AppID:          "app",
		TenantID:       "tenant",
		FromSeq:        1,
		ToSeq:          100,
		FromHash:       "aaaa",
		ToHash:         "bbbb",
		EventCount:     100,
		PrevCheckpoint: "",
		CreatedAt:      time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC),
	}
}

func TestCanonicalPayloadIsDeterministic(t *testing.T) {
	cp := newCheckpoint()
	if checkpoint.CanonicalPayload(cp) != checkpoint.CanonicalPayload(cp) {
		t.Error("canonical payload is not deterministic")
	}
}

// Every field the checkpoint asserts must be covered, or an attacker edits the
// uncovered one and the signature still verifies.
func TestCanonicalPayloadCoversEveryAssertedField(t *testing.T) {
	base := checkpoint.CanonicalPayload(newCheckpoint())

	mutations := map[string]func(*checkpoint.Checkpoint){
		"StreamID":       func(c *checkpoint.Checkpoint) { c.StreamID = id.NewStreamID() },
		"AppID":          func(c *checkpoint.Checkpoint) { c.AppID = "other" },
		"TenantID":       func(c *checkpoint.Checkpoint) { c.TenantID = "other" },
		"FromSeq":        func(c *checkpoint.Checkpoint) { c.FromSeq = 2 },
		"ToSeq":          func(c *checkpoint.Checkpoint) { c.ToSeq = 101 },
		"FromHash":       func(c *checkpoint.Checkpoint) { c.FromHash = "cccc" },
		"ToHash":         func(c *checkpoint.Checkpoint) { c.ToHash = "cccc" },
		"EventCount":     func(c *checkpoint.Checkpoint) { c.EventCount = 99 },
		"PrevCheckpoint": func(c *checkpoint.Checkpoint) { c.PrevCheckpoint = "dddd" },
		"CreatedAt":      func(c *checkpoint.Checkpoint) { c.CreatedAt = c.CreatedAt.Add(time.Second) },
	}

	for name, mutate := range mutations {
		cp := newCheckpoint()
		mutate(cp)
		if checkpoint.CanonicalPayload(cp) == base {
			t.Errorf("%s is not covered by the canonical payload", name)
		}
	}
}

func TestSignThenVerifyRoundTrips(t *testing.T) {
	ctx := context.Background()
	signer, _ := newSigner(t, false)
	cp := newCheckpoint()

	payload := checkpoint.CanonicalPayload(cp)
	sig, keyID, alg, err := signer.Sign(ctx, []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if keyID != "cp-1" {
		t.Errorf("keyID = %q, want cp-1", keyID)
	}
	if alg != checkpoint.AlgorithmEd25519 {
		t.Errorf("alg = %q, want %q", alg, checkpoint.AlgorithmEd25519)
	}

	if err := signer.Verify(ctx, []byte(payload), sig, keyID); err != nil {
		t.Errorf("Verify on a freshly signed payload: %v", err)
	}
}

// The point of signing: altering what was asserted invalidates the signature.
func TestVerifyRejectsAnAlteredPayload(t *testing.T) {
	ctx := context.Background()
	signer, _ := newSigner(t, false)
	cp := newCheckpoint()

	sig, keyID, _, err := signer.Sign(ctx, []byte(checkpoint.CanonicalPayload(cp)))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cp.ToHash = "tampered"
	if err := signer.Verify(ctx, []byte(checkpoint.CanonicalPayload(cp)), sig, keyID); err == nil {
		t.Fatal("Verify accepted a payload altered after signing")
	}
}

func TestVerifyRejectsAnUnknownKeyID(t *testing.T) {
	ctx := context.Background()
	signer, _ := newSigner(t, false)
	payload := []byte(checkpoint.CanonicalPayload(newCheckpoint()))

	sig, _, _, err := signer.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.Verify(ctx, payload, sig, "cp-does-not-exist"); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("Verify error = %v, want ErrKeyNotFound", err)
	}
}

// Revoking the signing key must invalidate every checkpoint it signed, the same
// way revoking an hmac key invalidates the events it digested.
func TestVerifyRejectsARevokedKey(t *testing.T) {
	ctx := context.Background()
	live, priv := newSigner(t, false)
	payload := []byte(checkpoint.CanonicalPayload(newCheckpoint()))
	sig, keyID, _, err := live.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	revoked := checkpoint.NewEd25519Signer(stubProvider{key: priv, activeID: keyID, revoked: true})
	if err := revoked.Verify(ctx, payload, sig, keyID); !errors.Is(err, keys.ErrKeyRevoked) {
		t.Errorf("Verify error = %v, want ErrKeyRevoked", err)
	}
}

// A third party must be able to check a signature without the private key.
func TestPublicKeyIsDerivableForThirdPartyVerification(t *testing.T) {
	ctx := context.Background()
	signer, priv := newSigner(t, false)

	pub, err := signer.PublicKey(ctx, "cp-1")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	payload := []byte(checkpoint.CanonicalPayload(newCheckpoint()))
	sig, _, _, err := signer.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		t.Error("stdlib ed25519.Verify rejected a signature the exported public key should validate")
	}
	if !ed25519.PublicKey(pub).Equal(priv.Public()) {
		t.Error("exported public key does not match the signing key")
	}
}

func TestSignerRejectsWrongSizedKeyMaterial(t *testing.T) {
	ctx := context.Background()
	signer := checkpoint.NewEd25519Signer(stubProvider{key: make([]byte, 7), activeID: "cp-1"})
	if _, _, _, err := signer.Sign(ctx, []byte("x")); err == nil {
		t.Fatal("Sign accepted 7-byte key material for ed25519")
	}
}

func TestDigestIsHexSHA256(t *testing.T) {
	d := checkpoint.Digest("payload")
	if len(d) != 64 {
		t.Errorf("digest length = %d, want 64", len(d))
	}
	if strings.ToLower(d) != d {
		t.Error("digest should be lowercase hex")
	}
	if checkpoint.Digest("payload") != d {
		t.Error("digest is not deterministic")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./checkpoint/ -v`
Expected: build failure, `no required module provides package github.com/xraph/chronicle/checkpoint`.

- [ ] **Step 3: Write the implementation**

First, `id` needs a checkpoint identifier. Read `id/id.go` and follow how `NewStreamID`/`NewAuditID` are declared, then add `NewCheckpointID()` and `ParseCheckpointID(string)` with prefix `ckpt`, matching the existing pattern exactly.

Then add to `keys/keys.go`, beside `HMACKeySize`:

```go
// Ed25519KeySize is the required length of a UseCheckpointSig key. It is the
// full ed25519 private key, which carries its own public half in the trailing
// 32 bytes, so a verifier needs nothing else to check a signature.
const Ed25519KeySize = 64
```

And in `keys/file.go`, extend the per-entry validation that already checks `UseHMAC`:

```go
		if entry.Use == UseCheckpointSig && len(material) != Ed25519KeySize {
			return nil, fmt.Errorf(
				"keys: key %q is %d bytes; a %s key must be %d",
				entry.ID, len(material), UseCheckpointSig, Ed25519KeySize)
		}
```

Create `checkpoint/checkpoint.go`:

```go
// Package checkpoint records signed statements about where a hash chain stood,
// so that rewriting an event after the fact becomes provable.
//
// A chain of unkeyed digests can be recomputed by anyone who can write to the
// store. Keying the digest raises that bar, but both the event's scheme and its
// stream's pin live in the same database, so an attacker with write access can
// still rewrite both. A checkpoint is different: it asserts that at sequence N
// the chain hash was H, and it is signed, so the assertion cannot be restated
// without the signing key. If the event now at N hashes to something else, the
// chain was rewritten after the checkpoint was taken and the signature proves it.
package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
)

// payloadVersion prefixes the signed bytes so the canonical encoding can change
// later without a verifier misreading an old signature.
const payloadVersion = "chronicle-checkpoint/v1"

// Checkpoint is a signed statement about one stream's chain over a sequence
// range.
type Checkpoint struct {
	chronicle.Entity

	ID       id.ID `json:"id"`
	StreamID id.ID `json:"stream_id"`

	AppID    string `json:"app_id"`
	TenantID string `json:"tenant_id,omitempty"`

	// FromSeq and ToSeq bound the range this checkpoint covers, inclusive.
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`

	// FromHash and ToHash are the chain hashes at those boundaries. ToHash is
	// the assertion that matters: recomputing the event at ToSeq must reproduce
	// it, or the chain was rewritten after this checkpoint.
	FromHash string `json:"from_hash"`
	ToHash   string `json:"to_hash"`

	EventCount int64 `json:"event_count"`

	// PrevCheckpoint is the digest of the preceding checkpoint's signed payload,
	// which is what makes deleting one from the middle detectable. It is empty
	// for a stream's first checkpoint.
	PrevCheckpoint string `json:"prev_checkpoint,omitempty"`

	Algorithm string `json:"algorithm"`
	SignKeyID string `json:"sign_key_id"`
	Signature []byte `json:"signature"`

	// SignedPayload is the exact bytes that were signed. Storing them rather
	// than re-deriving from the columns means a later change to the canonical
	// encoding cannot silently invalidate every historical signature.
	SignedPayload string `json:"signed_payload"`

	CreatedAt time.Time `json:"created_at"`
}

// CanonicalPayload renders the bytes a checkpoint's signature covers.
//
// Every field the checkpoint asserts appears here. A field left out is a field
// an attacker can edit while the signature still verifies.
func CanonicalPayload(c *Checkpoint) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d|%s|%s|%d|%s|%s",
		payloadVersion,
		c.StreamID.String(),
		c.AppID,
		c.TenantID,
		c.FromSeq,
		c.ToSeq,
		c.FromHash,
		c.ToHash,
		c.EventCount,
		c.PrevCheckpoint,
		c.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
}

// Digest returns the hex SHA-256 of a canonical payload, which is what the next
// checkpoint records as its PrevCheckpoint.
func Digest(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ListOpts bounds a checkpoint listing.
type ListOpts struct {
	Limit  int
	Offset int
}
```

Create `checkpoint/signer.go`:

```go
package checkpoint

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/xraph/chronicle/keys"
)

// AlgorithmEd25519 names the signature algorithm recorded on a checkpoint.
const AlgorithmEd25519 = "ed25519"

// Signer signs and verifies checkpoint payloads.
type Signer interface {
	// Sign returns the signature, the ID of the key used, and the algorithm.
	Sign(ctx context.Context, payload []byte) (sig []byte, keyID, alg string, err error)

	// Verify checks a signature against the key that made it.
	Verify(ctx context.Context, payload, sig []byte, keyID string) error

	// PublicKey returns the public half of a signing key, so an auditor can
	// check a checkpoint without holding anything secret.
	PublicKey(ctx context.Context, keyID string) ([]byte, error)
}

// Ed25519Signer signs checkpoints with an ed25519 key from a keys.Provider.
//
// Verification resolves the key through the provider by ID, so revoking a
// signing key invalidates every checkpoint it signed. That is deliberate and
// matches how revoking an hmac key invalidates the events it digested.
type Ed25519Signer struct {
	keys keys.Provider
}

// NewEd25519Signer creates a signer backed by the given provider.
func NewEd25519Signer(provider keys.Provider) *Ed25519Signer {
	return &Ed25519Signer{keys: provider}
}

// Sign signs payload with the provider's active checkpoint key.
func (s *Ed25519Signer) Sign(ctx context.Context, payload []byte) ([]byte, string, string, error) {
	material, keyID, err := s.keys.Current(ctx, keys.UseCheckpointSig)
	if err != nil {
		return nil, "", "", fmt.Errorf("checkpoint: resolve signing key: %w", err)
	}
	if len(material) != ed25519.PrivateKeySize {
		return nil, "", "", fmt.Errorf(
			"checkpoint: signing key %q is %d bytes, want %d",
			keyID, len(material), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(ed25519.PrivateKey(material), payload), keyID, AlgorithmEd25519, nil
}

// Verify checks sig against payload under the key named by keyID.
func (s *Ed25519Signer) Verify(ctx context.Context, payload, sig []byte, keyID string) error {
	pub, err := s.PublicKey(ctx, keyID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("checkpoint: signature does not verify under key %q", keyID)
	}
	return nil
}

// PublicKey derives the public half of a stored signing key.
func (s *Ed25519Signer) PublicKey(ctx context.Context, keyID string) ([]byte, error) {
	material, err := s.keys.ByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: resolve signing key %q: %w", keyID, err)
	}
	if len(material) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"checkpoint: signing key %q is %d bytes, want %d",
			keyID, len(material), ed25519.PrivateKeySize)
	}
	pub, ok := ed25519.PrivateKey(material).Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("checkpoint: signing key %q does not yield an ed25519 public key", keyID)
	}
	return pub, nil
}

// Compile-time check.
var _ Signer = (*Ed25519Signer)(nil)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./checkpoint/ ./keys/ -v`
Expected: all PASS, including the pre-existing `keys` suite.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./... && golangci-lint run
git add checkpoint/ keys/ id/
git commit -m "feat(checkpoint): signed checkpoint entity and its ed25519 signer"
```

---

### Task 2: `checkpoint.Store` and the memory implementation

**Files:**
- Create: `checkpoint/store.go`
- Modify: `store/memory/store.go`
- Modify: `store/store.go` (embed `checkpoint.Store` in the composite)
- Test: `store/memory/checkpoint_test.go`

**Interfaces:**
- Consumes: `checkpoint.Checkpoint`, `checkpoint.ListOpts` from Task 1.
- Produces: `checkpoint.Store` with `AppendCheckpoint`, `LatestCheckpoint`, `CheckpointsInRange`, `GetCheckpoint`, `ListCheckpoints`; `chronicle.ErrCheckpointNotFound`; `chronicle.ErrCheckpointExists`; `chronicle.ErrCheckpointsUnsupported`.

- [ ] **Step 1: Write the failing test**

Create `store/memory/checkpoint_test.go`. Note the package: `store/memory/store_test.go` is an internal test (`package memory`), so match it.

```go
package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

func newCP(streamID id.ID, from, to uint64, prev string) *checkpoint.Checkpoint {
	cp := &checkpoint.Checkpoint{
		ID:             id.NewCheckpointID(),
		StreamID:       streamID,
		AppID:          "app",
		TenantID:       "tenant",
		FromSeq:        from,
		ToSeq:          to,
		FromHash:       "from",
		ToHash:         "to",
		EventCount:     int64(to - from + 1),
		PrevCheckpoint: prev,
		Algorithm:      checkpoint.AlgorithmEd25519,
		SignKeyID:      "cp-1",
		Signature:      []byte("sig"),
		CreatedAt:      time.Now().UTC(),
	}
	cp.SignedPayload = checkpoint.CanonicalPayload(cp)
	return cp
}

func TestAppendAndGetCheckpoint(t *testing.T) {
	ctx := context.Background()
	s := New()
	streamID := id.NewStreamID()

	cp := newCP(streamID, 1, 100, "")
	if err := s.AppendCheckpoint(ctx, cp); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	got, err := s.GetCheckpoint(ctx, cp.ID)
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if got.ToSeq != 100 || got.SignKeyID != "cp-1" || string(got.Signature) != "sig" {
		t.Errorf("round trip lost data: %+v", got)
	}
	if got.SignedPayload != cp.SignedPayload {
		t.Error("SignedPayload did not round trip; verification depends on the exact stored bytes")
	}
}

// The structural backstop against two checkpointers racing on one stream.
func TestAppendCheckpointRejectsADuplicateToSeq(t *testing.T) {
	ctx := context.Background()
	s := New()
	streamID := id.NewStreamID()

	if err := s.AppendCheckpoint(ctx, newCP(streamID, 1, 100, "")); err != nil {
		t.Fatalf("first AppendCheckpoint: %v", err)
	}
	err := s.AppendCheckpoint(ctx, newCP(streamID, 1, 100, ""))
	if !errors.Is(err, chronicle.ErrCheckpointExists) {
		t.Fatalf("second AppendCheckpoint error = %v, want ErrCheckpointExists", err)
	}
}

func TestLatestCheckpointReturnsTheHighestToSeq(t *testing.T) {
	ctx := context.Background()
	s := New()
	streamID := id.NewStreamID()

	for _, r := range [][2]uint64{{1, 100}, {101, 200}, {201, 300}} {
		if err := s.AppendCheckpoint(ctx, newCP(streamID, r[0], r[1], "")); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}
	}

	latest, err := s.LatestCheckpoint(ctx, streamID)
	if err != nil {
		t.Fatalf("LatestCheckpoint: %v", err)
	}
	if latest.ToSeq != 300 {
		t.Errorf("latest ToSeq = %d, want 300", latest.ToSeq)
	}
}

func TestLatestCheckpointOnAStreamWithNone(t *testing.T) {
	ctx := context.Background()
	if _, err := New().LatestCheckpoint(ctx, id.NewStreamID()); !errors.Is(err, chronicle.ErrCheckpointNotFound) {
		t.Errorf("LatestCheckpoint error = %v, want ErrCheckpointNotFound", err)
	}
}

// Verification asks for the checkpoints overlapping the range it is checking.
func TestCheckpointsInRangeOverlapsRatherThanContains(t *testing.T) {
	ctx := context.Background()
	s := New()
	streamID := id.NewStreamID()

	for _, r := range [][2]uint64{{1, 100}, {101, 200}, {201, 300}} {
		if err := s.AppendCheckpoint(ctx, newCP(streamID, r[0], r[1], "")); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}
	}

	// A range sitting inside the middle checkpoint must still return it.
	got, err := s.CheckpointsInRange(ctx, streamID, 150, 160)
	if err != nil {
		t.Fatalf("CheckpointsInRange: %v", err)
	}
	if len(got) != 1 || got[0].ToSeq != 200 {
		t.Fatalf("got %d checkpoints, want the one covering 101-200", len(got))
	}

	// A range spanning two must return both, ascending.
	got, err = s.CheckpointsInRange(ctx, streamID, 50, 250)
	if err != nil {
		t.Fatalf("CheckpointsInRange: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d checkpoints, want 3 overlapping 50-250", len(got))
	}
	if got[0].ToSeq != 100 || got[2].ToSeq != 300 {
		t.Error("CheckpointsInRange must return ascending by ToSeq")
	}
}

func TestCheckpointsAreScopedToTheirStream(t *testing.T) {
	ctx := context.Background()
	s := New()
	a, b := id.NewStreamID(), id.NewStreamID()

	if err := s.AppendCheckpoint(ctx, newCP(a, 1, 100, "")); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	got, err := s.CheckpointsInRange(ctx, b, 1, 1000)
	if err != nil {
		t.Fatalf("CheckpointsInRange: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("stream b saw %d of stream a's checkpoints", len(got))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./store/memory/ -run Checkpoint -v`
Expected: build failure, `undefined: chronicle.ErrCheckpointExists` and `s.AppendCheckpoint undefined`.

- [ ] **Step 3: Write the implementation**

Add to `errors.go` in the root package, beside the existing sentinels:

```go
	// ErrCheckpointNotFound is returned when a checkpoint cannot be found.
	ErrCheckpointNotFound = errors.New("chronicle: checkpoint not found")

	// ErrCheckpointExists is returned when a checkpoint already covers a
	// stream's sequence.
	//
	// Two checkpointers racing on one stream is expected: a background ticker
	// and an operator-triggered run can overlap. Rather than rely on lock
	// discipline, the store makes a duplicate structurally impossible and the
	// loser of the race gets this.
	ErrCheckpointExists = errors.New("chronicle: checkpoint already exists for this sequence")

	// ErrCheckpointsUnsupported is returned by backends that cannot store
	// checkpoints durably enough to be a root of trust.
	ErrCheckpointsUnsupported = errors.New("chronicle: this store does not support checkpoints")
```

Create `checkpoint/store.go`:

```go
package checkpoint

import (
	"context"

	"github.com/xraph/chronicle/id"
)

// Store persists signed checkpoints.
//
// Checkpoints are append-only. There is no update and no delete: a checkpoint
// that could be revised would assert nothing.
type Store interface {
	// AppendCheckpoint persists a checkpoint. It returns
	// chronicle.ErrCheckpointExists if one already covers the same
	// (stream, to_seq).
	AppendCheckpoint(ctx context.Context, cp *Checkpoint) error

	// LatestCheckpoint returns the checkpoint with the highest ToSeq for a
	// stream, or chronicle.ErrCheckpointNotFound when the stream has none.
	LatestCheckpoint(ctx context.Context, streamID id.ID) (*Checkpoint, error)

	// CheckpointsInRange returns every checkpoint whose range OVERLAPS
	// [fromSeq, toSeq], ascending by ToSeq.
	//
	// Overlap rather than containment, because a caller verifying sequences
	// 150 to 160 still needs the checkpoint covering 101 to 200: that is the
	// one whose assertion those events fall under.
	CheckpointsInRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*Checkpoint, error)

	// GetCheckpoint returns one checkpoint by ID.
	GetCheckpoint(ctx context.Context, checkpointID id.ID) (*Checkpoint, error)

	// ListCheckpoints returns a stream's checkpoints, newest first.
	ListCheckpoints(ctx context.Context, streamID id.ID, opts ListOpts) ([]*Checkpoint, error)
}
```

Embed it in the composite in `store/store.go`, alongside the others:

```go
	checkpoint.Store
```

Implement the five methods on `store/memory/store.go`'s `Store`. Follow the file's existing conventions exactly: a mutex-guarded slice, and clone on read the way `cloneEvent` does, because a caller adjusting a returned field must not rewrite the persisted checkpoint. Add a `checkpoints []*checkpoint.Checkpoint` field and initialise it in `New`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./store/memory/ ./checkpoint/ -v && go test ./... -count=1`
Expected: PASS. The composite now requires `checkpoint.Store`, so postgres, sqlite, mongo and redis will fail to compile until Task 3. To keep this task's commit building, add a temporary stub returning `chronicle.ErrCheckpointsUnsupported` on each of those four, and note in your report that Task 3 replaces three of them with real implementations.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./... && golangci-lint run
git add checkpoint/ errors.go store/
git commit -m "feat(checkpoint): store interface with the memory implementation"
```

---

### Task 3: Migration 007 and the SQL, Mongo and Redis backends

**Files:**
- Modify: `store/postgres/migrations.go`, `store/postgres/models.go`, create `store/postgres/checkpoint.go`
- Modify: `store/sqlite/migrations.go`, `store/sqlite/models.go`, create `store/sqlite/checkpoint.go`
- Modify: `store/mongo/models.go`, create `store/mongo/checkpoint.go`
- Modify: `store/redis/checkpoint.go` (keep the unsupported stub, make it deliberate)
- Test: `store/sqlite/checkpoint_test.go`

**Interfaces:**
- Consumes: `checkpoint.Store` from Task 2.
- Produces: `chronicle_checkpoints` on Postgres and SQLite; working `checkpoint.Store` on postgres, sqlite, mongo; `ErrCheckpointsUnsupported` on redis.

- [ ] **Step 1: Write the failing test**

Create `store/sqlite/checkpoint_test.go`, `package sqlite` (internal, matching `audit_test.go` and reusing its unexported `newTestStore` helper):

```go
package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

func seedStreamFor(t *testing.T, s *Store, streamID id.ID) {
	t.Helper()
	// Pre-seed rather than letting Chronicle create it: GetStreamByScope cannot
	// return ErrStreamNotFound on this backend yet, so resolveStream's
	// auto-create path is unreachable. Unrelated bug, fixed separately.
	if err := s.CreateStream(context.Background(), &stream.Stream{
		ID: streamID, AppID: "app", TenantID: "tenant",
		Scheme: "chronicle/v2", SchemeSince: 1,
	}); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
}

func newCP(streamID id.ID, from, to uint64, prev string) *checkpoint.Checkpoint {
	cp := &checkpoint.Checkpoint{
		ID: id.NewCheckpointID(), StreamID: streamID,
		AppID: "app", TenantID: "tenant",
		FromSeq: from, ToSeq: to, FromHash: "from", ToHash: "to",
		EventCount: int64(to - from + 1), PrevCheckpoint: prev,
		Algorithm: checkpoint.AlgorithmEd25519, SignKeyID: "cp-1",
		Signature: []byte{0x01, 0x02, 0x03},
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	cp.SignedPayload = checkpoint.CanonicalPayload(cp)
	return cp
}

func TestCheckpointRoundTripsThroughSQLite(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	streamID := id.NewStreamID()
	seedStreamFor(t, s, streamID)

	cp := newCP(streamID, 1, 100, "prevdigest")
	if err := s.AppendCheckpoint(ctx, cp); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	got, err := s.GetCheckpoint(ctx, cp.ID)
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if got.SignedPayload != cp.SignedPayload {
		t.Errorf("SignedPayload = %q, want %q", got.SignedPayload, cp.SignedPayload)
	}
	if string(got.Signature) != string(cp.Signature) {
		t.Errorf("Signature = %v, want %v", got.Signature, cp.Signature)
	}
	if got.PrevCheckpoint != "prevdigest" {
		t.Errorf("PrevCheckpoint = %q, want prevdigest", got.PrevCheckpoint)
	}
	if got.EventCount != 100 || got.FromSeq != 1 || got.ToSeq != 100 {
		t.Errorf("range fields lost: %+v", got)
	}
}

// The database is the backstop against two checkpointers racing.
func TestSQLiteRejectsADuplicateCheckpointSequence(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	streamID := id.NewStreamID()
	seedStreamFor(t, s, streamID)

	if err := s.AppendCheckpoint(ctx, newCP(streamID, 1, 100, "")); err != nil {
		t.Fatalf("first AppendCheckpoint: %v", err)
	}
	err := s.AppendCheckpoint(ctx, newCP(streamID, 1, 100, ""))
	if !errors.Is(err, chronicle.ErrCheckpointExists) {
		t.Fatalf("second AppendCheckpoint error = %v, want ErrCheckpointExists", err)
	}
}

func TestSQLiteCheckpointsInRangeOverlaps(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	streamID := id.NewStreamID()
	seedStreamFor(t, s, streamID)

	for _, r := range [][2]uint64{{1, 100}, {101, 200}, {201, 300}} {
		if err := s.AppendCheckpoint(ctx, newCP(streamID, r[0], r[1], "")); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}
	}

	got, err := s.CheckpointsInRange(ctx, streamID, 150, 160)
	if err != nil {
		t.Fatalf("CheckpointsInRange: %v", err)
	}
	if len(got) != 1 || got[0].ToSeq != 200 {
		t.Fatalf("got %d, want the checkpoint covering 101-200", len(got))
	}

	latest, err := s.LatestCheckpoint(ctx, streamID)
	if err != nil {
		t.Fatalf("LatestCheckpoint: %v", err)
	}
	if latest.ToSeq != 300 {
		t.Errorf("latest ToSeq = %d, want 300", latest.ToSeq)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./store/sqlite/ -run Checkpoint -v`
Expected: FAIL, the table does not exist and the stub returns `ErrCheckpointsUnsupported`.

- [ ] **Step 3: Write the implementation**

Append a migration to `store/postgres/migrations.go`'s `MustRegister` list:

```go
		&migrate.Migration{
			Name:    "create_checkpoints_table",
			Version: "20240101000007",
			Comment: "Signed checkpoints over a stream's sequence range",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_checkpoints (
    id              TEXT PRIMARY KEY,
    stream_id       TEXT NOT NULL REFERENCES chronicle_streams(id),
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    from_seq        BIGINT NOT NULL,
    to_seq          BIGINT NOT NULL,
    from_hash       TEXT NOT NULL,
    to_hash         TEXT NOT NULL,
    event_count     BIGINT NOT NULL,
    prev_checkpoint TEXT NOT NULL DEFAULT '',
    algorithm       TEXT NOT NULL,
    sign_key_id     TEXT NOT NULL,
    signature       BYTEA NOT NULL,
    signed_payload  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(stream_id, to_seq)
);

CREATE INDEX IF NOT EXISTS idx_chronicle_checkpoints_stream
    ON chronicle_checkpoints (stream_id, to_seq DESC);
CREATE INDEX IF NOT EXISTS idx_chronicle_checkpoints_scope
    ON chronicle_checkpoints (app_id, tenant_id, created_at DESC);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS chronicle_checkpoints CASCADE;`)
				return err
			},
		},
```

Add the same to `store/sqlite/migrations.go` with `BLOB` for `signature`, `INTEGER` for the counters, and `DATETIME` for `created_at`, matching how that file already differs from Postgres. Do not disturb the `chronicle_retention_policies` rebuild earlier in the file; this is a new table so `CREATE TABLE` is all you need.

Add a `CheckpointModel` to `store/postgres/models.go` and `store/sqlite/models.go` with grove tags matching the columns, plus `toCheckpoint`/`fromCheckpoint` converters. Follow `EventModel` and `StreamModel` exactly, including `safeUint64`/`safeInt64` on the sequence fields the way `HeadSeq` is handled on Postgres.

Create `store/postgres/checkpoint.go` and `store/sqlite/checkpoint.go` implementing the five methods. `AppendCheckpoint` must map a unique-constraint violation to `chronicle.ErrCheckpointExists`; read how `groveError` is used elsewhere in the package and follow it, but note that a uniqueness violation is a different error than a missing row, so check the driver's error text for a constraint violation as well as using `errors.Is`.

`CheckpointsInRange` overlaps, so the predicate is `from_seq <= :toSeq AND to_seq >= :fromSeq`, ordered `to_seq ASC`.

Add `store/mongo/checkpoint.go` with a `CheckpointModel` and bson tags matching the other models in that package, and a unique index on `(stream_id, to_seq)` created the way the package creates its other indexes.

For `store/redis/checkpoint.go`, keep the unsupported stub but make it deliberate and documented:

```go
// Checkpoints are deliberately unsupported on Redis.
//
// The README positions this backend as a read-through cache layer, and a cache
// is the wrong home for a root of trust: a checkpoint that can be evicted
// asserts nothing. The extension refuses to start when checkpoints are enabled
// on a backend that returns this, rather than running silently without them.
func (s *Store) AppendCheckpoint(context.Context, *checkpoint.Checkpoint) error {
	return chronicle.ErrCheckpointsUnsupported
}
```

...and the same for the other four methods.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./store/... -count=1 -v`
Expected: PASS. Postgres and Mongo have no test files in this repo, so they are compile-verified only; say so in your report rather than claiming coverage.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./... && golangci-lint run
git add store/
git commit -m "feat(store): migration 007 and checkpoint persistence across backends"
```

---

### Task 4: The `Checkpointer`

**Files:**
- Create: `checkpoint/checkpointer.go`
- Test: `checkpoint/checkpointer_test.go`

**Interfaces:**
- Consumes: `checkpoint.Store`, `checkpoint.Signer`, `stream.Store`, `verify.Store`.
- Produces: `checkpoint.NewCheckpointer(...) *Checkpointer`, `(*Checkpointer).CheckpointStream(ctx, *stream.Stream) (*Checkpoint, error)`, `checkpoint.ErrNothingToCheckpoint`.

- [ ] **Step 1: Write the failing test**

Create `checkpoint/checkpointer_test.go`:

```go
package checkpoint_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// fakeStores is the smallest thing satisfying what a Checkpointer reads.
type fakeStores struct {
	mu     sync.Mutex
	events []*audit.Event
	cps    []*checkpoint.Checkpoint
}

func (f *fakeStores) EventRange(_ context.Context, _ id.ID, from, to uint64) ([]*audit.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*audit.Event
	for _, e := range f.events {
		if e.Sequence >= from && e.Sequence <= to {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeStores) Gaps(context.Context, id.ID, uint64, uint64) ([]uint64, error) { return nil, nil }

func (f *fakeStores) AppendCheckpoint(_ context.Context, cp *checkpoint.Checkpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.cps {
		if existing.StreamID == cp.StreamID && existing.ToSeq == cp.ToSeq {
			return chronicle.ErrCheckpointExists
		}
	}
	f.cps = append(f.cps, cp)
	return nil
}

func (f *fakeStores) LatestCheckpoint(_ context.Context, streamID id.ID) (*checkpoint.Checkpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var latest *checkpoint.Checkpoint
	for _, cp := range f.cps {
		if cp.StreamID == streamID && (latest == nil || cp.ToSeq > latest.ToSeq) {
			latest = cp
		}
	}
	if latest == nil {
		return nil, chronicle.ErrCheckpointNotFound
	}
	return latest, nil
}

func (f *fakeStores) CheckpointsInRange(context.Context, id.ID, uint64, uint64) ([]*checkpoint.Checkpoint, error) {
	return nil, nil
}
func (f *fakeStores) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, chronicle.ErrCheckpointNotFound
}
func (f *fakeStores) ListCheckpoints(context.Context, id.ID, checkpoint.ListOpts) ([]*checkpoint.Checkpoint, error) {
	return nil, nil
}

func seed(f *fakeStores, streamID id.ID, n uint64) *stream.Stream {
	for i := uint64(1); i <= n; i++ {
		f.events = append(f.events, &audit.Event{
			Sequence: i, StreamID: streamID,
			Hash: "hash-" + string(rune('a'+i)), Action: "a", Resource: "r", Category: "c",
		})
	}
	return &stream.Stream{
		ID: streamID, AppID: "app", TenantID: "tenant",
		HeadSeq: n, HeadHash: f.events[n-1].Hash,
	}
}

func newCheckpointer(t *testing.T, f *fakeStores) *checkpoint.Checkpointer {
	t.Helper()
	signer, _ := newSigner(t, false) // from signer_test.go, same package
	return checkpoint.NewCheckpointer(f, f, signer, nil)
}

func TestCheckpointStreamSignsTheHeadState(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	st := seed(f, id.NewStreamID(), 10)

	cp, err := newCheckpointer(t, f).CheckpointStream(ctx, st)
	if err != nil {
		t.Fatalf("CheckpointStream: %v", err)
	}
	if cp.FromSeq != 1 || cp.ToSeq != 10 {
		t.Errorf("range = %d..%d, want 1..10", cp.FromSeq, cp.ToSeq)
	}
	if cp.ToHash != st.HeadHash {
		t.Errorf("ToHash = %q, want the stream head %q", cp.ToHash, st.HeadHash)
	}
	if cp.EventCount != 10 {
		t.Errorf("EventCount = %d, want 10", cp.EventCount)
	}
	if cp.PrevCheckpoint != "" {
		t.Error("a stream's first checkpoint must have an empty PrevCheckpoint")
	}
	if len(cp.Signature) == 0 || cp.SignKeyID == "" || cp.SignedPayload == "" {
		t.Error("checkpoint was stored unsigned")
	}
}

// Continuity is what makes deleting a checkpoint from the middle detectable.
func TestSecondCheckpointChainsToTheFirst(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	st := seed(f, id.NewStreamID(), 10)
	c := newCheckpointer(t, f)

	first, err := c.CheckpointStream(ctx, st)
	if err != nil {
		t.Fatalf("first CheckpointStream: %v", err)
	}

	// Ten more events arrive.
	for i := uint64(11); i <= 20; i++ {
		f.events = append(f.events, &audit.Event{Sequence: i, StreamID: st.ID, Hash: "h", Action: "a", Resource: "r", Category: "c"})
	}
	st.HeadSeq, st.HeadHash = 20, "h"

	second, err := c.CheckpointStream(ctx, st)
	if err != nil {
		t.Fatalf("second CheckpointStream: %v", err)
	}
	if second.FromSeq != 11 {
		t.Errorf("second FromSeq = %d, want 11 (one past the first's ToSeq)", second.FromSeq)
	}
	if second.PrevCheckpoint != checkpoint.Digest(first.SignedPayload) {
		t.Error("second checkpoint does not chain to the first's signed payload")
	}
}

func TestCheckpointStreamWithNothingNew(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	st := seed(f, id.NewStreamID(), 10)
	c := newCheckpointer(t, f)

	if _, err := c.CheckpointStream(ctx, st); err != nil {
		t.Fatalf("first CheckpointStream: %v", err)
	}
	if _, err := c.CheckpointStream(ctx, st); !errors.Is(err, checkpoint.ErrNothingToCheckpoint) {
		t.Errorf("second CheckpointStream error = %v, want ErrNothingToCheckpoint", err)
	}
}

// The shape that produced a duplicate-and-panic bug elsewhere in this repo: a
// background ticker and a handler racing. The database uniqueness constraint is
// the backstop, so exactly one wins and the loser reports cleanly.
func TestConcurrentCheckpointersProduceExactlyOne(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	st := seed(f, id.NewStreamID(), 10)
	c := newCheckpointer(t, f)

	var wg sync.WaitGroup
	results := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = c.CheckpointStream(ctx, st)
		}(i)
	}
	wg.Wait()

	var created int
	for _, err := range results {
		switch {
		case err == nil:
			created++
		case errors.Is(err, chronicle.ErrCheckpointExists), errors.Is(err, checkpoint.ErrNothingToCheckpoint):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if created != 1 {
		t.Errorf("%d checkpointers created one, want exactly 1", created)
	}
	if len(f.cps) != 1 {
		t.Errorf("%d checkpoints stored, want 1", len(f.cps))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./checkpoint/ -run Checkpoint -v`
Expected: build failure, `undefined: checkpoint.NewCheckpointer`.

- [ ] **Step 3: Write the implementation**

Create `checkpoint/checkpointer.go`:

```go
package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// ErrNothingToCheckpoint is returned when a stream has gained no events since
// its last checkpoint. It is an ordinary outcome on a quiet stream, not a fault.
var ErrNothingToCheckpoint = errors.New("checkpoint: no new events since the last checkpoint")

// EventReader is the slice of verify.Store a Checkpointer needs. It is declared
// here rather than imported so this package does not depend on verify.
type EventReader interface {
	EventRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error)
}

// Checkpointer takes signed checkpoints over a stream's sequence range.
//
// It holds its own per-stream lock rather than sharing Chronicle's. Sharing
// would make checkpointing block event writes, and that lock is already the
// per-tenant write ceiling. A checkpoint reads the head at some instant and
// signs that; concurrent appends simply land in the next window.
type Checkpointer struct {
	events EventReader
	store  Store
	signer Signer
	logger log.Logger

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
}

// NewCheckpointer creates a Checkpointer. A nil logger is replaced with a no-op.
func NewCheckpointer(events EventReader, store Store, signer Signer, logger log.Logger) *Checkpointer {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	return &Checkpointer{
		events: events, store: store, signer: signer, logger: logger,
		locks: make(map[string]*sync.Mutex),
	}
}

// lockStream serialises checkpointing of one stream and returns the unlock.
func (c *Checkpointer) lockStream(streamID id.ID) func() {
	key := streamID.String()

	c.locksMu.Lock()
	mu, ok := c.locks[key]
	if !ok {
		mu = &sync.Mutex{}
		c.locks[key] = mu
	}
	c.locksMu.Unlock()

	mu.Lock()
	return mu.Unlock
}

// CheckpointStream signs the stream's current head state and stores the result.
//
// The window runs from one past the previous checkpoint's ToSeq (or 1 for a
// stream's first) up to the stream's head.
func (c *Checkpointer) CheckpointStream(ctx context.Context, st *stream.Stream) (*Checkpoint, error) {
	unlock := c.lockStream(st.ID)
	defer unlock()

	var (
		fromSeq  uint64 = 1
		fromHash string
		prev     string
	)

	latest, err := c.store.LatestCheckpoint(ctx, st.ID)
	switch {
	case err == nil:
		fromSeq = latest.ToSeq + 1
		fromHash = latest.ToHash
		prev = Digest(latest.SignedPayload)
	case errors.Is(err, chronicle.ErrCheckpointNotFound):
		// First checkpoint for this stream; the zero values above are right.
	default:
		return nil, fmt.Errorf("checkpoint: read latest: %w", err)
	}

	if st.HeadSeq < fromSeq {
		return nil, ErrNothingToCheckpoint
	}

	events, err := c.events.EventRange(ctx, st.ID, fromSeq, st.HeadSeq)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: read events %d..%d: %w", fromSeq, st.HeadSeq, err)
	}
	if len(events) == 0 {
		return nil, ErrNothingToCheckpoint
	}

	cp := &Checkpoint{
		ID:             id.NewCheckpointID(),
		StreamID:       st.ID,
		AppID:          st.AppID,
		TenantID:       st.TenantID,
		FromSeq:        fromSeq,
		ToSeq:          st.HeadSeq,
		FromHash:       fromHash,
		ToHash:         st.HeadHash,
		EventCount:     int64(len(events)),
		PrevCheckpoint: prev,
		CreatedAt:      time.Now().UTC(),
	}

	// Render and sign before storing. The stored payload is what a verifier
	// checks, so it must be the exact bytes that went through the signer.
	cp.SignedPayload = CanonicalPayload(cp)
	sig, keyID, alg, err := c.signer.Sign(ctx, []byte(cp.SignedPayload))
	if err != nil {
		return nil, fmt.Errorf("checkpoint: sign: %w", err)
	}
	cp.Signature, cp.SignKeyID, cp.Algorithm = sig, keyID, alg

	if err := c.store.AppendCheckpoint(ctx, cp); err != nil {
		// A concurrent checkpointer winning the race is expected, not a fault.
		return nil, err
	}

	c.logger.Info("chronicle: checkpoint taken",
		log.String("stream_id", st.ID.String()),
		log.Uint64("from_seq", cp.FromSeq),
		log.Uint64("to_seq", cp.ToSeq),
		log.String("sign_key_id", cp.SignKeyID),
	)
	return cp, nil
}
```

If `log.Uint64` does not exist in `github.com/xraph/go-utils/log`, check what the package offers and use the nearest equivalent; do not add a dependency.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./checkpoint/ -v -race`
Expected: PASS, including the concurrency test under the race detector.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./... && golangci-lint run
git add checkpoint/
git commit -m "feat(checkpoint): checkpointer with per-stream locking and chained payloads"
```

---

### Task 5: Coverage, head anchoring, and genesis-by-default verification

**Files:**
- Modify: `verify/verify.go`
- Modify: `verify/verifier.go`
- Modify: `chronicle.go` (`VerifyChain` supplies head and pin)
- Modify: `handler/verify.go` (drop the `to_seq > 0` requirement, supply head)
- Modify: `dashboard/contributor.go` (supply head)
- Test: `verify/coverage_test.go`

**Interfaces:**
- Consumes: `hash.Pin`, `hash.Scheme`, `hash.Rank`.
- Produces: `verify.Level` with `LevelUnkeyed`, `LevelKeyed`, `LevelSigned`, `LevelAnchored`; `verify.Coverage{FromSeq, ToSeq, Level, Note}`; `verify.Input.HeadSeq`, `verify.Input.HeadHash`; `verify.Report.Coverage`, `verify.Report.HeadMatch`, `verify.Report.HeadSeq`, `verify.Report.Partial`.

- [ ] **Step 1: Write the failing test**

Create `verify/coverage_test.go`:

```go
package verify_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// Truncating the newest events is invisible unless the tail is compared to the
// stream head. Before this, deleting the last 500 events passed on every range.
func TestVerifyChainDetectsTruncationAgainstTheHead(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5) // helper below

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID,
		HeadSeq:  10,                    // the stream says 10
		HeadHash: "hash-that-is-gone",   // and this is its head
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.HeadMatch {
		t.Error("HeadMatch is true although the tail stops five events short of the head")
	}
	if report.Valid {
		t.Error("a truncated chain reported Valid")
	}
}

func TestVerifyChainMatchesAnIntactHead(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID,
		HeadSeq:  5,
		HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.HeadMatch {
		t.Error("HeadMatch is false on an intact chain")
	}
	if report.Partial {
		t.Error("a genesis-to-head verification should not be Partial")
	}
}

// An explicitly bounded range is legitimate, but it must say it did not cover
// the whole chain rather than implying it did.
func TestBoundedRangeReportsPartial(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, FromSeq: 2, ToSeq: 4,
		HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Partial {
		t.Error("a bounded range did not report Partial")
	}
	if report.HeadMatch {
		t.Error("a range stopping short of the head must not claim HeadMatch")
	}
}

func TestCoverageReportsKeyedForAnHMACPin(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	v := verify.NewVerifier(fakeStore{events: events})
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
		Pin: hash.Pin{Scheme: hash.SchemePlain, Since: 1},
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if len(report.Coverage) == 0 {
		t.Fatal("Coverage is empty")
	}
	if report.Coverage[0].Level != verify.LevelUnkeyed {
		t.Errorf("Level = %q, want %q for a plain pin", report.Coverage[0].Level, verify.LevelUnkeyed)
	}
}

func TestLevelsAreOrdered(t *testing.T) {
	ordered := []verify.Level{
		verify.LevelUnkeyed, verify.LevelKeyed, verify.LevelSigned, verify.LevelAnchored,
	}
	for i := 1; i < len(ordered); i++ {
		if verify.LevelRank(ordered[i]) <= verify.LevelRank(ordered[i-1]) {
			t.Errorf("%q does not rank above %q", ordered[i], ordered[i-1])
		}
	}
}
```

Write `buildChain(t, streamID, n)` and `fakeStore` in the same file. `buildChain` must produce a genuinely linked chain: compute each event's `Hash` with a zero-value `hash.Chain` over the previous hash and set `PrevHash` accordingly, so the linkage assertions in `VerifyChain` are exercised rather than bypassed. `fakeStore` implements `verify.Store` (`EventRange` and `Gaps`).

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./verify/ -run 'Coverage|Truncation|Head|Partial|Levels' -v`
Expected: build failure, `unknown field HeadSeq in struct literal`.

- [ ] **Step 3: Write the implementation**

In `verify/verify.go` add the coverage vocabulary:

```go
// Level grades how much a range's integrity actually rests on. The four are
// ordered: each implies the ones below it.
//
// A single boolean cannot express this, because assurance varies inside one
// stream. A chain migrated last month is unkeyed below its pin and keyed above
// it, and signed only as far as its last checkpoint. Flattening that into a
// green tick is what makes an auditor stop trusting the tool.
type Level string

const (
	// LevelUnkeyed means digests are reproducible by anyone who can read the
	// store. Detects corruption, not tampering.
	LevelUnkeyed Level = "unkeyed"

	// LevelKeyed means digests depend on key material the store does not hold.
	LevelKeyed Level = "keyed"

	// LevelSigned means a signed checkpoint covers the range, so a rewrite
	// after the checkpoint was taken is provable.
	LevelSigned Level = "signed"

	// LevelAnchored means a covering checkpoint was also confirmed from an
	// external publisher. Nothing emits this yet; external anchoring is the
	// next piece of work.
	LevelAnchored Level = "anchored"
)

// LevelRank orders the levels so callers can compare assurance.
func LevelRank(l Level) int {
	switch l {
	case LevelAnchored:
		return 3
	case LevelSigned:
		return 2
	case LevelKeyed:
		return 1
	default:
		return 0
	}
}

// Coverage is the assurance level over one span of sequences.
type Coverage struct {
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`
	Level   Level  `json:"level"`
	Note    string `json:"note,omitempty"`
}
```

Extend `Input`:

```go
	// HeadSeq and HeadHash are the stream's recorded head, supplied by the
	// caller because it already holds the stream row. They are what lets
	// verification notice a truncated tail: without them, deleting the newest
	// events passes on every range you think to ask about.
	HeadSeq  uint64
	HeadHash string
```

Extend `Report`:

```go
	// Partial is true when the caller bounded the range rather than verifying
	// genesis to head.
	Partial bool `json:"partial,omitempty"`

	// HeadMatch is whether the last verified hash equals the stream's recorded
	// head hash. False on a truncated chain.
	HeadMatch bool `json:"head_match"`

	// HeadSeq is the stream's recorded head at verification time.
	HeadSeq uint64 `json:"head_seq"`

	// Coverage grades assurance by span. Read it rather than Valid alone.
	Coverage []Coverage `json:"coverage,omitempty"`
```

In `verify/verifier.go`, resolve the range before reading events:

```go
	// FromSeq 0 means genesis and ToSeq 0 means the stream head, so the default
	// is to verify the whole chain. A caller that wants less says so, and gets
	// Partial set.
	fromSeq := input.FromSeq
	if fromSeq == 0 {
		fromSeq = 1
	}
	toSeq := input.ToSeq
	if toSeq == 0 {
		toSeq = input.HeadSeq
	}
	report.Partial = fromSeq > 1 || (input.HeadSeq > 0 && toSeq < input.HeadSeq)
	report.HeadSeq = input.HeadSeq
```

Use `fromSeq`/`toSeq` for both the `Gaps` and `EventRange` calls instead of `input.FromSeq`/`input.ToSeq`.

After the per-event loop, assert the tail and grade coverage:

```go
	// Anchor the tail. A chain whose last verified hash is not the stream's
	// head has had events removed from the end, which no amount of internal
	// linkage can reveal.
	if input.HeadHash != "" && !report.Partial {
		last := events[len(events)-1]
		report.HeadMatch = last.Hash == input.HeadHash && last.Sequence == input.HeadSeq
		if !report.HeadMatch {
			report.Valid = false
		}
	}

	report.Coverage = gradeCoverage(input, fromSeq, toSeq)
```

Add `gradeCoverage`, which for now grades on the pin only. Task 6 extends it with checkpoints:

```go
// gradeCoverage grades assurance across the verified span.
//
// Below the pin's Since the events predate it and were resolved tolerantly, so
// they rest on an unkeyed digest whatever the stream is pinned to now.
func gradeCoverage(input *Input, fromSeq, toSeq uint64) []Coverage {
	pinned := LevelUnkeyed
	if hash.Rank(input.Pin.Scheme) >= hash.Rank(hash.SchemeHMAC) {
		pinned = LevelKeyed
	}

	if input.Pin.Since <= fromSeq {
		return []Coverage{{FromSeq: fromSeq, ToSeq: toSeq, Level: pinned}}
	}
	if input.Pin.Since > toSeq {
		return []Coverage{{
			FromSeq: fromSeq, ToSeq: toSeq, Level: LevelUnkeyed,
			Note: "entirely below the stream's scheme pin; resolved tolerantly",
		}}
	}
	return []Coverage{
		{
			FromSeq: fromSeq, ToSeq: input.Pin.Since - 1, Level: LevelUnkeyed,
			Note: "below the stream's scheme pin; resolved tolerantly",
		},
		{FromSeq: input.Pin.Since, ToSeq: toSeq, Level: pinned},
	}
}
```

Now supply the head at all three call sites. In `chronicle.go`'s `VerifyChain`, resolve the stream and fill `HeadSeq`/`HeadHash`/`Pin` when the caller left them zero. In `handler/verify.go`, delete the `req.ToSeq == 0` rejection and set `HeadSeq: st.HeadSeq, HeadHash: st.HeadHash` on the input beside the `Pin` already there. Do the same in `dashboard/contributor.go`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./verify/ ./handler/ ./dashboard/ . -count=1 -v`
Expected: PASS. Existing handler tests that relied on `to_seq` being required will need updating; update them rather than reinstating the requirement, and say which you changed in your report.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./... && golangci-lint run
git add verify/ chronicle.go handler/ dashboard/
git commit -m "feat(verify): coverage levels, head anchoring, and genesis-by-default range"
```

---

### Task 6: Verify events against their covering checkpoints

**Files:**
- Modify: `verify/verify.go` (`CheckpointResult`, `Report.Checkpoints`, `Input.Checkpoints`)
- Modify: `verify/verifier.go`
- Modify: `chronicle.go` (pass the checkpoint store through)
- Test: `verify/checkpoint_test.go`

**Interfaces:**
- Consumes: `checkpoint.Store`, `checkpoint.Signer`, `checkpoint.CanonicalPayload`, `checkpoint.Digest`, `verify.Coverage` from Task 5.
- Produces: `verify.CheckpointResult`, `verify.NewVerifierWithCheckpoints(store, chain, cps, signer)`.

- [ ] **Step 1: Write the failing test**

Create `verify/checkpoint_test.go` with four tests. Reuse `buildChain` and `fakeStore` from `coverage_test.go` (same package).

```go
package verify_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// The whole point: a signed checkpoint says the chain hash at N was H. If the
// event now at N hashes to something else, the rewrite happened after the
// checkpoint and the signature proves it.
func TestRewriteAfterACheckpointIsDetected(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)

	cps, signer := checkpointOver(t, streamID, events) // helper below

	// The attacker rewrites the chain and relinks it perfectly.
	rewritten := buildChainWithActor(t, streamID, 5, "attacker-was-not-here")

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: rewritten}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: rewritten[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatal("a rewrite of checkpointed events reported Valid")
	}
	if len(report.Checkpoints) != 1 || report.Checkpoints[0].HashMatch {
		t.Error("the covering checkpoint did not report a ToHash mismatch")
	}
}

func TestIntactCheckpointedChainReportsSigned(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)
	cps, signer := checkpointOver(t, streamID, events)

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("an intact checkpointed chain reported invalid: %+v", report)
	}
	if len(report.Coverage) == 0 || report.Coverage[len(report.Coverage)-1].Level != verify.LevelSigned {
		t.Errorf("coverage = %+v, want the checkpointed span at %q", report.Coverage, verify.LevelSigned)
	}
	if !report.Checkpoints[0].SignatureValid || !report.Checkpoints[0].HashMatch {
		t.Error("an untampered checkpoint did not verify")
	}
}

func TestForgedCheckpointSignatureIsRejected(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 5)
	cps, signer := checkpointOver(t, streamID, events)

	// The attacker rewrites what the checkpoint asserts but cannot re-sign it.
	cps.list[0].ToHash = "forged"
	cps.list[0].SignedPayload = checkpoint.CanonicalPayload(cps.list[0])

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 5, HeadHash: events[4].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatal("a checkpoint whose payload was edited after signing reported Valid")
	}
	if report.Checkpoints[0].SignatureValid {
		t.Error("SignatureValid is true for an edited payload")
	}
}

// Continuity: deleting a checkpoint from the middle leaves a hole the next
// one's PrevCheckpoint no longer matches.
func TestDeletedMiddleCheckpointBreaksContinuity(t *testing.T) {
	ctx := context.Background()
	streamID := id.NewStreamID()
	events := buildChain(t, streamID, 15)
	cps, signer := checkpointsOverThree(t, streamID, events) // 1-5, 6-10, 11-15

	// Delete the middle one.
	cps.list = []*checkpoint.Checkpoint{cps.list[0], cps.list[2]}

	v := verify.NewVerifierWithCheckpoints(fakeStore{events: events}, nil, cps, signer)
	report, err := v.VerifyChain(ctx, &verify.Input{
		StreamID: streamID, HeadSeq: 15, HeadHash: events[14].Hash,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Valid {
		t.Fatal("a stream missing a middle checkpoint reported Valid")
	}
	var sawBreak bool
	for _, r := range report.Checkpoints {
		if !r.ContinuityOK {
			sawBreak = true
		}
	}
	if !sawBreak {
		t.Error("no checkpoint reported a continuity break")
	}
}
```

Write the helpers `checkpointOver`, `checkpointsOverThree`, `buildChainWithActor`, and a `fakeCheckpointStore` (with an exported-to-the-test `list` field) in this file.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./verify/ -run Checkpoint -v`
Expected: build failure, `undefined: verify.NewVerifierWithCheckpoints`.

- [ ] **Step 3: Write the implementation**

Add to `verify/verify.go`:

```go
// CheckpointResult is what one covering checkpoint asserted and whether it holds.
type CheckpointResult struct {
	ID      string `json:"id"`
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`

	// SignatureValid is whether the stored payload verifies under the key that
	// signed it. False means the checkpoint was edited after signing.
	SignatureValid bool `json:"signature_valid"`

	// HashMatch is whether the event now at ToSeq still hashes to the recorded
	// ToHash. False means the chain was rewritten after this checkpoint.
	HashMatch bool `json:"hash_match"`

	// ContinuityOK is whether this checkpoint follows the previous one without
	// a gap. False means a checkpoint was removed.
	ContinuityOK bool `json:"continuity_ok"`

	Note string `json:"note,omitempty"`
}
```

and to `Report`:

```go
	// Checkpoints is what each covering checkpoint asserted and whether it held.
	Checkpoints []CheckpointResult `json:"checkpoints,omitempty"`
```

In `verify/verifier.go`, add the constructor and the fields:

```go
// NewVerifierWithCheckpoints creates a Verifier that also checks signed
// checkpoints covering the range.
//
// Both cps and signer may be nil, in which case verification behaves exactly as
// it did before checkpoints existed, and coverage tops out at keyed.
func NewVerifierWithCheckpoints(store Store, chain *hash.Chain, cps checkpoint.Store, signer checkpoint.Signer) *Verifier {
	v := NewVerifierWithChain(store, chain)
	v.checkpoints, v.signer = cps, signer
	return v
}
```

After the per-event loop and the head assertion, evaluate checkpoints:

```go
	// A checkpoint is a signed assertion about where the chain stood. Three
	// things have to hold: the signature is genuine, the events still hash to
	// what it recorded, and it follows its predecessor without a gap.
	if v.checkpoints != nil && v.signer != nil {
		results, covered, err := v.verifyCheckpoints(ctx, input, fromSeq, toSeq, events)
		if err != nil {
			return nil, err
		}
		report.Checkpoints = results
		for _, r := range results {
			if !r.SignatureValid || !r.HashMatch || !r.ContinuityOK {
				report.Valid = false
			}
		}
		report.Coverage = upgradeCoverage(report.Coverage, covered)
	}
```

Implement `verifyCheckpoints` to: fetch `CheckpointsInRange`; for each, recompute `CanonicalPayload` from the stored fields and compare it to the stored `SignedPayload` (a mismatch means the row was edited, so fail `SignatureValid` without even calling the signer); call `signer.Verify` on the stored payload; find the event at `ToSeq` in `events` and compare its `Hash` to `ToHash`; and check `PrevCheckpoint` against `Digest(previous.SignedPayload)` with `FromSeq == previous.ToSeq+1`, treating the first checkpoint of a stream as continuous when `FromSeq == 1` and `PrevCheckpoint == ""`.

Implement `upgradeCoverage` to raise any span fully inside a fully-valid checkpoint's range to `LevelSigned`, splitting spans where a checkpoint covers only part of one. Leave spans below the pin at `LevelUnkeyed`, because a signature over an unkeyed digest still only proves the digest was not changed after the checkpoint.

In `chronicle.go`, have `VerifyChain` build the verifier with the checkpoint store and signer when Chronicle has them, and keep working when it does not.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./verify/ . -count=1 -v -race`
Expected: PASS.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./... && golangci-lint run
git add verify/ chronicle.go
git commit -m "feat(verify): check events against their covering signed checkpoints"
```

---

### Task 7: Admin API and dashboard

**Files:**
- Modify: `handler/api.go` (routes and `Dependencies`)
- Create: `handler/checkpoints.go`
- Modify: `handler/requests.go`
- Modify: `dashboard/pages/verify.templ` and its generated Go
- Test: `handler/checkpoints_test.go`

**Interfaces:**
- Consumes: `checkpoint.Store`, `checkpoint.Checkpointer`, `verify.Report`.
- Produces: `GET /v1/checkpoints`, `GET /v1/checkpoints/:id`, `POST /v1/checkpoints`.

- [ ] **Step 1: Write the failing test**

Create `handler/checkpoints_test.go`, `package handler_test`. It builds its own router the way `verifyEventWithChain` already does at `handler/handler_test.go:845`, because the shared `newTestSetup` does not wire a checkpoint store. `testAppID` and `testTenantID` are the constants that file already defines, and `scopedContext` is its helper.

```go
package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/handler"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store/memory"
)

type cpSetup struct {
	handler http.Handler
	store   *memory.Store
}

func newCheckpointSetup(t *testing.T) *cpSetup {
	t.Helper()
	store := memory.New()
	router := forge.NewRouter()
	api := handler.New(handler.Dependencies{
		AuditStore:      store,
		VerifyStore:     store,
		StreamStore:     store,
		ErasureStore:    store,
		RetentionStore:  store,
		ReportStore:     store,
		CheckpointStore: store,
		Logger:          log.NewNoopLogger(),
	}, router)
	api.RegisterRoutes(router)
	return &cpSetup{handler: router.Handler(), store: store}
}

func (s *cpSetup) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf := &bytes.Buffer{}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		buf = bytes.NewBuffer(b)
	}
	req, err := http.NewRequestWithContext(scopedContext(context.Background()), method, path, buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func seedCheckpoint(t *testing.T, s *cpSetup, appID, tenantID string) *checkpoint.Checkpoint {
	t.Helper()
	cp := &checkpoint.Checkpoint{
		ID: id.NewCheckpointID(), StreamID: id.NewStreamID(),
		AppID: appID, TenantID: tenantID,
		FromSeq: 1, ToSeq: 10, FromHash: "", ToHash: "head",
		EventCount: 10, Algorithm: checkpoint.AlgorithmEd25519,
		SignKeyID: "cp-1", Signature: []byte("sig"),
		CreatedAt: time.Now().UTC(),
	}
	cp.SignedPayload = checkpoint.CanonicalPayload(cp)
	if err := s.store.AppendCheckpoint(context.Background(), cp); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	return cp
}

// Checkpoints name a stream and a scope, so the listing has to be scoped the
// same way events and erasures already are.
func TestListCheckpointsIsTenantScoped(t *testing.T) {
	s := newCheckpointSetup(t)
	mine := seedCheckpoint(t, s, testAppID, testTenantID)
	seedCheckpoint(t, s, testAppID, "someone-else")

	rec := s.do(t, http.MethodGet, "/v1/checkpoints", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got []checkpoint.Checkpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if len(got) != 1 {
		t.Fatalf("got %d checkpoints, want only the caller's 1", len(got))
	}
	if got[0].ID.String() != mine.ID.String() {
		t.Errorf("returned another tenant's checkpoint")
	}
}

// 404 rather than 403, matching getEvent and getErasure, so an ID cannot be
// probed for existence across a tenant boundary.
func TestGetCheckpointRefusesAnotherTenantsIDAsNotFound(t *testing.T) {
	s := newCheckpointSetup(t)
	theirs := seedCheckpoint(t, s, testAppID, "someone-else")

	rec := s.do(t, http.MethodGet, "/v1/checkpoints/"+theirs.ID.String(), nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for another tenant's checkpoint", rec.Code)
	}
}

func TestGetCheckpointReturnsTheCallersOwn(t *testing.T) {
	s := newCheckpointSetup(t)
	mine := seedCheckpoint(t, s, testAppID, testTenantID)

	rec := s.do(t, http.MethodGet, "/v1/checkpoints/"+mine.ID.String(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got checkpoint.Checkpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SignedPayload != mine.SignedPayload {
		t.Error("SignedPayload did not survive the response; a verifier needs the exact bytes")
	}
}

// With no checkpointer configured the route must say so rather than 500, the
// way generateSOC2 handles a nil compliance engine.
func TestForceCheckpointWithoutACheckpointerIsUnavailable(t *testing.T) {
	s := newCheckpointSetup(t) // no Checkpointer in Dependencies
	rec := s.do(t, http.MethodPost, "/v1/checkpoints", map[string]any{})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when no checkpointer is configured", rec.Code)
	}
}

// The verify response is what an auditor reads, so coverage and the head
// assertion have to be in the JSON, not just in the Go struct.
func TestVerifyResponseCarriesCoverageAndHeadMatch(t *testing.T) {
	s := newCheckpointSetup(t)

	// Seed a stream and one event so verification has something to report on.
	// Follow seedEvents in handler_test.go for the shape.
	rec := s.do(t, http.MethodPost, "/v1/verify", map[string]any{
		"stream_id": seedVerifiableStream(t, s),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["coverage"]; !ok {
		t.Error("verify response has no coverage field")
	}
	if _, ok := body["head_match"]; !ok {
		t.Error("verify response has no head_match field")
	}
}
```

Write `seedVerifiableStream(t, s) string`, which creates a stream through `s.store` and records one event into it, returning the stream ID. Model it on `seedEvents` in `handler/handler_test.go`. Note that `POST /v1/verify` no longer requires `to_seq`, which Task 5 changed; that is what this test relies on.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./handler/ -run Checkpoint -v`
Expected: build failure, the routes and handlers do not exist.

- [ ] **Step 3: Write the implementation**

Add `CheckpointStore checkpoint.Store` and `Checkpointer *checkpoint.Checkpointer` to `handler.Dependencies`, both optional.

Create `handler/checkpoints.go` with `listCheckpoints`, `getCheckpoint` and `forceCheckpoint`, following `handler/erasure.go` exactly for scope handling: call `scopedContext`, then `requireScope`, then check ownership with `ownedByCaller` and return `forge.NotFound` on a miss. When `a.deps.CheckpointStore` is nil, return `503` with a message saying checkpoints are not configured, the way `generateSOC2` handles a nil compliance engine.

Register the routes in `handler/api.go` in a new group beside the verify group:

```go
	must(g.GET("/checkpoints", a.listCheckpoints, a.read(
		forge.WithSummary("List checkpoints"),
		forge.WithOperationID("listCheckpoints"),
	)...))
	must(g.GET("/checkpoints/:id", a.getCheckpoint, a.read(
		forge.WithSummary("Get a checkpoint"),
		forge.WithOperationID("getCheckpoint"),
	)...))
	// Write, not admin: taking a checkpoint creates a record and destroys nothing.
	must(g.POST("/checkpoints", a.forceCheckpoint, a.write(
		forge.WithSummary("Take a checkpoint now"),
		forge.WithOperationID("forceCheckpoint"),
	)...))
```

In `dashboard/pages/verify.templ`, add blocks for coverage and checkpoints beside the existing Gaps, Tampered, Downgrades and Tolerant blocks. Coverage renders each span as `from-to: level` with its note. A checkpoint whose signature or hash failed renders with the destructive styling already used for Downgrades; an intact one renders muted. Regenerate the templ output with the same templ version the repo already uses and commit the generated Go.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./handler/ ./dashboard/... -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./... && golangci-lint run
git add handler/ dashboard/
git commit -m "feat(handler): checkpoint routes, and coverage on the verify page"
```

---

### Task 8: Extension configuration and the scheduler

**Files:**
- Modify: `extension/config.go`, `extension/options.go`, `extension/errors.go`, `extension/extension.go`
- Test: `extension/checkpoints_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1 through 7.
- Produces: `extension.CheckpointConfig`, `extension.WithCheckpoints`, `extension.ErrCheckpointSignerRequired`, `extension.ErrCheckpointsUnsupportedByStore`.

- [ ] **Step 1: Write the failing test**

Create `extension/checkpoints_test.go`, `package extension_test`, with five tests:

`TestCheckpointConfigValidateRejectsEnabledWithoutSigner` asserts `ErrCheckpointSignerRequired`.
`TestCheckpointConfigValidateAcceptsDisabled` asserts the zero config is fine.
`TestRegisterRefusesCheckpointsOnRedis` asserts `ErrCheckpointsUnsupportedByStore`, because running silently without checkpoints is the failure this whole feature exists to prevent.
`TestCheckpointsReachTheCheckpointerThroughYAML` writes a real `config.yaml` with a `checkpoints` block and asserts the extension ends up with a live checkpointer. Axis 1 found that `mergeConfigurations` silently drops any config block nobody added to it, so this test is the guard against the same bug reappearing.
`TestDefaultConfigTakesNoCheckpoints` asserts a deployment with no `checkpoints` block records none.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./extension/ -run Checkpoint -v`
Expected: build failure, `undefined: extension.CheckpointConfig`.

- [ ] **Step 3: Write the implementation**

Add to `extension/config.go`:

```go
// CheckpointConfig controls periodic signed checkpoints.
//
// A checkpoint is a signed statement about where a stream's chain stood.
// Keying the digest stops per-event forgery; a checkpoint is what makes a
// later rewrite of already-recorded events provable, because the assertion
// cannot be restated without the signing key.
type CheckpointConfig struct {
	// Enabled turns on periodic checkpointing.
	Enabled bool `json:"enabled" mapstructure:"enabled" yaml:"enabled"`

	// EveryEvents takes a checkpoint once a stream has gained this many events.
	EveryEvents int `json:"every_events" mapstructure:"every_events" yaml:"every_events"`

	// EveryInterval takes one at least this often, whatever the volume.
	//
	// The interval matters more than it looks: the window between checkpoints
	// is exactly the span an attacker can still rewrite, so a quiet stream that
	// never reaches EveryEvents would otherwise sit unprotected indefinitely.
	EveryInterval time.Duration `json:"every_interval" mapstructure:"every_interval" yaml:"every_interval"`

	// Signer configures where the ed25519 signing key comes from.
	Signer KeyConfig `json:"signer" mapstructure:"signer" yaml:"signer"`
}

// Validate checks that enabled checkpointing has somewhere to get a key.
func (c CheckpointConfig) Validate(hasSigner bool) error {
	if !c.Enabled {
		return nil
	}
	if !hasSigner && c.Signer.Provider == "" && c.Signer.Path == "" {
		return ErrCheckpointSignerRequired
	}
	if c.Signer.Provider == "file" && c.Signer.Path == "" {
		return errors.New("chronicle: checkpoints.signer.provider is file but no path was given")
	}
	if c.EveryEvents < 0 {
		return fmt.Errorf("chronicle: checkpoints.every_events is %d; it cannot be negative", c.EveryEvents)
	}
	return nil
}
```

Note the `Validate(hasSigner bool)` signature. Axis 1 learned this the hard way: a no-argument `Validate` could not see a provider supplied programmatically and wrongly rejected a documented path. `AuthConfig.Validate(routesEnabled bool)` is the house precedent.

Add `Checkpoints CheckpointConfig` to `Config` with the `checkpoints` mapstructure tag, and defaults of 10000 events / 1 hour when enabled with zeros.

**Carry `Checkpoints` through `mergeConfigurations` field by field.** This is not optional and it is the single most likely bug in this task. Read what that function does with `TamperEvidence` and do exactly the same.

In `extension.go`: build the signer in `buildCheckpointSigner` next to `buildHashChain`; after the store is resolved, probe it for checkpoint support by type-asserting `checkpoint.Store` and, if `Checkpoints.Enabled`, calling `LatestCheckpoint` against a zero stream ID and treating `ErrCheckpointsUnsupported` as a refusal with `ErrCheckpointsUnsupportedByStore`; construct the `Checkpointer`; and in `Start`, launch `runCheckpointScheduler(ctx)` beside `runRetentionScheduler`.

The scheduler ticks on `EveryInterval`, lists streams, and calls `CheckpointStream` on each, treating `ErrNothingToCheckpoint` and `ErrCheckpointExists` as ordinary and logging anything else. Follow `runRetentionScheduler`'s shape exactly, including its `ctx.Done()` handling.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./extension/ -count=1 -v -race`
Expected: PASS.

- [ ] **Step 5: Build, vet, and commit**

```bash
go build ./... && go vet ./... && golangci-lint run
git add extension/
git commit -m "feat(extension): checkpoints config, signer wiring, and the scheduler"
```

---

### Task 9: The adversarial suite, and the README

**Files:**
- Create: `checkpoint_tamper_test.go` (root, `package chronicle_test`)
- Modify: `README.md`
- Modify: `tamper_test.go` (cross-reference the new limits)

**Interfaces:**
- Consumes: everything. Produces nothing; this is the evidence.

- [ ] **Step 1: Write the failing tests**

Create `checkpoint_tamper_test.go`. Four tests, matching the four outcomes named at the top of this plan. Reuse `rewriteAndRelink`, `persist`, `seedChain` and `stubProvider` from the existing `tamper_test.go` (same package) rather than redefining them.

| Test | Asserts |
|---|---|
| `TestRewriteAfterACheckpointIsProvable` | rewrite checkpointed events, `Valid` false, the covering checkpoint reports `HashMatch: false` |
| `TestDeletingAMiddleCheckpointIsDetected` | remove one of three, `Valid` false, a `ContinuityOK: false` appears |
| `TestTruncationBeyondTheLastCheckpointIsNotDetected` | delete the newest checkpoint and every event after the previous one, assert `Valid` **true**, documenting that truncation needs an external anchor |
| `TestDeletingEveryCheckpointDropsCoverageNotValidity` | remove all checkpoints, assert `Valid` true but no coverage span reaches `LevelSigned` |

The last two assert that something is NOT detected. That is deliberate, exactly as `TestPlainChainDoesNotDetectARewrite` is in `tamper_test.go`. Comment both with what closes the gap: external anchoring. Make their failure messages print the report, so if the behaviour ever changes the next engineer sees why rather than being pointed at a stale claim.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test . -run 'Checkpoint|Truncation|Deleting' -v`
Expected: build failure or assertion failures naming the missing wiring.

- [ ] **Step 3: Implement the helpers and prove each test by mutation**

For every test in the table, break the control it exercises, confirm the test fails, restore, confirm it passes. Record each mutation and its output in your report. A test that passes for the wrong reason is worse than no test here, because this suite is the evidence the feature works.

- [ ] **Step 4: Run with race and the full suite**

Run: `go test ./... -count=1 -race`
Expected: PASS, no skipped tests anywhere in the new file.

- [ ] **Step 5: Update the README, then commit**

Extend `README.md`'s Tamper evidence section with a Checkpoints subsection covering: what to configure, what a checkpoint proves, and precisely what it does not. State that a rewrite of checkpointed events is provable, that a deleted middle checkpoint is detectable, and that truncation past the last checkpoint is not, because a local checkpoint lives in the same database as the events. Say that external anchoring closes it and is the next piece of work.

Correct anything in the existing Tamper evidence prose that checkpoints now make inaccurate.

**README prose rules, strictly:** no em dashes, ever. Use a comma, a full stop, a colon, or parentheses. Address the reader as "you". Vary sentence length hard. Put the practical before the rationale. Do not open paragraph after paragraph with a bolded lead-in. Keep the file's existing list formatting; do not restyle the rest.

```bash
go build ./... && go vet ./... && golangci-lint run
go test ./... -count=1 -race
git add checkpoint_tamper_test.go tamper_test.go README.md
git commit -m "test: adversarial suite for checkpoint tampering, and README on its limits"
```

---

## Self-review

**Spec coverage for part 1.** `checkpoint` package with its own entity and Store embedded in the composite: Tasks 1 to 3. `Signer` as an interface with an ed25519 implementation over `keys.Provider`, consuming the `UseCheckpointSig` constant Axis 1 declared: Task 1. `signed_payload` stored rather than re-derived, and `prev_checkpoint` holding the SHA-256 of the previous payload as pinned in the spec's own self-review: Tasks 1 and 3. `UNIQUE(stream_id, to_seq)` as the structural backstop against racing checkpointers: Tasks 3 and 4. Per-stream lock separate from `Chronicle.lockStream`: Task 4. The ordered coverage ladder with the highest satisfied level winning: Tasks 5 and 6. Genesis-to-head by default with `Partial` on a bounded range, and the tail asserted against the stream head: Task 5. Signature, continuity and `to_hash` checks: Task 6. API routes with `POST /v1/checkpoints` under the write guard because it destroys nothing: Task 7. Cadence as events-or-interval, whichever first, with the interval justified: Task 8. `ErrCheckpointsUnsupported` on Redis and a startup refusal rather than silent omission: Tasks 3 and 8.

**Deliberately deferred to part 2:** `Publisher` and its `Fetch`, the file and S3 publishers, `chronicle_anchors` and its retry queue, `fail_closed` with the unanchored lag bound, `verify_anchors` and the `LevelAnchored` emission, and the anchors API. `LevelAnchored` is declared in Task 5 so part 2 changes no types.

**Also deferred, and separable:** the `storetest` conformance suite, and the compliance report's verification block. Both are specced, neither is needed for checkpoints to work.

**Placeholder scan.** No TBDs. Task 3 names Postgres and Mongo as compile-verified only, which is a stated limitation rather than a gap: neither has a test file in this repo, and standing up live servers is outside this plan. Every task carries its test code in full. Task 7's file builds its own router rather than reusing `newTestSetup`, because that helper wires no checkpoint store; it reuses `testAppID`, `testTenantID` and `scopedContext` from `handler/handler_test.go`, and names one helper (`seedVerifiableStream`) for the implementer to write against an existing model in that file.

**Type consistency.** `Checkpoint` fields are spelled identically in Tasks 1, 2, 3, 4 and 6. `CanonicalPayload` and `Digest` take and return the same types in Tasks 1, 4 and 6. `Signer`'s four methods match across Tasks 1, 4 and 6. `checkpoint.Store`'s five methods match across Tasks 2, 3, 4 and 6. `Level` and `LevelRank` are consistent across Tasks 5, 6 and 9. `Input.HeadSeq`/`HeadHash` are introduced in Task 5 and consumed in 5, 6, 7 and 9.

**Known ordering hazard.** Task 2 embeds `checkpoint.Store` in the composite, which breaks four backends until Task 3. Task 2's Step 4 says to add temporary unsupported stubs so every commit builds, and Task 3 replaces three of them. Run the tasks in order.
