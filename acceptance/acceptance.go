// Package acceptance defines recoverable audit ingestion contracts.
package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
)

var (
	ErrUnsupported  = errors.New("chronicle: reliable ingestion unsupported")
	ErrConflict     = errors.New("chronicle: acceptance conflict")
	ErrInvalid      = errors.New("chronicle: invalid acceptance")
	ErrHeadConflict = errors.New("chronicle: stream head conflict")
)

// Request binds a trusted source delivery to explicit scope and event content.
// Your host must authenticate Producer and Installation and authorize scope.
// SourceFingerprint describes the source envelope, not the audit event digest.
// Timestamp is required and keeps nanosecond precision. Context never overrides scope.
type Request struct {
	Producer          string       `json:"producer"`
	Installation      string       `json:"installation"`
	SourceKey         string       `json:"source_key"`
	SourceFingerprint string       `json:"source_fingerprint"`
	OrgID             string       `json:"org_id"`
	Event             *audit.Event `json:"event"`
}

// Receipt survives payload retention and erasure without an automatic expiry.
// HashScheme and HashKeyID describe the accepted digest, not signed checkpoints
// or external anchoring. A plain digest provides no protection from a database writer.
type Receipt struct {
	Producer          string `json:"producer"`
	Installation      string `json:"installation"`
	SourceKey         string `json:"source_key"`
	SourceFingerprint string `json:"source_fingerprint"`
	Fingerprint       string `json:"fingerprint"`
	AppID             string `json:"app_id"`
	OrgID             string `json:"org_id"`
	TenantID          string `json:"tenant_id"`
	EventID           id.ID  `json:"event_id"`
	StreamID          id.ID  `json:"stream_id"`
	Sequence          uint64 `json:"sequence"`
	Hash              string `json:"hash"`
	HashScheme        string `json:"hash_scheme"`
	HashKeyID         string `json:"hash_key_id"`
}

// Store serializes receipt recovery before prepare, then atomically commits the
// event, stream creation/pin/head, and receipt. prepare seals only a new event.
// It must never run for a replay or the losing concurrent first request.
type Store interface {
	Accept(context.Context, Request, *hash.Chain, func(*audit.Event) error) (*Receipt, error)
}

// Appender lets legacy writers share the backend's chain lock and configured
// hasher with reliable writers. It does not make legacy Record idempotent.
type Appender interface {
	AppendWithChain(context.Context, *audit.Event, *hash.Chain) error
}

// Identity encodes the source identity without delimiter collisions.
func Identity(r Request) string {
	return strconv.Itoa(len(r.Producer)) + ":" + r.Producer + strconv.Itoa(len(r.Installation)) + ":" + r.Installation + strconv.Itoa(len(r.SourceKey)) + ":" + r.SourceKey
}

// Normalize makes a private semantic snapshot before encryption or allocation.
// Backend identity and chain fields are excluded. Pre-sealed or erased inputs
// are rejected. JSON numbers normalize exactly without a float64 conversion.
func Normalize(r Request) (Request, string, error) {
	for _, v := range []string{r.Producer, r.Installation, r.SourceKey, r.SourceFingerprint} {
		if strings.TrimSpace(v) == "" || len(v) > 512 || strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
			return Request{}, "", ErrInvalid
		}
	}
	if r.Event == nil {
		return Request{}, "", ErrInvalid
	}
	e := *r.Event
	if e.AppID == "" || e.Timestamp.IsZero() || e.Action == "" || e.Resource == "" || e.Category == "" || e.EncryptionKeyID != "" || e.Erased || e.ErasedAt != nil || e.ErasureID != "" {
		return Request{}, "", ErrInvalid
	}
	for _, v := range []string{e.AppID, r.OrgID, e.TenantID} {
		if len(v) > 512 || strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
			return Request{}, "", ErrInvalid
		}
	}
	e.ID, e.StreamID = id.ID{}, id.ID{}
	e.Sequence = 0
	e.ExactMetadata = false
	e.Hash, e.PrevHash, e.HashScheme, e.HashKeyID = "", "", "", ""
	e.Timestamp = e.Timestamp.UTC()
	raw, err := json.Marshal(e.Metadata)
	if err != nil || len(raw) > 1048576 {
		return Request{}, "", fmt.Errorf("%w: metadata", ErrInvalid)
	}
	e.Metadata, err = normalizeMetadata(raw)
	if err != nil {
		return Request{}, "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.Event = &e
	raw, err = json.Marshal(r)
	if err != nil {
		return Request{}, "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if len(raw) > 2097152 {
		return Request{}, "", fmt.Errorf("%w: event exceeds 2 MiB", ErrInvalid)
	}
	sum := sha256.Sum256(append([]byte("chronicle/acceptance/v1\x00"), raw...))
	return r, hex.EncodeToString(sum[:]), nil
}

// Fingerprint returns the digest your adapter can check against a receipt.
func Fingerprint(r Request) (string, error) { _, f, err := Normalize(r); return f, err }

// Match returns no receipt data when the immutable binding differs.
func Match(r *Receipt, fingerprint string) (*Receipt, error) {
	if r.Fingerprint != fingerprint {
		return nil, ErrConflict
	}
	snapshot := *r
	return &snapshot, nil
}

// NewReceipt captures durable identity and actual protection provenance.
func NewReceipt(r Request, fingerprint string, e *audit.Event) *Receipt {
	return &Receipt{Producer: r.Producer, Installation: r.Installation, SourceKey: r.SourceKey, SourceFingerprint: r.SourceFingerprint, Fingerprint: fingerprint, AppID: e.AppID, OrgID: r.OrgID, TenantID: e.TenantID, EventID: e.ID, StreamID: e.StreamID, Sequence: e.Sequence, Hash: e.Hash, HashScheme: e.HashScheme, HashKeyID: e.HashKeyID}
}
