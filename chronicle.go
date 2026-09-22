package chronicle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/verify"
)

// StreamInfo is a minimal stream representation used by the Chronicle pipeline
// to avoid importing the stream package (which would create an import cycle).
type StreamInfo struct {
	ID       id.ID
	AppID    string
	TenantID string
	HeadHash string
	HeadSeq  uint64

	Scheme      string
	SchemeSince uint64
}

// Storer is the minimal store interface used by Chronicle to avoid import cycles.
// The full store.Store interface is defined in the store package.
type Storer interface {
	// Audit event operations.
	Append(ctx context.Context, event *audit.Event) error
	AppendBatch(ctx context.Context, events []*audit.Event) error
	Get(ctx context.Context, eventID id.ID) (*audit.Event, error)
	Query(ctx context.Context, q *audit.Query) (*audit.QueryResult, error)
	Aggregate(ctx context.Context, q *audit.AggregateQuery) (*audit.AggregateResult, error)
	ByUser(ctx context.Context, userID string, opts audit.TimeRange) (*audit.QueryResult, error)
	Count(ctx context.Context, q *audit.CountQuery) (int64, error)
	LastSequence(ctx context.Context, streamID id.ID) (uint64, error)
	LastHash(ctx context.Context, streamID id.ID) (string, error)

	// Stream operations for hash chain (uses StreamInfo to avoid import cycle).
	CreateStreamInfo(ctx context.Context, s *StreamInfo) error
	GetStreamByScope(ctx context.Context, appID, tenantID string) (*StreamInfo, error)
	UpdateStreamHead(ctx context.Context, streamID id.ID, hash string, seq uint64) error
	UpdateStreamScheme(ctx context.Context, streamID id.ID, scheme string, since uint64) error

	// Verification operations.
	EventRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error)
	Gaps(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]uint64, error)

	// Lifecycle.
	Migrate(ctx context.Context) error
	Ping(ctx context.Context) error
	Close() error
}

// EventSealer encrypts an event's personal payload before the event is hashed
// and stored, and is what makes crypto-erasure possible: destroying the
// subject's key leaves the payload unrecoverable.
//
// crypto.Sealer implements this. It is an interface here so the root package
// does not import crypto, which imports this package for its error sentinels.
type EventSealer interface {
	// Seal encrypts the event's personal payload in place.
	Seal(event *audit.Event) error
}

// Compile-time check: Chronicle implements Emitter.
var _ Emitter = (*Chronicle)(nil)

// Chronicle is the root audit trail engine.
// It orchestrates event recording, hash chain computation, batching,
// sink fan-out, plugin hooks, and query execution.
type Chronicle struct {
	config Config
	store  Storer
	hasher *hash.Chain
	sealer EventSealer
	keys   keys.Provider
	logger log.Logger

	// checkpointSigner is what VerifyChain checks signed checkpoints under.
	// Nil unless [WithCheckpointSigner] was given, and nil is the whole of
	// the pre-checkpoint behaviour: see newVerifier.
	checkpointSigner checkpoint.Signer

	// streamLocks serialises the hash-chain critical section per stream scope,
	// keyed by appID + "\x00" + tenantID. See Record for why this is required.
	streamLocksMu sync.Mutex
	streamLocks   map[string]*sync.Mutex
}

// lockStream serialises appends to one app+tenant stream and returns the unlock
// function.
//
// Linking an event into the chain is a read-modify-write over the stream head:
// read the head hash, derive the new hash from it, append, then advance the
// head. Two goroutines interleaving there both read the same head and produce
// two events claiming the same predecessor, which makes VerifyChain report
// tampering on a healthy log.
//
// The key is the stream's scope, so unrelated tenants never contend. Entries are
// retained for the process lifetime: they are two words each, bounded by the
// number of active scopes, and dropping one while a waiter held it would
// reintroduce the race.
//
// This guards a single process. Deployments running several replicas against one
// database also rely on the store's own transaction: the SQL backends re-derive
// the sequence and the previous hash while holding a row lock on the stream, so
// the chain stays linked even across processes.
func (c *Chronicle) lockStream(appID, tenantID string) func() {
	key := appID + "\x00" + tenantID

	c.streamLocksMu.Lock()
	if c.streamLocks == nil {
		c.streamLocks = make(map[string]*sync.Mutex)
	}
	mu, ok := c.streamLocks[key]
	if !ok {
		mu = &sync.Mutex{}
		c.streamLocks[key] = mu
	}
	c.streamLocksMu.Unlock()

	mu.Lock()
	return mu.Unlock
}

// Health checks the health of the Chronicle by pinging its store.
func (c *Chronicle) Health(ctx context.Context) error {
	if c.store != nil {
		return c.store.Ping(ctx)
	}
	return nil
}

// New creates a new Chronicle instance with the given options.
func New(opts ...Option) (*Chronicle, error) {
	c := &Chronicle{
		config: DefaultConfig(),
		logger: log.NewNoopLogger(),
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	// Checked after every option has run, because the flag and the sealer can be
	// supplied in either order.
	if c.config.EnableCryptoErasure && c.sealer == nil {
		return nil, ErrCryptoErasureUnavailable
	}

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

	return c, nil
}

// Record persists an audit event through the Chronicle pipeline.
// Pipeline: apply scope → assign ID/timestamp → validate → resolve stream →
// compute hash chain → store.Append → update stream head
func (c *Chronicle) Record(ctx context.Context, event *audit.Event) error {
	if c.store == nil {
		return ErrNoStore
	}

	// 1. Apply scope from context (fills AppID, TenantID, UserID, IP if not set).
	scope.ApplyToEvent(ctx, event)

	// 2. Assign identity if not already set.
	if event.ID.String() == "" {
		event.ID = id.NewAuditID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// 3. Validate required fields.
	if err := validateEvent(event); err != nil {
		return err
	}

	// 3a. Seal the subject's personal payload before anything hashes it.
	//
	// Order is critical: the hash must cover the stored (encrypted) bytes. If it
	// covered the plaintext, destroying a subject's key would leave every one of
	// their events unverifiable, and a healthy chain would report tampering.
	if c.sealer != nil {
		if err := c.sealer.Seal(event); err != nil {
			return fmt.Errorf("chronicle: seal event: %w", err)
		}
	}

	// Steps 4 through 7 are one critical section: reading the stream head,
	// deriving this event's hash from it, appending, and advancing the head must
	// not interleave with another append to the same stream, or two events end
	// up sharing a prev_hash and the chain verifies as tampered.
	unlock := c.lockStream(event.AppID, event.TenantID)
	defer unlock()

	// 4. Resolve or create stream for this app+tenant scope.
	s, err := c.resolveStream(ctx, event.AppID, event.TenantID)
	if err != nil {
		return fmt.Errorf("chronicle: resolve stream: %w", err)
	}

	// 5. Compute hash chain. Backends that can hold a row lock re-derive the
	// sequence and prev_hash inside their append transaction and overwrite these,
	// which is what keeps the chain linked across replicas.
	event.StreamID = s.ID
	event.Sequence = s.HeadSeq + 1
	event.PrevHash = s.HeadHash
	digest, keyID, hErr := c.hasher.Compute(ctx, event.PrevHash, event)
	if hErr != nil {
		return fmt.Errorf("chronicle: compute hash: %w", hErr)
	}
	event.Hash = digest
	event.HashScheme = string(c.hasher.Scheme())
	event.HashKeyID = keyID

	// 6. Persist to store.
	if err := c.store.Append(ctx, event); err != nil {
		return fmt.Errorf("chronicle: append: %w", err)
	}

	// 7. Update stream head. Read back from the event: a store that re-linked
	// under its own lock has updated these in place.
	if err := c.store.UpdateStreamHead(ctx, s.ID, event.Hash, event.Sequence); err != nil {
		return fmt.Errorf("chronicle: update stream head: %w", err)
	}

	return nil
}

// StoredReader is implemented by stores that decrypt on read, to expose the
// stored representation that hash verification requires.
type StoredReader interface {
	// GetStored returns an event exactly as persisted, without decrypting.
	GetStored(ctx context.Context, eventID id.ID) (*audit.Event, error)
}

// getStored fetches an event in its stored form, falling back to Get for stores
// that never transform events on read.
func getStored(ctx context.Context, s Storer, eventID id.ID) (*audit.Event, error) {
	if sr, ok := s.(StoredReader); ok {
		return sr.GetStored(ctx, eventID)
	}
	return s.Get(ctx, eventID)
}

// resolveStream gets or creates the hash chain stream for an app+tenant scope,
// and brings an existing stream's digest pin up to the scheme this process
// writes under.
//
// Callers hold the per-stream lock from Record, which is what makes the pin
// move safe: the read of the pin, the write that advances it, and the append
// that lands above the new boundary cannot interleave with another append to
// the same stream.
func (c *Chronicle) resolveStream(ctx context.Context, appID, tenantID string) (*StreamInfo, error) {
	s, err := c.store.GetStreamByScope(ctx, appID, tenantID)
	if err == nil {
		if pinErr := c.reconcileStreamPin(ctx, s); pinErr != nil {
			return nil, pinErr
		}
		return s, nil
	}

	if !errors.Is(err, ErrStreamNotFound) {
		return nil, err
	}

	// Create a new stream, pinned from sequence 1, so every event it will ever
	// hold is covered by the pin and none of them fall into the tolerant window.
	s = &StreamInfo{
		ID:          id.NewStreamID(),
		AppID:       appID,
		TenantID:    tenantID,
		Scheme:      string(c.hasher.Scheme()),
		SchemeSince: 1,
	}
	if err := c.store.CreateStreamInfo(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
}

// reconcileStreamPin brings an existing stream's scheme pin into line with the
// scheme this process writes under, in the strengthening direction only.
//
// Writing the pin once at stream creation is not enough. Migration 006 backfills
// every pre-existing stream to the plain scheme, so an operator who turns HMAC
// on afterwards has streams advertising plain forever while HMAC events land in
// them. A verifier comparing an event's claimed scheme against that stale pin
// finds nothing to object to, and an attacker who rewrites every event back to
// plain (recomputing the unkeyed digests, which anyone can) never has to touch
// chronicle_streams at all. Moving the pin is what makes the two records
// cross-check, which is the whole point of recording the scheme twice.
//
// Three cases:
//
//   - Configured ranks above the pin: move the pin to the configured scheme,
//     applying from one past the stream's high-water mark, and persist that
//     before the event is appended. Everything already written stays below the
//     new boundary and keeps verifying under its own recorded scheme.
//   - Configured ranks below the pin: refuse. Silently weakening would let a
//     misconfigured restart, or an attacker who got the pin lowered, quietly
//     reduce the guarantee, and the operator would see nothing but green.
//   - Equal: nothing to do, which is every ordinary append.
//
// The boundary comes from the high-water mark rather than HeadSeq alone,
// matching migration 006: a crash between an event insert and the head update
// leaves HeadSeq lagging behind MAX(sequence), and pinning from the lagging
// value would drop already-written events above the new boundary, where their
// weaker recorded scheme reads as a downgrade rather than as history.
func (c *Chronicle) reconcileStreamPin(ctx context.Context, s *StreamInfo) error {
	configured := c.hasher.Scheme()
	pinned := hash.Scheme(s.Scheme)

	switch {
	case hash.Rank(configured) == hash.Rank(pinned):
		return nil

	case hash.Rank(configured) < hash.Rank(pinned):
		return fmt.Errorf(
			"%w: stream %s (app %q, tenant %q) is pinned to %s from sequence %d, "+
				"but this process is configured to write %s",
			ErrSchemeWeakeningRefused, s.ID, s.AppID, s.TenantID, pinned, s.SchemeSince, configured)
	}

	since, err := c.pinBoundary(ctx, s)
	if err != nil {
		return err
	}

	if err := c.store.UpdateStreamScheme(ctx, s.ID, string(configured), since); err != nil {
		return fmt.Errorf("advance stream scheme pin: %w", err)
	}

	c.logger.Info("chronicle: stream digest scheme advanced",
		log.String("stream_id", s.ID.String()),
		log.String("from", string(pinned)),
		log.String("to", string(configured)),
		log.Uint64("since", since),
	)

	s.Scheme = string(configured)
	s.SchemeSince = since
	return nil
}

// pinBoundary returns the first sequence a newly advanced pin applies from:
// one past whichever of the stream head and the last stored event is higher.
//
// A store that cannot report its last sequence falls back to the head, which is
// the value the stream itself carries; over-reporting the boundary is the safe
// direction, since it leaves an extra event or two resolving tolerantly instead
// of flagging honest history as a downgrade.
func (c *Chronicle) pinBoundary(ctx context.Context, s *StreamInfo) (uint64, error) {
	high := s.HeadSeq

	last, err := c.store.LastSequence(ctx, s.ID)
	if err != nil {
		if !errors.Is(err, ErrStreamNotFound) && !errors.Is(err, ErrEventNotFound) {
			return 0, fmt.Errorf("resolve stream high-water mark: %w", err)
		}
	} else if last > high {
		high = last
	}

	return high + 1, nil
}

// VerifyEvent recomputes and verifies a single event's hash.
func (c *Chronicle) VerifyEvent(ctx context.Context, eventID id.ID) (bool, error) {
	if c.store == nil {
		return false, ErrNoStore
	}

	// Read the stored form. A store that decrypts on read would hand back
	// plaintext, which no longer matches the digest computed over the sealed
	// bytes, and every sealed event would look tampered.
	event, err := getStored(ctx, c.store, eventID)
	if err != nil {
		return false, err
	}

	// Resolve the event's stream so its pin can be supplied. Without a pin, a
	// downgraded event verifies as an ordinary (weaker-scheme) success instead
	// of being caught.
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
}

// VerifyChain verifies the integrity of a hash chain for a stream.
//
// A caller that supplies AppID (the scope GetStreamByScope needs) gets
// HeadSeq/HeadHash and Pin filled in from the actual stream row for whichever
// of those it left entirely unset, so it gets head anchoring and pin-aware
// downgrade detection without having to resolve the stream itself. Three
// things keep that fill from doing the wrong thing silently:
//
//   - It never mutates the caller's *Input. It fills a local copy and only
//     verifies against that copy, so a caller reusing one Input across a loop
//     of streams does not have it progressively overwritten by whichever
//     stream happened to resolve first.
//   - It only applies when the resolved stream's ID matches the StreamID
//     being verified. A caller whose StreamID does not belong to the
//     AppID/TenantID scope it also supplied must not get that scope's
//     unrelated stream silently anchoring its tail -- a false "tampered" from
//     an audit tool is an expensive thing to be wrong about.
//   - HeadSeq and HeadHash fill as a pair, only when both are unset. A caller
//     who already supplied one half (a HeadHash sourced out of band, from a
//     checkpoint or an external notary) keeps both, rather than having the
//     value it specifically wanted cross-checked silently replaced.
//
// The StreamID fills from the resolved stream too, whenever the caller left
// it nil. That is the call every doc page shows -- scope in, nothing else --
// and without it the range query ran against a nil ID and came back empty,
// which the head fill then turned into a confident report naming every
// sequence in the stream as a gap. Verifying a healthy five-event stream
// reported five deleted events.
//
// A caller with only a StreamID in hand -- no scope, no stream row -- gets
// the old, narrower behaviour: no head anchoring, no downgrade detection,
// matching Input.Pin's documented contract for callers with no stream in
// hand.
func (c *Chronicle) VerifyChain(ctx context.Context, input *verify.Input) (*verify.Report, error) {
	if c.store == nil {
		return nil, ErrNoStore
	}

	needsHead := input.HeadSeq == 0 && input.HeadHash == ""
	needsPin := input.Pin == (hash.Pin{})
	// A nil StreamID is a reason to resolve in its own right, not only when
	// the head or the pin also need filling: a caller who supplied both of
	// those and no StreamID still has nothing to query events by.
	needsStream := input.StreamID.IsNil()
	if input.AppID != "" && (needsHead || needsPin || needsStream) {
		s, err := c.store.GetStreamByScope(ctx, input.AppID, input.TenantID)
		if err != nil {
			return nil, fmt.Errorf("chronicle: resolve stream for verification: %w", err)
		}
		if needsStream || s.ID == input.StreamID {
			in := *input
			if needsStream {
				in.StreamID = s.ID
			}
			if needsHead {
				in.HeadSeq = s.HeadSeq
				in.HeadHash = s.HeadHash
			}
			if needsPin {
				in.Pin = hash.Pin{Scheme: hash.Scheme(s.Scheme), Since: s.SchemeSince}
			}
			input = &in
		}
	}

	verifier := c.newVerifier()
	return verifier.VerifyChain(ctx, input)
}

// newVerifier builds a Verifier that also checks signed checkpoints when
// Chronicle has both a store that can hold them and a signer to check their
// signatures under, and falls back to plain chain verification when it does
// not.
//
// The store is the same Storer c.store already is: every real backend also
// implements checkpoint.Store, so this passes c.store through as-is rather
// than wiring a second store. The signer comes from [WithCheckpointSigner]
// and nowhere else. It used to be derived from c.keys, the provider HMAC
// digests resolve from, which broke both configurations the spec endorses:
// a checkpointed plain chain has no key provider at all and so never fetched
// a checkpoint, and an HMAC deployment whose checkpoints are signed from a
// separate keyset resolved the wrong provider and reported a false tamper
// verdict on an intact chain, every time, forever.
//
// A store that technically satisfies the interface but refuses every call
// (redis, which is deliberately unsupported) is handled inside
// verify.Verifier itself, not here: it treats checkpoint.ErrUnsupported as
// "no checkpoints", not a verification failure.
func (c *Chronicle) newVerifier() *verify.Verifier {
	cps, ok := c.store.(checkpoint.Store)
	if !ok || c.checkpointSigner == nil {
		return verify.NewVerifierWithChain(c.store, c.hasher)
	}
	return verify.NewVerifierWithCheckpoints(c.store, c.hasher, cps, c.checkpointSigner)
}

// Info creates an EventBuilder for an info-severity event.
func (c *Chronicle) Info(ctx context.Context, action, resource, resourceID string) *EventBuilder {
	return newBuilder(ctx, c, action, resource, resourceID, audit.SeverityInfo)
}

// Warning creates an EventBuilder for a warning-severity event.
func (c *Chronicle) Warning(ctx context.Context, action, resource, resourceID string) *EventBuilder {
	return newBuilder(ctx, c, action, resource, resourceID, audit.SeverityWarning)
}

// Critical creates an EventBuilder for a critical-severity event.
func (c *Chronicle) Critical(ctx context.Context, action, resource, resourceID string) *EventBuilder {
	return newBuilder(ctx, c, action, resource, resourceID, audit.SeverityCritical)
}

// Query returns events matching filters, scoped to the caller's tenant.
func (c *Chronicle) Query(ctx context.Context, q *audit.Query) (*audit.QueryResult, error) {
	if c.store == nil {
		return nil, ErrNoStore
	}
	scope.ApplyToQuery(ctx, q)
	return c.store.Query(ctx, q)
}

// Aggregate returns grouped counts/stats, scoped to the caller's tenant.
func (c *Chronicle) Aggregate(ctx context.Context, q *audit.AggregateQuery) (*audit.AggregateResult, error) {
	if c.store == nil {
		return nil, ErrNoStore
	}
	scope.ApplyToAggregateQuery(ctx, q)
	return c.store.Aggregate(ctx, q)
}

// ByUser returns events for a specific user within a time range.
func (c *Chronicle) ByUser(ctx context.Context, userID string, opts audit.TimeRange) (*audit.QueryResult, error) {
	if c.store == nil {
		return nil, ErrNoStore
	}
	return c.store.ByUser(ctx, userID, opts)
}

// Store returns the underlying store for direct access.
func (c *Chronicle) Store() Storer {
	return c.store
}

// validateEvent checks that required fields are present.
func validateEvent(event *audit.Event) error {
	var errs []error

	if event.Action == "" {
		errs = append(errs, fmt.Errorf("action is required"))
	}
	if event.Resource == "" {
		errs = append(errs, fmt.Errorf("resource is required"))
	}
	if event.Category == "" {
		errs = append(errs, fmt.Errorf("category is required"))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidQuery, errors.Join(errs...))
	}
	return nil
}
