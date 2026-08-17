package chronicle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
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
	logger log.Logger

	// streamLocks serialises the hash-chain critical section per stream scope.
	// See Record for why this is required.
	streamLocks sync.Map // map[string]*sync.Mutex, keyed by appID + "\x00" + tenantID
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
	actual, _ := c.streamLocks.LoadOrStore(key, &sync.Mutex{})
	mu := actual.(*sync.Mutex)
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
		hasher: &hash.Chain{},
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
	event.Hash = c.hasher.Compute(event.PrevHash, event)

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

// resolveStream gets or creates the hash chain stream for an app+tenant scope.
func (c *Chronicle) resolveStream(ctx context.Context, appID, tenantID string) (*StreamInfo, error) {
	s, err := c.store.GetStreamByScope(ctx, appID, tenantID)
	if err == nil {
		return s, nil
	}

	if !errors.Is(err, ErrStreamNotFound) {
		return nil, err
	}

	// Create a new stream.
	s = &StreamInfo{
		ID:       id.NewStreamID(),
		AppID:    appID,
		TenantID: tenantID,
	}
	if err := c.store.CreateStreamInfo(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
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

	// Verify accepts the legacy hash scheme too, so events written before the
	// hash coverage was extended are not all reported as tampered.
	return c.hasher.Verify(event.PrevHash, event), nil
}

// VerifyChain verifies the integrity of a hash chain for a stream.
func (c *Chronicle) VerifyChain(ctx context.Context, input *verify.Input) (*verify.Report, error) {
	if c.store == nil {
		return nil, ErrNoStore
	}

	verifier := verify.NewVerifier(c.store)
	return verifier.VerifyChain(ctx, input)
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
