package chronicle

import (
	"context"
	"errors"
	"fmt"
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

// Compile-time check: Chronicle implements Emitter.
var _ Emitter = (*Chronicle)(nil)

// Chronicle is the root audit trail engine.
// It orchestrates event recording, hash chain computation, batching,
// sink fan-out, plugin hooks, and query execution.
type Chronicle struct {
	config Config
	store  Storer
	hasher *hash.Chain
	logger log.Logger
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

	// 4. Resolve or create stream for this app+tenant scope.
	s, err := c.resolveStream(ctx, event.AppID, event.TenantID)
	if err != nil {
		return fmt.Errorf("chronicle: resolve stream: %w", err)
	}

	// 5. Compute hash chain.
	event.StreamID = s.ID
	event.Sequence = s.HeadSeq + 1
	event.PrevHash = s.HeadHash
	event.Hash = c.hasher.Compute(event.PrevHash, event)

	// 6. Persist to store.
	if err := c.store.Append(ctx, event); err != nil {
		return fmt.Errorf("chronicle: append: %w", err)
	}

	// 7. Update stream head.
	if err := c.store.UpdateStreamHead(ctx, s.ID, event.Hash, event.Sequence); err != nil {
		return fmt.Errorf("chronicle: update stream head: %w", err)
	}

	return nil
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

	event, err := c.store.Get(ctx, eventID)
	if err != nil {
		return false, err
	}

	computed := c.hasher.Compute(event.PrevHash, event)
	return computed == event.Hash, nil
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
