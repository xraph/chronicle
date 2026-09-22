package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// ErrNothingToCheckpoint is returned when a stream has gained no events since
// its last checkpoint. It is an ordinary outcome on a quiet stream, not a fault.
var ErrNothingToCheckpoint = errors.New("checkpoint: no new events since the last checkpoint")

// EventReader is the slice of verify.Store a Checkpointer needs. It is declared
// here rather than imported so this package does not depend on verify.
type EventReader interface {
	EventRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error)
}

// StreamHead is the minimal view of a stream a checkpoint is taken over.
//
// It exists so this package does not import stream, which imports chronicle,
// which imports verify, which imports this package. chronicle.StreamInfo is the
// same device for the same reason; callers convert at the boundary.
type StreamHead struct {
	ID       id.ID
	AppID    string
	TenantID string
	HeadSeq  uint64
	HeadHash string
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
func (c *Checkpointer) CheckpointStream(ctx context.Context, st StreamHead) (*Checkpoint, error) {
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
	case errors.Is(err, ErrNotFound):
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
