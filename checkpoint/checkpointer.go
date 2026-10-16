package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	log "github.com/xraph/go-utils/log"
	gometrics "github.com/xraph/go-utils/metrics"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/internal/telemetry"
	"github.com/xraph/chronicle/keys"
)

// ErrNothingToCheckpoint is returned when a stream has gained no events since
// its last checkpoint. It is an ordinary outcome on a quiet stream, not a fault.
var ErrNothingToCheckpoint = errors.New("checkpoint: no new events since the last checkpoint")

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
	store   Store
	signer  Signer
	logger  log.Logger
	metrics *telemetry.CheckpointMetrics

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
}

// CheckpointerOption configures a Checkpointer.
type CheckpointerOption func(*Checkpointer)

// WithMetrics counts every CheckpointStream call on m by result (ok,
// nothing_new, lost_race, error). In a Forge app pass app.Metrics(), and the
// series lands on /_/metrics as forge_chronicle_checkpoints_attempted_total.
// The Forge extension does this for you. A nil m records nothing.
func WithMetrics(m gometrics.Metrics) CheckpointerOption {
	return func(c *Checkpointer) { c.metrics = telemetry.NewCheckpointMetrics(m) }
}

// NewCheckpointer creates a Checkpointer. A nil logger is replaced with a no-op.
//
// It does not take an EventReader: CheckpointStream never reads an event, so
// there is nothing here for one to do. See CheckpointStream's doc for why.
func NewCheckpointer(store Store, signer Signer, logger log.Logger, opts ...CheckpointerOption) *Checkpointer {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	c := &Checkpointer{
		store: store, signer: signer, logger: logger,
		locks: make(map[string]*sync.Mutex),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// checkpointSentinels name the errors CheckpointStream can fail with, for the
// span status.
var checkpointSentinels = []telemetry.Sentinel{
	{Err: ErrUnsupported, Name: "checkpoint.ErrUnsupported"},
	{Err: keys.ErrKeyNotFound, Name: "keys.ErrKeyNotFound"},
	{Err: keys.ErrNoActiveKey, Name: "keys.ErrNoActiveKey"},
	{Err: keys.ErrKeyRevoked, Name: "keys.ErrKeyRevoked"},
}

// lockStream serialises checkpointing of one stream and returns the unlock.
//
// This mirrors Chronicle.lockStream deliberately: same map-of-mutexes shape,
// same choice to never prune an entry once created. An entry is two words,
// and the map is bounded by the number of streams a process has checkpointed
// at least once, not by event volume or checkpoint count, so retaining it for
// the process lifetime costs little. Dropping an entry while another
// goroutine still held it would let two checkpointers reacquire distinct
// mutexes for the same stream, defeating the point of locking at all; keeping
// the entry avoids having to prove that race can't happen.
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
//
// It does not read a single event to do this. Everything a checkpoint
// asserts -- FromSeq, ToSeq, EventCount -- is arithmetic on sequence numbers
// the caller already supplied (st.HeadSeq) or this function already read
// (latest.ToSeq); reading and counting the actual event rows would add
// nothing a verifier trusts, since ToHash already pins the head and a gap in
// between is Store.Gaps' job to find, not a checkpoint's. Before this,
// materialising every event in [fromSeq, st.HeadSeq] just to call len() on
// the result meant a first checkpoint over a stream with millions of
// existing events read that entire history into memory, serially, per
// stream, in one goroutine -- and runCheckpointScheduler is what put this on
// an automatic, per-stream, per-tick path across an entire deployment.
//
// Each call is one "take checkpoint" span. A stream with nothing new and a
// checkpoint another writer took first are ordinary outcomes: the span
// records them in chronicle.checkpoint.result and keeps an unset status.
func (c *Checkpointer) CheckpointStream(ctx context.Context, st StreamHead) (*Checkpoint, error) {
	ctx, span := telemetry.Start(ctx, telemetry.SpanTakeCheckpoint,
		trace.WithAttributes(telemetry.AttrStreamID.String(st.ID.String())))
	defer span.End()

	cp, err := c.checkpointStream(ctx, st)

	result := telemetry.ResultOK
	switch {
	case err == nil:
		span.SetAttributes(
			telemetry.AttrCheckpointEvents.Int64(cp.EventCount),
			telemetry.AttrCheckpointAlgorithm.String(cp.Algorithm),
		)
	case errors.Is(err, ErrNothingToCheckpoint):
		result = telemetry.ResultNothingNew
	case errors.Is(err, ErrExists):
		result = telemetry.ResultLostRace
	default:
		result = telemetry.ResultError
		telemetry.Fail(span, err, checkpointSentinels...)
	}
	span.SetAttributes(telemetry.AttrCheckpointResult.String(result))
	c.metrics.Inc(result)
	return cp, err
}

// checkpointStream is CheckpointStream without its telemetry.
func (c *Checkpointer) checkpointStream(ctx context.Context, st StreamHead) (*Checkpoint, error) {
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

	// st.HeadSeq >= fromSeq below is the only "is there anything new" check
	// this function needs: the range [fromSeq, st.HeadSeq] is non-empty by
	// construction whenever it holds, so there is no separate empty-read case
	// to guard against the way there was when events were actually fetched.
	if st.HeadSeq < fromSeq {
		return nil, ErrNothingToCheckpoint
	}

	span := st.HeadSeq - fromSeq
	if span >= math.MaxInt64 {
		return nil, fmt.Errorf("checkpoint: event span exceeds int64")
	}
	cp := &Checkpoint{
		ID:       id.NewCheckpointID(),
		StreamID: st.ID,
		AppID:    st.AppID,
		TenantID: st.TenantID,
		FromSeq:  fromSeq,
		ToSeq:    st.HeadSeq,
		FromHash: fromHash,
		ToHash:   st.HeadHash,
		// The bounded span, not a verified count. See EventCount's doc.
		EventCount:     int64(span) + 1,
		PrevCheckpoint: prev,

		// Truncated to millisecond, not left at time.Now's nanosecond
		// resolution, because CreatedAt is part of the signed payload
		// (CanonicalPayload renders it via RFC3339Nano) and a verifier
		// recomputes that payload from a checkpoint it read back from the
		// store. Postgres's TIMESTAMPTZ keeps microseconds and Mongo's BSON
		// keeps milliseconds, so a nanosecond-precision timestamp signed here
		// comes back truncated on those backends, the recomputed payload
		// differs from what was signed, and a healthy checkpoint reports as
		// edited-after-signing. Millisecond is exactly representable in both,
		// so truncating to it here makes the round trip lossless on every
		// backend, including sqlite's RFC3339Nano text column. Do not remove
		// this truncation to "restore precision" -- there is no backend that
		// stores it.
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
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
