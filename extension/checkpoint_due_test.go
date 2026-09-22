package extension

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/stream"
)

// This file is package extension, not extension_test, because everything it
// covers is unexported: the scheduler's trigger decision, the poll interval
// derived from it, and the store read in between. All four existing test
// files are extension_test, so none of them can reach these.

// TestCheckpointDue covers all three branches of the scheduler's trigger.
//
// The EveryInterval branch matters most and had no coverage at all. It is
// what the argument for dual triggers rests on: the window between two
// checkpoints is exactly the span an attacker can still rewrite, so a quiet
// stream that never reaches EveryEvents would otherwise sit unprotected
// indefinitely. Nothing in the suite exercised it, and the only paths any
// test reached were "never checkpointed" and EveryEvents.
func TestCheckpointDue(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	cfg := CheckpointConfig{Enabled: true, EveryEvents: 1000, EveryInterval: time.Hour}

	for _, tc := range []struct {
		name          string
		hasCheckpoint bool
		lastCreatedAt time.Time
		lastToSeq     uint64
		headSeq       uint64
		cfg           CheckpointConfig
		want          bool
	}{
		{
			name: "never checkpointed is due immediately",
			// A new stream should be covered within one poll period of its
			// first event, not after a full EveryInterval. CheckpointStream
			// returns ErrNothingToCheckpoint cheaply if it has no events, so
			// attempting costs nothing on an empty one.
			hasCheckpoint: false, headSeq: 0, cfg: cfg, want: true,
		},
		{
			name:          "interval elapsed on a stream with no new events",
			hasCheckpoint: true, lastCreatedAt: now.Add(-2 * time.Hour),
			lastToSeq: 10, headSeq: 10, cfg: cfg, want: true,
		},
		{
			name:          "interval reached exactly",
			hasCheckpoint: true, lastCreatedAt: now.Add(-time.Hour),
			lastToSeq: 10, headSeq: 10, cfg: cfg, want: true,
		},
		{
			name:          "interval not yet elapsed and too few events",
			hasCheckpoint: true, lastCreatedAt: now.Add(-30 * time.Minute),
			lastToSeq: 10, headSeq: 500, cfg: cfg, want: false,
		},
		{
			name: "event count reached well inside the interval",
			// The busy-stream case: thousands of events a minute should not
			// wait out an hour before the window closes again.
			hasCheckpoint: true, lastCreatedAt: now.Add(-time.Minute),
			lastToSeq: 10, headSeq: 1010, cfg: cfg, want: true,
		},
		{
			name:          "event count reached exactly",
			hasCheckpoint: true, lastCreatedAt: now.Add(-time.Minute),
			lastToSeq: 0, headSeq: 1000, cfg: cfg, want: true,
		},
		{
			name: "event trigger disabled leaves only the interval",
			// EveryEvents 0 means "count never triggers", not "trigger on
			// every event".
			hasCheckpoint: true, lastCreatedAt: now.Add(-time.Minute),
			lastToSeq: 0, headSeq: 1_000_000,
			cfg:  CheckpointConfig{Enabled: true, EveryInterval: time.Hour},
			want: false,
		},
		{
			name: "a head below the last checkpoint does not underflow into due",
			// headSeq - lastToSeq on unsigned integers would wrap to an
			// enormous number and fire the event trigger on every poll. A
			// head below its own latest checkpoint means someone rewrote it
			// downward, which the verifier reports; the scheduler's job here
			// is only to not go haywire.
			hasCheckpoint: true, lastCreatedAt: now.Add(-time.Minute),
			lastToSeq: 5000, headSeq: 10, cfg: cfg, want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkpointDue(now, tc.hasCheckpoint, tc.lastCreatedAt, tc.lastToSeq, tc.headSeq, tc.cfg)
			if got != tc.want {
				t.Errorf("checkpointDue = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCheckpointPollInterval pins the base tick the scheduler ticks on.
//
// It has to be finer than EveryInterval or the event trigger could never
// fire meaningfully ahead of the time trigger, and it has to have a floor or
// an aggressive setting (or a test) would poll faster than once a second,
// with a ListStreams plus one LatestCheckpoint per stream behind every tick.
func TestCheckpointPollInterval(t *testing.T) {
	for _, tc := range []struct {
		name  string
		every time.Duration
		want  time.Duration
	}{
		{name: "the documented default polls every five minutes", every: time.Hour, want: 5 * time.Minute},
		{name: "a long interval scales with it", every: 24 * time.Hour, want: 2 * time.Hour},
		{name: "twelve seconds lands exactly on the floor", every: 12 * time.Second, want: time.Second},
		{name: "a short interval is held at the floor", every: 6 * time.Second, want: time.Second},
		{name: "zero cannot reach time.NewTicker as zero", every: 0, want: time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &Extension{config: Config{Checkpoints: CheckpointConfig{EveryInterval: tc.every}}}
			if got := e.checkpointPollInterval(); got != tc.want {
				t.Errorf("checkpointPollInterval = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestStreamCheckpointDue covers the store read that sits between the
// scheduler and the pure decision: a stream with a checkpoint, one without,
// and a backend that fails.
func TestStreamCheckpointDue(t *testing.T) {
	ctx := context.Background()
	cfg := CheckpointConfig{Enabled: true, EveryEvents: 100, EveryInterval: time.Hour}
	st := &stream.Stream{ID: id.NewStreamID(), AppID: "app", HeadSeq: 50}

	t.Run("a stream with no checkpoint is due", func(t *testing.T) {
		e := &Extension{store: cpDueStore{err: checkpoint.ErrNotFound}, config: Config{Checkpoints: cfg}}
		due, err := e.streamCheckpointDue(ctx, st)
		if err != nil {
			t.Fatalf("streamCheckpointDue: %v", err)
		}
		if !due {
			t.Error("a stream that has never been checkpointed is not due")
		}
	})

	t.Run("a recent checkpoint with few new events is not due", func(t *testing.T) {
		e := &Extension{
			store: cpDueStore{latest: &checkpoint.Checkpoint{
				StreamID: st.ID, ToSeq: 40, CreatedAt: time.Now(),
			}},
			config: Config{Checkpoints: cfg},
		}
		due, err := e.streamCheckpointDue(ctx, st)
		if err != nil {
			t.Fatalf("streamCheckpointDue: %v", err)
		}
		if due {
			t.Error("a stream ten events past a checkpoint taken just now is due")
		}
	})

	t.Run("a stale checkpoint makes the stream due", func(t *testing.T) {
		e := &Extension{
			store: cpDueStore{latest: &checkpoint.Checkpoint{
				StreamID: st.ID, ToSeq: 50, CreatedAt: time.Now().Add(-2 * time.Hour),
			}},
			config: Config{Checkpoints: cfg},
		}
		due, err := e.streamCheckpointDue(ctx, st)
		if err != nil {
			t.Fatalf("streamCheckpointDue: %v", err)
		}
		if !due {
			t.Error("a stream whose last checkpoint is two hours old is not due under a one-hour interval")
		}
	})

	t.Run("a store failure is reported, not read as not due", func(t *testing.T) {
		boom := errors.New("backend unavailable")
		e := &Extension{store: cpDueStore{err: boom}, config: Config{Checkpoints: cfg}}
		if _, err := e.streamCheckpointDue(ctx, st); !errors.Is(err, boom) {
			t.Errorf("error = %v, want the store's own error: a failed read must be logged by the "+
				"caller, not silently skipped as a stream that is not due", err)
		}
	})
}

// cpDueStore is a store.Store whose only real method is LatestCheckpoint.
// Embedding the interface keeps this to the one method under test; anything
// else the scheduler might call would panic loudly rather than quietly
// returning a zero value.
type cpDueStore struct {
	store.Store
	latest *checkpoint.Checkpoint
	err    error
}

func (s cpDueStore) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.latest, nil
}
