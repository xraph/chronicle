// Package acceptancetest exercises the common reliable backend contract.
package acceptancetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// Request returns a deterministic source event, including precision-sensitive data.
func Request() acceptance.Request {
	return acceptance.Request{Producer: "dispatch", Installation: "host-a", SourceKey: "delivery-1", SourceFingerprint: "source-sha", OrgID: "org-a", Event: &audit.Event{AppID: "app-a", TenantID: "tenant-a", Action: "run.completed", Resource: "run", Category: "workflow", Timestamp: time.Date(2026, 10, 9, 1, 2, 3, 123456789, time.UTC), Metadata: map[string]any{"nested": []any{map[string]any{"n": json.Number("9007199254740993")}}, "decimal": json.Number("1e3"), "fraction": json.Number("0.123456789012345678901234567890123456789"), "tiny": json.Number("1e-30"), "huge": json.Number("12345678901234567890123456789012345678901234567890")}}}
}

type provider struct{ offline atomic.Bool }

func (p *provider) Current(context.Context, keys.Use) (key []byte, keyID string, err error) {
	if p.offline.Load() {
		return nil, "", errors.New("key unavailable")
	}
	return make([]byte, 32), "hmac-1", nil
}
func (p *provider) ByID(context.Context, string) ([]byte, error) {
	if p.offline.Load() {
		return nil, errors.New("key unavailable")
	}
	return make([]byte, 32), nil
}

type sealCounter struct{ n atomic.Int64 }

func (s *sealCounter) Seal(*audit.Event) error { s.n.Add(1); return nil }

func engine(t *testing.T, s store.Store, p *provider, sealer chronicle.EventSealer) *chronicle.Chronicle {
	t.Helper()
	opts := []chronicle.Option{chronicle.WithStore(store.NewAdapter(s)), chronicle.WithDigestScheme(hash.SchemeHMACV5), chronicle.WithKeyProvider(p)}
	if sealer != nil {
		opts = append(opts, chronicle.WithSealer(sealer))
	}
	c, err := chronicle.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Run checks independent engines, mixed writers, replay and immutable bindings.
func Run(t *testing.T, newStore func(*testing.T) store.Store) {
	t.Helper()
	t.Run("concurrent receipts and recovery without keys", func(t *testing.T) {
		s := newStore(t)
		p := &provider{}
		seals := &sealCounter{}
		a, b := engine(t, s, p, seals), engine(t, s, p, seals)
		ctx := context.Background()
		r := Request()
		const n = 24
		receipts := make([]*acceptance.Receipt, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				c := a
				if i%2 == 1 {
					c = b
				}
				receipts[i], errs[i] = c.RecordOnce(ctx, r)
			})
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("caller %d: %v", i, err)
			}
			if !reflect.DeepEqual(receipts[0], receipts[i]) {
				t.Fatal("different receipts")
			}
		}
		if seals.n.Load() != 1 {
			t.Fatalf("sealed %d times", seals.n.Load())
		}
		if !r.Event.ID.IsNil() || r.Event.Metadata["decimal"] != json.Number("1e3") {
			t.Fatal("mutated caller")
		}
		got, err := s.Get(ctx, receipts[0].EventID)
		if err != nil {
			t.Fatal(err)
		}
		nested, ok := got.Metadata["nested"].([]any)
		if !ok || len(nested) != 1 {
			t.Fatal("missing nested metadata")
		}
		object, ok := nested[0].(map[string]any)
		if !ok {
			t.Fatal("missing nested object")
		}
		if object["n"] != json.Number("9007199254740993") || !got.Timestamp.Equal(r.Event.Timestamp) {
			t.Fatalf("lost content precision: %+v", got)
		}
		object["n"] = "changed"
		report, err := a.VerifyChain(ctx, &verify.Input{AppID: r.Event.AppID, TenantID: r.Event.TenantID})
		if err != nil || !report.Valid || report.Verified != 1 {
			t.Fatalf("verification: %+v %v", report, err)
		}
		p.offline.Store(true)
		replay, err := b.RecordOnce(ctx, r)
		if err != nil || !reflect.DeepEqual(replay, receipts[0]) {
			t.Fatalf("keyless recovery: %+v %v", replay, err)
		}
		if _, err = s.PurgeEvents(ctx, []id.ID{receipts[0].EventID}); err != nil {
			t.Fatal(err)
		}
		replay, err = a.RecordOnce(ctx, r)
		if err != nil || !reflect.DeepEqual(replay, receipts[0]) {
			t.Fatalf("purged recovery: %+v %v", replay, err)
		}
		for _, kind := range []string{"app", "org", "tenant", "content", "source fingerprint"} {
			changed := Request()
			switch kind {
			case "app":
				changed.Event.AppID = "other"
			case "org":
				changed.OrgID = "other"
			case "tenant":
				changed.Event.TenantID = "other"
			case "content":
				changed.Event.Action = "other"
			case "source fingerprint":
				changed.SourceFingerprint = "other"
			}
			receipt, conflictErr := a.RecordOnce(ctx, changed)
			if !errors.Is(conflictErr, acceptance.ErrConflict) || receipt != nil {
				t.Fatalf("%s leaked/accepted: %+v %v", kind, receipt, conflictErr)
			}
		}
		p.offline.Store(false)
		r.Installation = "host-b"
		other, err := a.RecordOnce(ctx, r)
		if err != nil || other.EventID == receipts[0].EventID || other.Sequence != 2 {
			t.Fatalf("other installation: %+v %v", other, err)
		}
	})
	t.Run("lost acknowledgement uses primary acceptance interception", func(t *testing.T) {
		s := newStore(t)
		wrapper := &lostAck{Store: s}
		p := &provider{}
		c := engine(t, wrapper, p, nil)
		if receipt, err := c.RecordOnce(context.Background(), Request()); err == nil || receipt != nil {
			t.Fatalf("expected lost acknowledgement: %+v %v", receipt, err)
		}
		receipt, err := c.RecordOnce(context.Background(), Request())
		if err != nil || receipt.Sequence != 1 || wrapper.calls.Load() != 2 {
			t.Fatalf("recovery bypassed wrapper or duplicated: %+v %v", receipt, err)
		}
		st, err := s.GetStream(context.Background(), receipt.StreamID)
		if err != nil || st.HeadSeq != 1 {
			t.Fatalf("head: %+v %v", st, err)
		}
	})

	t.Run("concurrent conflicting first requests", func(t *testing.T) {
		s := newStore(t)
		p := &provider{}
		a, b := engine(t, s, p, nil), engine(t, s, p, nil)
		var wg sync.WaitGroup
		var wins, conflicts atomic.Int64
		for i := range 20 {
			wg.Go(func() {
				r := Request()
				r.Event.Action = fmt.Sprint("action-", i)
				c := a
				if i%2 == 1 {
					c = b
				}
				receipt, err := c.RecordOnce(context.Background(), r)
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, acceptance.ErrConflict) && receipt == nil:
					conflicts.Add(1)
				default:
					t.Errorf("unexpected: %v", err)
				}
			})
		}
		wg.Wait()
		if wins.Load() != 1 || conflicts.Load() != 19 {
			t.Fatalf("wins=%d conflicts=%d", wins.Load(), conflicts.Load())
		}
	})
	t.Run("first stream and mixed writers", func(t *testing.T) {
		s := newStore(t)
		p := &provider{}
		a, b := engine(t, s, p, nil), engine(t, s, p, nil)
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Go(func() {
				r := Request()
				r.SourceKey = fmt.Sprint("delivery-", i)
				var err error
				if i%2 == 0 {
					_, err = a.RecordOnce(context.Background(), r)
				} else {
					r.Event.Metadata = map[string]any{"legacy": 1}
					err = b.Record(context.Background(), r.Event)
				}
				if err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		streams, err := s.ListStreams(context.Background(), stream.ListOpts{Limit: 100})
		if err != nil || len(streams) != 1 || streams[0].HeadSeq != 32 {
			t.Fatalf("streams=%+v err=%v", streams, err)
		}
		r := Request()
		report, err := a.VerifyChain(context.Background(), &verify.Input{AppID: r.Event.AppID, TenantID: r.Event.TenantID})
		if err != nil || !report.Valid || report.Verified != 32 {
			t.Fatalf("verify=%+v err=%v", report, err)
		}
	})
	t.Run("delayed legacy head cannot rewind", func(t *testing.T) {
		s := newStore(t)
		p := &provider{}
		paused := &lateHead{Store: s, entered: make(chan struct{}), resume: make(chan struct{})}
		a := engine(t, paused, p, nil)
		b := engine(t, s, p, nil)
		r := Request()
		done := make(chan error, 1)
		go func() { done <- a.Record(context.Background(), r.Event) }()
		<-paused.entered
		receipt, err := b.RecordOnce(context.Background(), Request())
		if err != nil {
			close(paused.resume)
			t.Fatal(err)
		}
		close(paused.resume)
		if err = <-done; err != nil {
			t.Fatal(err)
		}
		st, err := s.GetStream(context.Background(), receipt.StreamID)
		if err != nil || st.HeadSeq != 2 || st.HeadHash != receipt.Hash {
			t.Fatalf("rewound: %+v %v", st, err)
		}
		if err = s.UpdateStreamHead(context.Background(), st.ID, "different", st.HeadSeq); !errors.Is(err, acceptance.ErrHeadConflict) {
			t.Fatalf("equal conflict: %v", err)
		}
	})
}

type lateHead struct {
	store.Store
	entered, resume chan struct{}
}

func (s *lateHead) AppendWithChain(ctx context.Context, e *audit.Event, h *hash.Chain) error {
	backend, ok := s.Store.(acceptance.Appender)
	if !ok {
		return acceptance.ErrUnsupported
	}
	return backend.AppendWithChain(ctx, e, h)
}
func (s *lateHead) UpdateStreamHead(ctx context.Context, i id.ID, h string, n uint64) error {
	close(s.entered)
	<-s.resume
	return s.Store.UpdateStreamHead(ctx, i, h, n)
}

type lostAck struct {
	store.Store
	calls atomic.Int64
}

func (s *lostAck) Accept(ctx context.Context, r acceptance.Request, h *hash.Chain, prepare func(*audit.Event) error) (*acceptance.Receipt, error) {
	backend, ok := s.Store.(acceptance.Store)
	if !ok {
		return nil, acceptance.ErrUnsupported
	}
	receipt, err := backend.Accept(ctx, r, h, prepare)
	if err != nil {
		return nil, err
	}
	if s.calls.Add(1) == 1 {
		return nil, errors.New("connection lost after commit")
	}
	return receipt, nil
}
