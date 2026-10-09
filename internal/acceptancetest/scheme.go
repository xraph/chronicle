package acceptancetest

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/store"
)

// Scheme checks transactional pin changes and replay before mutable protection.
func Scheme(t *testing.T, s store.Store) {
	t.Helper()
	ctx := context.Background()
	backend, ok := s.(acceptance.Store)
	if !ok {
		t.Fatal("missing capability")
	}
	r := Request()
	plain := &hash.Chain{}
	first, err := backend.Accept(ctx, r, plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := hash.NewChain(hash.SchemeHMACV5, &provider{})
	if err != nil {
		t.Fatal(err)
	}
	next := Request()
	next.SourceKey = "second"
	fail := errors.New("prepare failed")
	if receipt, prepareErr := backend.Accept(ctx, next, keyed, func(*audit.Event) error { return fail }); !errors.Is(prepareErr, fail) || receipt != nil {
		t.Fatalf("prepare failure: %+v %v", receipt, prepareErr)
	}
	st, err := s.GetStream(ctx, first.StreamID)
	if err != nil || st.HeadSeq != 1 || st.Scheme != string(hash.SchemePlainV4) {
		t.Fatalf("failed acceptance changed stream: %+v %v", st, err)
	}
	second, err := backend.Accept(ctx, next, keyed, nil)
	if err != nil || second.Sequence != 2 {
		t.Fatalf("keyed acceptance: %+v %v", second, err)
	}
	st, err = s.GetStream(ctx, first.StreamID)
	if err != nil || st.SchemeSince != 2 || st.Scheme != string(hash.SchemeHMACV5) {
		t.Fatalf("bad pin: %+v %v", st, err)
	}
	recovered, err := backend.Accept(ctx, r, plain, nil)
	if err != nil || recovered.EventID != first.EventID {
		t.Fatalf("replay required current scheme: %+v %v", recovered, err)
	}
	next.SourceKey = "weaker"
	if receipt, err := backend.Accept(ctx, next, plain, nil); !errors.Is(err, chronicle.ErrSchemeWeakeningRefused) || receipt != nil {
		t.Fatalf("weakened: %+v %v", receipt, err)
	}
}
