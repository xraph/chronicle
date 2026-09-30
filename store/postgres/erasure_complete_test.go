package postgres

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure/erasuretest"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// openMigratedPostgres is openLivePostgres with the migrations applied.
func openMigratedPostgres(t *testing.T) *Store {
	t.Helper()
	s, _ := openLivePostgres(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

func TestCompleteErasure(t *testing.T) {
	erasuretest.CompleteErasure(t, openMigratedPostgres(t), "pg")
}

func TestMarkErasedAgain(t *testing.T) {
	s := openMigratedPostgres(t)
	ctx := context.Background()

	streams := make(map[[2]string]id.ID)
	erasuretest.MarkErasedAgain(t, s, func(t *testing.T, e *audit.Event) {
		scope := [2]string{e.AppID, e.TenantID}
		if _, ok := streams[scope]; !ok {
			st := &stream.Stream{ID: id.NewStreamID(), AppID: e.AppID, TenantID: e.TenantID}
			if err := s.CreateStream(ctx, st); err != nil {
				t.Fatalf("CreateStream: %v", err)
			}
			streams[scope] = st.ID
		}
		e.StreamID = streams[scope]
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}, func(t *testing.T, eventID id.ID) *audit.Event {
		e, err := s.Get(ctx, eventID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		return e
	}, "pg")
}
