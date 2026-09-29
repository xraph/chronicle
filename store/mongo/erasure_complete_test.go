package mongo

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure/erasuretest"
	"github.com/xraph/chronicle/id"
)

// openMigratedMongo is openLiveStore with the migrations applied.
func openMigratedMongo(t *testing.T) *Store {
	t.Helper()
	s, _ := openLiveStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

func TestCompleteErasure(t *testing.T) {
	erasuretest.CompleteErasure(t, openMigratedMongo(t), "mongo")
}

func TestMarkErasedAgain(t *testing.T) {
	s := openMigratedMongo(t)
	ctx := context.Background()
	erasuretest.MarkErasedAgain(t, s, func(t *testing.T, e *audit.Event) {
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}, func(t *testing.T, eventID id.ID) *audit.Event {
		e, err := s.Get(ctx, eventID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		return e
	}, "mongo")
}
