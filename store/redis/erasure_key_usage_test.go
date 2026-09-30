package redis

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure/erasuretest"
	"github.com/xraph/chronicle/id"
)

func TestSubjectKeyUsage(t *testing.T) {
	s, _ := openTestStore(t, true)
	erasuretest.SubjectKeyUsage(t, s, func(t *testing.T, e *audit.Event) {
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}, runSuffix(t))
}

func TestCompleteErasure(t *testing.T) {
	s, _ := openTestStore(t, true)
	erasuretest.CompleteErasure(t, s, runSuffix(t))
}

func TestMarkErasedAgain(t *testing.T) {
	s, _ := openTestStore(t, true)
	erasuretest.MarkErasedAgain(t, s, func(t *testing.T, e *audit.Event) {
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}, func(t *testing.T, eventID id.ID) *audit.Event {
		e, err := s.Get(context.Background(), eventID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		return e
	}, runSuffix(t))
}
