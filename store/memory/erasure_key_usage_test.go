package memory_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure/erasuretest"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store/memory"
)

func TestSubjectKeyUsage(t *testing.T) {
	s := memory.New()
	erasuretest.SubjectKeyUsage(t, s, func(t *testing.T, e *audit.Event) {
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}, "mem")
}

func TestCompleteErasure(t *testing.T) {
	erasuretest.CompleteErasure(t, memory.New(), "mem")
}

func TestMarkErasedAgain(t *testing.T) {
	s := memory.New()
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
	}, "mem")
}
