package sqlite

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure/erasuretest"
	"github.com/xraph/chronicle/id"
)

func TestSubjectKeyUsage(t *testing.T) {
	s := newTestStore(t)
	erasuretest.SubjectKeyUsage(t, s, streamAppender(s), "sqlite")
}

func TestCompleteErasure(t *testing.T) {
	erasuretest.CompleteErasure(t, newTestStore(t), "sqlite")
}

func TestMarkErasedAgain(t *testing.T) {
	s := newTestStore(t)
	erasuretest.MarkErasedAgain(t, s, streamAppender(s), func(t *testing.T, eventID id.ID) *audit.Event {
		e, err := s.Get(context.Background(), eventID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		return e
	}, "sqlite")
}

// streamAppender appends events under their scope's stream, creating it on
// first use. Events reference their scope's stream, and a scope has exactly
// one.
func streamAppender(s *Store) erasuretest.Appender {
	streams := make(map[[2]string]id.ID)
	return func(t *testing.T, e *audit.Event) {
		scope := [2]string{e.AppID, e.TenantID}
		if _, ok := streams[scope]; !ok {
			streams[scope] = seedStream(t, s, e.AppID, e.TenantID)
		}
		e.StreamID = streams[scope]
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
}
