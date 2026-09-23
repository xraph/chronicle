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

	// Events reference their scope's stream, and a scope has exactly one.
	streams := make(map[[2]string]id.ID)
	erasuretest.SubjectKeyUsage(t, s, func(t *testing.T, e *audit.Event) {
		scope := [2]string{e.AppID, e.TenantID}
		if _, ok := streams[scope]; !ok {
			streams[scope] = seedStream(t, s, e.AppID, e.TenantID)
		}
		e.StreamID = streams[scope]
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}, "sqlite")
}
