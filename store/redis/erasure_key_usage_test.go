package redis

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure/erasuretest"
)

func TestSubjectKeyUsage(t *testing.T) {
	s, _ := openTestStore(t, true)
	erasuretest.SubjectKeyUsage(t, s, func(t *testing.T, e *audit.Event) {
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}, runSuffix(t))
}
