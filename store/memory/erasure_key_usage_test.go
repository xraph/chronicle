package memory_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/erasure/erasuretest"
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
