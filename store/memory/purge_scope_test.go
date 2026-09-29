package memory

import (
	"testing"

	"github.com/xraph/chronicle/internal/retentiontest"
)

func TestEventsOlderThanMatchesScopeExactly(t *testing.T) {
	retentiontest.PurgeScope(t, New(), "mem")
}
