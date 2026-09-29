package redis

import (
	"testing"

	"github.com/xraph/chronicle/internal/retentiontest"
)

func TestEventsOlderThanMatchesScopeExactly(t *testing.T) {
	s, _ := openTestStore(t, true)
	retentiontest.PurgeScope(t, s, runSuffix(t))
}
