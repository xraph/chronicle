package memory_test

import (
	"testing"

	"github.com/xraph/chronicle/internal/acceptancetest"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
)

func TestAcceptance(t *testing.T) {
	acceptancetest.Run(t, func(*testing.T) store.Store { return memory.New() })
}

func TestAcceptanceScheme(t *testing.T) { acceptancetest.Scheme(t, memory.New()) }
