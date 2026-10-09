package chronicle

import (
	"context"

	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/audit"
)

// RecordOnce recovers or atomically accepts one source delivery. Your host must
// supply trusted producer/installation and authorized explicit event scope.
// Recovery does not seal, resolve keys, or change a stream. Unsupported stores
// fail explicitly. Record retains its separate, non-idempotent contract.
func (c *Chronicle) RecordOnce(ctx context.Context, request acceptance.Request) (*acceptance.Receipt, error) {
	if c.store == nil {
		return nil, ErrNoStore
	}
	s, ok := c.store.(acceptance.Store)
	if !ok {
		return nil, acceptance.ErrUnsupported
	}
	var prepare func(*audit.Event) error
	if c.sealer != nil {
		prepare = c.sealer.Seal
	}
	return s.Accept(ctx, request, c.hasher, prepare)
}
