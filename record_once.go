package chronicle

import (
	"context"
	"time"

	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/internal/telemetry"
)

// RecordOnce recovers or atomically accepts one source delivery. Your host must
// supply trusted producer/installation and authorized explicit event scope.
// Recovery does not seal, resolve keys, or change a stream. Unsupported stores
// fail explicitly. Record retains its separate, non-idempotent contract.
//
// Each call is one "accept event" span and one observation on the record
// metrics, labelled record_once. A recovered receipt counts as ok.
func (c *Chronicle) RecordOnce(ctx context.Context, request acceptance.Request) (*acceptance.Receipt, error) {
	start := time.Now()
	ctx, span := telemetry.Start(ctx, telemetry.SpanAcceptEvent, c.schemeAttr())

	receipt, err := c.recordOnce(ctx, request)
	if receipt != nil {
		span.SetAttributes(telemetry.AttrStreamID.String(receipt.StreamID.String()))
	}

	telemetry.Fail(span, err, recordSentinels...)
	span.End()
	c.recordMetrics.Observe(telemetry.OperationRecordOnce, err, time.Since(start))
	return receipt, err
}

// recordOnce is RecordOnce without its telemetry.
func (c *Chronicle) recordOnce(ctx context.Context, request acceptance.Request) (*acceptance.Receipt, error) {
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
