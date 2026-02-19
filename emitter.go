package chronicle

import (
	"context"

	"github.com/xraph/chronicle/audit"
)

// Emitter is the interface Forge extensions use to emit audit events.
// Extensions receive this via DI — they don't import Chronicle directly.
type Emitter interface {
	Record(ctx context.Context, event *audit.Event) error
	Info(ctx context.Context, action, resource, resourceID string) *EventBuilder
	Warning(ctx context.Context, action, resource, resourceID string) *EventBuilder
	Critical(ctx context.Context, action, resource, resourceID string) *EventBuilder
}
