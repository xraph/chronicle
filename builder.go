package chronicle

import (
	"context"

	"github.com/xraph/chronicle/audit"
)

// EventBuilder provides a fluent API for constructing and recording audit events.
type EventBuilder struct {
	ctx       context.Context
	event     *audit.Event
	chronicle *Chronicle
}

func newBuilder(ctx context.Context, c *Chronicle, action, resource, resourceID, severity string) *EventBuilder {
	return &EventBuilder{
		ctx:       ctx,
		chronicle: c,
		event: &audit.Event{
			Action:     action,
			Resource:   resource,
			ResourceID: resourceID,
			Severity:   severity,
			Outcome:    audit.OutcomeSuccess,
			Metadata:   make(map[string]any),
		},
	}
}

// Category sets the event category.
func (b *EventBuilder) Category(cat string) *EventBuilder {
	b.event.Category = cat
	return b
}

// Reason sets the event reason.
func (b *EventBuilder) Reason(r string) *EventBuilder {
	b.event.Reason = r
	return b
}

// Meta adds a key-value pair to the event metadata.
func (b *EventBuilder) Meta(key string, value any) *EventBuilder {
	b.event.Metadata[key] = value
	return b
}

// SubjectID sets the GDPR subject ID for crypto-erasure.
func (b *EventBuilder) SubjectID(sid string) *EventBuilder {
	b.event.SubjectID = sid
	return b
}

// Outcome sets the event outcome.
func (b *EventBuilder) Outcome(o string) *EventBuilder {
	b.event.Outcome = o
	return b
}

// TenantID sets the tenant scope explicitly.
func (b *EventBuilder) TenantID(tid string) *EventBuilder {
	b.event.TenantID = tid
	return b
}

// UserID sets the user who performed the action.
func (b *EventBuilder) UserID(uid string) *EventBuilder {
	b.event.UserID = uid
	return b
}

// AppID sets the application scope explicitly.
func (b *EventBuilder) AppID(aid string) *EventBuilder {
	b.event.AppID = aid
	return b
}

// Record persists the built event through the Chronicle pipeline.
func (b *EventBuilder) Record() error {
	return b.chronicle.Record(b.ctx, b.event)
}

// Event returns the underlying event without recording it.
// Useful for inspection/testing.
func (b *EventBuilder) Event() *audit.Event {
	return b.event
}
