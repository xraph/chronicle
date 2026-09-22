package chronicle_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
)

func TestBuilderSetsRequestFields(t *testing.T) {
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(memory.New())))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := c.Info(context.Background(), "signin", "session", "sess_1").
		IP("203.0.113.9").
		UserAgent("Mozilla/5.0").
		RequestID("req_abc").
		SessionID("sess_1").
		Event()

	if ev.IP != "203.0.113.9" {
		t.Errorf("IP = %q", ev.IP)
	}
	if ev.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %q", ev.UserAgent)
	}
	if ev.RequestID != "req_abc" {
		t.Errorf("RequestID = %q", ev.RequestID)
	}
	if ev.SessionID != "sess_1" {
		t.Errorf("SessionID = %q", ev.SessionID)
	}
}
