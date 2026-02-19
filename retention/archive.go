package retention

import (
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
)

// Archive records that a batch of events was archived to cold storage.
type Archive struct {
	chronicle.Entity
	ID            id.ID     `json:"id"`
	PolicyID      id.ID     `json:"policy_id"`
	Category      string    `json:"category"`
	EventCount    int64     `json:"event_count"`
	FromTimestamp time.Time `json:"from_timestamp"`
	ToTimestamp   time.Time `json:"to_timestamp"`
	SinkName      string    `json:"sink_name"`
	SinkRef       string    `json:"sink_ref"` // e.g. S3 key
}

// ListOpts defines pagination options for listing archives.
type ListOpts struct {
	Limit  int
	Offset int
}
