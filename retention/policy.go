// Package retention defines retention policy and archive entities.
package retention

import (
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
)

// Policy defines how long events of a given category are retained.
type Policy struct {
	chronicle.Entity
	ID       id.ID         `json:"id"`
	Category string        `json:"category"` // "*" for default
	Duration time.Duration `json:"duration"`
	Archive  bool          `json:"archive"` // archive before purge?
	AppID    string        `json:"app_id"`
}
