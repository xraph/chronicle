package chronicle

import "time"

// Entity is the base type embedded by all Chronicle entities.
// It provides common timestamp fields.
type Entity struct {
	CreatedAt time.Time `json:"created_at" bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt time.Time `json:"updated_at" bun:"updated_at,notnull,default:current_timestamp"`
}

// NewEntity returns an Entity with both timestamps set to the current UTC time.
func NewEntity() Entity {
	now := time.Now().UTC()
	return Entity{CreatedAt: now, UpdatedAt: now}
}
