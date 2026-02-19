package audit

import "time"

// Query defines filters for querying audit events.
type Query struct {
	// Time range
	After  time.Time `json:"after"`
	Before time.Time `json:"before"`

	// Scope (auto-set from forge.Scope if not explicit)
	AppID    string `json:"app_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`

	// Filters
	Categories []string `json:"categories,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	Resources  []string `json:"resources,omitempty"`
	Severity   []string `json:"severity,omitempty"`
	Outcome    []string `json:"outcome,omitempty"`

	// Pagination
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
	Order  string `json:"order"` // "asc" or "desc"
}

// QueryResult is the paginated result of an event query.
type QueryResult struct {
	Events  []*Event `json:"events"`
	Total   int64    `json:"total"`
	HasMore bool     `json:"has_more"`
}

// AggregateQuery defines parameters for grouped event statistics.
type AggregateQuery struct {
	After    time.Time `json:"after"`
	Before   time.Time `json:"before"`
	AppID    string    `json:"app_id,omitempty"`
	TenantID string    `json:"tenant_id,omitempty"`
	GroupBy  []string  `json:"group_by"` // "category", "action", "outcome", "severity", "resource"
}

// AggregateResult is the result of an aggregation query.
type AggregateResult struct {
	Groups []AggregateGroup `json:"groups"`
	Total  int64            `json:"total"`
}

// AggregateGroup is a single group in an aggregation result.
type AggregateGroup struct {
	Category string `json:"category,omitempty"`
	Action   string `json:"action,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
	Severity string `json:"severity,omitempty"`
	Resource string `json:"resource,omitempty"`
	Count    int64  `json:"count"`
}

// CountQuery defines filters for counting events.
type CountQuery struct {
	After    time.Time `json:"after"`
	Before   time.Time `json:"before"`
	AppID    string    `json:"app_id,omitempty"`
	TenantID string    `json:"tenant_id,omitempty"`
	Category string    `json:"category,omitempty"`
}

// TimeRange defines a time range for queries.
type TimeRange struct {
	After  time.Time `json:"after"`
	Before time.Time `json:"before"`
}
