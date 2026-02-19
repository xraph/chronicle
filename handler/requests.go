package handler

import (
	"strconv"

	"github.com/xraph/forge"

	"github.com/xraph/chronicle/audit"
)

// ──────────────────────────────────────────────────
// Event request/response DTOs
// ──────────────────────────────────────────────────

// ListEventsRequest is the request for listing audit events.
type ListEventsRequest struct {
	Category string `query:"category" optional:"true" description:"Filter by category (comma-separated)"`
	Action   string `query:"action" optional:"true" description:"Filter by action (comma-separated)"`
	Severity string `query:"severity" optional:"true" description:"Filter by severity (comma-separated)"`
	Outcome  string `query:"outcome" optional:"true" description:"Filter by outcome (comma-separated)"`
	After    string `query:"after" optional:"true" description:"Events after this time (RFC3339)"`
	Before   string `query:"before" optional:"true" description:"Events before this time (RFC3339)"`
	Limit    int    `query:"limit" optional:"true" description:"Maximum results (default: 50, max: 1000)"`
	Offset   int    `query:"offset" optional:"true" description:"Number of results to skip"`
	Order    string `query:"order" optional:"true" description:"Sort order: asc or desc (default: desc)"`
}

// GetEventRequest is the request for fetching a single event.
type GetEventRequest struct {
	EventID string `path:"id" description:"Audit event ID"`
}

// EventsByUserRequest is the request for fetching events by user.
type EventsByUserRequest struct {
	UserID string `path:"userId" description:"User ID"`
	After  string `query:"after" optional:"true" description:"Events after this time (RFC3339)"`
	Before string `query:"before" optional:"true" description:"Events before this time (RFC3339)"`
}

// ──────────────────────────────────────────────────
// Verify request DTOs
// ──────────────────────────────────────────────────

// VerifyChainRequest is the JSON request body for chain verification.
type VerifyChainRequest struct {
	StreamID string `json:"stream_id" description:"Stream ID to verify"`
	FromSeq  uint64 `json:"from_seq" description:"Starting sequence number"`
	ToSeq    uint64 `json:"to_seq" description:"Ending sequence number"`
}

// ──────────────────────────────────────────────────
// Erasure request/response DTOs
// ──────────────────────────────────────────────────

// RequestErasureRequest is the JSON request body for creating an erasure.
type RequestErasureRequest struct {
	SubjectID   string `json:"subject_id" description:"Subject ID to erase"`
	Reason      string `json:"reason" description:"Reason for erasure"`
	RequestedBy string `json:"requested_by" description:"Who requested the erasure"`
}

// ListErasuresRequest is the request for listing erasure records.
type ListErasuresRequest struct {
	Limit  int `query:"limit" optional:"true" description:"Maximum results (default: 50)"`
	Offset int `query:"offset" optional:"true" description:"Number of results to skip"`
}

// GetErasureRequest is the request for fetching a single erasure.
type GetErasureRequest struct {
	ErasureID string `path:"id" description:"Erasure record ID"`
}

// ──────────────────────────────────────────────────
// Retention request/response DTOs
// ──────────────────────────────────────────────────

// SavePolicyRequest is the JSON request body for saving a retention policy.
type SavePolicyRequest struct {
	Category string `json:"category" description:"Event category to apply retention to"`
	Duration string `json:"duration" description:"Retention duration (Go duration string, e.g. 720h)"`
	Archive  bool   `json:"archive" description:"Whether to archive events before purging"`
}

// DeletePolicyRequest is the request for deleting a retention policy.
type DeletePolicyRequest struct {
	PolicyID string `path:"id" description:"Policy ID"`
}

// ListArchivesRequest is the request for listing archive records.
type ListArchivesRequest struct {
	Limit  int `query:"limit" optional:"true" description:"Maximum results (default: 50)"`
	Offset int `query:"offset" optional:"true" description:"Number of results to skip"`
}

// ──────────────────────────────────────────────────
// Report request/response DTOs
// ──────────────────────────────────────────────────

// ListReportsRequest is the request for listing compliance reports.
type ListReportsRequest struct {
	Limit  int `query:"limit" optional:"true" description:"Maximum results (default: 50)"`
	Offset int `query:"offset" optional:"true" description:"Number of results to skip"`
}

// GetReportRequest is the request for fetching a single report.
type GetReportRequest struct {
	ReportID string `path:"id" description:"Report ID"`
}

// ExportReportRequest is the request for exporting a report.
type ExportReportRequest struct {
	ReportID string `path:"id" description:"Report ID"`
	Format   string `path:"format" description:"Export format: json, csv, markdown, html"`
}

// ──────────────────────────────────────────────────
// Stats response
// ──────────────────────────────────────────────────

// StatsResponse contains aggregate audit event statistics.
type StatsResponse struct {
	TotalEvents  int64                  `json:"total_events"`
	Categories   []audit.AggregateGroup `json:"categories"`
	Severities   []audit.AggregateGroup `json:"severities"`
	Outcomes     []audit.AggregateGroup `json:"outcomes"`
	RecentEvents []*audit.Event         `json:"recent_events"`
}

// ──────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────

// defaultLimit applies default pagination values.
func defaultLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

// defaultOffset ensures offset is non-negative.
func defaultOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

// queryInt extracts an integer query parameter from the request.
// Returns 0 for missing or malformed values.
func queryInt(ctx forge.Context, name string) int {
	v := ctx.Query(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}
