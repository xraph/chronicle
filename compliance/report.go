// Package compliance defines compliance report entities and the report store interface.
package compliance

import (
	"context"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// Format defines the export format for compliance reports.
type Format string

// Supported export formats.
const (
	FormatJSON     Format = "json"
	FormatCSV      Format = "csv"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
	FormatPDF      Format = "pdf"
)

// DateRange defines a period for compliance reports.
type DateRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Report is a generated compliance report.
type Report struct {
	chronicle.Entity
	ID           id.ID          `json:"id"`
	Title        string         `json:"title"`
	Type         string         `json:"type"`
	Period       DateRange      `json:"period"`
	AppID        string         `json:"app_id"`
	TenantID     string         `json:"tenant_id"`
	Sections     []Section      `json:"sections"`
	Stats        *Stats         `json:"stats,omitempty"`
	Verification *verify.Report `json:"verification,omitempty"`
	GeneratedBy  string         `json:"generated_by"`
	Format       Format         `json:"format"`
	Data         []byte         `json:"data,omitempty"`
}

// Section is a part of a compliance report.
type Section struct {
	Title  string                 `json:"title"`
	Events []*audit.Event         `json:"events,omitempty"`
	Stats  *audit.AggregateResult `json:"stats,omitempty"`
	Notes  string                 `json:"notes,omitempty"`
}

// Stats holds summary statistics for a report.
type Stats struct {
	TotalEvents    int64 `json:"total_events"`
	CriticalEvents int64 `json:"critical_events"`
	FailedEvents   int64 `json:"failed_events"`
	DeniedEvents   int64 `json:"denied_events"`
}

// ListOpts defines pagination options for listing reports.
type ListOpts struct {
	Limit  int
	Offset int
}

// ReportStore manages generated compliance reports.
type ReportStore interface {
	// SaveReport persists a generated compliance report.
	SaveReport(ctx context.Context, r *Report) error

	// GetReport returns a report by ID.
	GetReport(ctx context.Context, reportID id.ID) (*Report, error)

	// ListReports returns reports, optionally filtered.
	ListReports(ctx context.Context, opts ListOpts) ([]*Report, error)

	// DeleteReport removes a report.
	DeleteReport(ctx context.Context, reportID id.ID) error
}
