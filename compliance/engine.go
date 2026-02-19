package compliance

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// Engine generates compliance reports from audit data.
type Engine struct {
	auditStore  audit.Store
	verifyStore verify.Store
	reportStore ReportStore
	logger      *slog.Logger
}

// NewEngine creates a compliance engine.
func NewEngine(auditStore audit.Store, verifyStore verify.Store, reportStore ReportStore, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		auditStore:  auditStore,
		verifyStore: verifyStore,
		reportStore: reportStore,
		logger:      logger,
	}
}

// SOC2 generates a SOC2 Type II compliance report.
func (e *Engine) SOC2(ctx context.Context, input *SOC2Input) (*Report, error) {
	e.logger.InfoContext(ctx, "generating SOC2 Type II report",
		"app_id", input.AppID,
		"from", input.Period.From,
		"to", input.Period.To,
	)

	sections, err := e.buildSOC2(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("building SOC2 sections: %w", err)
	}

	stats := calculateStats(sections)

	report := &Report{
		Entity:      chronicle.NewEntity(),
		ID:          id.NewReportID(),
		Title:       "SOC2 Type II Compliance Report",
		Type:        "soc2",
		Period:      input.Period,
		AppID:       input.AppID,
		TenantID:    input.TenantID,
		Sections:    sections,
		Stats:       stats,
		GeneratedBy: input.GeneratedBy,
		Format:      FormatJSON,
	}

	if err := e.reportStore.SaveReport(ctx, report); err != nil {
		return nil, fmt.Errorf("saving report: %w", err)
	}

	e.logger.InfoContext(ctx, "SOC2 report generated",
		"report_id", report.ID.String(),
		"total_events", stats.TotalEvents,
	)

	return report, nil
}

// HIPAA generates a HIPAA audit report.
func (e *Engine) HIPAA(ctx context.Context, input *HIPAAInput) (*Report, error) {
	e.logger.InfoContext(ctx, "generating HIPAA report",
		"app_id", input.AppID,
		"from", input.Period.From,
		"to", input.Period.To,
	)

	sections, err := e.buildHIPAA(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("building HIPAA sections: %w", err)
	}

	stats := calculateStats(sections)

	report := &Report{
		Entity:      chronicle.NewEntity(),
		ID:          id.NewReportID(),
		Title:       "HIPAA Audit Report",
		Type:        "hipaa",
		Period:      input.Period,
		AppID:       input.AppID,
		TenantID:    input.TenantID,
		Sections:    sections,
		Stats:       stats,
		GeneratedBy: input.GeneratedBy,
		Format:      FormatJSON,
	}

	if err := e.reportStore.SaveReport(ctx, report); err != nil {
		return nil, fmt.Errorf("saving report: %w", err)
	}

	e.logger.InfoContext(ctx, "HIPAA report generated",
		"report_id", report.ID.String(),
		"total_events", stats.TotalEvents,
	)

	return report, nil
}

// EUAIAct generates an EU AI Act transparency report.
func (e *Engine) EUAIAct(ctx context.Context, input *EUAIActInput) (*Report, error) {
	e.logger.InfoContext(ctx, "generating EU AI Act report",
		"app_id", input.AppID,
		"from", input.Period.From,
		"to", input.Period.To,
	)

	sections, err := e.buildEUAIAct(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("building EU AI Act sections: %w", err)
	}

	stats := calculateStats(sections)

	report := &Report{
		Entity:      chronicle.NewEntity(),
		ID:          id.NewReportID(),
		Title:       "EU AI Act Transparency Report",
		Type:        "eu_ai_act",
		Period:      input.Period,
		AppID:       input.AppID,
		TenantID:    input.TenantID,
		Sections:    sections,
		Stats:       stats,
		GeneratedBy: input.GeneratedBy,
		Format:      FormatJSON,
	}

	if err := e.reportStore.SaveReport(ctx, report); err != nil {
		return nil, fmt.Errorf("saving report: %w", err)
	}

	e.logger.InfoContext(ctx, "EU AI Act report generated",
		"report_id", report.ID.String(),
		"total_events", stats.TotalEvents,
	)

	return report, nil
}

// Custom generates a custom compliance report.
func (e *Engine) Custom(ctx context.Context, input *CustomInput) (*Report, error) {
	e.logger.InfoContext(ctx, "generating custom report",
		"title", input.Title,
		"app_id", input.AppID,
		"from", input.Period.From,
		"to", input.Period.To,
	)

	sections, err := e.buildCustom(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("building custom sections: %w", err)
	}

	stats := calculateStats(sections)

	report := &Report{
		Entity:      chronicle.NewEntity(),
		ID:          id.NewReportID(),
		Title:       input.Title,
		Type:        "custom",
		Period:      input.Period,
		AppID:       input.AppID,
		TenantID:    input.TenantID,
		Sections:    sections,
		Stats:       stats,
		GeneratedBy: input.GeneratedBy,
		Format:      FormatJSON,
	}

	if err := e.reportStore.SaveReport(ctx, report); err != nil {
		return nil, fmt.Errorf("saving report: %w", err)
	}

	e.logger.InfoContext(ctx, "custom report generated",
		"report_id", report.ID.String(),
		"total_events", stats.TotalEvents,
	)

	return report, nil
}

// Export exports a report to the given format and writer.
func (e *Engine) Export(_ context.Context, r *Report, format Format, w io.Writer) error {
	switch format {
	case FormatJSON:
		return exportJSON(r, w)
	case FormatCSV:
		return exportCSV(r, w)
	case FormatMarkdown:
		return exportMarkdown(r, w)
	case FormatHTML:
		return exportHTML(r, w)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// calculateStats computes summary statistics across all report sections.
func calculateStats(sections []Section) *Stats {
	stats := &Stats{}

	seen := make(map[string]bool)

	for _, s := range sections {
		for _, ev := range s.Events {
			key := ev.ID.String()
			if seen[key] {
				continue
			}
			seen[key] = true

			stats.TotalEvents++

			if ev.Severity == audit.SeverityCritical {
				stats.CriticalEvents++
			}
			if ev.Outcome == audit.OutcomeFailure {
				stats.FailedEvents++
			}
			if ev.Outcome == audit.OutcomeDenied {
				stats.DeniedEvents++
			}
		}
	}

	return stats
}
