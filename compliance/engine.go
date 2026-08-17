package compliance

import (
	"context"
	"fmt"
	"io"

	log "github.com/xraph/go-utils/log"

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
	logger      log.Logger
}

// NewEngine creates a compliance engine.
func NewEngine(auditStore audit.Store, verifyStore verify.Store, reportStore ReportStore, logger log.Logger) *Engine {
	if logger == nil {
		logger = log.NewNoopLogger()
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
	e.logger.Info("generating SOC2 Type II report",
		log.String("app_id", input.AppID),
		log.Any("from", input.Period.From),
		log.Any("to", input.Period.To),
	)

	sections, err := e.buildSOC2(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("building SOC2 sections: %w", err)
	}

	stats, err := e.periodStats(ctx, input.Period, input.AppID, input.TenantID)
	if err != nil {
		return nil, err
	}

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

	e.logger.Info("SOC2 report generated",
		log.String("report_id", report.ID.String()),
		log.Int64("total_events", stats.TotalEvents),
	)

	return report, nil
}

// HIPAA generates a HIPAA audit report.
func (e *Engine) HIPAA(ctx context.Context, input *HIPAAInput) (*Report, error) {
	e.logger.Info("generating HIPAA report",
		log.String("app_id", input.AppID),
		log.Any("from", input.Period.From),
		log.Any("to", input.Period.To),
	)

	sections, err := e.buildHIPAA(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("building HIPAA sections: %w", err)
	}

	stats, err := e.periodStats(ctx, input.Period, input.AppID, input.TenantID)
	if err != nil {
		return nil, err
	}

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

	e.logger.Info("HIPAA report generated",
		log.String("report_id", report.ID.String()),
		log.Int64("total_events", stats.TotalEvents),
	)

	return report, nil
}

// EUAIAct generates an EU AI Act transparency report.
func (e *Engine) EUAIAct(ctx context.Context, input *EUAIActInput) (*Report, error) {
	e.logger.Info("generating EU AI Act report",
		log.String("app_id", input.AppID),
		log.Any("from", input.Period.From),
		log.Any("to", input.Period.To),
	)

	sections, err := e.buildEUAIAct(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("building EU AI Act sections: %w", err)
	}

	stats, err := e.periodStats(ctx, input.Period, input.AppID, input.TenantID)
	if err != nil {
		return nil, err
	}

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

	e.logger.Info("EU AI Act report generated",
		log.String("report_id", report.ID.String()),
		log.Int64("total_events", stats.TotalEvents),
	)

	return report, nil
}

// Custom generates a custom compliance report.
func (e *Engine) Custom(ctx context.Context, input *CustomInput) (*Report, error) {
	e.logger.Info("generating custom report",
		log.String("title", input.Title),
		log.String("app_id", input.AppID),
		log.Any("from", input.Period.From),
		log.Any("to", input.Period.To),
	)

	sections, err := e.buildCustom(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("building custom sections: %w", err)
	}

	stats, err := e.periodStats(ctx, input.Period, input.AppID, input.TenantID)
	if err != nil {
		return nil, err
	}

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

	e.logger.Info("custom report generated",
		log.String("report_id", report.ID.String()),
		log.Int64("total_events", stats.TotalEvents),
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

// periodStats computes exact summary statistics for a report's period and scope.
//
// These counts must not be derived from the sections' embedded events: those are
// capped at MaxSectionEvents, so a busy period would report its cap instead of
// its real volume, contradicting the sections' own aggregate stats. A single
// grouped aggregate over the whole period is both exact and one round trip.
//
// The counts describe every event in the period, which is what an auditor reads
// "total events" to mean, rather than the union of the sections' filters.
func (e *Engine) periodStats(
	ctx context.Context, period DateRange, appID, tenantID string,
) (*Stats, error) {
	result, err := e.auditStore.Aggregate(ctx, &audit.AggregateQuery{
		After:    period.From,
		Before:   period.To,
		AppID:    appID,
		TenantID: tenantID,
		GroupBy:  []string{"outcome", "severity"},
	})
	if err != nil {
		return nil, fmt.Errorf("aggregating period stats: %w", err)
	}

	stats := &Stats{TotalEvents: result.Total}
	for _, g := range result.Groups {
		if g.Severity == audit.SeverityCritical {
			stats.CriticalEvents += g.Count
		}
		switch g.Outcome {
		case audit.OutcomeFailure:
			stats.FailedEvents += g.Count
		case audit.OutcomeDenied:
			stats.DeniedEvents += g.Count
		}
	}

	return stats, nil
}
