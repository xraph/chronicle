package handler

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/scope"
)

// formatContentTypes maps export formats to their HTTP Content-Type.
var formatContentTypes = map[compliance.Format]string{
	compliance.FormatJSON:     "application/json; charset=utf-8",
	compliance.FormatCSV:      "text/csv; charset=utf-8",
	compliance.FormatMarkdown: "text/markdown; charset=utf-8",
	compliance.FormatHTML:     "text/html; charset=utf-8",
}

// listReports handles GET /v1/reports.
func (a *API) listReports(ctx forge.Context) error {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return err
	}

	c, span := a.tracer.Start(c, "chronicle.listReports")
	defer span.End()

	opts := compliance.ListOpts{
		Limit:  defaultLimit(queryInt(ctx, "limit")),
		Offset: defaultOffset(queryInt(ctx, "offset")),
	}

	reports, err := a.deps.ReportStore.ListReports(c, opts)
	if err != nil {
		a.deps.Logger.Error("failed to list reports", log.Error(err))
		return fmt.Errorf("list reports: %w", err)
	}

	// Filter by app scope.
	info := scope.FromContext(c)
	filtered := make([]*compliance.Report, 0, len(reports))
	for _, rpt := range reports {
		if rpt.AppID == info.AppID {
			filtered = append(filtered, rpt)
		}
	}

	return ctx.JSON(http.StatusOK, filtered)
}

// generateSOC2 handles POST /v1/reports/soc2.
func (a *API) generateSOC2(ctx forge.Context, req *compliance.SOC2Input) (*compliance.Report, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if a.deps.Compliance == nil {
		return nil, forge.NewHTTPError(http.StatusServiceUnavailable, "compliance engine not configured")
	}

	c, span := a.tracer.Start(c, "chronicle.generateSOC2")
	defer span.End()

	// Override scope from context for security.
	info := scope.FromContext(c)
	req.AppID = info.AppID
	if info.TenantID != "" {
		req.TenantID = info.TenantID
	}

	report, err := a.deps.Compliance.SOC2(c, req)
	if err != nil {
		a.deps.Logger.Error("failed to generate SOC2 report", log.Error(err))
		return nil, fmt.Errorf("generate SOC2: %w", err)
	}

	return report, ctx.JSON(http.StatusCreated, report)
}

// generateHIPAA handles POST /v1/reports/hipaa.
func (a *API) generateHIPAA(ctx forge.Context, req *compliance.HIPAAInput) (*compliance.Report, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if a.deps.Compliance == nil {
		return nil, forge.NewHTTPError(http.StatusServiceUnavailable, "compliance engine not configured")
	}

	c, span := a.tracer.Start(c, "chronicle.generateHIPAA")
	defer span.End()

	info := scope.FromContext(c)
	req.AppID = info.AppID
	if info.TenantID != "" {
		req.TenantID = info.TenantID
	}

	report, err := a.deps.Compliance.HIPAA(c, req)
	if err != nil {
		a.deps.Logger.Error("failed to generate HIPAA report", log.Error(err))
		return nil, fmt.Errorf("generate HIPAA: %w", err)
	}

	return report, ctx.JSON(http.StatusCreated, report)
}

// generateEUAIAct handles POST /v1/reports/euaiact.
func (a *API) generateEUAIAct(ctx forge.Context, req *compliance.EUAIActInput) (*compliance.Report, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if a.deps.Compliance == nil {
		return nil, forge.NewHTTPError(http.StatusServiceUnavailable, "compliance engine not configured")
	}

	c, span := a.tracer.Start(c, "chronicle.generateEUAIAct")
	defer span.End()

	info := scope.FromContext(c)
	req.AppID = info.AppID
	if info.TenantID != "" {
		req.TenantID = info.TenantID
	}

	report, err := a.deps.Compliance.EUAIAct(c, req)
	if err != nil {
		a.deps.Logger.Error("failed to generate EU AI Act report", log.Error(err))
		return nil, fmt.Errorf("generate EU AI Act: %w", err)
	}

	return report, ctx.JSON(http.StatusCreated, report)
}

// generateCustom handles POST /v1/reports/custom.
func (a *API) generateCustom(ctx forge.Context, req *compliance.CustomInput) (*compliance.Report, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if a.deps.Compliance == nil {
		return nil, forge.NewHTTPError(http.StatusServiceUnavailable, "compliance engine not configured")
	}

	c, span := a.tracer.Start(c, "chronicle.generateCustom")
	defer span.End()

	info := scope.FromContext(c)
	req.AppID = info.AppID
	if info.TenantID != "" {
		req.TenantID = info.TenantID
	}

	report, err := a.deps.Compliance.Custom(c, req)
	if err != nil {
		a.deps.Logger.Error("failed to generate custom report", log.Error(err))
		return nil, fmt.Errorf("generate custom: %w", err)
	}

	return report, ctx.JSON(http.StatusCreated, report)
}

// getReport handles GET /v1/reports/:id.
func (a *API) getReport(ctx forge.Context, _ *GetReportRequest) (*compliance.Report, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	c, span := a.tracer.Start(c, "chronicle.getReport")
	defer span.End()

	reportID, err := parseReportID(ctx.Param("id"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid report ID: %v", err))
	}

	report, err := a.deps.ReportStore.GetReport(c, reportID)
	if err != nil {
		return nil, mapStoreError(err)
	}

	// Verify the report belongs to the caller's scope.
	info := scope.FromContext(c)
	if info.AppID != "" && report.AppID != info.AppID {
		return nil, forge.NotFound("report not found")
	}

	return report, ctx.JSON(http.StatusOK, report)
}

// exportReport handles GET /v1/reports/:id/export/:format.
// This handler writes non-JSON content types directly to the response.
func (a *API) exportReport(ctx forge.Context) error {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return err
	}

	if a.deps.Compliance == nil {
		return forge.NewHTTPError(http.StatusServiceUnavailable, "compliance engine not configured")
	}

	reportID, err := parseReportID(ctx.Param("id"))
	if err != nil {
		return forge.BadRequest(fmt.Sprintf("invalid report ID: %v", err))
	}

	format := compliance.Format(ctx.Param("format"))

	ct, ok := formatContentTypes[format]
	if !ok {
		return forge.BadRequest("unsupported export format")
	}

	c, span := a.tracer.Start(c, "chronicle.exportReport",
		trace.WithAttributes(
			attribute.String("report_id", reportID.String()),
			attribute.String("format", string(format)),
		))
	defer span.End()

	report, err := a.deps.ReportStore.GetReport(c, reportID)
	if err != nil {
		return mapStoreError(err)
	}

	// Verify the report belongs to the caller's scope.
	info := scope.FromContext(c)
	if info.AppID != "" && report.AppID != info.AppID {
		return forge.NotFound("report not found")
	}

	var buf bytes.Buffer
	if err := a.deps.Compliance.Export(c, report, format, &buf); err != nil {
		a.deps.Logger.Error("failed to export report", log.String("format", string(format)), log.Error(err))
		return fmt.Errorf("export report: %w", err)
	}

	ctx.SetHeader("Content-Type", ct)
	return ctx.Bytes(http.StatusOK, buf.Bytes())
}
