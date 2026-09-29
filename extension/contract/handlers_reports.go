package contract

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/id"
)

// defaultReportListLimit and maxReportListLimit are the report list's page
// size and cap. See pageBounds for how a limit and offset are treated.
const (
	defaultReportListLimit = 50
	maxReportListLimit     = 1000
)

// defaultReportPeriodDays is the period a generate call covers when the
// request names none. It matches what the templ page generated.
const defaultReportPeriodDays = 90

// maxCustomReportSections bounds the sections one custom report may define.
// Each section runs its own query and embeds up to compliance.MaxSectionEvents
// events in the stored report, so an unbounded list lets one write-capable
// operator build a report of arbitrary size in a single call. The fixed
// frameworks have five or six sections; this leaves generous room above that.
const maxCustomReportSections = 20

// maxCustomReportTitleLen bounds a custom report's title, in characters. The
// title is stored with the report and shown in every list of them, so an
// unbounded one is caller-chosen storage.
const maxCustomReportTitleLen = 200

// maxCustomSectionFilters bounds each of a section's filter lists
// (categories, actions and severity) to this many values. Each value widens
// the section's query, and a list of thousands is a request built to be slow,
// not a filter anybody wrote by hand.
const maxCustomSectionFilters = 50

// maxCustomSectionTitleLen, maxCustomSectionNotesLen and
// maxCustomFilterValueLen bound the rest of what a custom report stores from
// the request, in characters. A section's title and notes are written into
// the report and its exports, and each filter value is stored beside them, so
// leaving them open would make the report title's bound worth nothing: the
// same caller-chosen storage, one field over.
const (
	maxCustomSectionTitleLen = 200
	maxCustomSectionNotesLen = 4000
	maxCustomFilterValueLen  = 128
)

// Report types accepted by reports.generate, matched exactly. A whitelist
// that quietly normalised case is one somebody later widens.
const (
	reportTypeSOC2    = "soc2"
	reportTypeHIPAA   = "hipaa"
	reportTypeEUAIAct = "euaiact"
)

// Export formats accepted by reports.export, matched exactly.
const (
	exportFormatJSON     = "json"
	exportFormatCSV      = "csv"
	exportFormatMarkdown = "markdown"
	exportFormatHTML     = "html"
)

// ReportPeriod is a report's period on the wire, as RFC 3339 timestamps.
type ReportPeriod struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// ReportStats is compliance.Stats on the wire. The counts are exact for the
// whole period and scope: the engine aggregates them separately from the
// sections, whose embedded events are capped.
type ReportStats struct {
	TotalEvents    int64 `json:"totalEvents"`
	CriticalEvents int64 `json:"criticalEvents"`
	FailedEvents   int64 `json:"failedEvents"`
	DeniedEvents   int64 `json:"deniedEvents"`
}

// ReportSummary is one report as a list shows it. It carries no sections and
// so no events: a report can embed up to MaxSectionEvents events per section,
// and a list of those would dominate the response. reports.detail carries
// them.
//
// Type is the engine's own stored value, which is not always the value
// reports.generate accepted: a report requested as "euaiact" is stored, and
// reported here, as "eu_ai_act".
type ReportSummary struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Type        string       `json:"type"`
	Period      ReportPeriod `json:"period"`
	GeneratedBy string       `json:"generatedBy"`
	Format      string       `json:"format"`
	CreatedAt   string       `json:"createdAt"`
	Stats       *ReportStats `json:"stats,omitempty"`
}

// ReportSection is one section of a report with its evidence.
//
// Events is a sample when EventsTruncated is true: the engine caps it at
// compliance.MaxSectionEvents, and MatchedEvents is how many events matched
// the section's filters. A page that showed Events without saying so would
// present a partial listing as complete evidence.
type ReportSection struct {
	Title           string             `json:"title"`
	Notes           string             `json:"notes,omitempty"`
	Events          []EventSummary     `json:"events"`
	MatchedEvents   int64              `json:"matchedEvents"`
	EventsTruncated bool               `json:"eventsTruncated"`
	Stats           *AggregateResponse `json:"stats,omitempty"`
}

// ReportDetail is a report with its sections and any embedded verification.
//
// Verification is nil when the report carries no integrity verification. A
// nil value means exactly that and never that verification passed: the page
// must not render it as a pass. When present it crosses in VerifyReport's
// full shape, so the page can show the same three states (not checked,
// checked and held, checked and failed) as the verify page.
//
// There is no raw-data field: compliance.Report.Data is never written.
type ReportDetail struct {
	ReportSummary
	Sections     []ReportSection `json:"sections"`
	Verification *VerifyReport   `json:"verification,omitempty"`
}

// ReportListInput pages through the viewer's own scope's reports. There is
// deliberately no appId or tenantId field: scope comes from the principal.
type ReportListInput struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// ReportListResponse is one page of reports. It carries HasMore and no
// total: compliance.ReportStore has no count method, so a total would mean
// counting a bounded list, which understates it on every page after the
// first. HasMore comes from asking the store for one row past the page.
type ReportListResponse struct {
	Reports []ReportSummary `json:"reports"`
	HasMore bool            `json:"hasMore"`
}

// GetReportInput names one report by ID.
type GetReportInput struct {
	ID string `json:"id"`
}

// GenerateReportInput asks for one of the fixed frameworks: type is exactly
// "soc2", "hipaa" or "euaiact". Period is optional; nil, or both bounds
// empty, means the last 90 days. There is no appId or tenantId field, and
// none for who generated it: those come from the principal.
type GenerateReportInput struct {
	Type   string        `json:"type"`
	Period *ReportPeriod `json:"period,omitempty"`
}

// CustomReportSection defines one section of a custom report. Empty
// categories, actions and severity match everything. The title is bounded by
// maxCustomSectionTitleLen, the notes by maxCustomSectionNotesLen, each filter
// list by maxCustomSectionFilters and each filter value by
// maxCustomFilterValueLen.
type CustomReportSection struct {
	Title      string   `json:"title"`
	Categories []string `json:"categories,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	Severity   []string `json:"severity,omitempty"`
	Notes      string   `json:"notes,omitempty"`
}

// GenerateCustomReportInput asks for a report of the caller's own design.
type GenerateCustomReportInput struct {
	Title    string                `json:"title"`
	Period   *ReportPeriod         `json:"period,omitempty"`
	Sections []CustomReportSection `json:"sections"`
}

// GenerateReportResponse names the report the engine just stored.
type GenerateReportResponse struct {
	ID     string        `json:"id"`
	Report ReportSummary `json:"report"`
}

// ExportReportInput names a report and a format: exactly "json", "csv",
// "markdown" or "html".
type ExportReportInput struct {
	ID     string `json:"id"`
	Format string `json:"format"`
}

// ExportReportResponse is a rendered report. Content is the whole document as
// text, for the client to save as a file named Filename. The html format is
// a complete page whose values were escaped by html/template; the client
// should offer it as a download and not inject it into the dashboard's own
// DOM.
type ExportReportResponse struct {
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

func reportsRegistrations() []registration {
	return []registration{
		query("reports.list", reportsListHandler),
		query("reports.detail", reportsDetailHandler),
		command("reports.generate", reportsGenerateHandler),
		command("reports.generateCustom", reportsGenerateCustomHandler),
		query("reports.export", reportsExportHandler),
	}
}

func reportNotFound() error {
	return &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
}

func reportBadRequest(msg string) error {
	return &fcontract.Error{Code: fcontract.CodeBadRequest, Message: msg}
}

func projectReportStats(s *compliance.Stats) *ReportStats {
	if s == nil {
		return nil
	}
	return &ReportStats{
		TotalEvents:    s.TotalEvents,
		CriticalEvents: s.CriticalEvents,
		FailedEvents:   s.FailedEvents,
		DeniedEvents:   s.DeniedEvents,
	}
}

// projectReportSummary turns a stored report into its wire summary. It reads
// no section.
func projectReportSummary(r *compliance.Report) ReportSummary {
	return ReportSummary{
		ID:    r.ID.String(),
		Title: r.Title,
		Type:  r.Type,
		Period: ReportPeriod{
			From: formatTime(r.Period.From),
			To:   formatTime(r.Period.To),
		},
		GeneratedBy: r.GeneratedBy,
		Format:      string(r.Format),
		CreatedAt:   formatTime(r.CreatedAt),
		Stats:       projectReportStats(r.Stats),
	}
}

func projectAggregateResult(a *audit.AggregateResult) *AggregateResponse {
	if a == nil {
		return nil
	}
	out := &AggregateResponse{
		Groups: make([]AggregateGroupDTO, 0, len(a.Groups)),
		Total:  a.Total,
	}
	for _, g := range a.Groups {
		out.Groups = append(out.Groups, AggregateGroupDTO{
			Bucket:   g.Bucket,
			Category: g.Category,
			Action:   g.Action,
			Outcome:  g.Outcome,
			Severity: g.Severity,
			Resource: g.Resource,
			Count:    g.Count,
		})
	}
	return out
}

// projectReportDetail turns a stored report into its wire detail. The
// embedded verification is projected through projectReport, the same
// projection verify.run uses, so the two cannot disagree about a field.
//
// projectReport leaves RetentionPolicies at zero, and zero is a real answer
// ("no policy can purge this chain"). Nobody counted policies for a report's
// embedded verification, so it says -1, unknown, rather than claiming there
// were none.
func projectReportDetail(r *compliance.Report) ReportDetail {
	out := ReportDetail{
		ReportSummary: projectReportSummary(r),
		Sections:      make([]ReportSection, 0, len(r.Sections)),
		Verification:  projectReport(r.Verification),
	}
	if out.Verification != nil {
		out.Verification.RetentionPolicies = -1
	}
	for _, s := range r.Sections {
		sec := ReportSection{
			Title:           s.Title,
			Notes:           s.Notes,
			Events:          make([]EventSummary, 0, len(s.Events)),
			MatchedEvents:   s.MatchedEvents,
			EventsTruncated: s.EventsTruncated,
			Stats:           projectAggregateResult(s.Stats),
		}
		for _, e := range s.Events {
			if e == nil {
				continue
			}
			sec.Events = append(sec.Events, projectEventSummary(e))
		}
		out.Sections = append(out.Sections, sec)
	}
	return out
}

// reportPeriod resolves a request's period. Nil, or both bounds empty, is
// the last 90 days. One bound without the other is refused rather than
// filled in: a compliance report's period is part of what it attests to, and
// guessing the missing half would attest to a period nobody asked for.
func reportPeriod(p *ReportPeriod) (compliance.DateRange, error) {
	if p == nil || (p.From == "" && p.To == "") {
		now := time.Now().UTC()
		return compliance.DateRange{From: now.AddDate(0, 0, -defaultReportPeriodDays), To: now}, nil
	}
	if p.From == "" || p.To == "" {
		return compliance.DateRange{}, reportBadRequest("period needs both from and to, or neither")
	}

	from, err := time.Parse(time.RFC3339, p.From)
	if err != nil {
		return compliance.DateRange{}, reportBadRequest("period.from is not a valid RFC3339 timestamp")
	}
	to, err := time.Parse(time.RFC3339, p.To)
	if err != nil {
		return compliance.DateRange{}, reportBadRequest("period.to is not a valid RFC3339 timestamp")
	}
	if to.Before(from) {
		return compliance.DateRange{}, reportBadRequest("period.to cannot be before period.from")
	}
	return compliance.DateRange{From: from, To: to}, nil
}

// reportGeneratedBy names who is generating a report, from the principal.
// A compliance report has to say who produced it, so a principal with no
// user, or a user with no subject, is refused rather than recorded as
// nobody.
func reportGeneratedBy(p fcontract.Principal) (string, error) {
	if p.User == nil || p.User.Subject == "" {
		return "", &fcontract.Error{
			Code:    fcontract.CodeUnauthenticated,
			Message: "a report must name the user who generated it",
		}
	}
	return p.User.Subject, nil
}

func reportsEngineUnavailable() error {
	return &fcontract.Error{
		Code:    fcontract.CodeUnavailable,
		Message: "report generation is not configured on this deployment",
	}
}

func reportsListHandler(deps Deps) func(context.Context, ReportListInput, fcontract.Principal) (ReportListResponse, error) {
	return func(ctx context.Context, in ReportListInput, p fcontract.Principal) (ReportListResponse, error) {
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return ReportListResponse{}, err
		}
		limit, offset, err := pageBounds(in.Limit, in.Offset, defaultReportListLimit, maxReportListLimit)
		if err != nil {
			return ReportListResponse{}, err
		}

		// compliance.ListOpts carries AppID and TenantID directly and the
		// stores read an empty AppID as every app, so both are stamped by
		// hand from the viewer. One row past the page tells whether another
		// page exists without a count.
		list, err := deps.Store.ListReports(ctx, compliance.ListOpts{
			AppID:    v.AppID,
			TenantID: v.TenantID,
			Limit:    limit + 1,
			Offset:   offset,
		})
		if err != nil {
			return ReportListResponse{}, deps.mapStoreError("reports.list", err)
		}

		hasMore := len(list) > limit
		if hasMore {
			list = list[:limit]
		}

		out := ReportListResponse{Reports: make([]ReportSummary, 0, len(list)), HasMore: hasMore}
		for _, r := range list {
			if r == nil {
				continue
			}
			// A store that answers outside the requested scope has a bug
			// this contract must not paper over or pass on. Compliance
			// reports are evidence about one tenant's events.
			if !v.owns(r.AppID, r.TenantID) {
				deps.logger().Error("chronicle/contract: store returned a report outside the requested scope",
					log.String("op", "reports.list"),
					log.String("report_id", r.ID.String()),
				)
				return ReportListResponse{}, &fcontract.Error{
					Code:    fcontract.CodeInternal,
					Message: "the audit store returned a report outside this scope",
				}
			}
			out.Reports = append(out.Reports, projectReportSummary(r))
		}
		return out, nil
	}
}

func reportsDetailHandler(deps Deps) func(context.Context, GetReportInput, fcontract.Principal) (ReportDetail, error) {
	return func(ctx context.Context, in GetReportInput, p fcontract.Principal) (ReportDetail, error) {
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return ReportDetail{}, err
		}

		reportID, err := id.ParseReportID(in.ID)
		if err != nil {
			return ReportDetail{}, reportNotFound()
		}

		report, err := deps.Store.GetReport(ctx, reportID)
		if err != nil {
			return ReportDetail{}, deps.mapStoreError("reports.detail", err)
		}
		if report == nil {
			return ReportDetail{}, reportNotFound()
		}

		// Security-critical: a report is evidence about one tenant's events,
		// and resolving it by ID bypasses every list filter. CodeNotFound, not
		// PermissionDenied, so a caller cannot probe which IDs exist in other
		// apps or tenants.
		if !v.owns(report.AppID, report.TenantID) {
			return ReportDetail{}, reportNotFound()
		}

		return projectReportDetail(report), nil
	}
}

func reportsGenerateHandler(deps Deps) func(context.Context, GenerateReportInput, fcontract.Principal) (GenerateReportResponse, error) {
	return func(ctx context.Context, in GenerateReportInput, p fcontract.Principal) (GenerateReportResponse, error) {
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return GenerateReportResponse{}, err
		}
		by, err := reportGeneratedBy(p)
		if err != nil {
			return GenerateReportResponse{}, err
		}

		switch in.Type {
		case reportTypeSOC2, reportTypeHIPAA, reportTypeEUAIAct:
		default:
			return GenerateReportResponse{}, reportBadRequest(
				fmt.Sprintf("type must be one of %q, %q or %q", reportTypeSOC2, reportTypeHIPAA, reportTypeEUAIAct))
		}

		period, err := reportPeriod(in.Period)
		if err != nil {
			return GenerateReportResponse{}, err
		}
		if deps.Engine == nil {
			return GenerateReportResponse{}, reportsEngineUnavailable()
		}

		// The engine saves the report itself. SaveReport is never called
		// here: the templ page did, and stored every dashboard-generated
		// report twice.
		//
		// Scope goes in from the viewer, never from the request. An input
		// with an empty AppID aggregates every app's events into one report.
		var report *compliance.Report
		switch in.Type {
		case reportTypeSOC2:
			report, err = deps.Engine.SOC2(ctx, &compliance.SOC2Input{
				Period: period, AppID: v.AppID, TenantID: v.TenantID, GeneratedBy: by,
			})
		case reportTypeHIPAA:
			report, err = deps.Engine.HIPAA(ctx, &compliance.HIPAAInput{
				Period: period, AppID: v.AppID, TenantID: v.TenantID, GeneratedBy: by,
			})
		case reportTypeEUAIAct:
			report, err = deps.Engine.EUAIAct(ctx, &compliance.EUAIActInput{
				Period: period, AppID: v.AppID, TenantID: v.TenantID, GeneratedBy: by,
			})
		}
		if err != nil {
			return GenerateReportResponse{}, deps.mapStoreError("reports.generate", err)
		}

		return GenerateReportResponse{ID: report.ID.String(), Report: projectReportSummary(report)}, nil
	}
}

func reportsGenerateCustomHandler(deps Deps) func(context.Context, GenerateCustomReportInput, fcontract.Principal) (GenerateReportResponse, error) {
	return func(ctx context.Context, in GenerateCustomReportInput, p fcontract.Principal) (GenerateReportResponse, error) {
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return GenerateReportResponse{}, err
		}
		by, err := reportGeneratedBy(p)
		if err != nil {
			return GenerateReportResponse{}, err
		}

		if strings.TrimSpace(in.Title) == "" {
			return GenerateReportResponse{}, reportBadRequest("title is required")
		}
		if utf8.RuneCountInString(in.Title) > maxCustomReportTitleLen {
			return GenerateReportResponse{}, reportBadRequest(
				fmt.Sprintf("title can be at most %d characters", maxCustomReportTitleLen))
		}
		if len(in.Sections) == 0 {
			return GenerateReportResponse{}, reportBadRequest("at least one section is required")
		}
		if len(in.Sections) > maxCustomReportSections {
			return GenerateReportResponse{}, reportBadRequest(
				fmt.Sprintf("a custom report can have at most %d sections", maxCustomReportSections))
		}
		sections := make([]compliance.CustomSection, 0, len(in.Sections))
		for i, s := range in.Sections {
			if strings.TrimSpace(s.Title) == "" {
				return GenerateReportResponse{}, reportBadRequest(fmt.Sprintf("section %d needs a title", i+1))
			}
			if utf8.RuneCountInString(s.Title) > maxCustomSectionTitleLen {
				return GenerateReportResponse{}, reportBadRequest(fmt.Sprintf(
					"the title of section %d can be at most %d characters", i+1, maxCustomSectionTitleLen))
			}
			if utf8.RuneCountInString(s.Notes) > maxCustomSectionNotesLen {
				return GenerateReportResponse{}, reportBadRequest(fmt.Sprintf(
					"the notes of section %d can be at most %d characters", i+1, maxCustomSectionNotesLen))
			}
			for _, f := range []struct {
				name   string
				values []string
			}{{"categories", s.Categories}, {"actions", s.Actions}, {"severity", s.Severity}} {
				if len(f.values) > maxCustomSectionFilters {
					return GenerateReportResponse{}, reportBadRequest(fmt.Sprintf(
						"section %d can filter on at most %d %s", i+1, maxCustomSectionFilters, f.name))
				}
				for _, value := range f.values {
					if utf8.RuneCountInString(value) > maxCustomFilterValueLen {
						return GenerateReportResponse{}, reportBadRequest(fmt.Sprintf(
							"a %s filter value in section %d can be at most %d characters",
							f.name, i+1, maxCustomFilterValueLen))
					}
				}
			}
			sections = append(sections, compliance.CustomSection{
				Title:      s.Title,
				Categories: s.Categories,
				Actions:    s.Actions,
				Severity:   s.Severity,
				Notes:      s.Notes,
			})
		}

		period, err := reportPeriod(in.Period)
		if err != nil {
			return GenerateReportResponse{}, err
		}
		if deps.Engine == nil {
			return GenerateReportResponse{}, reportsEngineUnavailable()
		}

		// As in reports.generate: the engine saves, and scope comes from the
		// viewer.
		report, err := deps.Engine.Custom(ctx, &compliance.CustomInput{
			Title:       in.Title,
			Period:      period,
			AppID:       v.AppID,
			TenantID:    v.TenantID,
			GeneratedBy: by,
			Sections:    sections,
		})
		if err != nil {
			return GenerateReportResponse{}, deps.mapStoreError("reports.generateCustom", err)
		}

		return GenerateReportResponse{ID: report.ID.String(), Report: projectReportSummary(report)}, nil
	}
}

// reportExportFormats maps each accepted wire format to the engine's format,
// a file extension and a content type. It is the whitelist: a format not in
// it is refused before anything is fetched.
var reportExportFormats = map[string]struct {
	format      compliance.Format
	ext         string
	contentType string
}{
	exportFormatJSON:     {compliance.FormatJSON, "json", "application/json; charset=utf-8"},
	exportFormatCSV:      {compliance.FormatCSV, "csv", "text/csv; charset=utf-8"},
	exportFormatMarkdown: {compliance.FormatMarkdown, "md", "text/markdown; charset=utf-8"},
	exportFormatHTML:     {compliance.FormatHTML, "html", "text/html; charset=utf-8"},
}

func reportsExportHandler(deps Deps) func(context.Context, ExportReportInput, fcontract.Principal) (ExportReportResponse, error) {
	return func(ctx context.Context, in ExportReportInput, p fcontract.Principal) (ExportReportResponse, error) {
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return ExportReportResponse{}, err
		}

		f, ok := reportExportFormats[in.Format]
		if !ok {
			return ExportReportResponse{}, reportBadRequest(
				fmt.Sprintf("format must be one of %q, %q, %q or %q",
					exportFormatJSON, exportFormatCSV, exportFormatMarkdown, exportFormatHTML))
		}

		reportID, err := id.ParseReportID(in.ID)
		if err != nil {
			return ExportReportResponse{}, reportNotFound()
		}
		report, err := deps.Store.GetReport(ctx, reportID)
		if err != nil {
			return ExportReportResponse{}, deps.mapStoreError("reports.export", err)
		}
		if report == nil {
			return ExportReportResponse{}, reportNotFound()
		}

		// Security-critical: ownership is decided before Export runs, so
		// another tenant's report is never rendered, let alone returned. It
		// answers NotFound for the same reason reports.detail does.
		if !v.owns(report.AppID, report.TenantID) {
			return ExportReportResponse{}, reportNotFound()
		}

		if deps.Engine == nil {
			return ExportReportResponse{}, reportsEngineUnavailable()
		}

		var buf bytes.Buffer
		if err := deps.Engine.Export(ctx, report, f.format, &buf); err != nil {
			return ExportReportResponse{}, deps.mapStoreError("reports.export", err)
		}

		// The filename comes from the report's ID and never its title: a
		// custom report's title is caller-chosen text.
		return ExportReportResponse{
			Filename:    fmt.Sprintf("report-%s.%s", report.ID.String(), f.ext),
			ContentType: f.contentType,
			Content:     buf.String(),
		}, nil
	}
}
