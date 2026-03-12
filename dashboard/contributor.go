package dashboard

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/dashboard/pages"
	"github.com/xraph/chronicle/dashboard/widgets"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/verify"
)

// Ensure Contributor implements the required interface at compile time.
var _ contributor.LocalContributor = (*Contributor)(nil)

// Config holds the chronicle configuration fields needed for the dashboard.
// This avoids importing the extension package and creating a circular dependency.
type Config struct {
	BatchSize           int
	FlushInterval       time.Duration
	RetentionInterval   time.Duration
	EnableCryptoErasure bool
	BasePath            string
}

// Contributor implements the dashboard LocalContributor interface for the
// chronicle extension. It renders pages, widgets, and settings using templ
// components and ForgeUI.
type Contributor struct {
	manifest *contributor.Manifest
	store    store.Store
	engine   *compliance.Engine
	enforcer *retention.Enforcer
	config   Config
}

// New creates a new chronicle dashboard contributor.
func New(manifest *contributor.Manifest, s store.Store, engine *compliance.Engine, enforcer *retention.Enforcer, config Config) *Contributor {
	return &Contributor{
		manifest: manifest,
		store:    s,
		engine:   engine,
		enforcer: enforcer,
		config:   config,
	}
}

// Manifest returns the contributor manifest.
func (c *Contributor) Manifest() *contributor.Manifest { return c.manifest }

// RenderPage renders a page for the given route.
func (c *Contributor) RenderPage(ctx context.Context, route string, params contributor.Params) (templ.Component, error) {
	switch route {
	case "/", "":
		return c.renderOverview(ctx)
	case "/events":
		return c.renderEvents(ctx, params)
	case "/events/detail":
		return c.renderEventDetail(ctx, params)
	case "/verify":
		return c.renderVerification(ctx, params)
	case "/reports":
		return c.renderReports(ctx, params)
	case "/reports/detail":
		return c.renderReportDetail(ctx, params)
	case "/erasures":
		return c.renderErasures(ctx)
	case "/erasures/detail":
		return c.renderErasureDetail(ctx, params)
	case "/retention":
		return c.renderRetention(ctx, params)
	case "/retention/detail":
		return c.renderRetentionDetail(ctx, params)
	case "/retention/archives":
		return c.renderArchives(ctx)
	case "/settings":
		return c.renderSettings(ctx)
	default:
		return nil, contributor.ErrPageNotFound
	}
}

// RenderWidget renders a widget by ID.
func (c *Contributor) RenderWidget(ctx context.Context, widgetID string) (templ.Component, error) {
	switch widgetID {
	case "chronicle-stats":
		return c.renderStatsWidget(ctx)
	case "chronicle-recent-events":
		return c.renderRecentEventsWidget(ctx)
	default:
		return nil, contributor.ErrWidgetNotFound
	}
}

// RenderSettings renders a settings panel by ID.
func (c *Contributor) RenderSettings(ctx context.Context, settingID string) (templ.Component, error) {
	switch settingID {
	case "chronicle-config":
		return c.renderSettingsPanel(ctx)
	default:
		return nil, contributor.ErrSettingNotFound
	}
}

// ─── Page Renderers ──────────────────────────────────────────────────────────

func (c *Contributor) renderOverview(ctx context.Context) (templ.Component, error) {
	stats := pages.OverviewStats{
		TotalEvents:    fetchTotalEventCount(ctx, c.store),
		CriticalEvents: fetchCriticalEventCount(ctx, c.store),
		FailedEvents:   fetchFailedEventCount(ctx, c.store),
		ErasureCount:   fetchErasureCount(ctx, c.store),
	}

	recentEvents := fetchRecentEvents(ctx, c.store, 10)
	recentCritical := fetchRecentCriticalEvents(ctx, c.store, 10)

	return pages.OverviewPage(stats, recentEvents, recentCritical), nil
}

func (c *Contributor) renderEvents(ctx context.Context, params contributor.Params) (templ.Component, error) {
	q := &audit.Query{
		Limit: 50,
		Order: "desc",
	}

	categoryFilter := params.QueryParams["category"]
	severityFilter := params.QueryParams["severity"]
	outcomeFilter := params.QueryParams["outcome"]

	if categoryFilter != "" {
		q.Categories = []string{categoryFilter}
	}
	if severityFilter != "" {
		q.Severity = []string{severityFilter}
	}
	if outcomeFilter != "" {
		q.Outcome = []string{outcomeFilter}
	}

	events, total, err := fetchEvents(ctx, c.store, q)
	if err != nil {
		events = nil
		total = 0
	}

	return pages.EventsPage(pages.EventsPageData{
		Events:         events,
		Total:          total,
		CategoryFilter: categoryFilter,
		SeverityFilter: severityFilter,
		OutcomeFilter:  outcomeFilter,
	}), nil
}

func (c *Contributor) renderEventDetail(ctx context.Context, params contributor.Params) (templ.Component, error) {
	eventIDStr := params.QueryParams["id"]
	if eventIDStr == "" {
		eventIDStr = params.PathParams["id"]
	}
	if eventIDStr == "" {
		return nil, contributor.ErrPageNotFound
	}

	eventID, err := id.Parse(eventIDStr)
	if err != nil {
		return nil, contributor.ErrPageNotFound
	}

	event, err := c.store.Get(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve event: %w", err)
	}

	return pages.EventDetailPage(event), nil
}

func (c *Contributor) renderVerification(ctx context.Context, params contributor.Params) (templ.Component, error) {
	data := pages.VerifyPageData{
		StreamID: params.QueryParams["stream_id"],
		FromSeq:  params.QueryParams["from_seq"],
		ToSeq:    params.QueryParams["to_seq"],
	}

	// Handle form submission.
	if params.FormData["action"] == "verify" {
		data.StreamID = strings.TrimSpace(params.FormData["stream_id"])
		data.FromSeq = strings.TrimSpace(params.FormData["from_seq"])
		data.ToSeq = strings.TrimSpace(params.FormData["to_seq"])

		if data.StreamID == "" {
			data.Error = "Stream ID is required"
			return pages.VerifyPage(data), nil
		}

		streamID, err := id.Parse(data.StreamID)
		if err != nil {
			data.Error = "Invalid Stream ID format"
			return pages.VerifyPage(data), nil
		}

		var fromSeq, toSeq uint64
		if data.FromSeq != "" {
			fromSeq, err = strconv.ParseUint(data.FromSeq, 10, 64)
			if err != nil {
				data.Error = "Invalid From Sequence number"
				return pages.VerifyPage(data), nil
			}
		}
		if data.ToSeq != "" {
			toSeq, err = strconv.ParseUint(data.ToSeq, 10, 64)
			if err != nil {
				data.Error = "Invalid To Sequence number"
				return pages.VerifyPage(data), nil
			}
		}

		verifier := verify.NewVerifier(c.store)
		report, err := verifier.VerifyChain(ctx, &verify.Input{
			StreamID: streamID,
			FromSeq:  fromSeq,
			ToSeq:    toSeq,
		})
		if err != nil {
			data.Error = fmt.Sprintf("Verification failed: %v", err)
			return pages.VerifyPage(data), nil
		}

		data.Report = report
	}

	return pages.VerifyPage(data), nil
}

func (c *Contributor) renderReports(ctx context.Context, params contributor.Params) (templ.Component, error) {
	data := pages.ReportsPageData{}

	// Handle report generation actions.
	if action := params.QueryParams["action"]; action != "" {
		now := time.Now()
		period := compliance.DateRange{
			From: now.AddDate(0, 0, -90),
			To:   now,
		}

		var report *compliance.Report
		var err error

		switch action {
		case "generate_soc2":
			report, err = c.engine.SOC2(ctx, &compliance.SOC2Input{
				Period:      period,
				GeneratedBy: "dashboard",
			})
		case "generate_hipaa":
			report, err = c.engine.HIPAA(ctx, &compliance.HIPAAInput{
				Period:      period,
				GeneratedBy: "dashboard",
			})
		case "generate_euaiact":
			report, err = c.engine.EUAIAct(ctx, &compliance.EUAIActInput{
				Period:      period,
				GeneratedBy: "dashboard",
			})
		}

		if err != nil {
			data.Error = fmt.Sprintf("Report generation failed: %v", err)
		} else if report != nil {
			// Save the generated report.
			if saveErr := c.store.SaveReport(ctx, report); saveErr != nil {
				data.Error = fmt.Sprintf("Report generated but save failed: %v", saveErr)
			}
		}
	}

	reports, err := fetchReports(ctx, c.store, compliance.ListOpts{Limit: 50})
	if err != nil {
		reports = nil
	}
	data.Reports = reports

	return pages.ReportsPage(data), nil
}

func (c *Contributor) renderReportDetail(ctx context.Context, params contributor.Params) (templ.Component, error) {
	reportIDStr := params.QueryParams["id"]
	if reportIDStr == "" {
		reportIDStr = params.PathParams["id"]
	}
	if reportIDStr == "" {
		return nil, contributor.ErrPageNotFound
	}

	reportID, err := id.Parse(reportIDStr)
	if err != nil {
		return nil, contributor.ErrPageNotFound
	}

	report, err := c.store.GetReport(ctx, reportID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve report: %w", err)
	}

	return pages.ReportDetailPage(report), nil
}

func (c *Contributor) renderErasures(ctx context.Context) (templ.Component, error) {
	erasures, err := fetchErasures(ctx, c.store, erasure.ListOpts{Limit: 50})
	if err != nil {
		erasures = nil
	}

	return pages.ErasuresPage(pages.ErasuresPageData{
		Erasures: erasures,
	}), nil
}

func (c *Contributor) renderErasureDetail(ctx context.Context, params contributor.Params) (templ.Component, error) {
	erasureIDStr := params.QueryParams["id"]
	if erasureIDStr == "" {
		erasureIDStr = params.PathParams["id"]
	}
	if erasureIDStr == "" {
		return nil, contributor.ErrPageNotFound
	}

	erasureID, err := id.Parse(erasureIDStr)
	if err != nil {
		return nil, contributor.ErrPageNotFound
	}

	e, err := c.store.GetErasure(ctx, erasureID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve erasure: %w", err)
	}

	return pages.ErasureDetailPage(e), nil
}

func (c *Contributor) renderRetention(ctx context.Context, params contributor.Params) (templ.Component, error) {
	data := pages.RetentionPageData{}

	// Handle create policy form submission.
	if params.FormData["action"] == "create_policy" {
		category := strings.TrimSpace(params.FormData["category"])
		durationStr := strings.TrimSpace(params.FormData["duration"])
		archiveStr := params.FormData["archive"]

		if category == "" || durationStr == "" {
			data.Error = "Category and duration are required"
		} else {
			duration, err := time.ParseDuration(durationStr)
			if err != nil {
				data.Error = fmt.Sprintf("Invalid duration: %v", err)
			} else {
				policy := &retention.Policy{
					ID:       id.New(id.PrefixPolicy),
					Category: category,
					Duration: duration,
					Archive:  archiveStr == "on" || archiveStr == "true",
				}
				if err := c.store.SavePolicy(ctx, policy); err != nil {
					data.Error = fmt.Sprintf("Failed to save policy: %v", err)
				}
			}
		}
	}

	// Handle delete action.
	if params.QueryParams["action"] == "delete" {
		if delIDStr := params.QueryParams["id"]; delIDStr != "" {
			if delID, err := id.Parse(delIDStr); err == nil {
				if delErr := c.store.DeletePolicy(ctx, delID); delErr != nil {
					data.Error = fmt.Sprintf("Failed to delete policy: %v", delErr)
				}
			}
		}
	}

	// Handle enforce action.
	if params.QueryParams["action"] == "enforce" {
		if c.enforcer != nil {
			result, err := c.enforcer.Enforce(ctx)
			if err != nil {
				data.Error = fmt.Sprintf("Enforcement failed: %v", err)
			} else {
				_ = result // Enforcement succeeded.
			}
		}
	}

	policies, err := fetchPolicies(ctx, c.store)
	if err != nil {
		policies = nil
	}
	data.Policies = policies

	return pages.RetentionPage(data), nil
}

func (c *Contributor) renderRetentionDetail(ctx context.Context, params contributor.Params) (templ.Component, error) {
	policyIDStr := params.QueryParams["id"]
	if policyIDStr == "" {
		policyIDStr = params.PathParams["id"]
	}
	if policyIDStr == "" {
		return nil, contributor.ErrPageNotFound
	}

	policyID, err := id.Parse(policyIDStr)
	if err != nil {
		return nil, contributor.ErrPageNotFound
	}

	policy, err := c.store.GetPolicy(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve retention policy: %w", err)
	}

	return pages.RetentionDetailPage(policy), nil
}

func (c *Contributor) renderArchives(ctx context.Context) (templ.Component, error) {
	archives, err := fetchArchives(ctx, c.store, retention.ListOpts{Limit: 50})
	if err != nil {
		archives = nil
	}

	return pages.ArchivesPage(pages.ArchivesPageData{
		Archives: archives,
	}), nil
}

func (c *Contributor) renderSettings(_ context.Context) (templ.Component, error) {
	return pages.SettingsPage(pages.SettingsData{
		BatchSize:           c.config.BatchSize,
		FlushInterval:       c.config.FlushInterval,
		RetentionInterval:   c.config.RetentionInterval,
		EnableCryptoErasure: c.config.EnableCryptoErasure,
		BasePath:            c.config.BasePath,
	}), nil
}

// ─── Widget Renderers ────────────────────────────────────────────────────────

func (c *Contributor) renderStatsWidget(ctx context.Context) (templ.Component, error) {
	data := widgets.StatsData{
		TotalEvents:    fetchTotalEventCount(ctx, c.store),
		CriticalEvents: fetchCriticalEventCount(ctx, c.store),
		FailedEvents:   fetchFailedEventCount(ctx, c.store),
		ErasureCount:   fetchErasureCount(ctx, c.store),
	}
	return widgets.StatsWidget(data), nil
}

func (c *Contributor) renderRecentEventsWidget(ctx context.Context) (templ.Component, error) {
	events := fetchRecentEvents(ctx, c.store, 5)
	return widgets.RecentEventsWidget(events), nil
}

// ─── Settings Renderer ───────────────────────────────────────────────────────

func (c *Contributor) renderSettingsPanel(_ context.Context) (templ.Component, error) {
	return pages.SettingsPage(pages.SettingsData{
		BatchSize:           c.config.BatchSize,
		FlushInterval:       c.config.FlushInterval,
		RetentionInterval:   c.config.RetentionInterval,
		EnableCryptoErasure: c.config.EnableCryptoErasure,
		BasePath:            c.config.BasePath,
	}), nil
}
