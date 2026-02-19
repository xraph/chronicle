package compliance_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store/memory"
)

// seedEvents populates the store with a variety of audit events for testing.
func seedEvents(t *testing.T, store *memory.Store) {
	t.Helper()

	ctx := context.Background()
	now := time.Now().UTC()
	streamID := id.NewStreamID()

	events := []*audit.Event{
		// Auth events
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-24 * time.Hour), Sequence: 1,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "login", Resource: "session", Category: "auth",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "user-1", IP: "192.168.1.1",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-23 * time.Hour), Sequence: 2,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "login", Resource: "session", Category: "auth",
			Outcome: audit.OutcomeFailure, Severity: audit.SeverityWarning,
			UserID: "user-2", IP: "10.0.0.1",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-22 * time.Hour), Sequence: 3,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "logout", Resource: "session", Category: "auth",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "user-1",
		},
		// Access events
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-21 * time.Hour), Sequence: 4,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "access.grant", Resource: "role", Category: "access",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "admin-1",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-20 * time.Hour), Sequence: 5,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "access.revoke", Resource: "role", Category: "access",
			Outcome: audit.OutcomeDenied, Severity: audit.SeverityWarning,
			UserID: "user-3",
		},
		// Data events
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-19 * time.Hour), Sequence: 6,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "read", Resource: "patient_record", Category: "data",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "user-1", ResourceID: "rec-001",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-18 * time.Hour), Sequence: 7,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "write", Resource: "patient_record", Category: "data",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "user-1", ResourceID: "rec-002",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-17 * time.Hour), Sequence: 8,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "delete", Resource: "patient_record", Category: "data",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityWarning,
			UserID: "admin-1", ResourceID: "rec-003",
		},
		// Security incident (critical)
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-16 * time.Hour), Sequence: 9,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "brute_force_detected", Resource: "firewall", Category: "security",
			Outcome: audit.OutcomeFailure, Severity: audit.SeverityCritical,
			UserID: "system", Reason: "Multiple failed login attempts",
		},
		// Config/deployment events
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-15 * time.Hour), Sequence: 10,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "update", Resource: "config", Category: "config",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "admin-1",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-14 * time.Hour), Sequence: 11,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "deploy", Resource: "service", Category: "deployment",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "admin-1",
		},
		// AI/ML events
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-13 * time.Hour), Sequence: 12,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "decision", Resource: "model-v2", Category: "ai",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "system",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-12 * time.Hour), Sequence: 13,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "prediction", Resource: "model-v2", Category: "ai",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "system",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-11 * time.Hour), Sequence: 14,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "training", Resource: "model-v3", Category: "ml",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "data-engineer-1",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-10 * time.Hour), Sequence: 15,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "decision", Resource: "model-v2", Category: "ai",
			Outcome: audit.OutcomeFailure, Severity: audit.SeverityCritical,
			UserID: "system", Reason: "Model confidence below threshold",
		},
		// Human oversight events
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-9 * time.Hour), Sequence: 16,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "review", Resource: "model-v2", Category: "ai",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "reviewer-1",
		},
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-8 * time.Hour), Sequence: 17,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "override", Resource: "model-v2", Category: "ai",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityWarning,
			UserID: "reviewer-1",
		},
		// Purge event for HIPAA
		{
			ID: id.NewAuditID(), Timestamp: now.Add(-7 * time.Hour), Sequence: 18,
			StreamID: streamID, AppID: "test-app", TenantID: "tenant-1",
			Action: "purge", Resource: "patient_record", Category: "data",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
			UserID: "admin-1", ResourceID: "rec-old-batch",
		},
	}

	if err := store.AppendBatch(ctx, events); err != nil {
		t.Fatalf("seeding events: %v", err)
	}
}

func newTestEngine(t *testing.T) (*compliance.Engine, *memory.Store) {
	t.Helper()

	store := memory.New()
	seedEvents(t, store)

	logger := slog.Default()
	engine := compliance.NewEngine(store, store, store, logger)
	return engine, store
}

func testPeriod() compliance.DateRange {
	now := time.Now().UTC()
	return compliance.DateRange{
		From: now.Add(-48 * time.Hour),
		To:   now.Add(time.Hour),
	}
}

// ──────────────────────────────────────────────────
// Report generation tests
// ──────────────────────────────────────────────────

func TestSOC2Report(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("SOC2 report generation failed: %v", err)
	}

	if report.Type != "soc2" {
		t.Errorf("expected type %q, got %q", "soc2", report.Type)
	}
	if report.Title != "SOC2 Type II Compliance Report" {
		t.Errorf("unexpected title: %s", report.Title)
	}
	if len(report.Sections) != 5 {
		t.Errorf("expected 5 sections, got %d", len(report.Sections))
	}

	expectedSections := []string{
		"CC6.1 Logical Access",
		"CC6.2 Authentication Events",
		"CC6.3 Data Access",
		"CC7.2 Security Incidents",
		"CC8.1 Change Management",
	}
	for i, name := range expectedSections {
		if i < len(report.Sections) && report.Sections[i].Title != name {
			t.Errorf("section %d: expected %q, got %q", i, name, report.Sections[i].Title)
		}
	}

	// CC6.1 should have auth+access events with matching actions
	if len(report.Sections[0].Events) == 0 {
		t.Error("CC6.1 Logical Access should have events")
	}

	// CC7.2 should have warning and critical events
	if len(report.Sections[3].Events) == 0 {
		t.Error("CC7.2 Security Incidents should have events")
	}
}

func TestHIPAAReport(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.HIPAA(ctx, &compliance.HIPAAInput{
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("HIPAA report generation failed: %v", err)
	}

	if report.Type != "hipaa" {
		t.Errorf("expected type %q, got %q", "hipaa", report.Type)
	}
	if len(report.Sections) != 4 {
		t.Errorf("expected 4 sections, got %d", len(report.Sections))
	}

	expectedSections := []string{
		"PHI Access",
		"Authentication Logs",
		"Security Incidents",
		"Data Disposition",
	}
	for i, name := range expectedSections {
		if i < len(report.Sections) && report.Sections[i].Title != name {
			t.Errorf("section %d: expected %q, got %q", i, name, report.Sections[i].Title)
		}
	}

	// PHI Access should have data events
	if len(report.Sections[0].Events) == 0 {
		t.Error("PHI Access should have events")
	}

	// Data Disposition should have delete/purge events
	if len(report.Sections[3].Events) == 0 {
		t.Error("Data Disposition should have events")
	}
}

func TestEUAIActReport(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.EUAIAct(ctx, &compliance.EUAIActInput{
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("EU AI Act report generation failed: %v", err)
	}

	if report.Type != "eu_ai_act" {
		t.Errorf("expected type %q, got %q", "eu_ai_act", report.Type)
	}
	if len(report.Sections) != 5 {
		t.Errorf("expected 5 sections, got %d", len(report.Sections))
	}

	expectedSections := []string{
		"AI System Inventory",
		"AI Decision Log",
		"AI Incidents",
		"Data Governance",
		"Human Oversight",
	}
	for i, name := range expectedSections {
		if i < len(report.Sections) && report.Sections[i].Title != name {
			t.Errorf("section %d: expected %q, got %q", i, name, report.Sections[i].Title)
		}
	}

	// AI System Inventory should have ai+ml events
	if len(report.Sections[0].Events) == 0 {
		t.Error("AI System Inventory should have events")
	}

	// AI Decision Log should have decision/prediction events
	if len(report.Sections[1].Events) == 0 {
		t.Error("AI Decision Log should have events")
	}

	// Human Oversight should have review/override events
	if len(report.Sections[4].Events) == 0 {
		t.Error("Human Oversight should have events")
	}
}

func TestCustomReport(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.Custom(ctx, &compliance.CustomInput{
		Title:       "My Custom Audit",
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
		Sections: []compliance.CustomSection{
			{
				Title:      "Auth Overview",
				Categories: []string{"auth"},
				Notes:      "Custom auth section",
			},
			{
				Title:    "Critical Alerts",
				Severity: []string{"critical"},
				Notes:    "All critical events",
			},
		},
	})
	if err != nil {
		t.Fatalf("Custom report generation failed: %v", err)
	}

	if report.Type != "custom" {
		t.Errorf("expected type %q, got %q", "custom", report.Type)
	}
	if report.Title != "My Custom Audit" {
		t.Errorf("unexpected title: %s", report.Title)
	}
	if len(report.Sections) != 2 {
		t.Errorf("expected 2 sections, got %d", len(report.Sections))
	}

	if report.Sections[0].Title != "Auth Overview" {
		t.Errorf("section 0: expected %q, got %q", "Auth Overview", report.Sections[0].Title)
	}
	if len(report.Sections[0].Events) == 0 {
		t.Error("Auth Overview should have events")
	}

	if report.Sections[1].Title != "Critical Alerts" {
		t.Errorf("section 1: expected %q, got %q", "Critical Alerts", report.Sections[1].Title)
	}
	if len(report.Sections[1].Events) == 0 {
		t.Error("Critical Alerts should have events")
	}
}

// ──────────────────────────────────────────────────
// Stats tests
// ──────────────────────────────────────────────────

func TestStatsCalculation(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("SOC2 report generation failed: %v", err)
	}

	if report.Stats == nil {
		t.Fatal("stats should not be nil")
	}

	if report.Stats.TotalEvents == 0 {
		t.Error("total events should be > 0")
	}

	// We have at least one critical event (brute_force_detected)
	if report.Stats.CriticalEvents == 0 {
		t.Error("critical events should be > 0")
	}

	// We have at least one failure (login failure)
	if report.Stats.FailedEvents == 0 {
		t.Error("failed events should be > 0")
	}

	// We have at least one denied (access.revoke denied)
	if report.Stats.DeniedEvents == 0 {
		t.Error("denied events should be > 0")
	}

	// Total should be >= sum of critical + failed + denied (events can be critical AND failed)
	if report.Stats.TotalEvents < report.Stats.CriticalEvents {
		t.Error("total events should be >= critical events")
	}
}

// ──────────────────────────────────────────────────
// Export tests
// ──────────────────────────────────────────────────

func TestExportJSON(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("SOC2 report generation failed: %v", err)
	}

	var buf bytes.Buffer
	if err := engine.Export(ctx, report, compliance.FormatJSON, &buf); err != nil {
		t.Fatalf("JSON export failed: %v", err)
	}

	// Validate it's parseable JSON.
	var parsed compliance.Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("exported JSON is not valid: %v", err)
	}

	if parsed.Title != report.Title {
		t.Errorf("expected title %q, got %q", report.Title, parsed.Title)
	}
	if parsed.Type != "soc2" {
		t.Errorf("expected type %q, got %q", "soc2", parsed.Type)
	}
}

func TestExportCSV(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("SOC2 report generation failed: %v", err)
	}

	var buf bytes.Buffer
	err = engine.Export(ctx, report, compliance.FormatCSV, &buf)
	if err != nil {
		t.Fatalf("CSV export failed: %v", err)
	}

	// Validate it's parseable CSV.
	reader := csv.NewReader(strings.NewReader(buf.String()))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("exported CSV is not valid: %v", err)
	}

	if len(records) < 2 {
		t.Fatal("CSV should have at least a header and one data row")
	}

	// Check header.
	header := records[0]
	expectedHeader := []string{
		"section", "timestamp", "action", "resource", "resource_id",
		"category", "outcome", "severity", "user_id", "ip", "reason",
	}
	if len(header) != len(expectedHeader) {
		t.Fatalf("expected %d header columns, got %d", len(expectedHeader), len(header))
	}
	for i, col := range expectedHeader {
		if header[i] != col {
			t.Errorf("header[%d]: expected %q, got %q", i, col, header[i])
		}
	}
}

func TestExportMarkdown(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("SOC2 report generation failed: %v", err)
	}

	var buf bytes.Buffer
	if err := engine.Export(ctx, report, compliance.FormatMarkdown, &buf); err != nil {
		t.Fatalf("Markdown export failed: %v", err)
	}

	md := buf.String()

	if !strings.Contains(md, "# SOC2 Type II Compliance Report") {
		t.Error("markdown should contain report title as H1")
	}
	if !strings.Contains(md, "## Summary") {
		t.Error("markdown should contain Summary section")
	}
	if !strings.Contains(md, "## CC6.1 Logical Access") {
		t.Error("markdown should contain CC6.1 section")
	}
	if !strings.Contains(md, "| Timestamp |") {
		t.Error("markdown should contain event table headers")
	}
	if !strings.Contains(md, "**App ID:**") {
		t.Error("markdown should contain app ID metadata")
	}
}

func TestExportHTML(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("SOC2 report generation failed: %v", err)
	}

	var buf bytes.Buffer
	if err := engine.Export(ctx, report, compliance.FormatHTML, &buf); err != nil {
		t.Fatalf("HTML export failed: %v", err)
	}

	html := buf.String()

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTML should contain DOCTYPE")
	}
	if !strings.Contains(html, "<title>SOC2 Type II Compliance Report</title>") {
		t.Error("HTML should contain title tag")
	}
	if !strings.Contains(html, "CC6.1 Logical Access") {
		t.Error("HTML should contain section headers")
	}
	if !strings.Contains(html, "<table>") {
		t.Error("HTML should contain event tables")
	}
	if !strings.Contains(html, "Total Events") {
		t.Error("HTML should contain stats cards")
	}
}

func TestExportUnsupportedFormat(t *testing.T) {
	engine, _ := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period:      testPeriod(),
		AppID:       "test-app",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("SOC2 report generation failed: %v", err)
	}

	var buf bytes.Buffer
	err = engine.Export(ctx, report, compliance.Format("xml"), &buf)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected 'unsupported format' error, got: %v", err)
	}
}

// ──────────────────────────────────────────────────
// Report persistence tests
// ──────────────────────────────────────────────────

func TestReportIsSaved(t *testing.T) {
	engine, store := newTestEngine(t)
	ctx := context.Background()

	report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period:      testPeriod(),
		AppID:       "test-app",
		TenantID:    "tenant-1",
		GeneratedBy: "test-runner",
	})
	if err != nil {
		t.Fatalf("SOC2 report generation failed: %v", err)
	}

	// Verify the report was saved to the store.
	saved, err := store.GetReport(ctx, report.ID)
	if err != nil {
		t.Fatalf("expected saved report, got error: %v", err)
	}

	if saved.ID.String() != report.ID.String() {
		t.Errorf("saved report ID mismatch: got %s, want %s", saved.ID.String(), report.ID.String())
	}
}
