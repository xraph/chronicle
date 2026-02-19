// Example: Chronicle compliance report generation.
//
// Demonstrates seeding audit events across multiple categories,
// then generating SOC2 and HIPAA compliance reports with the
// compliance engine. Reports are exported to JSON and Markdown.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
)

func main() {
	ctx := context.Background()
	ctx = scope.WithAppID(ctx, "myapp")
	ctx = scope.WithTenantID(ctx, "tenant-1")

	// 1. Set up store, adapter, and Chronicle.
	mem := memory.New()
	adapter := store.NewAdapter(mem)
	c, err := chronicle.New(chronicle.WithStore(adapter))
	if err != nil {
		log.Fatal(err)
	}

	// 2. Seed events across the categories that SOC2 and HIPAA inspect.
	fmt.Println("--- Seeding Audit Events ---")
	seedEvents := []struct {
		action   string
		resource string
		category string
		severity string
		outcome  string
		user     string
	}{
		// Auth events (SOC2 CC6.1/CC6.2, HIPAA Authentication)
		{"login", "session", "auth", audit.SeverityInfo, audit.OutcomeSuccess, "user-1"},
		{"login", "session", "auth", audit.SeverityInfo, audit.OutcomeFailure, "user-2"},
		{"login", "session", "auth", audit.SeverityInfo, audit.OutcomeSuccess, "user-3"},
		{"logout", "session", "auth", audit.SeverityInfo, audit.OutcomeSuccess, "user-1"},

		// Data access (SOC2 CC6.3, HIPAA PHI Access)
		{"read", "patient-record", "data", audit.SeverityInfo, audit.OutcomeSuccess, "user-1"},
		{"write", "patient-record", "data", audit.SeverityInfo, audit.OutcomeSuccess, "user-1"},
		{"read", "lab-results", "data", audit.SeverityInfo, audit.OutcomeSuccess, "user-3"},
		{"delete", "old-records", "data", audit.SeverityWarning, audit.OutcomeSuccess, "user-1"},

		// Access control (SOC2 CC6.1)
		{"access.grant", "role", "access", audit.SeverityInfo, audit.OutcomeSuccess, "admin-1"},
		{"access.revoke", "role", "access", audit.SeverityInfo, audit.OutcomeSuccess, "admin-1"},

		// Security incidents (SOC2 CC7.2, HIPAA Security Incidents)
		{"brute-force-detected", "auth-system", "security", audit.SeverityWarning, audit.OutcomeFailure, "unknown"},
		{"unauthorized-access", "admin-panel", "security", audit.SeverityCritical, audit.OutcomeDenied, "user-99"},

		// Configuration changes (SOC2 CC8.1)
		{"update", "firewall-rules", "config", audit.SeverityInfo, audit.OutcomeSuccess, "admin-1"},
		{"deploy", "api-v2.1", "deployment", audit.SeverityInfo, audit.OutcomeSuccess, "ci-bot"},
	}

	for _, ev := range seedEvents {
		builder := c.Info(ctx, ev.action, ev.resource, "res-1").
			Category(ev.category).
			Outcome(ev.outcome).
			UserID(ev.user)

		switch ev.severity {
		case audit.SeverityWarning:
			builder = c.Warning(ctx, ev.action, ev.resource, "res-1").
				Category(ev.category).
				Outcome(ev.outcome).
				UserID(ev.user)
		case audit.SeverityCritical:
			builder = c.Critical(ctx, ev.action, ev.resource, "res-1").
				Category(ev.category).
				Outcome(ev.outcome).
				UserID(ev.user)
		}

		if rerr := builder.Record(); rerr != nil {
			log.Fatal(rerr)
		}
	}
	fmt.Printf("Seeded %d events\n", len(seedEvents))

	// 3. Create the compliance engine.
	//    It needs audit.Store, verify.Store, and compliance.ReportStore.
	//    The memory store implements all three.
	engine := compliance.NewEngine(mem, mem, mem, nil)

	// 4. Generate a SOC2 Type II report.
	fmt.Println("\n--- SOC2 Type II Report ---")
	now := time.Now().UTC()
	soc2Report, err := engine.SOC2(ctx, &compliance.SOC2Input{
		Period: compliance.DateRange{
			From: now.Add(-24 * time.Hour),
			To:   now.Add(time.Hour),
		},
		AppID:       "myapp",
		TenantID:    "tenant-1",
		GeneratedBy: "compliance-admin",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Report ID:      %s\n", soc2Report.ID.String())
	fmt.Printf("Title:          %s\n", soc2Report.Title)
	fmt.Printf("Type:           %s\n", soc2Report.Type)
	fmt.Printf("Total Events:   %d\n", soc2Report.Stats.TotalEvents)
	fmt.Printf("Critical:       %d\n", soc2Report.Stats.CriticalEvents)
	fmt.Printf("Failed:         %d\n", soc2Report.Stats.FailedEvents)
	fmt.Printf("Denied:         %d\n", soc2Report.Stats.DeniedEvents)
	fmt.Printf("Sections:       %d\n", len(soc2Report.Sections))
	for _, s := range soc2Report.Sections {
		fmt.Printf("  - %-30s events=%d\n", s.Title, len(s.Events))
	}

	// 5. Generate a HIPAA report.
	fmt.Println("\n--- HIPAA Audit Report ---")
	hipaaReport, err := engine.HIPAA(ctx, &compliance.HIPAAInput{
		Period: compliance.DateRange{
			From: now.Add(-24 * time.Hour),
			To:   now.Add(time.Hour),
		},
		AppID:       "myapp",
		TenantID:    "tenant-1",
		GeneratedBy: "hipaa-officer",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Report ID:      %s\n", hipaaReport.ID.String())
	fmt.Printf("Title:          %s\n", hipaaReport.Title)
	fmt.Printf("Type:           %s\n", hipaaReport.Type)
	fmt.Printf("Total Events:   %d\n", hipaaReport.Stats.TotalEvents)
	fmt.Printf("Sections:       %d\n", len(hipaaReport.Sections))
	for _, s := range hipaaReport.Sections {
		fmt.Printf("  - %-30s events=%d\n", s.Title, len(s.Events))
	}

	// 6. Export SOC2 report to JSON.
	fmt.Println("\n--- Export: SOC2 as JSON (first 500 bytes) ---")
	var jsonBuf bytes.Buffer
	if err := engine.Export(ctx, soc2Report, compliance.FormatJSON, &jsonBuf); err != nil {
		log.Fatal(err)
	}
	output := jsonBuf.String()
	if len(output) > 500 {
		output = output[:500] + "..."
	}
	fmt.Println(output)

	// 7. Export HIPAA report to Markdown.
	fmt.Println("\n--- Export: HIPAA as Markdown (first 500 bytes) ---")
	var mdBuf bytes.Buffer
	if err := engine.Export(ctx, hipaaReport, compliance.FormatMarkdown, &mdBuf); err != nil {
		log.Fatal(err)
	}
	mdOutput := mdBuf.String()
	if len(mdOutput) > 500 {
		mdOutput = mdOutput[:500] + "..."
	}
	fmt.Println(mdOutput)
}
