// Package compliance generates audit-based compliance reports for Chronicle.
//
// # Engine
//
// [Engine] is the central type. Construct it with [NewEngine], which accepts
// three separate store interfaces drawn from the same composite backend, plus
// a *slog.Logger:
//
//	engine := compliance.NewEngine(
//	    s,       // audit.Store
//	    s,       // verify.Store
//	    s,       // ReportStore
//	    logger,
//	)
//
// When using a standard Chronicle backend (Postgres, Bun, SQLite, Memory) the
// same [store.Store] value satisfies all three interfaces.
//
// # Report Types
//
// Four report types are supported, each with its own input struct:
//
//   - [Engine.SOC2]    — SOC2 Type II: access events, authentication, authorisation
//     denials, critical errors; maps to SOC2 Trust Service Criteria CC6/CC7
//   - [Engine.HIPAA]   — HIPAA: PHI access, user activity, audit controls
//   - [Engine.EUAIAct] — EU AI Act: AI system interactions, decisions, outcomes
//   - [Engine.Custom]  — arbitrary filters, sections, and metadata
//
// All methods return a [*Report] and persist it to [ReportStore] automatically.
//
// # Report Structure
//
// [Report] embeds [chronicle.Entity] (CreatedAt, UpdatedAt) and contains:
//
//   - ID          — TypeID with "report_" prefix
//   - Title       — human-readable report name
//   - Type        — "soc2", "hipaa", "euaiact", or "custom"
//   - Period      — [DateRange] (From/To time.Time)
//   - AppID       — application scope
//   - TenantID    — tenant scope (empty for single-tenant)
//   - Sections    — []Section, each with a Title, Events, Stats, and Notes
//   - Stats       — [*Stats] aggregate (TotalEvents, CriticalEvents, FailedEvents, DeniedEvents)
//   - Verification — optional [*verify.Report] snapshot of chain integrity at generation time
//   - GeneratedBy  — identity of the requestor
//   - Format       — the [Format] the report was exported in
//   - Data         — raw exported bytes (populated by [Engine.Export])
//
// # Export
//
// [Engine.Export] serialises a [*Report] to an [io.Writer] in the requested [Format]:
//
//   - [FormatJSON]     — machine-readable JSON
//   - [FormatCSV]      — spreadsheet-compatible CSV
//   - [FormatMarkdown] — human-readable Markdown
//   - [FormatHTML]     — styled HTML for browser or email
//   - [FormatPDF]      — defined as a constant but not yet implemented
//
// # ReportStore
//
// [ReportStore] persists generated reports:
//
//   - [ReportStore.SaveReport]   — persist a new report
//   - [ReportStore.GetReport]    — retrieve by [id.ID]
//   - [ReportStore.ListReports]  — paginated listing
//   - [ReportStore.DeleteReport] — remove a report
package compliance
