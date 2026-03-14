// Package handler provides the Forge-style HTTP admin API for the Chronicle audit trail library.
// It uses forge.Router with OpenAPI metadata decorators and typed request DTOs.
package handler

import (
	"net/http"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/verify"
)

const tracerName = "github.com/xraph/chronicle/handler"

// Dependencies defines the handler dependencies.
type Dependencies struct {
	AuditStore     audit.Store
	VerifyStore    verify.Store
	ErasureStore   erasure.Store
	RetentionStore retention.Store
	ReportStore    compliance.ReportStore
	Compliance     *compliance.Engine
	Retention      *retention.Enforcer
	Logger         log.Logger
}

// API wires all Forge-style HTTP handlers together for the Chronicle system.
type API struct {
	deps   Dependencies
	router forge.Router
	tracer trace.Tracer
}

// New creates an API from handler dependencies and a Forge router.
func New(deps Dependencies, router forge.Router) *API {
	if deps.Logger == nil {
		deps.Logger = log.NewNoopLogger()
	}
	return &API{
		deps:   deps,
		router: router,
		tracer: otel.Tracer(tracerName),
	}
}

// Handler returns the fully assembled http.Handler with all routes.
// Use this for standalone mode outside Forge.
func (a *API) Handler() http.Handler {
	if a.router == nil {
		a.router = forge.NewRouter()
	}
	a.RegisterRoutes(a.router)
	return a.router.Handler()
}

// RegisterRoutes registers all Chronicle API routes into the given Forge router
// with full OpenAPI metadata.
func (a *API) RegisterRoutes(router forge.Router) {
	a.registerEventRoutes(router)
	a.registerVerifyRoutes(router)
	a.registerErasureRoutes(router)
	a.registerRetentionRoutes(router)
	a.registerReportRoutes(router)
	a.registerStatsRoutes(router)
}

// registerEventRoutes registers event management routes.
func (a *API) registerEventRoutes(router forge.Router) {
	g := router.Group("/v1", forge.WithGroupTags("events"))

	must(g.GET("/events", a.listEvents,
		forge.WithSummary("List events"),
		forge.WithDescription("Returns audit events filtered by category, action, severity, outcome, and time range."),
		forge.WithOperationID("chronicleListEvents"),
		forge.WithRequestSchema(ListEventsRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Event list", &audit.QueryResult{}),
		forge.WithErrorResponses(),
	))

	must(g.GET("/events/:id", a.getEvent,
		forge.WithSummary("Get event"),
		forge.WithDescription("Returns details of a specific audit event."),
		forge.WithOperationID("chronicleGetEvent"),
		forge.WithRequestSchema(GetEventRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Event details", &audit.Event{}),
		forge.WithErrorResponses(),
	))

	must(g.GET("/events/user/:userId", a.eventsByUser,
		forge.WithSummary("Events by user"),
		forge.WithDescription("Returns audit events for a specific user within a time range."),
		forge.WithOperationID("eventsByUser"),
		forge.WithRequestSchema(EventsByUserRequest{}),
		forge.WithResponseSchema(http.StatusOK, "User events", &audit.QueryResult{}),
		forge.WithErrorResponses(),
	))

	must(g.POST("/events/aggregate", a.aggregateEvents,
		forge.WithSummary("Aggregate events"),
		forge.WithDescription("Returns grouped counts/stats for analytics."),
		forge.WithOperationID("aggregateEvents"),
		forge.WithRequestSchema(audit.AggregateQuery{}),
		forge.WithResponseSchema(http.StatusOK, "Aggregate result", &audit.AggregateResult{}),
		forge.WithErrorResponses(),
	))
}

// registerVerifyRoutes registers hash chain verification routes.
func (a *API) registerVerifyRoutes(router forge.Router) {
	g := router.Group("/v1", forge.WithGroupTags("verify"))

	must(g.POST("/verify", a.verifyChain,
		forge.WithSummary("Verify hash chain"),
		forge.WithDescription("Verifies the integrity of an audit event hash chain."),
		forge.WithOperationID("verifyChain"),
		forge.WithRequestSchema(VerifyChainRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Verification report", &verify.Report{}),
		forge.WithErrorResponses(),
	))
}

// registerErasureRoutes registers GDPR erasure routes.
func (a *API) registerErasureRoutes(router forge.Router) {
	g := router.Group("/v1", forge.WithGroupTags("erasures"))

	must(g.POST("/erasures", a.requestErasure,
		forge.WithSummary("Request erasure"),
		forge.WithDescription("Records a GDPR erasure request and marks affected events."),
		forge.WithOperationID("requestErasure"),
		forge.WithRequestSchema(RequestErasureRequest{}),
		forge.WithCreatedResponse(&erasure.Result{}),
		forge.WithErrorResponses(),
	))

	must(g.GET("/erasures", a.listErasures,
		forge.WithSummary("List erasures"),
		forge.WithDescription("Returns erasure records."),
		forge.WithOperationID("listErasures"),
		forge.WithResponseSchema(http.StatusOK, "Erasure records", []*erasure.Erasure{}),
		forge.WithErrorResponses(),
	))

	must(g.GET("/erasures/:id", a.getErasure,
		forge.WithSummary("Get erasure"),
		forge.WithDescription("Returns details of a specific erasure record."),
		forge.WithOperationID("getErasure"),
		forge.WithRequestSchema(GetErasureRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Erasure details", &erasure.Erasure{}),
		forge.WithErrorResponses(),
	))
}

// registerRetentionRoutes registers retention policy and archive routes.
func (a *API) registerRetentionRoutes(router forge.Router) {
	g := router.Group("/v1", forge.WithGroupTags("retention"))

	must(g.GET("/retention", a.listPolicies,
		forge.WithSummary("List retention policies"),
		forge.WithDescription("Returns retention policies for the current app scope."),
		forge.WithOperationID("chronicleListPolicies"),
		forge.WithResponseSchema(http.StatusOK, "Retention policies", []*retention.Policy{}),
		forge.WithErrorResponses(),
	))

	must(g.POST("/retention", a.savePolicy,
		forge.WithSummary("Save retention policy"),
		forge.WithDescription("Creates or updates a retention policy."),
		forge.WithOperationID("savePolicy"),
		forge.WithRequestSchema(SavePolicyRequest{}),
		forge.WithCreatedResponse(&retention.Policy{}),
		forge.WithErrorResponses(),
	))

	must(g.DELETE("/retention/:id", a.deletePolicy,
		forge.WithSummary("Delete retention policy"),
		forge.WithDescription("Removes a retention policy."),
		forge.WithOperationID("chronicleDeletePolicy"),
		forge.WithRequestSchema(DeletePolicyRequest{}),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
	))

	must(g.POST("/retention/enforce", a.enforceRetention,
		forge.WithSummary("Enforce retention"),
		forge.WithDescription("Triggers immediate retention enforcement."),
		forge.WithOperationID("enforceRetention"),
		forge.WithResponseSchema(http.StatusOK, "Enforcement result", &retention.EnforceResult{}),
		forge.WithErrorResponses(),
	))

	must(g.GET("/retention/archives", a.listArchives,
		forge.WithSummary("List archives"),
		forge.WithDescription("Returns archive records."),
		forge.WithOperationID("listArchives"),
		forge.WithResponseSchema(http.StatusOK, "Archive records", []*retention.Archive{}),
		forge.WithErrorResponses(),
	))
}

// registerReportRoutes registers compliance report routes.
func (a *API) registerReportRoutes(router forge.Router) {
	g := router.Group("/v1", forge.WithGroupTags("reports"))

	must(g.GET("/reports", a.listReports,
		forge.WithSummary("List reports"),
		forge.WithDescription("Returns compliance reports for the current app scope."),
		forge.WithOperationID("listReports"),
		forge.WithResponseSchema(http.StatusOK, "Compliance reports", []*compliance.Report{}),
		forge.WithErrorResponses(),
	))

	must(g.POST("/reports/soc2", a.generateSOC2,
		forge.WithSummary("Generate SOC2 report"),
		forge.WithDescription("Generates a SOC2 compliance report."),
		forge.WithOperationID("generateSOC2"),
		forge.WithRequestSchema(compliance.SOC2Input{}),
		forge.WithCreatedResponse(&compliance.Report{}),
		forge.WithErrorResponses(),
	))

	must(g.POST("/reports/hipaa", a.generateHIPAA,
		forge.WithSummary("Generate HIPAA report"),
		forge.WithDescription("Generates a HIPAA compliance report."),
		forge.WithOperationID("generateHIPAA"),
		forge.WithRequestSchema(compliance.HIPAAInput{}),
		forge.WithCreatedResponse(&compliance.Report{}),
		forge.WithErrorResponses(),
	))

	must(g.POST("/reports/euaiact", a.generateEUAIAct,
		forge.WithSummary("Generate EU AI Act report"),
		forge.WithDescription("Generates an EU AI Act compliance report."),
		forge.WithOperationID("generateEUAIAct"),
		forge.WithRequestSchema(compliance.EUAIActInput{}),
		forge.WithCreatedResponse(&compliance.Report{}),
		forge.WithErrorResponses(),
	))

	must(g.POST("/reports/custom", a.generateCustom,
		forge.WithSummary("Generate custom report"),
		forge.WithDescription("Generates a custom compliance report."),
		forge.WithOperationID("generateCustom"),
		forge.WithRequestSchema(compliance.CustomInput{}),
		forge.WithCreatedResponse(&compliance.Report{}),
		forge.WithErrorResponses(),
	))

	must(g.GET("/reports/:id", a.getReport,
		forge.WithSummary("Get report"),
		forge.WithDescription("Returns details of a specific compliance report."),
		forge.WithOperationID("chronicleGetReport"),
		forge.WithRequestSchema(GetReportRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Report details", &compliance.Report{}),
		forge.WithErrorResponses(),
	))

	must(g.GET("/reports/:id/export/:format", a.exportReport,
		forge.WithSummary("Export report"),
		forge.WithDescription("Exports a compliance report in the specified format (json, csv, markdown, html)."),
		forge.WithOperationID("chronicleExportReport"),
		forge.WithRequestSchema(ExportReportRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Exported report content", ""),
		forge.WithErrorResponses(),
	))
}

// registerStatsRoutes registers aggregate statistics routes.
func (a *API) registerStatsRoutes(router forge.Router) {
	g := router.Group("/v1", forge.WithGroupTags("stats"))

	must(g.GET("/stats", a.getStats,
		forge.WithSummary("Chronicle stats"),
		forge.WithDescription("Returns aggregate statistics for audit events."),
		forge.WithOperationID("chronicleStats"),
		forge.WithResponseSchema(http.StatusOK, "Chronicle statistics", StatsResponse{}),
		forge.WithErrorResponses(),
	))
}

// must panics on route registration errors.
// Route registration errors indicate programmer mistakes (invalid handler signatures)
// and should be caught immediately at startup.
func must(err error) {
	if err != nil {
		panic("chronicle: route registration failed: " + err.Error())
	}
}
