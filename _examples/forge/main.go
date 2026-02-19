// Example: Chronicle as a Forge extension.
//
// Demonstrates creating the Chronicle Forge extension, initializing it
// with a memory store, starting background services, using the Emitter
// interface for recording events, and retrieving the HTTP handler routes.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

func main() {
	ctx := context.Background()

	// 1. Create the Chronicle Forge extension with options.
	ext := extension.New(
		extension.WithBatchSize(50),
		extension.WithCryptoErasure(false),
		extension.WithRetentionInterval(0), // disable auto-retention for this example
	)

	fmt.Printf("Extension name: %s\n", ext.Name())

	// 2. Create a memory store (in production, this would be postgres/sqlite).
	mem := memory.New()

	// 3. Initialize the extension -- runs migrations, creates Chronicle, etc.
	if err := ext.Init(ctx, mem); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Extension initialized.")

	// 4. Start the extension (begins background processing).
	if err := ext.Start(ctx); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Extension started.")
	defer func() {
		if err := ext.Stop(ctx); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Extension stopped.")
	}()

	// 5. Get the Emitter -- this is what other Forge extensions use via DI.
	emitter := ext.Emitter()

	// Set scope context as Forge middleware would.
	ctx = scope.WithAppID(ctx, "forge-app")
	ctx = scope.WithTenantID(ctx, "tenant-1")
	ctx = scope.WithUserID(ctx, "user-42")

	// 6. Record events via the Emitter interface.
	fmt.Println("\n--- Recording via Emitter ---")

	err := emitter.Info(ctx, "login", "session", "sess-001").
		Category("auth").
		Meta("method", "oauth2").
		Record()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Recorded: login (info)")

	err = emitter.Warning(ctx, "config.change", "feature-flags", "flags-1").
		Category("config").
		Reason("production feature flag toggled").
		Record()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Recorded: config.change (warning)")

	err = emitter.Critical(ctx, "delete", "database-table", "users").
		Category("data").
		Outcome(audit.OutcomeFailure).
		Reason("attempted table drop blocked").
		Record()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Recorded: delete (critical)")

	// 7. Access the Chronicle instance directly for queries.
	c := ext.Chronicle()

	result, err := c.Query(ctx, &audit.Query{Limit: 100, Order: "asc"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n--- Queried Events: %d ---\n", result.Total)
	for _, ev := range result.Events {
		fmt.Printf("  [%s] %s %s/%s (seq=%d)\n",
			ev.Severity, ev.Action, ev.Resource, ev.ResourceID, ev.Sequence)
	}

	// 8. Access the compliance engine.
	engine := ext.ComplianceEngine()
	fmt.Printf("\nCompliance engine available: %v\n", engine != nil)

	// 9. Access the retention enforcer.
	enforcer := ext.RetentionEnforcer()
	fmt.Printf("Retention enforcer available: %v\n", enforcer != nil)

	// 10. Get the HTTP handler for the admin API routes.
	routes := ext.Routes()
	fmt.Printf("HTTP handler available: %v\n", routes != nil)

	// 11. List the admin API endpoints.
	fmt.Println("\n--- Admin API Endpoints ---")
	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/chronicle/events"},
		{"GET", "/chronicle/events/{id}"},
		{"GET", "/chronicle/events/user/{user_id}"},
		{"POST", "/chronicle/events/aggregate"},
		{"POST", "/chronicle/verify"},
		{"POST", "/chronicle/erasures"},
		{"GET", "/chronicle/erasures"},
		{"GET", "/chronicle/erasures/{id}"},
		{"GET", "/chronicle/retention"},
		{"POST", "/chronicle/retention"},
		{"DELETE", "/chronicle/retention/{id}"},
		{"POST", "/chronicle/retention/enforce"},
		{"GET", "/chronicle/retention/archives"},
		{"GET", "/chronicle/reports"},
		{"POST", "/chronicle/reports/soc2"},
		{"POST", "/chronicle/reports/hipaa"},
		{"POST", "/chronicle/reports/euaiact"},
		{"POST", "/chronicle/reports/custom"},
		{"GET", "/chronicle/reports/{id}"},
		{"GET", "/chronicle/reports/{id}/export/{format}"},
		{"GET", "/chronicle/stats"},
	}
	for _, ep := range endpoints {
		fmt.Printf("  %-7s %s\n", ep.method, ep.path)
	}

	// 12. Verify the hash chain through the Chronicle instance.
	fmt.Println("\n--- Hash Chain Verification ---")
	first := result.Events[0]
	last := result.Events[len(result.Events)-1]
	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: first.StreamID,
		FromSeq:  first.Sequence,
		ToSeq:    last.Sequence,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Chain valid: %v (verified %d events)\n", report.Valid, report.Verified)

	// 13. Demonstrate the routes handler can be mounted on a server.
	mux := http.NewServeMux()
	mux.Handle("/", routes)
	fmt.Println("\nRoutes mounted on HTTP mux (ready to serve).")
}
