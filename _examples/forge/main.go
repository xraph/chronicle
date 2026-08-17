// Example: Chronicle as a Forge extension.
//
// Demonstrates registering the Chronicle Forge extension against a Forge app,
// starting background services, using the Emitter interface for recording
// events, and retrieving the HTTP handler.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/xraph/forge"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

func main() {
	ctx := context.Background()

	// 1. Create the Chronicle Forge extension with options.
	//
	// The store is supplied up front; in production this would be postgres,
	// sqlite or mongo, or auto-discovered from a grove.DB in the container.
	mem := memory.New()

	ext := extension.New(
		extension.WithStore(mem),
		extension.WithBatchSize(50),
		extension.WithCryptoErasure(false),
		extension.WithRetentionInterval(0), // disable auto-retention for this example

		// The admin API can purge audit history, so the extension refuses to
		// start unless access is decided explicitly. In production use WithAuth:
		//
		//	extension.WithAuth("jwt",
		//	    []string{"chronicle:read"},
		//	    []string{"chronicle:write"},
		//	    []string{"chronicle:admin"},
		//	)
		extension.WithUnauthenticatedAPI(),
	)

	fmt.Printf("Extension name: %s\n", ext.Name())

	// 2. Register the extension against a Forge app. Register wires Chronicle,
	// the compliance engine, the retention enforcer and the admin API, and
	// mounts the routes into the app's router.
	app := forge.New(forge.WithAppName("chronicle-example"))

	if err := ext.Register(app); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Extension registered.")

	// 3. Start the extension: runs migrations and begins background processing.
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

	// 4. Get the Emitter -- this is what other Forge extensions use via DI.
	emitter := ext.Emitter()

	// Set scope context as Forge middleware would.
	ctx = scope.WithAppID(ctx, "forge-app")
	ctx = scope.WithTenantID(ctx, "tenant-1")
	ctx = scope.WithUserID(ctx, "user-42")

	// 5. Record events via the Emitter interface.
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

	// 6. Access the Chronicle instance directly for queries.
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

	// 7. Access the compliance engine.
	engine := ext.ComplianceEngine()
	fmt.Printf("\nCompliance engine available: %v\n", engine != nil)

	// 8. Access the retention enforcer.
	enforcer := ext.RetentionEnforcer()
	fmt.Printf("Retention enforcer available: %v\n", enforcer != nil)

	// 9. Get the HTTP handler for the admin API routes.
	routes := ext.Handler()
	fmt.Printf("HTTP handler available: %v\n", routes != nil)

	// 10. List the admin API endpoints, with the guard class each one sits
	// behind. read observes; write creates records; admin is irreversible.
	fmt.Println("\n--- Admin API Endpoints ---")
	endpoints := []struct {
		method string
		path   string
		class  string
	}{
		{"GET", "/chronicle/events", "read"},
		{"GET", "/chronicle/events/{id}", "read"},
		{"GET", "/chronicle/events/user/{user_id}", "read"},
		{"POST", "/chronicle/events/aggregate", "read"},
		{"POST", "/chronicle/verify", "read"},
		{"POST", "/chronicle/erasures", "admin"},
		{"GET", "/chronicle/erasures", "read"},
		{"GET", "/chronicle/erasures/{id}", "read"},
		{"GET", "/chronicle/retention", "read"},
		{"POST", "/chronicle/retention", "write"},
		{"DELETE", "/chronicle/retention/{id}", "admin"},
		{"POST", "/chronicle/retention/enforce", "admin"},
		{"GET", "/chronicle/retention/archives", "read"},
		{"GET", "/chronicle/reports", "read"},
		{"POST", "/chronicle/reports/soc2", "write"},
		{"POST", "/chronicle/reports/hipaa", "write"},
		{"POST", "/chronicle/reports/euaiact", "write"},
		{"POST", "/chronicle/reports/custom", "write"},
		{"GET", "/chronicle/reports/{id}", "read"},
		{"GET", "/chronicle/reports/{id}/export/{format}", "read"},
		{"GET", "/chronicle/stats", "read"},
	}
	for _, ep := range endpoints {
		fmt.Printf("  %-7s %-46s [%s]\n", ep.method, ep.path, ep.class)
	}

	// 11. Verify the hash chain through the Chronicle instance.
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

	// 12. Demonstrate the routes handler can be mounted on a server.
	mux := http.NewServeMux()
	mux.Handle("/", routes)
	fmt.Println("\nRoutes mounted on HTTP mux (ready to serve).")
}
