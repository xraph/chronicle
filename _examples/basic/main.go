// Example: basic usage of Chronicle audit trail.
//
// Demonstrates creating a Chronicle instance with an in-memory store,
// recording events at different severity levels using the fluent builder API,
// querying events with filters, and verifying the hash chain.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

func main() {
	ctx := context.Background()

	// Set scope so all events are tagged with app + tenant.
	ctx = scope.WithAppID(ctx, "myapp")
	ctx = scope.WithTenantID(ctx, "tenant-1")
	ctx = scope.WithUserID(ctx, "user-42")

	// 1. Create an in-memory store and wrap it with the adapter.
	mem := memory.New()
	adapter := store.NewAdapter(mem)

	// 2. Create a Chronicle instance.
	c, err := chronicle.New(
		chronicle.WithStore(adapter),
	)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Record events using the fluent builder API.
	fmt.Println("--- Recording Events ---")

	err = c.Info(ctx, "login", "session", "sess-001").
		Category("auth").
		Reason("user logged in via SSO").
		Meta("provider", "okta").
		Record()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Recorded: info  | login")

	err = c.Info(ctx, "read", "document", "doc-99").
		Category("data").
		Meta("format", "pdf").
		Record()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Recorded: info  | read")

	err = c.Warning(ctx, "permission.change", "role", "role-admin").
		Category("access").
		Reason("admin role granted to user").
		Meta("granted_to", "user-99").
		Record()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Recorded: warn  | permission.change")

	err = c.Critical(ctx, "delete", "database", "db-prod").
		Category("data").
		Outcome(audit.OutcomeFailure).
		Reason("attempted production database deletion").
		Record()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Recorded: crit  | delete")

	err = c.Info(ctx, "logout", "session", "sess-001").
		Category("auth").
		Record()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Recorded: info  | logout")

	// 4. Query all events.
	fmt.Println("\n--- Query: All Events ---")
	result, err := c.Query(ctx, &audit.Query{
		Limit: 100,
		Order: "asc",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Total events: %d\n", result.Total)
	for _, ev := range result.Events {
		fmt.Printf("  [%s] %s %s/%s (seq=%d)\n",
			ev.Severity, ev.Action, ev.Resource, ev.ResourceID, ev.Sequence)
	}

	// 5. Query with filters -- only auth events.
	fmt.Println("\n--- Query: Auth Events Only ---")
	authResult, err := c.Query(ctx, &audit.Query{
		Categories: []string{"auth"},
		Limit:      100,
		Order:      "asc",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Auth events: %d\n", authResult.Total)
	for _, ev := range authResult.Events {
		fmt.Printf("  [%s] %s %s/%s\n",
			ev.Severity, ev.Action, ev.Resource, ev.ResourceID)
	}

	// 6. Query with filters -- critical severity only.
	fmt.Println("\n--- Query: Critical Events Only ---")
	critResult, err := c.Query(ctx, &audit.Query{
		Severity: []string{audit.SeverityCritical},
		Limit:    100,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Critical events: %d\n", critResult.Total)
	for _, ev := range critResult.Events {
		fmt.Printf("  [%s] %s %s/%s outcome=%s\n",
			ev.Severity, ev.Action, ev.Resource, ev.ResourceID, ev.Outcome)
	}

	// 7. Verify individual event hashes.
	fmt.Println("\n--- Verify Individual Events ---")
	for _, ev := range result.Events {
		valid, verr := c.VerifyEvent(ctx, ev.ID)
		if verr != nil {
			log.Fatal(verr)
		}
		fmt.Printf("  Event seq=%d hash valid: %v\n", ev.Sequence, valid)
	}

	// 8. Verify the entire hash chain.
	fmt.Println("\n--- Verify Hash Chain ---")
	firstEvent := result.Events[0]
	lastEvent := result.Events[len(result.Events)-1]

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: firstEvent.StreamID,
		FromSeq:  firstEvent.Sequence,
		ToSeq:    lastEvent.Sequence,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Chain valid:    %v\n", report.Valid)
	fmt.Printf("Events verified: %d\n", report.Verified)
	fmt.Printf("Gaps:           %v\n", report.Gaps)
	fmt.Printf("Tampered:       %v\n", report.Tampered)
}
