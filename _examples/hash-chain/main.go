// Example: Hash chain verification with Chronicle.
//
// Demonstrates recording a sequence of events, verifying individual
// event hashes, verifying the entire chain, and inspecting the
// verification report for tampered or missing events.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

func main() {
	ctx := context.Background()
	ctx = scope.WithAppID(ctx, "myapp")
	ctx = scope.WithTenantID(ctx, "tenant-1")

	// 1. Set up store and Chronicle.
	mem := memory.New()
	adapter := store.NewAdapter(mem)
	c, err := chronicle.New(chronicle.WithStore(adapter))
	if err != nil {
		log.Fatal(err)
	}

	// 2. Record a sequence of events to build a hash chain.
	fmt.Println("--- Recording Event Sequence ---")
	actions := []struct {
		action   string
		resource string
		category string
	}{
		{"create", "user", "auth"},
		{"login", "session", "auth"},
		{"read", "document", "data"},
		{"update", "document", "data"},
		{"share", "document", "data"},
		{"permission.grant", "role", "access"},
		{"deploy", "api-v3", "deployment"},
		{"config.update", "feature-flags", "config"},
		{"logout", "session", "auth"},
		{"delete", "temp-files", "data"},
	}

	for i, a := range actions {
		err = c.Info(ctx, a.action, a.resource, fmt.Sprintf("res-%d", i)).
			Category(a.category).
			UserID("user-1").
			Meta("step", i+1).
			Record()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("  [%2d] %s %s\n", i+1, a.action, a.resource)
	}

	// 3. Retrieve all events to inspect the chain structure.
	fmt.Println("\n--- Hash Chain Structure ---")
	result, err := c.Query(ctx, &audit.Query{Limit: 100, Order: "asc"})
	if err != nil {
		log.Fatal(err)
	}

	for _, ev := range result.Events {
		prevHashShort := "(genesis)"
		if ev.PrevHash != "" {
			prevHashShort = ev.PrevHash[:16] + "..."
		}
		fmt.Printf("  seq=%2d  hash=%s...  prev=%s\n",
			ev.Sequence, ev.Hash[:16], prevHashShort)
	}

	// 4. Verify individual event hashes.
	fmt.Println("\n--- Individual Event Verification ---")
	hasher := &hash.Chain{}
	allValid := true
	for _, ev := range result.Events {
		computed := hasher.Compute(ev.PrevHash, ev)
		valid := computed == ev.Hash
		if !valid {
			allValid = false
		}
		fmt.Printf("  seq=%2d  valid=%v\n", ev.Sequence, valid)
	}
	fmt.Printf("All individual hashes valid: %v\n", allValid)

	// 5. Verify chain linkage (each event's PrevHash matches the previous event's Hash).
	fmt.Println("\n--- Chain Linkage Verification ---")
	linkageValid := true
	for i := 1; i < len(result.Events); i++ {
		curr := result.Events[i]
		prev := result.Events[i-1]
		linked := curr.PrevHash == prev.Hash
		if !linked {
			linkageValid = false
			fmt.Printf("  BROKEN: seq=%d PrevHash does not match seq=%d Hash\n",
				curr.Sequence, prev.Sequence)
		}
	}
	if linkageValid {
		fmt.Println("  All chain links are valid.")
	}

	// 6. Full chain verification using the Verifier.
	fmt.Println("\n--- Full Chain Verification Report ---")
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

	fmt.Printf("  Valid:           %v\n", report.Valid)
	fmt.Printf("  Events verified: %d\n", report.Verified)
	fmt.Printf("  First event:     seq=%d\n", report.FirstEvent)
	fmt.Printf("  Last event:      seq=%d\n", report.LastEvent)
	fmt.Printf("  Gaps:            %v\n", report.Gaps)
	fmt.Printf("  Tampered:        %v\n", report.Tampered)

	// 7. Verify a sub-range of the chain.
	fmt.Println("\n--- Sub-Range Verification (seq 3-7) ---")
	subReport, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: firstEvent.StreamID,
		FromSeq:  3,
		ToSeq:    7,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("  Valid:           %v\n", subReport.Valid)
	fmt.Printf("  Events verified: %d\n", subReport.Verified)
	fmt.Printf("  First event:     seq=%d\n", subReport.FirstEvent)
	fmt.Printf("  Last event:      seq=%d\n", subReport.LastEvent)

	// 8. Summary.
	fmt.Println("\n--- Summary ---")
	fmt.Printf("Total events in chain: %d\n", len(result.Events))
	fmt.Printf("Stream ID:             %s\n", firstEvent.StreamID.String())
	fmt.Printf("Chain integrity:       %v\n", report.Valid)
}
