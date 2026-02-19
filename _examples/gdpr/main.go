// Example: GDPR crypto-erasure with Chronicle.
//
// Demonstrates recording events with a SubjectID (data subject),
// performing a GDPR erasure request that destroys the subject's
// encryption key, and verifying that erased data is irrecoverable
// while the hash chain remains intact.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/verify"
)

func main() {
	ctx := context.Background()
	ctx = scope.WithAppID(ctx, "myapp")
	ctx = scope.WithTenantID(ctx, "tenant-1")

	// 1. Create store, adapter, and Chronicle with crypto-erasure enabled.
	mem := memory.New()
	adapter := store.NewAdapter(mem)
	c, err := chronicle.New(
		chronicle.WithStore(adapter),
		chronicle.WithCryptoErasure(true),
	)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Create a key store and the erasure service.
	keyStore := crypto.NewInMemoryKeyStore()
	erasureService := erasure.NewService(mem, keyStore)

	// 3. Record events for two different data subjects.
	fmt.Println("--- Recording events for Subject A (user-alice) ---")
	for i := range 3 {
		err = c.Info(ctx, "read", "patient-record", fmt.Sprintf("rec-%d", i)).
			Category("data").
			SubjectID("user-alice").
			UserID("doctor-1").
			Meta("record_type", "lab-result").
			Record()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("  Recorded event %d for user-alice\n", i+1)
	}

	fmt.Println("\n--- Recording events for Subject B (user-bob) ---")
	for i := range 2 {
		err = c.Info(ctx, "write", "prescription", fmt.Sprintf("presc-%d", i)).
			Category("data").
			SubjectID("user-bob").
			UserID("doctor-2").
			Meta("medication", "aspirin").
			Record()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("  Recorded event %d for user-bob\n", i+1)
	}

	// 4. Create encryption keys for both subjects (simulating what happens
	//    when crypto-erasure is active during recording).
	_, _, _ = keyStore.GetOrCreate("user-alice")
	_, _, _ = keyStore.GetOrCreate("user-bob")

	// 5. Show current state -- all events are visible.
	fmt.Println("\n--- Before Erasure: All Events ---")
	result, err := c.Query(ctx, &audit.Query{Limit: 100, Order: "asc"})
	if err != nil {
		log.Fatal(err)
	}
	for _, ev := range result.Events {
		fmt.Printf("  seq=%d subject=%-12s action=%-6s erased=%v\n",
			ev.Sequence, ev.SubjectID, ev.Action, ev.Erased)
	}

	// 6. Verify Alice's key exists.
	aliceKey, err := keyStore.Get("user-alice")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nAlice's encryption key exists: true (len=%d bytes)\n", len(aliceKey))

	// 7. Perform GDPR erasure for user-alice.
	fmt.Println("\n--- Erasing Subject: user-alice ---")
	eraseResult, err := erasureService.Erase(ctx, &erasure.Input{
		SubjectID:   "user-alice",
		Reason:      "GDPR Article 17 right to erasure",
		RequestedBy: "dpo@company.com",
	}, "myapp", "tenant-1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Erasure ID:       %s\n", eraseResult.ID.String())
	fmt.Printf("Subject:          %s\n", eraseResult.SubjectID)
	fmt.Printf("Events affected:  %d\n", eraseResult.EventsAffected)
	fmt.Printf("Key destroyed:    %v\n", eraseResult.KeyDestroyed)

	// 8. Verify Alice's key is gone.
	fmt.Println("\n--- Verifying Key Destruction ---")
	_, err = keyStore.Get("user-alice")
	if err != nil {
		fmt.Printf("Alice's key lookup: %v\n", err)
	}

	// Bob's key should still exist.
	bobKey, err := keyStore.Get("user-bob")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bob's key still exists: true (len=%d bytes)\n", len(bobKey))

	// 9. Show state after erasure -- Alice's events are marked as erased.
	fmt.Println("\n--- After Erasure: All Events ---")
	result, err = c.Query(ctx, &audit.Query{Limit: 100, Order: "asc"})
	if err != nil {
		log.Fatal(err)
	}
	for _, ev := range result.Events {
		status := "active"
		if ev.Erased {
			status = "ERASED"
		}
		fmt.Printf("  seq=%d subject=%-12s action=%-6s status=%s\n",
			ev.Sequence, ev.SubjectID, ev.Action, status)
	}

	// 10. Verify hash chain is still valid after erasure.
	//     Crypto-erasure destroys the key but keeps the hash chain intact,
	//     preserving the audit trail's structural integrity.
	fmt.Println("\n--- Hash Chain Verification After Erasure ---")
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

	fmt.Printf("Chain valid:     %v\n", report.Valid)
	fmt.Printf("Events verified: %d\n", report.Verified)
	fmt.Printf("Tampered:        %v\n", report.Tampered)

	// 11. Show erasure records.
	fmt.Println("\n--- Erasure Records ---")
	erasures, err := mem.ListErasures(ctx, erasure.ListOpts{Limit: 100})
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range erasures {
		fmt.Printf("  id=%s subject=%s reason=%q events=%d key_destroyed=%v\n",
			e.ID.String(), e.SubjectID, e.Reason, e.EventsAffected, e.KeyDestroyed)
	}

	// 12. Count remaining active events per subject.
	fmt.Println("\n--- Summary ---")
	var aliceErased, bobActive int
	for _, ev := range result.Events {
		if ev.SubjectID == "user-alice" && ev.Erased {
			aliceErased++
		}
		if ev.SubjectID == "user-bob" && !ev.Erased {
			bobActive++
		}
	}
	fmt.Printf("Alice: %d events erased (data irrecoverable)\n", aliceErased)
	fmt.Printf("Bob:   %d events active (data intact)\n", bobActive)
}
