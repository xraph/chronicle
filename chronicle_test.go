package chronicle_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/store/sealedstore"
	"github.com/xraph/chronicle/verify"
)

func newTestChronicle(t *testing.T) *chronicle.Chronicle {
	t.Helper()
	s := store.NewAdapter(memory.New())
	c, err := chronicle.New(chronicle.WithStore(s))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestRecordValidation(t *testing.T) {
	c := newTestChronicle(t)

	tests := []struct {
		name    string
		event   *audit.Event
		wantErr bool
	}{
		{
			name: "valid event",
			event: &audit.Event{
				Action:   "create",
				Resource: "user",
				Category: "auth",
			},
			wantErr: false,
		},
		{
			name: "missing action",
			event: &audit.Event{
				Resource: "user",
				Category: "auth",
			},
			wantErr: true,
		},
		{
			name: "missing resource",
			event: &audit.Event{
				Action:   "create",
				Category: "auth",
			},
			wantErr: true,
		},
		{
			name: "missing category",
			event: &audit.Event{
				Action:   "create",
				Resource: "user",
			},
			wantErr: true,
		},
		{
			name:    "all missing",
			event:   &audit.Event{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := c.Record(context.Background(), tt.event)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, chronicle.ErrInvalidQuery) {
				t.Errorf("expected ErrInvalidQuery, got: %v", err)
			}
		})
	}
}

func TestRecordAssignsIDAndTimestamp(t *testing.T) {
	c := newTestChronicle(t)

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err := c.Record(context.Background(), event)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if event.ID.String() == "" {
		t.Error("expected ID to be assigned")
	}
	if event.Timestamp.IsZero() {
		t.Error("expected Timestamp to be assigned")
	}
}

func TestRecordAssignsHashChain(t *testing.T) {
	c := newTestChronicle(t)

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err := c.Record(context.Background(), event)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if event.Hash == "" {
		t.Error("expected Hash to be assigned")
	}
	if event.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1 (genesis)", event.Sequence)
	}
	if event.PrevHash != "" {
		t.Errorf("PrevHash = %q, want empty for genesis", event.PrevHash)
	}
	if event.StreamID.String() == "" {
		t.Error("expected StreamID to be assigned")
	}
}

func TestRecordChainLinkage(t *testing.T) {
	c := newTestChronicle(t)

	event1 := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenant1",
	}
	err := c.Record(context.Background(), event1)
	if err != nil {
		t.Fatalf("Record event1: %v", err)
	}

	event2 := &audit.Event{
		Action:   "update",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenant1",
	}
	err = c.Record(context.Background(), event2)
	if err != nil {
		t.Fatalf("Record event2: %v", err)
	}

	event3 := &audit.Event{
		Action:   "delete",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenant1",
	}
	err = c.Record(context.Background(), event3)
	if err != nil {
		t.Fatalf("Record event3: %v", err)
	}

	// Chain linkage: event2.PrevHash == event1.Hash, event3.PrevHash == event2.Hash.
	if event2.PrevHash != event1.Hash {
		t.Errorf("event2.PrevHash = %q, want event1.Hash = %q", event2.PrevHash, event1.Hash)
	}
	if event3.PrevHash != event2.Hash {
		t.Errorf("event3.PrevHash = %q, want event2.Hash = %q", event3.PrevHash, event2.Hash)
	}

	// All in same stream.
	if event1.StreamID != event2.StreamID || event2.StreamID != event3.StreamID {
		t.Error("all events should be in the same stream")
	}

	// Sequence increments.
	if event1.Sequence != 1 || event2.Sequence != 2 || event3.Sequence != 3 {
		t.Errorf("sequences = %d, %d, %d, want 1, 2, 3", event1.Sequence, event2.Sequence, event3.Sequence)
	}

	// All hashes unique.
	if event1.Hash == event2.Hash || event2.Hash == event3.Hash {
		t.Error("all hashes should be unique")
	}
}

func TestRecordDifferentStreamsPerTenant(t *testing.T) {
	c := newTestChronicle(t)

	event1 := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenantA",
	}
	err := c.Record(context.Background(), event1)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	event2 := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
		AppID:    "app1",
		TenantID: "tenantB",
	}
	err = c.Record(context.Background(), event2)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Different tenants get different streams.
	if event1.StreamID == event2.StreamID {
		t.Error("different tenants should have different streams")
	}

	// Both are genesis events.
	if event1.Sequence != 1 || event2.Sequence != 1 {
		t.Errorf("both should be sequence 1, got %d and %d", event1.Sequence, event2.Sequence)
	}
}

func TestVerifyEvent(t *testing.T) {
	c := newTestChronicle(t)

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err := c.Record(context.Background(), event)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	valid, err := c.VerifyEvent(context.Background(), event.ID)
	if err != nil {
		t.Fatalf("VerifyEvent: %v", err)
	}
	if !valid {
		t.Error("event should be valid")
	}
}

func TestVerifyChain(t *testing.T) {
	c := newTestChronicle(t)
	ctx := context.Background()

	// Record 10 events in a chain.
	var streamID chronicle.StreamInfo
	for i := range 10 {
		event := &audit.Event{
			Action:   "action",
			Resource: "resource",
			Category: "cat",
			AppID:    "app1",
			TenantID: "tenant1",
		}
		err := c.Record(ctx, event)
		if err != nil {
			t.Fatalf("Record event %d: %v", i, err)
		}
		if i == 0 {
			streamID = chronicle.StreamInfo{ID: event.StreamID}
		}
	}

	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID.ID,
		FromSeq:  1,
		ToSeq:    10,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if !report.Valid {
		t.Errorf("chain should be valid, gaps=%v, tampered=%v", report.Gaps, report.Tampered)
	}
	if report.Verified != 10 {
		t.Errorf("Verified = %d, want 10", report.Verified)
	}
	if report.FirstEvent != 1 {
		t.Errorf("FirstEvent = %d, want 1", report.FirstEvent)
	}
	if report.LastEvent != 10 {
		t.Errorf("LastEvent = %d, want 10", report.LastEvent)
	}
}

func TestRecordAppliesScope(t *testing.T) {
	c := newTestChronicle(t)

	ctx := scope.WithInfo(context.Background(), scope.Info{
		AppID:    "app1",
		TenantID: "tenant1",
		UserID:   "user1",
		IP:       "10.0.0.1",
	})

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err := c.Record(ctx, event)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if event.AppID != "app1" {
		t.Errorf("AppID = %q, want %q", event.AppID, "app1")
	}
	if event.TenantID != "tenant1" {
		t.Errorf("TenantID = %q, want %q", event.TenantID, "tenant1")
	}
	if event.UserID != "user1" {
		t.Errorf("UserID = %q, want %q", event.UserID, "user1")
	}
	if event.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want %q", event.IP, "10.0.0.1")
	}
}

func TestRecordNoStore(t *testing.T) {
	c, err := chronicle.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	event := &audit.Event{
		Action:   "create",
		Resource: "user",
		Category: "auth",
	}
	err = c.Record(context.Background(), event)
	if !errors.Is(err, chronicle.ErrNoStore) {
		t.Errorf("expected ErrNoStore, got: %v", err)
	}
}

func TestBuilderProducesEvent(t *testing.T) {
	c := newTestChronicle(t)

	b := c.Info(context.Background(), "login", "session", "sess-123").
		Category("auth").
		Reason("user authenticated").
		Meta("method", "oauth").
		SubjectID("user-42").
		Outcome(audit.OutcomeSuccess).
		TenantID("t1").
		UserID("u1").
		AppID("a1")

	event := b.Event()

	if event.Action != "login" {
		t.Errorf("Action = %q, want %q", event.Action, "login")
	}
	if event.Resource != "session" {
		t.Errorf("Resource = %q, want %q", event.Resource, "session")
	}
	if event.ResourceID != "sess-123" {
		t.Errorf("ResourceID = %q, want %q", event.ResourceID, "sess-123")
	}
	if event.Severity != audit.SeverityInfo {
		t.Errorf("Severity = %q, want %q", event.Severity, audit.SeverityInfo)
	}
	if event.Category != "auth" {
		t.Errorf("Category = %q, want %q", event.Category, "auth")
	}
	if event.Reason != "user authenticated" {
		t.Errorf("Reason = %q, want %q", event.Reason, "user authenticated")
	}
	if event.Metadata["method"] != "oauth" {
		t.Errorf("Metadata[method] = %v, want %q", event.Metadata["method"], "oauth")
	}
	if event.SubjectID != "user-42" {
		t.Errorf("SubjectID = %q, want %q", event.SubjectID, "user-42")
	}
	if event.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", event.Outcome, audit.OutcomeSuccess)
	}
	if event.TenantID != "t1" {
		t.Errorf("TenantID = %q, want %q", event.TenantID, "t1")
	}
}

func TestBuilderRecord(t *testing.T) {
	c := newTestChronicle(t)

	err := c.Warning(context.Background(), "delete", "document", "doc-1").
		Category("documents").
		Reason("user deleted document").
		Record()

	if err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func TestBuilderSeverityLevels(t *testing.T) {
	c := newTestChronicle(t)

	tests := []struct {
		name     string
		builder  *chronicle.EventBuilder
		severity string
	}{
		{"info", c.Info(context.Background(), "a", "r", "id"), audit.SeverityInfo},
		{"warning", c.Warning(context.Background(), "a", "r", "id"), audit.SeverityWarning},
		{"critical", c.Critical(context.Background(), "a", "r", "id"), audit.SeverityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := tt.builder.Event()
			if event.Severity != tt.severity {
				t.Errorf("Severity = %q, want %q", event.Severity, tt.severity)
			}
		})
	}
}

func TestQueryAppliesScope(t *testing.T) {
	c := newTestChronicle(t)

	ctx := scope.WithInfo(context.Background(), scope.Info{
		AppID:    "app1",
		TenantID: "tenant1",
	})

	// Record an event for tenant1.
	err := c.Record(ctx, &audit.Event{
		Action:   "read",
		Resource: "doc",
		Category: "docs",
		AppID:    "app1",
		TenantID: "tenant1",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Record an event for tenant2.
	err = c.Record(context.Background(), &audit.Event{
		Action:   "read",
		Resource: "doc",
		Category: "docs",
		AppID:    "app1",
		TenantID: "tenant2",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Query as tenant1 — should only see tenant1 events.
	q := &audit.Query{}
	result, err := c.Query(ctx, q)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("Total = %d, want 1 (tenant isolation)", result.Total)
	}
}

// TestConcurrentRecordProducesValidChain pins the hash-chain race.
//
// Record used to read the stream head, compute the hash, and append without
// holding anything, so two concurrent calls both linked to the same prev_hash.
// The store then serialised the sequence numbers, leaving two events at
// different positions claiming the same predecessor — a chain that verifies as
// tampered on a perfectly healthy log.
func TestConcurrentRecordProducesValidChain(t *testing.T) {
	c := newTestChronicle(t)
	ctx := scope.WithAppID(context.Background(), "app-1")

	const writers = 8
	const perWriter = 5

	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter)

	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range perWriter {
				err := c.Record(ctx, &audit.Event{
					Action:   fmt.Sprintf("w%d.action%d", w, i),
					Resource: "user",
					Category: "auth",
					UserID:   fmt.Sprintf("user-%d", w),
					Outcome:  audit.OutcomeSuccess,
					Severity: audit.SeverityInfo,
				})
				if err != nil {
					errs <- err
				}
			}
		}(w)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Record: %v", err)
	}

	// Every event must be present with a distinct sequence.
	result, err := c.Query(ctx, &audit.Query{Limit: writers * perWriter * 2})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(result.Events) != writers*perWriter {
		t.Fatalf("recorded %d events, want %d", len(result.Events), writers*perWriter)
	}

	seqs := make(map[uint64]bool, len(result.Events))
	var streamID = result.Events[0].StreamID
	for _, e := range result.Events {
		if seqs[e.Sequence] {
			t.Fatalf("sequence %d was allocated twice", e.Sequence)
		}
		seqs[e.Sequence] = true
	}

	// And the chain must verify clean.
	report, err := c.VerifyChain(ctx, &verify.Input{
		StreamID: streamID,
		FromSeq:  1,
		ToSeq:    uint64(writers * perWriter),
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("chain reported invalid after concurrent writes: tampered=%v gaps=%v",
			report.Tampered, report.Gaps)
	}
	if report.Verified != writers*perWriter {
		t.Fatalf("verified %d events, want %d", report.Verified, writers*perWriter)
	}
}

// TestConcurrentRecordAcrossScopesDoesNotSerialise checks that the per-stream
// lock is keyed by scope, so unrelated tenants do not contend.
func TestConcurrentRecordAcrossScopesDoesNotSerialise(t *testing.T) {
	c := newTestChronicle(t)

	var wg sync.WaitGroup
	errs := make(chan error, 16)

	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := scope.WithAppID(context.Background(), fmt.Sprintf("app-%d", i))
			for j := range 2 {
				err := c.Record(ctx, &audit.Event{
					Action:   fmt.Sprintf("action%d", j),
					Resource: "user",
					Category: "auth",
					Outcome:  audit.OutcomeSuccess,
					Severity: audit.SeverityInfo,
				})
				if err != nil {
					errs <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Record: %v", err)
	}

	// Each app has its own stream, each with sequences 1..2.
	for i := range 8 {
		ctx := scope.WithAppID(context.Background(), fmt.Sprintf("app-%d", i))
		result, err := c.Query(ctx, &audit.Query{Limit: 10})
		if err != nil {
			t.Fatalf("Query app-%d: %v", i, err)
		}
		if len(result.Events) != 2 {
			t.Fatalf("app-%d has %d events, want 2", i, len(result.Events))
		}
	}
}

// TestCryptoErasureOptionFailsLoudly pins that requesting crypto-erasure is an
// error rather than a silent no-op.
//
// The flag used to be accepted and ignored while README promised AES-256-GCM
// per-subject encryption, so an operator who set it believed subject data was
// destroyable by deleting a key when it was stored as plaintext. A compliance
// guarantee that silently does not hold is worse than one that refuses to start.
func TestCryptoErasureOptionFailsLoudly(t *testing.T) {
	_, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(memory.New())),
		chronicle.WithCryptoErasure(true),
	)
	if err == nil {
		t.Fatal("WithCryptoErasure(true) must fail while nothing in the pipeline encrypts")
	}
	if !errors.Is(err, chronicle.ErrCryptoErasureUnavailable) {
		t.Fatalf("error = %v, want ErrCryptoErasureUnavailable", err)
	}
}

func TestCryptoErasureDisabledIsAccepted(t *testing.T) {
	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(memory.New())),
		chronicle.WithCryptoErasure(false),
	)
	if err != nil {
		t.Fatalf("WithCryptoErasure(false): %v", err)
	}
	if c == nil {
		t.Fatal("expected a Chronicle instance")
	}
}

// ──────────────────────────────────────────────────
// Crypto-erasure
// ──────────────────────────────────────────────────

// newSealedChronicle builds a Chronicle with crypto-erasure on, plus the wrapped
// store so reads decrypt, mirroring how the extension wires it.
func newSealedChronicle(t *testing.T) (*chronicle.Chronicle, *memory.Store, crypto.KeyStore) {
	t.Helper()

	mem := memory.New()
	keys := crypto.NewInMemoryKeyStore()
	sealer := crypto.NewSealer(keys)
	sealed := sealedstore.New(mem, sealer)

	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(sealed)),
		chronicle.WithCryptoErasure(true),
		chronicle.WithSealer(sealer),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, mem, keys
}

func TestCryptoErasureRequiresASealer(t *testing.T) {
	_, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(memory.New())),
		chronicle.WithCryptoErasure(true),
	)
	if err == nil {
		t.Fatal("enabling crypto-erasure without a sealer must fail")
	}
	if !errors.Is(err, chronicle.ErrCryptoErasureUnavailable) {
		t.Fatalf("error = %v, want ErrCryptoErasureUnavailable", err)
	}
}

// TestRecordSealsSubjectPayload pins that what lands in the store is ciphertext.
func TestRecordSealsSubjectPayload(t *testing.T) {
	c, mem, _ := newSealedChronicle(t)
	ctx := scope.WithAppID(context.Background(), "app-1")

	err := c.Record(ctx, &audit.Event{
		Action:    "export",
		Resource:  "user",
		Category:  "data",
		SubjectID: "subject-1",
		Reason:    "subject access request",
		IP:        "203.0.113.9",
		Metadata:  map[string]any{"email": "alice@example.com"},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Read straight from the underlying store, bypassing decryption.
	stored, err := mem.Query(ctx, &audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(stored.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(stored.Events))
	}

	e := stored.Events[0]
	if strings.Contains(e.Reason, "subject access request") {
		t.Errorf("Reason stored as plaintext: %q", e.Reason)
	}
	if strings.Contains(e.IP, "203.0.113.9") {
		t.Errorf("IP stored as plaintext: %q", e.IP)
	}
	if v, ok := e.Metadata["email"]; ok {
		t.Errorf("Metadata stored as plaintext: %v", v)
	}
	if e.EncryptionKeyID == "" {
		t.Error("stored event should record its encryption key")
	}
}

// TestSealedEventsReadBackDecrypted pins that the wrapped store hides the
// encryption from ordinary consumers.
func TestSealedEventsReadBackDecrypted(t *testing.T) {
	c, _, _ := newSealedChronicle(t)
	ctx := scope.WithAppID(context.Background(), "app-1")

	if err := c.Record(ctx, &audit.Event{
		Action:    "export",
		Resource:  "user",
		Category:  "data",
		SubjectID: "subject-1",
		Reason:    "subject access request",
		Metadata:  map[string]any{"email": "alice@example.com"},
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	result, err := c.Query(ctx, &audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}

	e := result.Events[0]
	if e.Reason != "subject access request" {
		t.Errorf("Reason = %q, want the decrypted value", e.Reason)
	}
	if e.Metadata["email"] != "alice@example.com" {
		t.Errorf("Metadata email = %v, want the decrypted value", e.Metadata["email"])
	}
}

// TestErasureMakesPayloadIrrecoverableButKeepsChainValid is the guarantee the
// README makes, end to end through the real pipeline.
func TestErasureMakesPayloadIrrecoverableButKeepsChainValid(t *testing.T) {
	c, _, keys := newSealedChronicle(t)
	ctx := scope.WithAppID(context.Background(), "app-1")

	// Two events for the subject, plus one unrelated, so the chain has length.
	for i := range 2 {
		if err := c.Record(ctx, &audit.Event{
			Action:    fmt.Sprintf("export-%d", i),
			Resource:  "user",
			Category:  "data",
			SubjectID: "subject-1",
			Reason:    "subject access request",
			IP:        "203.0.113.9",
			Metadata:  map[string]any{"email": "alice@example.com"},
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := c.Record(ctx, &audit.Event{
		Action:   "login",
		Resource: "session",
		Category: "auth",
	}); err != nil {
		t.Fatalf("Record unrelated: %v", err)
	}

	before, err := c.Query(ctx, &audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	streamID := before.Events[0].StreamID

	// Erase the subject by destroying its key.
	if err := keys.Delete("subject-1"); err != nil {
		t.Fatalf("Delete key: %v", err)
	}

	after, err := c.Query(ctx, &audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query after erasure: %v", err)
	}
	if len(after.Events) != 3 {
		t.Fatalf("expected 3 events to remain, got %d", len(after.Events))
	}

	var erased int
	for _, e := range after.Events {
		if e.SubjectID != "subject-1" {
			continue
		}
		erased++

		if strings.Contains(e.Reason, "subject access request") {
			t.Errorf("Reason is still recoverable after key destruction: %q", e.Reason)
		}
		if e.Reason != crypto.ErasedMarker {
			t.Errorf("Reason = %q, want %q", e.Reason, crypto.ErasedMarker)
		}
		if e.Metadata != nil {
			t.Errorf("Metadata should be gone, got %v", e.Metadata)
		}
		if !e.Erased {
			t.Error("an erased event should report Erased")
		}
		// The operational record survives.
		if e.Action == "" || e.Category != "data" {
			t.Error("the operational record must outlive the erasure")
		}
	}
	if erased != 2 {
		t.Fatalf("expected 2 erased events, got %d", erased)
	}

	// And the chain must still verify: the digest covers the sealed bytes, which
	// key destruction does not touch.
	report, err := c.VerifyChain(ctx, &verify.Input{StreamID: streamID, FromSeq: 1, ToSeq: 3})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("chain reported invalid after erasure: tampered=%v gaps=%v",
			report.Tampered, report.Gaps)
	}
	if report.Verified != 3 {
		t.Fatalf("verified %d events, want 3", report.Verified)
	}
}

// TestVerifyEventUsesStoredForm pins that single-event verification reads the
// sealed bytes rather than the decrypted ones.
func TestVerifyEventUsesStoredForm(t *testing.T) {
	c, _, keys := newSealedChronicle(t)
	ctx := scope.WithAppID(context.Background(), "app-1")

	if err := c.Record(ctx, &audit.Event{
		Action:    "export",
		Resource:  "user",
		Category:  "data",
		SubjectID: "subject-1",
		Reason:    "subject access request",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	result, err := c.Query(ctx, &audit.Query{Limit: 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	eventID := result.Events[0].ID

	valid, err := c.VerifyEvent(ctx, eventID)
	if err != nil {
		t.Fatalf("VerifyEvent: %v", err)
	}
	if !valid {
		t.Fatal("a sealed event should verify against its stored digest")
	}

	// Still valid once the key is gone.
	if err := keys.Delete("subject-1"); err != nil {
		t.Fatalf("Delete key: %v", err)
	}

	valid, err = c.VerifyEvent(ctx, eventID)
	if err != nil {
		t.Fatalf("VerifyEvent after erasure: %v", err)
	}
	if !valid {
		t.Fatal("verification must survive key destruction")
	}
}

// TestEventsWithoutSubjectAreNotSealed keeps ordinary operational events readable
// and unencrypted, since they have no subject key that could ever be destroyed.
func TestEventsWithoutSubjectAreNotSealed(t *testing.T) {
	c, mem, _ := newSealedChronicle(t)
	ctx := scope.WithAppID(context.Background(), "app-1")

	if err := c.Record(ctx, &audit.Event{
		Action:   "login",
		Resource: "session",
		Category: "auth",
		Reason:   "password grant",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	stored, err := mem.Query(ctx, &audit.Query{Limit: 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if stored.Events[0].Reason != "password grant" {
		t.Errorf("Reason = %q, want plaintext for a subject-less event",
			stored.Events[0].Reason)
	}
	if stored.Events[0].EncryptionKeyID != "" {
		t.Error("a subject-less event should not claim an encryption key")
	}
}
