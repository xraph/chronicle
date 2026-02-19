package memory

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/stream"
)

func TestAppendAndGet(t *testing.T) {
	s := New()
	ctx := context.Background()

	event := &audit.Event{
		ID: id.NewAuditID(), Timestamp: time.Now().UTC(), AppID: "app1", TenantID: "tenant1",
		Action: "create", Resource: "user", Category: "auth", Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo,
	}
	if err := s.Append(ctx, event); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := s.Get(ctx, event.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID.String() != event.ID.String() {
		t.Errorf("got ID %s, want %s", got.ID, event.ID)
	}
}

func TestAppendBatch(t *testing.T) {
	s := New()
	ctx := context.Background()

	events := []*audit.Event{
		{ID: id.NewAuditID(), Timestamp: time.Now().UTC(), AppID: "app1", TenantID: "tenant1", Action: "create", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), Timestamp: time.Now().UTC(), AppID: "app1", TenantID: "tenant1", Action: "update", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), Timestamp: time.Now().UTC(), AppID: "app1", TenantID: "tenant1", Action: "delete", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
	}
	if err := s.AppendBatch(ctx, events); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	count, err := s.Count(ctx, &audit.CountQuery{AppID: "app1"})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 3 {
		t.Errorf("got count %d, want 3", count)
	}
}

func TestGetNotFound(t *testing.T) {
	s := New()
	ctx := context.Background()

	_, err := s.Get(ctx, id.NewAuditID())
	if err == nil {
		t.Fatal("expected error for missing event")
	}
}

func TestQuery(t *testing.T) {
	s := New()
	ctx := context.Background()

	now := time.Now().UTC()
	tests := []struct {
		name     string
		events   []*audit.Event
		query    *audit.Query
		wantLen  int
		wantMore bool
	}{
		{
			name: "filter by category",
			events: []*audit.Event{
				{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", Action: "create", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
				{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", Action: "create", Resource: "user", Category: "billing", Outcome: "success", Severity: "info"},
			},
			query:   &audit.Query{AppID: "app1", Categories: []string{"auth"}},
			wantLen: 1,
		},
		{
			name: "filter by tenant",
			events: []*audit.Event{
				{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", TenantID: "t1", Action: "create", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
				{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", TenantID: "t2", Action: "create", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
			},
			query:   &audit.Query{AppID: "app1", TenantID: "t1"},
			wantLen: 1,
		},
		{
			name: "pagination with has_more",
			events: []*audit.Event{
				{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", Action: "a1", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
				{ID: id.NewAuditID(), Timestamp: now.Add(time.Second), AppID: "app1", Action: "a2", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
				{ID: id.NewAuditID(), Timestamp: now.Add(2 * time.Second), AppID: "app1", Action: "a3", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
			},
			query:    &audit.Query{AppID: "app1", Limit: 2},
			wantLen:  2,
			wantMore: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := New()
			for _, e := range tt.events {
				if err := store.Append(ctx, e); err != nil {
					t.Fatalf("Append: %v", err)
				}
			}

			result, err := store.Query(ctx, tt.query)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(result.Events) != tt.wantLen {
				t.Errorf("got %d events, want %d", len(result.Events), tt.wantLen)
			}
			if result.HasMore != tt.wantMore {
				t.Errorf("got HasMore=%v, want %v", result.HasMore, tt.wantMore)
			}
		})
	}

	_ = s
}

func TestAggregate(t *testing.T) {
	s := New()
	ctx := context.Background()

	now := time.Now().UTC()
	events := []*audit.Event{
		{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", Action: "create", Resource: "user", Category: "auth", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", Action: "create", Resource: "user", Category: "auth", Outcome: "failure", Severity: "warning"},
		{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", Action: "delete", Resource: "user", Category: "billing", Outcome: "success", Severity: "info"},
	}
	for _, e := range events {
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	result, err := s.Aggregate(ctx, &audit.AggregateQuery{
		AppID:   "app1",
		GroupBy: []string{"category"},
	})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("got total %d, want 3", result.Total)
	}
	if len(result.Groups) != 2 {
		t.Errorf("got %d groups, want 2", len(result.Groups))
	}
}

func TestByUser(t *testing.T) {
	s := New()
	ctx := context.Background()

	now := time.Now().UTC()
	events := []*audit.Event{
		{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", UserID: "user1", Action: "create", Resource: "doc", Category: "docs", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", UserID: "user2", Action: "update", Resource: "doc", Category: "docs", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), Timestamp: now, AppID: "app1", UserID: "user1", Action: "delete", Resource: "doc", Category: "docs", Outcome: "success", Severity: "info"},
	}
	for _, e := range events {
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	result, err := s.ByUser(ctx, "user1", audit.TimeRange{})
	if err != nil {
		t.Fatalf("ByUser: %v", err)
	}
	if len(result.Events) != 2 {
		t.Errorf("got %d events, want 2", len(result.Events))
	}
}

func TestStreamCRUD(t *testing.T) {
	s := New()
	ctx := context.Background()

	st := &stream.Stream{
		Entity:   chronicle.NewEntity(),
		ID:       id.NewStreamID(),
		AppID:    "app1",
		TenantID: "tenant1",
	}

	if err := s.CreateStream(ctx, st); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	got, err := s.GetStream(ctx, st.ID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.AppID != "app1" {
		t.Errorf("got AppID %s, want app1", got.AppID)
	}

	gotByScope, err := s.GetStreamByScope(ctx, "app1", "tenant1")
	if err != nil {
		t.Fatalf("GetStreamByScope: %v", err)
	}
	if gotByScope.ID.String() != st.ID.String() {
		t.Errorf("got stream ID %s, want %s", gotByScope.ID, st.ID)
	}

	err = s.UpdateStreamHead(ctx, st.ID, "abc123", 5)
	if err != nil {
		t.Fatalf("UpdateStreamHead: %v", err)
	}

	updated, _ := s.GetStream(ctx, st.ID)
	if updated.HeadHash != "abc123" || updated.HeadSeq != 5 {
		t.Errorf("got hash=%s seq=%d, want abc123/5", updated.HeadHash, updated.HeadSeq)
	}

	list, err := s.ListStreams(ctx, stream.ListOpts{})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("got %d streams, want 1", len(list))
	}
}

func TestEventRangeAndGaps(t *testing.T) {
	s := New()
	ctx := context.Background()

	streamID := id.NewStreamID()
	events := []*audit.Event{
		{ID: id.NewAuditID(), StreamID: streamID, Sequence: 1, Timestamp: time.Now().UTC(), Action: "a", Resource: "r", Category: "c", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), StreamID: streamID, Sequence: 2, Timestamp: time.Now().UTC(), Action: "b", Resource: "r", Category: "c", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), StreamID: streamID, Sequence: 4, Timestamp: time.Now().UTC(), Action: "d", Resource: "r", Category: "c", Outcome: "success", Severity: "info"},
	}
	if err := s.AppendBatch(ctx, events); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	rangeResult, err := s.EventRange(ctx, streamID, 1, 4)
	if err != nil {
		t.Fatalf("EventRange: %v", err)
	}
	if len(rangeResult) != 3 {
		t.Errorf("got %d events, want 3", len(rangeResult))
	}

	gaps, err := s.Gaps(ctx, streamID, 1, 4)
	if err != nil {
		t.Fatalf("Gaps: %v", err)
	}
	if len(gaps) != 1 || gaps[0] != 3 {
		t.Errorf("got gaps %v, want [3]", gaps)
	}
}

func TestErasureCRUD(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Add events with subject
	events := []*audit.Event{
		{ID: id.NewAuditID(), Timestamp: time.Now().UTC(), SubjectID: "subj1", Action: "view", Resource: "profile", Category: "data", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), Timestamp: time.Now().UTC(), SubjectID: "subj1", Action: "edit", Resource: "profile", Category: "data", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), Timestamp: time.Now().UTC(), SubjectID: "subj2", Action: "view", Resource: "profile", Category: "data", Outcome: "success", Severity: "info"},
	}
	if err := s.AppendBatch(ctx, events); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	count, err := s.CountBySubject(ctx, "subj1")
	if err != nil {
		t.Fatalf("CountBySubject: %v", err)
	}
	if count != 2 {
		t.Errorf("got count %d, want 2", count)
	}

	erasureID := id.NewErasureID()
	marked, err := s.MarkErased(ctx, "subj1", erasureID)
	if err != nil {
		t.Fatalf("MarkErased: %v", err)
	}
	if marked != 2 {
		t.Errorf("got marked %d, want 2", marked)
	}

	er := &erasure.Erasure{
		Entity:         chronicle.NewEntity(),
		ID:             erasureID,
		SubjectID:      "subj1",
		Reason:         "GDPR request",
		RequestedBy:    "admin",
		EventsAffected: marked,
		KeyDestroyed:   true,
		AppID:          "app1",
	}
	err = s.RecordErasure(ctx, er)
	if err != nil {
		t.Fatalf("RecordErasure: %v", err)
	}

	got, err := s.GetErasure(ctx, erasureID)
	if err != nil {
		t.Fatalf("GetErasure: %v", err)
	}
	if got.SubjectID != "subj1" {
		t.Errorf("got SubjectID %s, want subj1", got.SubjectID)
	}

	list, err := s.ListErasures(ctx, erasure.ListOpts{})
	if err != nil {
		t.Fatalf("ListErasures: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("got %d erasures, want 1", len(list))
	}
}

func TestRetentionPolicyCRUD(t *testing.T) {
	s := New()
	ctx := context.Background()

	policy := &retention.Policy{
		Entity:   chronicle.NewEntity(),
		ID:       id.NewPolicyID(),
		Category: "auth",
		Duration: 90 * 24 * time.Hour,
		Archive:  true,
		AppID:    "app1",
	}

	if err := s.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	got, err := s.GetPolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.Category != "auth" {
		t.Errorf("got Category %s, want auth", got.Category)
	}

	list, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("got %d policies, want 1", len(list))
	}

	err = s.DeletePolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}

	list, err = s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies after delete: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("got %d policies after delete, want 0", len(list))
	}
}

func TestEventsOlderThanAndPurge(t *testing.T) {
	s := New()
	ctx := context.Background()

	old := time.Now().UTC().Add(-48 * time.Hour)
	recent := time.Now().UTC()

	events := []*audit.Event{
		{ID: id.NewAuditID(), Timestamp: old, Action: "old1", Resource: "r", Category: "auth", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), Timestamp: old, Action: "old2", Resource: "r", Category: "billing", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), Timestamp: recent, Action: "new1", Resource: "r", Category: "auth", Outcome: "success", Severity: "info"},
	}
	if err := s.AppendBatch(ctx, events); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	oldEvents, err := s.EventsOlderThan(ctx, "auth", cutoff)
	if err != nil {
		t.Fatalf("EventsOlderThan: %v", err)
	}
	if len(oldEvents) != 1 {
		t.Errorf("got %d old auth events, want 1", len(oldEvents))
	}

	ids := make([]id.ID, len(oldEvents))
	for i, e := range oldEvents {
		ids[i] = e.ID
	}
	purged, err := s.PurgeEvents(ctx, ids)
	if err != nil {
		t.Fatalf("PurgeEvents: %v", err)
	}
	if purged != 1 {
		t.Errorf("got purged %d, want 1", purged)
	}

	total, _ := s.Count(ctx, &audit.CountQuery{})
	if total != 2 {
		t.Errorf("got total %d after purge, want 2", total)
	}
}

func TestArchiveCRUD(t *testing.T) {
	s := New()
	ctx := context.Background()

	archive := &retention.Archive{
		Entity:        chronicle.NewEntity(),
		ID:            id.NewArchiveID(),
		PolicyID:      id.NewPolicyID(),
		Category:      "auth",
		EventCount:    100,
		FromTimestamp: time.Now().UTC().Add(-48 * time.Hour),
		ToTimestamp:   time.Now().UTC().Add(-24 * time.Hour),
		SinkName:      "s3",
		SinkRef:       "s3://bucket/audit/auth/2024/01/01/events.jsonl.gz",
	}

	if err := s.RecordArchive(ctx, archive); err != nil {
		t.Fatalf("RecordArchive: %v", err)
	}

	list, err := s.ListArchives(ctx, retention.ListOpts{})
	if err != nil {
		t.Fatalf("ListArchives: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("got %d archives, want 1", len(list))
	}
}

func TestReportCRUD(t *testing.T) {
	s := New()
	ctx := context.Background()

	report := &compliance.Report{
		Entity:      chronicle.NewEntity(),
		ID:          id.NewReportID(),
		Title:       "SOC2 Q1 2024",
		Type:        "soc2",
		AppID:       "app1",
		TenantID:    "tenant1",
		GeneratedBy: "admin",
		Format:      compliance.FormatJSON,
	}

	if err := s.SaveReport(ctx, report); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}

	got, err := s.GetReport(ctx, report.ID)
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	if got.Title != "SOC2 Q1 2024" {
		t.Errorf("got Title %s, want SOC2 Q1 2024", got.Title)
	}

	list, err := s.ListReports(ctx, compliance.ListOpts{})
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("got %d reports, want 1", len(list))
	}

	err = s.DeleteReport(ctx, report.ID)
	if err != nil {
		t.Fatalf("DeleteReport: %v", err)
	}

	list, err = s.ListReports(ctx, compliance.ListOpts{})
	if err != nil {
		t.Fatalf("ListReports after delete: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("got %d reports after delete, want 0", len(list))
	}
}

func TestLastSequenceAndHash(t *testing.T) {
	s := New()
	ctx := context.Background()

	streamID := id.NewStreamID()
	events := []*audit.Event{
		{ID: id.NewAuditID(), StreamID: streamID, Sequence: 1, Hash: "hash1", Timestamp: time.Now().UTC(), Action: "a", Resource: "r", Category: "c", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), StreamID: streamID, Sequence: 2, Hash: "hash2", Timestamp: time.Now().UTC(), Action: "b", Resource: "r", Category: "c", Outcome: "success", Severity: "info"},
		{ID: id.NewAuditID(), StreamID: streamID, Sequence: 3, Hash: "hash3", Timestamp: time.Now().UTC(), Action: "c", Resource: "r", Category: "c", Outcome: "success", Severity: "info"},
	}
	if err := s.AppendBatch(ctx, events); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	seq, err := s.LastSequence(ctx, streamID)
	if err != nil {
		t.Fatalf("LastSequence: %v", err)
	}
	if seq != 3 {
		t.Errorf("got sequence %d, want 3", seq)
	}

	hash, err := s.LastHash(ctx, streamID)
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if hash != "hash3" {
		t.Errorf("got hash %s, want hash3", hash)
	}
}

func TestMigrateAndPing(t *testing.T) {
	s := New()
	ctx := context.Background()

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
