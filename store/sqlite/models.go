package sqlite

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/xraph/grove"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/stream"
)

// ──────────────────────────────────────────────────
// EventModel
// ──────────────────────────────────────────────────

// EventModel is the grove ORM model for the chronicle_events table.
type EventModel struct {
	grove.BaseModel `grove:"table:chronicle_events,alias:e"`

	ID              string `grove:"id,pk"`
	StreamID        string `grove:"stream_id"`
	Sequence        uint64 `grove:"sequence"`
	Hash            string `grove:"hash"`
	PrevHash        string `grove:"prev_hash"`
	AppID           string `grove:"app_id"`
	TenantID        string `grove:"tenant_id"`
	UserID          string `grove:"user_id"`
	IP              string `grove:"ip"`
	Action          string `grove:"action"`
	Resource        string `grove:"resource"`
	Category        string `grove:"category"`
	ResourceID      string `grove:"resource_id"`
	Metadata        string `grove:"metadata"` // JSON TEXT in SQLite
	Outcome         string `grove:"outcome"`
	Severity        string `grove:"severity"`
	Reason          string `grove:"reason"`
	SubjectID       string `grove:"subject_id"`
	EncryptionKeyID string `grove:"encryption_key_id"`
	Erased          int    `grove:"erased"`    // INTEGER boolean in SQLite
	ErasedAt        string `grove:"erased_at"` // TEXT nullable timestamp
	ErasureID       string `grove:"erasure_id"`
	Timestamp       string `grove:"timestamp"`  // TEXT RFC3339Nano
	CreatedAt       string `grove:"created_at"` // TEXT RFC3339Nano
}

func toEvent(m *EventModel) (*audit.Event, error) {
	eventID, err := id.ParseAuditID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse audit id %q: %w", m.ID, err)
	}

	streamID, err := id.ParseStreamID(m.StreamID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream id %q: %w", m.StreamID, err)
	}

	var metadata map[string]any
	if m.Metadata != "" {
		if unmarshalErr := json.Unmarshal([]byte(m.Metadata), &metadata); unmarshalErr != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", unmarshalErr)
		}
	}

	ts, err := time.Parse(time.RFC3339Nano, m.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	event := &audit.Event{
		ID:              eventID,
		StreamID:        streamID,
		Sequence:        m.Sequence,
		Hash:            m.Hash,
		PrevHash:        m.PrevHash,
		AppID:           m.AppID,
		TenantID:        m.TenantID,
		UserID:          m.UserID,
		IP:              m.IP,
		Action:          m.Action,
		Resource:        m.Resource,
		Category:        m.Category,
		ResourceID:      m.ResourceID,
		Metadata:        metadata,
		Outcome:         m.Outcome,
		Severity:        m.Severity,
		Reason:          m.Reason,
		SubjectID:       m.SubjectID,
		EncryptionKeyID: m.EncryptionKeyID,
		Erased:          m.Erased != 0,
		ErasureID:       m.ErasureID,
		Timestamp:       ts,
	}

	if m.ErasedAt != "" {
		t, err := time.Parse(time.RFC3339Nano, m.ErasedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse erased_at: %w", err)
		}
		event.ErasedAt = &t
	}

	return event, nil
}

func fromEvent(e *audit.Event) *EventModel {
	metadata := "{}"
	if e.Metadata != nil {
		if b, err := json.Marshal(e.Metadata); err == nil {
			metadata = string(b)
		}
	}

	erasedAt := ""
	if e.ErasedAt != nil {
		erasedAt = e.ErasedAt.UTC().Format(time.RFC3339Nano)
	}

	erased := 0
	if e.Erased {
		erased = 1
	}

	return &EventModel{
		ID:              e.ID.String(),
		StreamID:        e.StreamID.String(),
		Sequence:        e.Sequence,
		Hash:            e.Hash,
		PrevHash:        e.PrevHash,
		AppID:           e.AppID,
		TenantID:        e.TenantID,
		UserID:          e.UserID,
		IP:              e.IP,
		Action:          e.Action,
		Resource:        e.Resource,
		Category:        e.Category,
		ResourceID:      e.ResourceID,
		Metadata:        metadata,
		Outcome:         e.Outcome,
		Severity:        e.Severity,
		Reason:          e.Reason,
		SubjectID:       e.SubjectID,
		EncryptionKeyID: e.EncryptionKeyID,
		Erased:          erased,
		ErasedAt:        erasedAt,
		ErasureID:       e.ErasureID,
		Timestamp:       e.Timestamp.UTC().Format(time.RFC3339Nano),
		CreatedAt:       now().Format(time.RFC3339Nano),
	}
}

// toEventSlice converts a slice of EventModel to a slice of audit.Event.
func toEventSlice(models []EventModel) ([]*audit.Event, error) {
	events := make([]*audit.Event, 0, len(models))
	for i := range models {
		event, err := toEvent(&models[i])
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

// ──────────────────────────────────────────────────
// StreamModel
// ──────────────────────────────────────────────────

// StreamModel is the grove ORM model for the chronicle_streams table.
type StreamModel struct {
	grove.BaseModel `grove:"table:chronicle_streams,alias:s"`

	ID        string `grove:"id,pk"`
	AppID     string `grove:"app_id"`
	TenantID  string `grove:"tenant_id"`
	HeadHash  string `grove:"head_hash"`
	HeadSeq   uint64 `grove:"head_seq"`
	CreatedAt string `grove:"created_at"` // TEXT RFC3339Nano
	UpdatedAt string `grove:"updated_at"` // TEXT RFC3339Nano
}

func toStream(m *StreamModel) (*stream.Stream, error) {
	streamID, err := id.ParseStreamID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream id %q: %w", m.ID, err)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	updatedAt, err := time.Parse(time.RFC3339Nano, m.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at: %w", err)
	}

	return &stream.Stream{
		Entity: chronicle.Entity{
			CreatedAt: createdAt,
			UpdatedAt: updatedAt,
		},
		ID:       streamID,
		AppID:    m.AppID,
		TenantID: m.TenantID,
		HeadHash: m.HeadHash,
		HeadSeq:  m.HeadSeq,
	}, nil
}

func fromStream(st *stream.Stream) *StreamModel {
	return &StreamModel{
		ID:        st.ID.String(),
		AppID:     st.AppID,
		TenantID:  st.TenantID,
		HeadHash:  st.HeadHash,
		HeadSeq:   st.HeadSeq,
		CreatedAt: st.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: st.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// ──────────────────────────────────────────────────
// ErasureModel
// ──────────────────────────────────────────────────

// ErasureModel is the grove ORM model for the chronicle_erasures table.
type ErasureModel struct {
	grove.BaseModel `grove:"table:chronicle_erasures,alias:er"`

	ID             string `grove:"id,pk"`
	SubjectID      string `grove:"subject_id"`
	Reason         string `grove:"reason"`
	RequestedBy    string `grove:"requested_by"`
	EventsAffected int64  `grove:"events_affected"`
	KeyDestroyed   int    `grove:"key_destroyed"` // INTEGER boolean
	AppID          string `grove:"app_id"`
	TenantID       string `grove:"tenant_id"`
	CreatedAt      string `grove:"created_at"` // TEXT RFC3339Nano
}

func toErasure(m *ErasureModel) (*erasure.Erasure, error) {
	erasureID, err := id.ParseErasureID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse erasure id %q: %w", m.ID, err)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	return &erasure.Erasure{
		Entity: chronicle.Entity{
			CreatedAt: createdAt,
		},
		ID:             erasureID,
		SubjectID:      m.SubjectID,
		Reason:         m.Reason,
		RequestedBy:    m.RequestedBy,
		EventsAffected: m.EventsAffected,
		KeyDestroyed:   m.KeyDestroyed != 0,
		AppID:          m.AppID,
		TenantID:       m.TenantID,
	}, nil
}

func fromErasure(e *erasure.Erasure) *ErasureModel {
	kd := 0
	if e.KeyDestroyed {
		kd = 1
	}
	return &ErasureModel{
		ID:             e.ID.String(),
		SubjectID:      e.SubjectID,
		Reason:         e.Reason,
		RequestedBy:    e.RequestedBy,
		EventsAffected: e.EventsAffected,
		KeyDestroyed:   kd,
		AppID:          e.AppID,
		TenantID:       e.TenantID,
		CreatedAt:      e.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// ──────────────────────────────────────────────────
// RetentionPolicyModel
// ──────────────────────────────────────────────────

// RetentionPolicyModel is the grove ORM model for the chronicle_retention_policies table.
type RetentionPolicyModel struct {
	grove.BaseModel `grove:"table:chronicle_retention_policies,alias:rp"`

	ID        string `grove:"id,pk"`
	Category  string `grove:"category"`
	Duration  int64  `grove:"duration"` // nanoseconds
	Archive   int    `grove:"archive"`  // INTEGER boolean
	AppID     string `grove:"app_id"`
	CreatedAt string `grove:"created_at"` // TEXT RFC3339Nano
	UpdatedAt string `grove:"updated_at"` // TEXT RFC3339Nano
}

func toPolicy(m *RetentionPolicyModel) (*retention.Policy, error) {
	policyID, err := id.ParsePolicyID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy id %q: %w", m.ID, err)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	updatedAt, err := time.Parse(time.RFC3339Nano, m.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at: %w", err)
	}

	return &retention.Policy{
		Entity: chronicle.Entity{
			CreatedAt: createdAt,
			UpdatedAt: updatedAt,
		},
		ID:       policyID,
		Category: m.Category,
		Duration: time.Duration(m.Duration),
		Archive:  m.Archive != 0,
		AppID:    m.AppID,
	}, nil
}

func fromPolicy(p *retention.Policy) *RetentionPolicyModel {
	archive := 0
	if p.Archive {
		archive = 1
	}
	return &RetentionPolicyModel{
		ID:        p.ID.String(),
		Category:  p.Category,
		Duration:  int64(p.Duration),
		Archive:   archive,
		AppID:     p.AppID,
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: p.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// ──────────────────────────────────────────────────
// ArchiveModel
// ──────────────────────────────────────────────────

// ArchiveModel is the grove ORM model for the chronicle_archives table.
type ArchiveModel struct {
	grove.BaseModel `grove:"table:chronicle_archives,alias:a"`

	ID            string `grove:"id,pk"`
	PolicyID      string `grove:"policy_id"`
	Category      string `grove:"category"`
	EventCount    int64  `grove:"event_count"`
	FromTimestamp string `grove:"from_timestamp"` // TEXT RFC3339Nano
	ToTimestamp   string `grove:"to_timestamp"`   // TEXT RFC3339Nano
	SinkName      string `grove:"sink_name"`
	SinkRef       string `grove:"sink_ref"`
	CreatedAt     string `grove:"created_at"` // TEXT RFC3339Nano
}

func toArchive(m *ArchiveModel) (*retention.Archive, error) {
	archiveID, err := id.ParseArchiveID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse archive id %q: %w", m.ID, err)
	}

	policyID, err := id.ParsePolicyID(m.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy id %q: %w", m.PolicyID, err)
	}

	fromTs, err := time.Parse(time.RFC3339Nano, m.FromTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse from_timestamp: %w", err)
	}

	toTs, err := time.Parse(time.RFC3339Nano, m.ToTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse to_timestamp: %w", err)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	return &retention.Archive{
		Entity: chronicle.Entity{
			CreatedAt: createdAt,
		},
		ID:            archiveID,
		PolicyID:      policyID,
		Category:      m.Category,
		EventCount:    m.EventCount,
		FromTimestamp: fromTs,
		ToTimestamp:   toTs,
		SinkName:      m.SinkName,
		SinkRef:       m.SinkRef,
	}, nil
}

func fromArchive(a *retention.Archive) *ArchiveModel {
	return &ArchiveModel{
		ID:            a.ID.String(),
		PolicyID:      a.PolicyID.String(),
		Category:      a.Category,
		EventCount:    a.EventCount,
		FromTimestamp: a.FromTimestamp.UTC().Format(time.RFC3339Nano),
		ToTimestamp:   a.ToTimestamp.UTC().Format(time.RFC3339Nano),
		SinkName:      a.SinkName,
		SinkRef:       a.SinkRef,
		CreatedAt:     a.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// ──────────────────────────────────────────────────
// ReportModel
// ──────────────────────────────────────────────────

// ReportModel is the grove ORM model for the chronicle_reports table.
type ReportModel struct {
	grove.BaseModel `grove:"table:chronicle_reports,alias:r"`

	ID          string `grove:"id,pk"`
	Title       string `grove:"title"`
	Type        string `grove:"type"`
	PeriodFrom  string `grove:"period_from"` // TEXT RFC3339Nano
	PeriodTo    string `grove:"period_to"`   // TEXT RFC3339Nano
	AppID       string `grove:"app_id"`
	TenantID    string `grove:"tenant_id"`
	Format      string `grove:"format"`
	Data        string `grove:"data"` // JSON TEXT for sections
	GeneratedBy string `grove:"generated_by"`
	CreatedAt   string `grove:"created_at"` // TEXT RFC3339Nano
}

func toReport(m *ReportModel) (*compliance.Report, error) {
	reportID, err := id.ParseReportID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report id %q: %w", m.ID, err)
	}

	var sections []compliance.Section
	if unmarshalErr := json.Unmarshal([]byte(m.Data), &sections); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to unmarshal report sections: %w", unmarshalErr)
	}

	periodFrom, err := time.Parse(time.RFC3339Nano, m.PeriodFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to parse period_from: %w", err)
	}

	periodTo, err := time.Parse(time.RFC3339Nano, m.PeriodTo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse period_to: %w", err)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	return &compliance.Report{
		Entity: chronicle.Entity{
			CreatedAt: createdAt,
		},
		ID:    reportID,
		Title: m.Title,
		Type:  m.Type,
		Period: compliance.DateRange{
			From: periodFrom,
			To:   periodTo,
		},
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		Format:      compliance.Format(m.Format),
		Sections:    sections,
		GeneratedBy: m.GeneratedBy,
	}, nil
}

func fromReport(r *compliance.Report) (*ReportModel, error) {
	data, err := json.Marshal(r.Sections)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report sections: %w", err)
	}

	return &ReportModel{
		ID:          r.ID.String(),
		Title:       r.Title,
		Type:        r.Type,
		PeriodFrom:  r.Period.From.UTC().Format(time.RFC3339Nano),
		PeriodTo:    r.Period.To.UTC().Format(time.RFC3339Nano),
		AppID:       r.AppID,
		TenantID:    r.TenantID,
		Format:      string(r.Format),
		Data:        string(data),
		GeneratedBy: r.GeneratedBy,
		CreatedAt:   r.CreatedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}
