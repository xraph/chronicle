// Package bunstore implements the Chronicle store interface using Bun ORM.
package bunstore

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/uptrace/bun"

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

// EventModel is the Bun ORM model for the chronicle_events table.
type EventModel struct {
	bun.BaseModel `bun:"table:chronicle_events,alias:e"`

	ID              string         `bun:"id,pk"`
	StreamID        string         `bun:"stream_id"`
	Sequence        uint64         `bun:"sequence"`
	Hash            string         `bun:"hash"`
	PrevHash        string         `bun:"prev_hash"`
	AppID           string         `bun:"app_id"`
	TenantID        string         `bun:"tenant_id"`
	UserID          string         `bun:"user_id"`
	IP              string         `bun:"ip"`
	Action          string         `bun:"action"`
	Resource        string         `bun:"resource"`
	Category        string         `bun:"category"`
	ResourceID      string         `bun:"resource_id"`
	Metadata        map[string]any `bun:"metadata,type:jsonb"`
	Outcome         string         `bun:"outcome"`
	Severity        string         `bun:"severity"`
	Reason          string         `bun:"reason"`
	SubjectID       string         `bun:"subject_id"`
	EncryptionKeyID string         `bun:"encryption_key_id"`
	Erased          bool           `bun:"erased"`
	ErasedAt        *time.Time     `bun:"erased_at"`
	ErasureID       string         `bun:"erasure_id"`
	Timestamp       time.Time      `bun:"timestamp"`
	CreatedAt       time.Time      `bun:"created_at"`
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

	return &audit.Event{
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
		Metadata:        m.Metadata,
		Outcome:         m.Outcome,
		Severity:        m.Severity,
		Reason:          m.Reason,
		SubjectID:       m.SubjectID,
		EncryptionKeyID: m.EncryptionKeyID,
		Erased:          m.Erased,
		ErasedAt:        m.ErasedAt,
		ErasureID:       m.ErasureID,
		Timestamp:       m.Timestamp,
	}, nil
}

func fromEvent(e *audit.Event) *EventModel {
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
		Metadata:        e.Metadata,
		Outcome:         e.Outcome,
		Severity:        e.Severity,
		Reason:          e.Reason,
		SubjectID:       e.SubjectID,
		EncryptionKeyID: e.EncryptionKeyID,
		Erased:          e.Erased,
		ErasedAt:        e.ErasedAt,
		ErasureID:       e.ErasureID,
		Timestamp:       e.Timestamp,
		CreatedAt:       time.Now().UTC(),
	}
}

// ──────────────────────────────────────────────────
// StreamModel
// ──────────────────────────────────────────────────

// StreamModel is the Bun ORM model for the chronicle_streams table.
type StreamModel struct {
	bun.BaseModel `bun:"table:chronicle_streams,alias:s"`

	ID        string    `bun:"id,pk"`
	AppID     string    `bun:"app_id"`
	TenantID  string    `bun:"tenant_id"`
	HeadHash  string    `bun:"head_hash"`
	HeadSeq   uint64    `bun:"head_seq"`
	CreatedAt time.Time `bun:"created_at"`
	UpdatedAt time.Time `bun:"updated_at"`
}

func toStream(m *StreamModel) (*stream.Stream, error) {
	streamID, err := id.ParseStreamID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream id %q: %w", m.ID, err)
	}

	return &stream.Stream{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
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
		CreatedAt: st.CreatedAt,
		UpdatedAt: st.UpdatedAt,
	}
}

// ──────────────────────────────────────────────────
// ErasureModel
// ──────────────────────────────────────────────────

// ErasureModel is the Bun ORM model for the chronicle_erasures table.
type ErasureModel struct {
	bun.BaseModel `bun:"table:chronicle_erasures,alias:er"`

	ID             string    `bun:"id,pk"`
	SubjectID      string    `bun:"subject_id"`
	Reason         string    `bun:"reason"`
	RequestedBy    string    `bun:"requested_by"`
	EventsAffected int64     `bun:"events_affected"`
	KeyDestroyed   bool      `bun:"key_destroyed"`
	AppID          string    `bun:"app_id"`
	TenantID       string    `bun:"tenant_id"`
	CreatedAt      time.Time `bun:"created_at"`
}

func toErasure(m *ErasureModel) (*erasure.Erasure, error) {
	erasureID, err := id.ParseErasureID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse erasure id %q: %w", m.ID, err)
	}

	return &erasure.Erasure{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
		},
		ID:             erasureID,
		SubjectID:      m.SubjectID,
		Reason:         m.Reason,
		RequestedBy:    m.RequestedBy,
		EventsAffected: m.EventsAffected,
		KeyDestroyed:   m.KeyDestroyed,
		AppID:          m.AppID,
		TenantID:       m.TenantID,
	}, nil
}

func fromErasure(e *erasure.Erasure) *ErasureModel {
	return &ErasureModel{
		ID:             e.ID.String(),
		SubjectID:      e.SubjectID,
		Reason:         e.Reason,
		RequestedBy:    e.RequestedBy,
		EventsAffected: e.EventsAffected,
		KeyDestroyed:   e.KeyDestroyed,
		AppID:          e.AppID,
		TenantID:       e.TenantID,
		CreatedAt:      e.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// RetentionPolicyModel
// ──────────────────────────────────────────────────

// RetentionPolicyModel is the Bun ORM model for the chronicle_retention_policies table.
type RetentionPolicyModel struct {
	bun.BaseModel `bun:"table:chronicle_retention_policies,alias:rp"`

	ID        string    `bun:"id,pk"`
	Category  string    `bun:"category"`
	Duration  int64     `bun:"duration"` // nanoseconds
	Archive   bool      `bun:"archive"`
	AppID     string    `bun:"app_id"`
	CreatedAt time.Time `bun:"created_at"`
	UpdatedAt time.Time `bun:"updated_at"`
}

func toPolicy(m *RetentionPolicyModel) (*retention.Policy, error) {
	policyID, err := id.ParsePolicyID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy id %q: %w", m.ID, err)
	}

	return &retention.Policy{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		},
		ID:       policyID,
		Category: m.Category,
		Duration: time.Duration(m.Duration),
		Archive:  m.Archive,
		AppID:    m.AppID,
	}, nil
}

func fromPolicy(p *retention.Policy) *RetentionPolicyModel {
	return &RetentionPolicyModel{
		ID:        p.ID.String(),
		Category:  p.Category,
		Duration:  int64(p.Duration),
		Archive:   p.Archive,
		AppID:     p.AppID,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

// ──────────────────────────────────────────────────
// ArchiveModel
// ──────────────────────────────────────────────────

// ArchiveModel is the Bun ORM model for the chronicle_archives table.
type ArchiveModel struct {
	bun.BaseModel `bun:"table:chronicle_archives,alias:a"`

	ID            string    `bun:"id,pk"`
	PolicyID      string    `bun:"policy_id"`
	Category      string    `bun:"category"`
	EventCount    int64     `bun:"event_count"`
	FromTimestamp time.Time `bun:"from_timestamp"`
	ToTimestamp   time.Time `bun:"to_timestamp"`
	SinkName      string    `bun:"sink_name"`
	SinkRef       string    `bun:"sink_ref"`
	CreatedAt     time.Time `bun:"created_at"`
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

	return &retention.Archive{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
		},
		ID:            archiveID,
		PolicyID:      policyID,
		Category:      m.Category,
		EventCount:    m.EventCount,
		FromTimestamp: m.FromTimestamp,
		ToTimestamp:   m.ToTimestamp,
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
		FromTimestamp: a.FromTimestamp,
		ToTimestamp:   a.ToTimestamp,
		SinkName:      a.SinkName,
		SinkRef:       a.SinkRef,
		CreatedAt:     a.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// ReportModel
// ──────────────────────────────────────────────────

// ReportModel is the Bun ORM model for the chronicle_reports table.
type ReportModel struct {
	bun.BaseModel `bun:"table:chronicle_reports,alias:r"`

	ID          string    `bun:"id,pk"`
	Title       string    `bun:"title"`
	Type        string    `bun:"type"`
	PeriodFrom  time.Time `bun:"period_from"`
	PeriodTo    time.Time `bun:"period_to"`
	AppID       string    `bun:"app_id"`
	TenantID    string    `bun:"tenant_id"`
	Format      string    `bun:"format"`
	Data        []byte    `bun:"data,type:jsonb"` // Sections serialized as JSON
	GeneratedBy string    `bun:"generated_by"`
	CreatedAt   time.Time `bun:"created_at"`
}

func toReport(m *ReportModel) (*compliance.Report, error) {
	reportID, err := id.ParseReportID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report id %q: %w", m.ID, err)
	}

	var sections []compliance.Section
	if err := json.Unmarshal(m.Data, &sections); err != nil {
		return nil, fmt.Errorf("failed to unmarshal report sections: %w", err)
	}

	return &compliance.Report{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
		},
		ID:    reportID,
		Title: m.Title,
		Type:  m.Type,
		Period: compliance.DateRange{
			From: m.PeriodFrom,
			To:   m.PeriodTo,
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
		PeriodFrom:  r.Period.From,
		PeriodTo:    r.Period.To,
		AppID:       r.AppID,
		TenantID:    r.TenantID,
		Format:      string(r.Format),
		Data:        data,
		GeneratedBy: r.GeneratedBy,
		CreatedAt:   r.CreatedAt,
	}, nil
}
