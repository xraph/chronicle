// Package postgres implements the Chronicle store interface using grove ORM.
package postgres

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/xraph/grove"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/stream"
)

// safeInt64 converts a uint64 to int64, clamping at math.MaxInt64.
func safeInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// safeUint64 converts an int64 to uint64, clamping negative values to 0.
func safeUint64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// ──────────────────────────────────────────────────
// EventModel
// ──────────────────────────────────────────────────

// EventModel is the grove ORM model for the chronicle_events table.
//
// Timestamp is split across two columns. See splitTimestamp for why.
type EventModel struct {
	grove.BaseModel `grove:"table:chronicle_events,alias:e"`

	ID              string         `grove:"id,pk"`
	StreamID        string         `grove:"stream_id"`
	Sequence        int64          `grove:"sequence"`
	Hash            string         `grove:"hash"`
	PrevHash        string         `grove:"prev_hash"`
	AppID           string         `grove:"app_id"`
	TenantID        string         `grove:"tenant_id"`
	UserID          string         `grove:"user_id"`
	IP              string         `grove:"ip"`
	UserAgent       string         `grove:"user_agent"`
	RequestID       string         `grove:"request_id"`
	SessionID       string         `grove:"session_id"`
	Action          string         `grove:"action"`
	Resource        string         `grove:"resource"`
	Category        string         `grove:"category"`
	ResourceID      string         `grove:"resource_id"`
	Metadata        map[string]any `grove:"metadata,type:jsonb"`
	Outcome         string         `grove:"outcome"`
	Severity        string         `grove:"severity"`
	Reason          string         `grove:"reason"`
	SubjectID       string         `grove:"subject_id"`
	EncryptionKeyID string         `grove:"encryption_key_id"`
	Erased          bool           `grove:"erased"`
	ErasedAt        *time.Time     `grove:"erased_at"`
	ErasureID       string         `grove:"erasure_id"`
	Timestamp       time.Time      `grove:"timestamp"`
	TimestampSubUs  int32          `grove:"timestamp_sub_us"`
	CreatedAt       time.Time      `grove:"created_at"`
	HashScheme      string         `grove:"hash_scheme"`
	HashKeyID       string         `grove:"hash_key_id"`
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
		Sequence:        safeUint64(m.Sequence),
		Hash:            m.Hash,
		PrevHash:        m.PrevHash,
		AppID:           m.AppID,
		TenantID:        m.TenantID,
		UserID:          m.UserID,
		IP:              m.IP,
		UserAgent:       m.UserAgent,
		RequestID:       m.RequestID,
		SessionID:       m.SessionID,
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
		Timestamp:       joinTimestamp(m.Timestamp, m.TimestampSubUs),
		HashScheme:      m.HashScheme,
		HashKeyID:       m.HashKeyID,
	}, nil
}

func fromEvent(e *audit.Event) *EventModel {
	ts, subUs := splitTimestamp(e.Timestamp)
	return &EventModel{
		ID:              e.ID.String(),
		StreamID:        e.StreamID.String(),
		Sequence:        safeInt64(e.Sequence),
		Hash:            e.Hash,
		PrevHash:        e.PrevHash,
		AppID:           e.AppID,
		TenantID:        e.TenantID,
		UserID:          e.UserID,
		IP:              e.IP,
		UserAgent:       e.UserAgent,
		RequestID:       e.RequestID,
		SessionID:       e.SessionID,
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
		Timestamp:       ts,
		TimestampSubUs:  subUs,
		CreatedAt:       time.Now().UTC(),
		HashScheme:      e.HashScheme,
		HashKeyID:       e.HashKeyID,
	}
}

// splitTimestamp divides an event timestamp into the part a TIMESTAMPTZ
// column can hold and the nanoseconds below it.
//
// The hash chain covers the timestamp to the nanosecond (hash.Chain formats it
// with time.RFC3339Nano), and TIMESTAMPTZ keeps microseconds. Storing the
// timestamp in that column alone handed every reader a different instant from
// the one Append hashed, so any event with a sub-microsecond component read
// back as tampered. On Linux, where time.Now() has nanosecond resolution, that
// is nearly all of them. A Mac's clock usually ticks in whole microseconds,
// which is why the tests there never saw it.
//
// We keep the full value rather than truncating before hashing. An audit log
// records when something happened as the caller reported it. Rounding that to
// suit one backend's storage would change the evidence, and would mean events
// hashed on a different backend could never verify here. The column stays the
// microsecond floor, so the timestamp indexes, range filters and sort order
// behave exactly as they did.
//
// The column value is truncated here rather than handed to the driver whole.
// What the server does with extra digits depends on how they arrive: pgx's
// binary encoding drops them, but PostgreSQL's text input rounds to the nearest
// microsecond, and a rounded-up floor plus the remainder would add up to the
// wrong instant.
func splitTimestamp(t time.Time) (floor time.Time, subUs int32) {
	floor = t.Truncate(time.Microsecond)
	return floor, int32(t.Sub(floor)) //nolint:gosec // always in [0, 1000)
}

// joinTimestamp reverses splitTimestamp.
//
// A row written before timestamp_sub_us existed has it defaulted to zero and
// reads back as the microsecond value it holds, as it always did. Those rows
// lost their sub-microsecond digits on insert and the row no longer holds
// them, so a row whose original timestamp had any still fails verification.
// That is not reported wrongly: the stored digest covers an instant the row no
// longer holds.
//
// The remainder is not range-checked. A tampered value moves the timestamp,
// and verification reports that event as tampered, which is the right answer.
func joinTimestamp(floor time.Time, subUs int32) time.Time {
	return floor.Add(time.Duration(subUs))
}

// ──────────────────────────────────────────────────
// StreamModel
// ──────────────────────────────────────────────────

// StreamModel is the grove ORM model for the chronicle_streams table.
type StreamModel struct {
	grove.BaseModel `grove:"table:chronicle_streams,alias:s"`

	ID          string    `grove:"id,pk"`
	AppID       string    `grove:"app_id"`
	TenantID    string    `grove:"tenant_id"`
	HeadHash    string    `grove:"head_hash"`
	HeadSeq     int64     `grove:"head_seq"`
	CreatedAt   time.Time `grove:"created_at"`
	UpdatedAt   time.Time `grove:"updated_at"`
	Scheme      string    `grove:"scheme"`
	SchemeSince int64     `grove:"scheme_since"`
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
		ID:          streamID,
		AppID:       m.AppID,
		TenantID:    m.TenantID,
		HeadHash:    m.HeadHash,
		HeadSeq:     safeUint64(m.HeadSeq),
		Scheme:      m.Scheme,
		SchemeSince: safeUint64(m.SchemeSince),
	}, nil
}

func fromStream(st *stream.Stream) *StreamModel {
	return &StreamModel{
		ID:          st.ID.String(),
		AppID:       st.AppID,
		TenantID:    st.TenantID,
		HeadHash:    st.HeadHash,
		HeadSeq:     safeInt64(st.HeadSeq),
		CreatedAt:   st.CreatedAt,
		UpdatedAt:   st.UpdatedAt,
		Scheme:      st.Scheme,
		SchemeSince: safeInt64(st.SchemeSince),
	}
}

// ──────────────────────────────────────────────────
// ErasureModel
// ──────────────────────────────────────────────────

// ErasureModel is the grove ORM model for the chronicle_erasures table.
type ErasureModel struct {
	grove.BaseModel `grove:"table:chronicle_erasures,alias:er"`

	ID             string    `grove:"id,pk"`
	SubjectID      string    `grove:"subject_id"`
	Reason         string    `grove:"reason"`
	RequestedBy    string    `grove:"requested_by"`
	EventsAffected int64     `grove:"events_affected"`
	KeyDestroyed   bool      `grove:"key_destroyed"`
	AppID          string    `grove:"app_id"`
	TenantID       string    `grove:"tenant_id"`
	CreatedAt      time.Time `grove:"created_at"`
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

// RetentionPolicyModel is the grove ORM model for the chronicle_retention_policies table.
type RetentionPolicyModel struct {
	grove.BaseModel `grove:"table:chronicle_retention_policies,alias:rp"`

	ID        string    `grove:"id,pk"`
	Category  string    `grove:"category"`
	Duration  int64     `grove:"duration"` // nanoseconds
	Archive   bool      `grove:"archive"`
	AppID     string    `grove:"app_id"`
	TenantID  string    `grove:"tenant_id"`
	CreatedAt time.Time `grove:"created_at"`
	UpdatedAt time.Time `grove:"updated_at"`
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
		TenantID: m.TenantID,
	}, nil
}

func fromPolicy(p *retention.Policy) *RetentionPolicyModel {
	return &RetentionPolicyModel{
		ID:        p.ID.String(),
		Category:  p.Category,
		Duration:  int64(p.Duration),
		Archive:   p.Archive,
		AppID:     p.AppID,
		TenantID:  p.TenantID,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

// ──────────────────────────────────────────────────
// ArchiveModel
// ──────────────────────────────────────────────────

// ArchiveModel is the grove ORM model for the chronicle_archives table.
type ArchiveModel struct {
	grove.BaseModel `grove:"table:chronicle_archives,alias:a"`

	ID            string    `grove:"id,pk"`
	PolicyID      string    `grove:"policy_id"`
	Category      string    `grove:"category"`
	EventCount    int64     `grove:"event_count"`
	FromTimestamp time.Time `grove:"from_timestamp"`
	ToTimestamp   time.Time `grove:"to_timestamp"`
	SinkName      string    `grove:"sink_name"`
	SinkRef       string    `grove:"sink_ref"`
	AppID         string    `grove:"app_id"`
	TenantID      string    `grove:"tenant_id"`
	CreatedAt     time.Time `grove:"created_at"`
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
		AppID:         m.AppID,
		TenantID:      m.TenantID,
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
		AppID:         a.AppID,
		TenantID:      a.TenantID,
		CreatedAt:     a.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// ReportModel
// ──────────────────────────────────────────────────

// ReportModel is the grove ORM model for the chronicle_reports table.
type ReportModel struct {
	grove.BaseModel `grove:"table:chronicle_reports,alias:r"`

	ID          string    `grove:"id,pk"`
	Title       string    `grove:"title"`
	Type        string    `grove:"type"`
	PeriodFrom  time.Time `grove:"period_from"`
	PeriodTo    time.Time `grove:"period_to"`
	AppID       string    `grove:"app_id"`
	TenantID    string    `grove:"tenant_id"`
	Format      string    `grove:"format"`
	Data        []byte    `grove:"data,type:jsonb"` // Sections serialized as JSON
	GeneratedBy string    `grove:"generated_by"`
	CreatedAt   time.Time `grove:"created_at"`
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

// ──────────────────────────────────────────────────
// CheckpointModel
// ──────────────────────────────────────────────────

// CheckpointModel is the grove ORM model for the chronicle_checkpoints table.
type CheckpointModel struct {
	grove.BaseModel `grove:"table:chronicle_checkpoints,alias:cp"`

	ID             string    `grove:"id,pk"`
	StreamID       string    `grove:"stream_id"`
	AppID          string    `grove:"app_id"`
	TenantID       string    `grove:"tenant_id"`
	FromSeq        int64     `grove:"from_seq"`
	ToSeq          int64     `grove:"to_seq"`
	FromHash       string    `grove:"from_hash"`
	ToHash         string    `grove:"to_hash"`
	EventCount     int64     `grove:"event_count"`
	PrevCheckpoint string    `grove:"prev_checkpoint"`
	Algorithm      string    `grove:"algorithm"`
	SignKeyID      string    `grove:"sign_key_id"`
	Signature      []byte    `grove:"signature"`
	SignedPayload  string    `grove:"signed_payload"`
	CreatedAt      time.Time `grove:"created_at"`
}

func toCheckpoint(m *CheckpointModel) (*checkpoint.Checkpoint, error) {
	checkpointID, err := id.ParseCheckpointID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint id %q: %w", m.ID, err)
	}

	streamID, err := id.ParseStreamID(m.StreamID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream id %q: %w", m.StreamID, err)
	}

	return &checkpoint.Checkpoint{
		ID:             checkpointID,
		StreamID:       streamID,
		AppID:          m.AppID,
		TenantID:       m.TenantID,
		FromSeq:        safeUint64(m.FromSeq),
		ToSeq:          safeUint64(m.ToSeq),
		FromHash:       m.FromHash,
		ToHash:         m.ToHash,
		EventCount:     m.EventCount,
		PrevCheckpoint: m.PrevCheckpoint,
		Algorithm:      m.Algorithm,
		SignKeyID:      m.SignKeyID,
		Signature:      m.Signature,
		SignedPayload:  m.SignedPayload,
		CreatedAt:      m.CreatedAt,
	}, nil
}

// fromCheckpoint does NOT stamp CreatedAt with the insertion time the way
// fromEvent and fromStream stamp theirs: CreatedAt is part of what
// checkpoint.CanonicalPayload signs, so overriding it here would silently
// invalidate the signature the caller already computed.
func fromCheckpoint(cp *checkpoint.Checkpoint) *CheckpointModel {
	return &CheckpointModel{
		ID:             cp.ID.String(),
		StreamID:       cp.StreamID.String(),
		AppID:          cp.AppID,
		TenantID:       cp.TenantID,
		FromSeq:        safeInt64(cp.FromSeq),
		ToSeq:          safeInt64(cp.ToSeq),
		FromHash:       cp.FromHash,
		ToHash:         cp.ToHash,
		EventCount:     cp.EventCount,
		PrevCheckpoint: cp.PrevCheckpoint,
		Algorithm:      cp.Algorithm,
		SignKeyID:      cp.SignKeyID,
		Signature:      cp.Signature,
		SignedPayload:  cp.SignedPayload,
		CreatedAt:      cp.CreatedAt,
	}
}
