package mongo

import (
	"encoding/json"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

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

// ──────────────────────────────────────────────────
// EventModel
// ──────────────────────────────────────────────────

// EventModel is the grove ORM model for the chronicle_events collection.
//
// Timestamp is split across two fields. See splitTimestamp for why.
type EventModel struct {
	grove.BaseModel `grove:"table:chronicle_events"`

	ID              string         `grove:"id,pk"              bson:"_id"`
	StreamID        string         `grove:"stream_id"          bson:"stream_id"`
	Sequence        uint64         `grove:"sequence"           bson:"sequence"`
	Hash            string         `grove:"hash"               bson:"hash"`
	PrevHash        string         `grove:"prev_hash"          bson:"prev_hash"`
	AppID           string         `grove:"app_id"             bson:"app_id"`
	TenantID        string         `grove:"tenant_id"          bson:"tenant_id"`
	UserID          string         `grove:"user_id"            bson:"user_id"`
	IP              string         `grove:"ip"                 bson:"ip"`
	UserAgent       string         `grove:"user_agent"         bson:"user_agent"`
	RequestID       string         `grove:"request_id"         bson:"request_id"`
	SessionID       string         `grove:"session_id"         bson:"session_id"`
	Action          string         `grove:"action"             bson:"action"`
	Resource        string         `grove:"resource"           bson:"resource"`
	Category        string         `grove:"category"           bson:"category"`
	ResourceID      string         `grove:"resource_id"        bson:"resource_id"`
	Metadata        map[string]any `grove:"metadata"           bson:"metadata,omitempty"`
	Outcome         string         `grove:"outcome"            bson:"outcome"`
	Severity        string         `grove:"severity"           bson:"severity"`
	Reason          string         `grove:"reason"             bson:"reason"`
	SubjectID       string         `grove:"subject_id"         bson:"subject_id"`
	EncryptionKeyID string         `grove:"encryption_key_id"  bson:"encryption_key_id"`
	Erased          bool           `grove:"erased"             bson:"erased"`
	ErasedAt        *time.Time     `grove:"erased_at"          bson:"erased_at,omitempty"`
	ErasureID       string         `grove:"erasure_id"         bson:"erasure_id,omitempty"`
	Timestamp       time.Time      `grove:"timestamp"          bson:"timestamp"`
	TimestampSubMs  int32          `grove:"timestamp_sub_ms"   bson:"timestamp_sub_ms"`
	CreatedAt       time.Time      `grove:"created_at"         bson:"created_at"`
	HashScheme      string         `grove:"hash_scheme"        bson:"hash_scheme,omitempty"`
	HashKeyID       string         `grove:"hash_key_id"        bson:"hash_key_id,omitempty"`
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
		UserAgent:       m.UserAgent,
		RequestID:       m.RequestID,
		SessionID:       m.SessionID,
		Action:          m.Action,
		Resource:        m.Resource,
		Category:        m.Category,
		ResourceID:      m.ResourceID,
		Metadata:        normalizeMetadata(m.Metadata),
		Outcome:         m.Outcome,
		Severity:        m.Severity,
		Reason:          m.Reason,
		SubjectID:       m.SubjectID,
		EncryptionKeyID: m.EncryptionKeyID,
		Erased:          m.Erased,
		ErasedAt:        m.ErasedAt,
		ErasureID:       m.ErasureID,
		Timestamp:       joinTimestamp(m.Timestamp, m.TimestampSubMs),
		HashScheme:      m.HashScheme,
		HashKeyID:       m.HashKeyID,
	}, nil
}

func fromEvent(e *audit.Event) *EventModel {
	ts, subMs := splitTimestamp(e.Timestamp)
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
		TimestampSubMs:  subMs,
		CreatedAt:       time.Now().UTC(),
		HashScheme:      e.HashScheme,
		HashKeyID:       e.HashKeyID,
	}
}

// splitTimestamp divides an event timestamp into the part a BSON date can hold
// and the nanoseconds below it.
//
// The hash chain covers the timestamp to the nanosecond (hash.Chain formats it
// with time.RFC3339Nano), and a BSON date keeps milliseconds. Storing the
// timestamp as a date alone handed every reader a different instant from the
// one that was hashed, so every event with a sub-millisecond component read
// back as tampered. On a clock with microsecond or nanosecond resolution that
// is nearly all of them.
//
// We keep the full value rather than truncating before hashing. An audit log
// records when something happened as the caller reported it. Rounding that to
// suit one backend's storage would change the evidence, and would mean events
// hashed on a different backend or an earlier release could never verify here.
// The date stays the millisecond floor, so the timestamp indexes, range
// filters and sort order behave exactly as they did.
//
// The date is truncated here rather than left for the driver to floor, so the
// two halves are guaranteed to add back up to the original.
func splitTimestamp(t time.Time) (date time.Time, subMs int32) {
	date = t.Truncate(time.Millisecond)
	return date, int32(t.Sub(date)) //nolint:gosec // always in [0, 1e6)
}

// joinTimestamp reverses splitTimestamp.
//
// A row written before timestamp_sub_ms existed decodes it as zero and reads
// back as the millisecond date it holds, as it always did. Those rows lost
// their sub-millisecond digits on insert and the row no longer holds them, so a
// row whose original timestamp had any will still fail verification. It is not
// reported wrongly: the stored digest covers an instant the row no longer
// holds.
//
// The remainder is not range-checked. A tampered value moves the timestamp,
// and verification reports that event as tampered, which is the right answer.
func joinTimestamp(date time.Time, subMs int32) time.Time {
	return date.Add(time.Duration(subMs))
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

// StreamModel is the grove ORM model for the chronicle_streams collection.
type StreamModel struct {
	grove.BaseModel `grove:"table:chronicle_streams"`

	ID          string    `grove:"id,pk"        bson:"_id"`
	AppID       string    `grove:"app_id"       bson:"app_id"`
	TenantID    string    `grove:"tenant_id"    bson:"tenant_id"`
	HeadHash    string    `grove:"head_hash"    bson:"head_hash"`
	HeadSeq     uint64    `grove:"head_seq"     bson:"head_seq"`
	CreatedAt   time.Time `grove:"created_at"   bson:"created_at"`
	UpdatedAt   time.Time `grove:"updated_at"   bson:"updated_at"`
	Scheme      string    `grove:"scheme"       bson:"scheme"`
	SchemeSince uint64    `grove:"scheme_since" bson:"scheme_since"`
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
		HeadSeq:     m.HeadSeq,
		Scheme:      m.Scheme,
		SchemeSince: m.SchemeSince,
	}, nil
}

func fromStream(st *stream.Stream) *StreamModel {
	return &StreamModel{
		ID:          st.ID.String(),
		AppID:       st.AppID,
		TenantID:    st.TenantID,
		HeadHash:    st.HeadHash,
		HeadSeq:     st.HeadSeq,
		CreatedAt:   st.CreatedAt,
		UpdatedAt:   st.UpdatedAt,
		Scheme:      st.Scheme,
		SchemeSince: st.SchemeSince,
	}
}

// ──────────────────────────────────────────────────
// ErasureModel
// ──────────────────────────────────────────────────

// ErasureModel is the grove ORM model for the chronicle_erasures collection.
type ErasureModel struct {
	grove.BaseModel `grove:"table:chronicle_erasures"`

	ID             string    `grove:"id,pk"           bson:"_id"`
	SubjectID      string    `grove:"subject_id"      bson:"subject_id"`
	Reason         string    `grove:"reason"          bson:"reason"`
	RequestedBy    string    `grove:"requested_by"    bson:"requested_by"`
	EventsAffected int64     `grove:"events_affected" bson:"events_affected"`
	KeyDestroyed   bool      `grove:"key_destroyed"   bson:"key_destroyed"`
	AppID          string    `grove:"app_id"          bson:"app_id"`
	TenantID       string    `grove:"tenant_id"       bson:"tenant_id"`
	CreatedAt      time.Time `grove:"created_at"      bson:"created_at"`
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

// RetentionPolicyModel is the grove ORM model for the chronicle_retention_policies collection.
type RetentionPolicyModel struct {
	grove.BaseModel `grove:"table:chronicle_retention_policies"`

	ID        string    `grove:"id,pk"      bson:"_id"`
	Category  string    `grove:"category"   bson:"category"`
	Duration  int64     `grove:"duration"   bson:"duration"` // nanoseconds
	Archive   bool      `grove:"archive"    bson:"archive"`
	AppID     string    `grove:"app_id"     bson:"app_id"`
	TenantID  string    `grove:"tenant_id"  bson:"tenant_id"`
	CreatedAt time.Time `grove:"created_at" bson:"created_at"`
	UpdatedAt time.Time `grove:"updated_at" bson:"updated_at"`
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

// ArchiveModel is the grove ORM model for the chronicle_archives collection.
type ArchiveModel struct {
	grove.BaseModel `grove:"table:chronicle_archives"`

	ID            string    `grove:"id,pk"           bson:"_id"`
	PolicyID      string    `grove:"policy_id"       bson:"policy_id"`
	Category      string    `grove:"category"        bson:"category"`
	EventCount    int64     `grove:"event_count"     bson:"event_count"`
	FromTimestamp time.Time `grove:"from_timestamp"  bson:"from_timestamp"`
	ToTimestamp   time.Time `grove:"to_timestamp"    bson:"to_timestamp"`
	SinkName      string    `grove:"sink_name"       bson:"sink_name"`
	SinkRef       string    `grove:"sink_ref"        bson:"sink_ref"`
	AppID         string    `grove:"app_id"          bson:"app_id"`
	TenantID      string    `grove:"tenant_id"       bson:"tenant_id"`
	CreatedAt     time.Time `grove:"created_at"      bson:"created_at"`
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

// ReportModel is the grove ORM model for the chronicle_reports collection.
type ReportModel struct {
	grove.BaseModel `grove:"table:chronicle_reports"`

	ID          string    `grove:"id,pk"       bson:"_id"`
	Title       string    `grove:"title"       bson:"title"`
	Type        string    `grove:"type"        bson:"type"`
	PeriodFrom  time.Time `grove:"period_from" bson:"period_from"`
	PeriodTo    time.Time `grove:"period_to"   bson:"period_to"`
	AppID       string    `grove:"app_id"      bson:"app_id"`
	TenantID    string    `grove:"tenant_id"   bson:"tenant_id"`
	Format      string    `grove:"format"      bson:"format"`
	Data        []byte    `grove:"data"        bson:"data"` // Sections serialized as JSON
	GeneratedBy string    `grove:"generated_by" bson:"generated_by"`
	CreatedAt   time.Time `grove:"created_at"  bson:"created_at"`
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

// CheckpointModel is the grove ORM model for the chronicle_checkpoints collection.
type CheckpointModel struct {
	grove.BaseModel `grove:"table:chronicle_checkpoints"`

	ID             string    `grove:"id,pk"             bson:"_id"`
	StreamID       string    `grove:"stream_id"         bson:"stream_id"`
	AppID          string    `grove:"app_id"            bson:"app_id"`
	TenantID       string    `grove:"tenant_id"         bson:"tenant_id"`
	FromSeq        uint64    `grove:"from_seq"          bson:"from_seq"`
	ToSeq          uint64    `grove:"to_seq"            bson:"to_seq"`
	FromHash       string    `grove:"from_hash"         bson:"from_hash"`
	ToHash         string    `grove:"to_hash"           bson:"to_hash"`
	EventCount     int64     `grove:"event_count"       bson:"event_count"`
	PrevCheckpoint string    `grove:"prev_checkpoint"   bson:"prev_checkpoint,omitempty"`
	Algorithm      string    `grove:"algorithm"         bson:"algorithm"`
	SignKeyID      string    `grove:"sign_key_id"       bson:"sign_key_id"`
	Signature      []byte    `grove:"signature"         bson:"signature"`
	SignedPayload  string    `grove:"signed_payload"    bson:"signed_payload"`
	CreatedAt      time.Time `grove:"created_at"        bson:"created_at"`
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
		FromSeq:        m.FromSeq,
		ToSeq:          m.ToSeq,
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
		FromSeq:        cp.FromSeq,
		ToSeq:          cp.ToSeq,
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

// normalizeMetadata turns the driver's decoded metadata back into the plain Go
// values it was recorded as.
//
// The driver decodes an embedded document inside a map[string]any as a bson.D,
// which keeps the order the keys were stored in, and json.Marshal writes a
// bson.D in that order. The digest was computed over json.Marshal of the
// original map[string]any, which sorts its keys. So an event with nested
// metadata read back its nested keys in a different order and failed
// verification, while its top-level keys, already in a map, were fine.
func normalizeMetadata(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = normalizeBSONValue(v)
	}
	return out
}

// normalizeBSONValue converts the driver's document and array types, at any
// depth, into map[string]any and []any. Every other value is returned as is.
func normalizeBSONValue(v any) any {
	switch val := v.(type) {
	case bson.D:
		out := make(map[string]any, len(val))
		for _, e := range val {
			out[e.Key] = normalizeBSONValue(e.Value)
		}
		return out
	case bson.M:
		return normalizeMetadata(val)
	case map[string]any:
		return normalizeMetadata(val)
	case bson.A:
		return normalizeSlice(val)
	case []any:
		return normalizeSlice(val)
	default:
		return v
	}
}

func normalizeSlice(s []any) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = normalizeBSONValue(v)
	}
	return out
}
