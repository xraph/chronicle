package contract

import (
	"context"
	"errors"
	"time"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/stream"
)

// StreamSummary is one chain as the dashboard reads it.
type StreamSummary struct {
	ID       string `json:"id"`
	AppID    string `json:"appId"`
	TenantID string `json:"tenantId,omitempty"`
	HeadHash string `json:"headHash"`
	HeadSeq  uint64 `json:"headSeq"`

	Scheme      string `json:"scheme"`
	SchemeSince uint64 `json:"schemeSince"`

	// CoverageCeiling is the best assurance level this deployment could
	// report for this chain, before any verification runs. It is what lets
	// the page tell an operator what is switched off without walking the
	// chain first, which for a default deployment is the most useful thing
	// it can say.
	CoverageCeiling string `json:"coverageCeiling"`

	// LatestCheckpoint is nil when this deployment takes no checkpoints, or
	// when this chain has none yet. The two are different and the page says
	// which: CheckpointingConfigured distinguishes them.
	LatestCheckpoint        *CheckpointSummary `json:"latestCheckpoint,omitempty"`
	CheckpointingConfigured bool               `json:"checkpointingConfigured"`
}

// CheckpointSummary is one signed checkpoint as the dashboard lists it.
//
// It lives here rather than beside the checkpoints handlers because
// StreamSummary embeds it. The checkpoints group reuses this type and must
// not declare a second one.
type CheckpointSummary struct {
	ID         string `json:"id"`
	FromSeq    uint64 `json:"fromSeq"`
	ToSeq      uint64 `json:"toSeq"`
	EventCount int64  `json:"eventCount"`
	CreatedAt  string `json:"createdAt"`
	SignKeyID  string `json:"signKeyId"`
}

// projectStream turns a stored stream into its wire summary, attaching the
// latest checkpoint when this deployment takes checkpoints.
//
// A chain with no checkpoint yet is a normal state, and so is a backend that
// refuses checkpoints, which is "no opinion" rather than a failure. Any other
// error reading the checkpoint store fails the call: answering nil there
// would tell the operator "no checkpoint yet" when the truth is "we could
// not look". op is the intent being answered, for the log line only.
func projectStream(ctx context.Context, deps Deps, op string, st *stream.Stream) (*StreamSummary, error) {
	out := &StreamSummary{
		ID:                      st.ID.String(),
		AppID:                   st.AppID,
		TenantID:                st.TenantID,
		HeadHash:                st.HeadHash,
		HeadSeq:                 st.HeadSeq,
		Scheme:                  st.Scheme,
		SchemeSince:             st.SchemeSince,
		CoverageCeiling:         coverageCeiling(deps, st),
		CheckpointingConfigured: deps.checkpointingConfigured(),
	}

	if !out.CheckpointingConfigured {
		return out, nil
	}

	cp, err := deps.CheckpointStore.LatestCheckpoint(ctx, st.ID)
	switch {
	case err == nil:
		out.LatestCheckpoint = projectCheckpoint(cp)
	case errors.Is(err, checkpoint.ErrNotFound), errors.Is(err, checkpoint.ErrUnsupported):
		// No checkpoint yet, or a backend with no opinion. Both leave it nil.
	default:
		return nil, deps.mapStoreError(op, err)
	}
	return out, nil
}

// projectCheckpoint turns a stored checkpoint into its wire summary. A nil
// checkpoint projects to nil.
func projectCheckpoint(cp *checkpoint.Checkpoint) *CheckpointSummary {
	if cp == nil {
		return nil
	}
	return &CheckpointSummary{
		ID:         cp.ID.String(),
		FromSeq:    cp.FromSeq,
		ToSeq:      cp.ToSeq,
		EventCount: cp.EventCount,
		CreatedAt:  formatTime(cp.CreatedAt),
		SignKeyID:  cp.SignKeyID,
	}
}

// formatTime renders a timestamp for the wire as RFC 3339 in UTC, and the
// zero time as an empty string rather than year one.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// errNotFound is the one answer for an ID that does not parse, does not
// exist, or belongs to someone else. All three look the same, so a caller
// cannot probe which IDs exist in other apps or tenants.
func errNotFound() error {
	return &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
}

// notFoundSentinels are the store errors that mean "no such record" rather
// than "the store failed". They are the only store errors a caller learns
// anything specific from.
var notFoundSentinels = []error{
	chronicle.ErrEventNotFound,
	chronicle.ErrStreamNotFound,
	chronicle.ErrSubjectNotFound,
	chronicle.ErrPolicyNotFound,
	chronicle.ErrReportNotFound,
	chronicle.ErrErasureNotFound,
	chronicle.ErrErasureKeyNotFound,
	checkpoint.ErrNotFound,
}

// mapStoreError turns a store error into a contract error that is safe to
// send to the browser. op names the intent or operation that failed, for the
// log line only.
//
// A known not-found sentinel becomes CodeNotFound. A cancelled request
// becomes CodeUnavailable. An error that is already a contract error was
// built by this package and passes through unchanged. Everything else
// becomes CodeInternal with a fixed message, never the error's own text: a
// driver or SQL error string can carry table names, query fragments and
// connection details, and none of that belongs in a browser. That branch
// logs the underlying error through Deps.Logger, because the dispatcher only
// logs errors that are not already contract errors, so once this function
// has converted one the log line here is the only record of the cause.
func (d Deps) mapStoreError(op string, err error) error {
	if err == nil {
		return nil
	}

	var ce *fcontract.Error
	if errors.As(err, &ce) {
		return ce
	}

	for _, sentinel := range notFoundSentinels {
		if errors.Is(err, sentinel) {
			return &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}
	}

	// A cancelled or timed-out request is the caller going away, not the
	// store failing. The dispatcher maps a bare context.Canceled the same
	// way; converting it to CodeInternal first would hide that from it.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &fcontract.Error{Code: fcontract.CodeUnavailable, Message: "request cancelled", Retryable: true}
	}

	d.logger().Error("chronicle/contract: store error",
		log.String("contributor", contributorName),
		log.String("op", op),
		log.Error(err),
	)
	return &fcontract.Error{Code: fcontract.CodeInternal, Message: "the audit store could not complete this request"}
}
