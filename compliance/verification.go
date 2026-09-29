package compliance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// DefaultVerifyWindow is how many sequences a report verifies when the engine
// was not given a window of its own.
//
// VerifyChain holds every event in its range in memory at once, so the window
// is a memory bound, not a sampling rate. Fifty thousand events is tens of
// megabytes on a typical event, which a report generator can afford on every
// run.
const DefaultVerifyWindow uint64 = 50_000

// VerificationStatus says whether a report's chain verification ran, and if
// not, why not.
type VerificationStatus string

const (
	// VerificationRan means the chain was verified and Report.Verification
	// holds the result, which may be valid or not.
	VerificationRan VerificationStatus = "verified"

	// VerificationNoChain means the report's scope has no hash chain stream,
	// so there was nothing to verify. It is not a failure: a scope that never
	// recorded an event has no chain.
	VerificationNoChain VerificationStatus = "no_chain"

	// VerificationNotConfigured means the engine was built without a hash
	// chain (see WithChain), so it could not verify anything. It never falls
	// back to an unkeyed chain, which would report every keyed event as
	// tampered.
	VerificationNotConfigured VerificationStatus = "not_configured"
)

// VerificationScope records what a report's chain verification covered.
//
// Report.Verification is the verifier's own result and says nothing about
// why a range was chosen. This does, so a report never implies more coverage
// than it checked: the exact sequences asked for, whether the window cut the
// chain short, and the caveats that apply to reading the result.
type VerificationScope struct {
	Status VerificationStatus `json:"status"`

	// StreamID is the stream verified, the one GetStreamByScope returns for
	// the report's AppID and TenantID.
	StreamID string `json:"stream_id,omitempty"`

	// Scheme and SchemeSince are the stream's digest pin, taken from the
	// stream row.
	Scheme      string `json:"scheme,omitempty"`
	SchemeSince uint64 `json:"scheme_since,omitempty"`

	// HeadSeq is the stream's head when the report was generated.
	HeadSeq uint64 `json:"head_seq"`

	// FromSeq and ToSeq are the sequences verification was asked to cover.
	// Verification.FirstEvent and LastEvent are the events it actually found
	// there.
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`

	// Window is the most sequences one report verifies, and Capped is whether
	// it cut this chain short. A capped report verified the newest Window
	// sequences up to the head and nothing before them.
	Window uint64 `json:"window"`
	Capped bool   `json:"capped"`

	// CheckpointsConfigured is whether the engine had a checkpoint store and
	// signer to consult.
	CheckpointsConfigured bool `json:"checkpoints_configured"`

	// Notes are the caveats a reader needs to interpret the result. Every
	// export renders them.
	Notes []string `json:"notes,omitempty"`
}

// StreamSource resolves the hash chain stream for a report's scope. Every
// standard backend implements it.
type StreamSource interface {
	GetStreamByScope(ctx context.Context, appID, tenantID string) (*stream.Stream, error)
}

// EngineOption configures an Engine.
type EngineOption func(*Engine)

// WithChain lets the engine verify the hash chain behind every report it
// generates.
//
// chain must be the deployment's own chain, carrying its key provider. A
// verifier built without it recomputes digests unkeyed, so on an HMAC
// deployment every event would read as tampered or downgraded. Without this
// option reports carry no verification and say so.
func WithChain(streams StreamSource, chain *hash.Chain) EngineOption {
	return func(e *Engine) {
		e.streams, e.chain = streams, chain
	}
}

// WithCheckpoints lets report verification check signed checkpoints. Both
// halves are needed: a checkpoint store without a signer holds rows nothing
// can authenticate. If either is nil the option does nothing, which matches
// how the admin API's verifier is built.
func WithCheckpoints(store checkpoint.Store, signer checkpoint.Signer) EngineOption {
	return func(e *Engine) {
		if store == nil || signer == nil {
			return
		}
		e.checkpoints, e.signer = store, signer
	}
}

// WithVerifyWindow sets how many sequences a report verifies at most. Zero
// keeps DefaultVerifyWindow.
func WithVerifyWindow(n uint64) EngineOption {
	return func(e *Engine) {
		if n > 0 {
			e.verifyWindow = n
		}
	}
}

// verifier builds the verifier reports use, the same way the admin API's
// newVerifier does, so a report and POST /v1/verify never disagree about what
// evidence they consulted.
func (e *Engine) verifier() *verify.Verifier {
	if e.checkpoints == nil || e.signer == nil {
		return verify.NewVerifierWithChain(e.verifyStore, e.chain)
	}
	return verify.NewVerifierWithCheckpoints(e.verifyStore, e.chain, e.checkpoints, e.signer)
}

// verifyWindowRange picks the sequences a report verifies on a stream whose
// head is headSeq.
//
// The rule is the newest window sequences, ending at the head. When the whole
// chain fits, that is genesis to head, which is the only range that anchors
// the tail and compares the latest checkpoint against the head. When it does
// not, the window stays at the head end, because that is where truncation
// shows and where reports usually look.
//
// The range comes from the stream row alone, never from event timestamps.
// Timestamps are event content, so choosing sequences by them would let
// whoever can edit an event also steer which events get checked.
func verifyWindowRange(headSeq, window uint64) (from, to uint64, capped bool) {
	if headSeq == 0 {
		return 0, 0, false
	}
	if headSeq <= window {
		return 1, headSeq, false
	}
	return headSeq - window + 1, headSeq, true
}

// verifyScope verifies the chain behind a report's scope.
//
// A scope with no stream records VerificationNoChain rather than failing.
// Every other error fails the report: a report that quietly dropped its
// integrity evidence would read as though nothing was wrong.
func (e *Engine) verifyScope(ctx context.Context, appID, tenantID string) (*verify.Report, *VerificationScope, error) {
	window := e.verifyWindow
	if window == 0 {
		window = DefaultVerifyWindow
	}
	scope := &VerificationScope{
		Window:                window,
		CheckpointsConfigured: e.checkpoints != nil && e.signer != nil,
	}

	if e.chain == nil || e.streams == nil || e.verifyStore == nil {
		scope.Status = VerificationNotConfigured
		scope.Notes = append(scope.Notes,
			"Chain verification did not run: this engine was not given the deployment's hash chain.")
		return nil, scope, nil
	}

	st, err := e.streams.GetStreamByScope(ctx, appID, tenantID)
	if err != nil {
		// sql.ErrNoRows as well as ErrStreamNotFound: some SQL backends hand
		// back the driver's error unmapped (see handler/checkpoints.go).
		if errors.Is(err, chronicle.ErrStreamNotFound) || errors.Is(err, sql.ErrNoRows) {
			scope.Status = VerificationNoChain
			scope.Notes = append(scope.Notes,
				"This scope has no hash chain stream, so there was no chain to verify.")
			return nil, scope, nil
		}
		return nil, nil, fmt.Errorf("resolving stream for verification: %w", err)
	}

	from, to, capped := verifyWindowRange(st.HeadSeq, window)
	scope.Status = VerificationRan
	scope.StreamID = st.ID.String()
	scope.Scheme, scope.SchemeSince = st.Scheme, st.SchemeSince
	scope.HeadSeq = st.HeadSeq
	scope.FromSeq, scope.ToSeq, scope.Capped = from, to, capped

	// A whole-chain run passes no bounds at all. That is how VerifyChain is
	// asked about genesis to head, and the only shape in which it compares
	// the latest checkpoint against a head of zero, which is what a chain
	// wiped along with its head row looks like.
	in := &verify.Input{
		StreamID: st.ID,
		AppID:    st.AppID,
		TenantID: st.TenantID,
		Pin:      hash.Pin{Scheme: hash.Scheme(st.Scheme), Since: st.SchemeSince},
		HeadSeq:  st.HeadSeq,
		HeadHash: st.HeadHash,
	}
	if capped {
		in.FromSeq, in.ToSeq = from, to
	}

	// Pin and head come from the stream row, never from the caller: they are
	// what downgrade and truncation detection compare against.
	report, err := e.verifier().VerifyChain(ctx, in)
	if err != nil {
		return nil, nil, fmt.Errorf("verifying chain: %w", err)
	}

	scope.Notes = verificationNotes(report, scope, tenantID)
	return report, scope, nil
}

// verificationNotes writes the caveats a reader needs next to the result.
func verificationNotes(r *verify.Report, s *VerificationScope, tenantID string) []string {
	var notes []string

	if s.Capped {
		notes = append(notes, fmt.Sprintf(
			"Verification covered sequences %d to %d, the newest %d of the stream's %d. "+
				"Sequences below %d were not verified, including any events of the report period recorded there.",
			s.FromSeq, s.ToSeq, s.Window, s.HeadSeq, s.FromSeq))
	}

	if tenantID == "" {
		notes = append(notes,
			"This report has no tenant, so its statistics and sections include every tenant's events. "+
				"Verification covered only the app's untenanted stream; each tenant's own stream was not verified.")
	}

	for _, c := range r.Coverage {
		if c.Level == verify.LevelUnkeyed {
			notes = append(notes, fmt.Sprintf(
				"Sequences %d to %d are unkeyed: anyone who can write the store can recompute their digests, "+
					"so verification there detects corruption, not tampering.", c.FromSeq, c.ToSeq))
		}
	}

	if len(r.Gaps) > 0 {
		notes = append(notes,
			"Gaps are missing sequences no authentic retention record accounts for. They include deletions, "+
				"and can include retention purges that left no record: purges from before retention records "+
				"existed that were never backfilled, or an enforcer run with WithUnrecordedPurge.")
	}

	return notes
}
