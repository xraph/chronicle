package contract

import (
	"context"
	"fmt"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/verify"
)

// maxVerifySpan is the largest number of sequences verify.run will walk in
// one call, when Deps.MaxVerifySpan does not override it.
//
// VerifyChain holds every event in the resolved range in memory at once, so
// an unbounded call on a long chain is an out-of-memory crash, and any
// read-capable operator could trigger one by sending fromSeq 0, toSeq 0 --
// the "verify everything" shorthand -- against a chain with millions of
// events. Capping the span turns that into a refusal the UI can act on: it
// names the limit and the chain's head, so the caller can ask for a bounded
// window instead.
const maxVerifySpan = 100_000

// verifySpanCap returns the configured cap, or maxVerifySpan when Deps
// carries none.
func (d Deps) verifySpanCap() uint64 {
	if d.MaxVerifySpan == 0 {
		return maxVerifySpan
	}
	return d.MaxVerifySpan
}

// CoverageSpan is one graded span of a chain. It is a slice on the report and
// not a single level, because a chain that had HMAC turned on later is
// unkeyed below its pin and keyed above it, and flattening that into one
// level misdescribes the oldest events, which are the ones an investigation
// usually cares about.
type CoverageSpan struct {
	FromSeq uint64 `json:"fromSeq"`
	ToSeq   uint64 `json:"toSeq"`
	Level   string `json:"level"`
	Note    string `json:"note,omitempty"`
}

// CheckpointResult mirrors verify.CheckpointResult field for field. Each
// *Checked flag travels with its value because false alone cannot say
// whether the check ran.
type CheckpointResult struct {
	ID      string `json:"id"`
	FromSeq uint64 `json:"fromSeq"`
	ToSeq   uint64 `json:"toSeq"`

	SignatureValid bool `json:"signatureValid"`

	HashMatch   bool `json:"hashMatch"`
	HashChecked bool `json:"hashChecked"`

	ContinuityOK      bool `json:"continuityOk"`
	ContinuityChecked bool `json:"continuityChecked"`

	Note string `json:"note,omitempty"`
}

// VerifyReport is verify.Report on the wire. Nothing is summarised and no
// flag is dropped: the page renders three states from each checked pair
// ("not checked", "checked and held", "checked and failed") and cannot
// reconstruct one that did not cross. That is why none of the six checked
// flags or their value partners carry omitempty: omitempty on a false bool
// would erase exactly the distinction this whole design exists to show.
type VerifyReport struct {
	Valid      bool     `json:"valid"`
	Verified   int64    `json:"verified"`
	Gaps       []uint64 `json:"gaps,omitempty"`
	Tampered   []uint64 `json:"tampered,omitempty"`
	Downgrades []uint64 `json:"downgrades,omitempty"`
	Tolerant   []uint64 `json:"tolerant,omitempty"`
	FirstEvent uint64   `json:"firstEvent"`
	LastEvent  uint64   `json:"lastEvent"`
	HeadSeq    uint64   `json:"headSeq"`

	Partial     bool `json:"partial"`
	HeadMatch   bool `json:"headMatch"`
	HeadChecked bool `json:"headChecked"`

	CheckpointsChecked    bool `json:"checkpointsChecked"`
	CheckpointHeadOK      bool `json:"checkpointHeadOk"`
	CheckpointHeadChecked bool `json:"checkpointHeadChecked"`

	Coverage    []CoverageSpan     `json:"coverage,omitempty"`
	Checkpoints []CheckpointResult `json:"checkpoints,omitempty"`
}

// VerifyInput bounds the range. Both zero means genesis to head, which is
// the whole chain. The React page sends an explicit bounded window by
// default, because VerifyChain holds every event in the range in memory at
// once; the server enforces that bound too, through Deps.MaxVerifySpan,
// because a client that forgot to bound its request must not be able to
// crash the server.
type VerifyInput struct {
	FromSeq uint64 `json:"fromSeq,omitempty"`
	ToSeq   uint64 `json:"toSeq,omitempty"`
}

// VerifyResponse carries NoChain rather than only a nil Report, because
// "this scope has never recorded an event" and "verification produced
// nothing" are different answers and the page says which.
type VerifyResponse struct {
	Report  *VerifyReport `json:"report,omitempty"`
	NoChain bool          `json:"noChain"`
}

// VerifyEventInput names one event by ID. There is no scope on it: the
// handler resolves scope from the principal and refuses an event that does
// not belong to it, the same as every other detail intent.
type VerifyEventInput struct {
	EventID string `json:"eventId"`
}

// VerifyEventResponse is everything Chronicle.VerifyEvent(eventID) can
// actually supply. It is a bare (bool, error): the OK/Downgrade/Tolerant
// distinction that hash.Result carries is flattened before it gets here, and
// the hasher that could recompute it is unexported.
//
// Two limits bound what a caller may conclude from it, and neither can be
// recovered from the response:
//
//   - On an unkeyed chain, Valid true does not rule out a rewrite. The
//     digest is reproducible by anyone who can write to the store, so a
//     rewritten event that also recomputed its own hash and PrevHash passes
//     this check the same as an untouched one.
//   - This checks only the event's own digest against its claimed PrevHash,
//     never whether that PrevHash matches the event actually stored before
//     it. It says nothing about the event's place in the chain. Chain
//     linkage needs verify.run over a range around the event.
type VerifyEventResponse struct {
	Valid      bool   `json:"valid"`
	HashScheme string `json:"hashScheme"`
	Keyed      bool   `json:"keyed"`
}

func verifyRegistrations() []registration {
	return []registration{
		query("verify.run", verifyRunHandler),
		query("verify.event", verifyEventHandler),
	}
}

// newVerifier mirrors dashboard/contributor.go's newVerifier deliberately.
// The contract path and the templ page answer the same question and must
// not disagree about what evidence they consulted. Checkpoints and signer
// travel together or not at all: a checkpoint store without a signer proves
// nothing, since whoever could write the row could write a fabricated one.
func newVerifier(deps Deps) *verify.Verifier {
	chain := deps.HashChain
	if chain == nil {
		chain = &hash.Chain{}
	}
	if deps.CheckpointStore == nil || deps.CheckpointSigner == nil {
		return verify.NewVerifierWithChain(deps.Store, chain)
	}
	return verify.NewVerifierWithCheckpoints(deps.Store, chain, deps.CheckpointStore, deps.CheckpointSigner)
}

// projectReport copies every field of a verify.Report onto its wire type
// unchanged. It is written as a field-for-field copy on purpose, not a loop
// over reflected fields: a report field added later without a matching line
// here is a compile-time reminder, not a silent drop.
func projectReport(r *verify.Report) *VerifyReport {
	if r == nil {
		return nil
	}

	out := &VerifyReport{
		Valid:      r.Valid,
		Verified:   r.Verified,
		Gaps:       r.Gaps,
		Tampered:   r.Tampered,
		Downgrades: r.Downgrades,
		Tolerant:   r.Tolerant,
		FirstEvent: r.FirstEvent,
		LastEvent:  r.LastEvent,
		HeadSeq:    r.HeadSeq,

		Partial:     r.Partial,
		HeadMatch:   r.HeadMatch,
		HeadChecked: r.HeadChecked,

		CheckpointsChecked:    r.CheckpointsChecked,
		CheckpointHeadOK:      r.CheckpointHeadOK,
		CheckpointHeadChecked: r.CheckpointHeadChecked,
	}

	for _, c := range r.Coverage {
		out.Coverage = append(out.Coverage, CoverageSpan{
			FromSeq: c.FromSeq,
			ToSeq:   c.ToSeq,
			Level:   string(c.Level),
			Note:    c.Note,
		})
	}
	for _, cp := range r.Checkpoints {
		out.Checkpoints = append(out.Checkpoints, CheckpointResult{
			ID:      cp.ID,
			FromSeq: cp.FromSeq,
			ToSeq:   cp.ToSeq,

			SignatureValid: cp.SignatureValid,

			HashMatch:   cp.HashMatch,
			HashChecked: cp.HashChecked,

			ContinuityOK:      cp.ContinuityOK,
			ContinuityChecked: cp.ContinuityChecked,

			Note: cp.Note,
		})
	}

	return out
}

// resolveVerifySpan resolves a requested range the same way VerifyChain
// itself does -- fromSeq 0 means genesis (1), toSeq 0 means the stream's
// recorded head -- and returns the number of sequences the resolved range
// covers. Callers use this to enforce the span cap BEFORE VerifyChain ever
// touches the store, since VerifyChain performs the identical resolution
// internally but only after it has already started reading.
func resolveVerifySpan(in VerifyInput, headSeq uint64) (fromSeq, toSeq uint64) {
	fromSeq = in.FromSeq
	if fromSeq == 0 {
		fromSeq = 1
	}
	toSeq = in.ToSeq
	if toSeq == 0 {
		toSeq = headSeq
	}
	return fromSeq, toSeq
}

func verifyRunHandler(deps Deps) func(context.Context, VerifyInput, fcontract.Principal) (VerifyResponse, error) {
	return func(ctx context.Context, in VerifyInput, p fcontract.Principal) (VerifyResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return VerifyResponse{}, err
		}

		st, err := scopedStream(ctx, deps, "verify.run", v)
		if err != nil {
			return VerifyResponse{}, err
		}
		if st == nil {
			return VerifyResponse{NoChain: true}, nil
		}

		fromSeq, toSeq := resolveVerifySpan(in, st.HeadSeq)
		if toSeq < fromSeq {
			return VerifyResponse{}, &fcontract.Error{
				Code:    fcontract.CodeBadRequest,
				Message: "toSeq cannot be less than fromSeq",
			}
		}

		span := toSeq - fromSeq + 1
		if maxSpan := deps.verifySpanCap(); span > maxSpan {
			return VerifyResponse{}, &fcontract.Error{
				Code: fcontract.CodeBadRequest,
				Message: fmt.Sprintf(
					"requested range covers %d events, which exceeds the %d-event limit on a single verification; "+
						"the chain's head is at sequence %d, so ask for a bounded window within it",
					span, maxSpan, st.HeadSeq,
				),
			}
		}

		// The pin and the head come off the stream row, never from the
		// request. A caller that could name its own pin could declare a
		// keyed chain plain and walk past every downgrade check.
		report, err := newVerifier(deps).VerifyChain(ctx, &verify.Input{
			StreamID: st.ID,
			FromSeq:  in.FromSeq,
			ToSeq:    in.ToSeq,
			AppID:    v.AppID,
			TenantID: v.TenantID,
			Pin:      hash.Pin{Scheme: hash.Scheme(st.Scheme), Since: st.SchemeSince},
			HeadSeq:  st.HeadSeq,
			HeadHash: st.HeadHash,
		})
		if err != nil {
			return VerifyResponse{}, deps.mapStoreError("verify.run", err)
		}

		return VerifyResponse{Report: projectReport(report)}, nil
	}
}

func verifyEventHandler(deps Deps) func(context.Context, VerifyEventInput, fcontract.Principal) (VerifyEventResponse, error) {
	return func(ctx context.Context, in VerifyEventInput, p fcontract.Principal) (VerifyEventResponse, error) {
		v, err := scopeFromPrincipal(p)
		if err != nil {
			return VerifyEventResponse{}, err
		}

		eventID, err := id.ParseAuditID(in.EventID)
		if err != nil {
			// An ID that does not even parse cannot name a real event, and
			// answering the same as a real miss tells a prober nothing about
			// which is true.
			return VerifyEventResponse{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		event, err := deps.Store.Get(ctx, eventID)
		if err != nil {
			return VerifyEventResponse{}, deps.mapStoreError("verify.event", err)
		}

		// Security-critical: an event must not be verifiable by ID alone any
		// more than it is readable by ID alone. This has to run, and refuse,
		// before Chronicle.VerifyEvent is ever called -- that call reaches
		// straight into the store by ID with no scope check of its own.
		if !v.owns(event.AppID, event.TenantID) {
			return VerifyEventResponse{}, &fcontract.Error{Code: fcontract.CodeNotFound, Message: "not found"}
		}

		if deps.Chronicle == nil {
			return VerifyEventResponse{}, &fcontract.Error{
				Code:    fcontract.CodeUnavailable,
				Message: "event verification is not configured on this deployment",
			}
		}

		valid, err := deps.Chronicle.VerifyEvent(ctx, eventID)
		if err != nil {
			return VerifyEventResponse{}, deps.mapStoreError("verify.event", err)
		}

		return VerifyEventResponse{
			Valid:      valid,
			HashScheme: event.HashScheme,
			Keyed:      hash.Keyed(hash.Scheme(event.HashScheme)),
		}, nil
	}
}
