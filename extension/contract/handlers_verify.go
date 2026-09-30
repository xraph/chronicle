package contract

import (
	"context"
	"fmt"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
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

// RetainedRangeDTO is verify.RetainedRange on the wire: a run of sequences a
// retention policy removed, which an authentic retention record in the chain
// accounts for. The page shows it as an authorised, recorded purge, not as a
// deletion.
//
// A retained range asserts linkage, never content. The record vouches that
// these sequences existed and gives the hashes either side of them, so the
// chain still links across the hole. It says nothing about what the removed
// events contained, and the events themselves are gone from the store.
type RetainedRangeDTO struct {
	// FromSeq and ToSeq bound the run of removed sequences, both inclusive.
	FromSeq uint64 `json:"fromSeq"`
	ToSeq   uint64 `json:"toSeq"`

	// RecordSeq is the sequence of the retention record that lists the run.
	// It is an ordinary event in the chain, so the page can link to it.
	RecordSeq uint64 `json:"recordSeq"`

	// PolicyID is the retention policy the record says it acted under. It is
	// the record's own claim, and it names a policy that may since have been
	// deleted. Empty when the record names none.
	PolicyID string `json:"policyId,omitempty"`

	// Backfill names the archive the record was recovered from, when it was
	// written afterwards for a purge that predates retention records. Empty
	// for a record the enforcer wrote at purge time, which is the ordinary
	// case.
	Backfill string `json:"backfill,omitempty"`
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

	// Retained lists the missing sequences that a retention policy removed
	// and an authentic retention record accounts for, as ranges. They are not
	// in Gaps and do not make the chain invalid. Absent when there are none.
	Retained []RetainedRangeDTO `json:"retained,omitempty"`

	Coverage    []CoverageSpan     `json:"coverage,omitempty"`
	Checkpoints []CheckpointResult `json:"checkpoints,omitempty"`

	// RetentionPolicies is how many retention policies can purge the chain
	// this report verified. Purges those policies recorded in the chain are
	// reported in Retained and are not gaps. A non-zero value therefore means
	// only this: Gaps may still include purges that were never recorded in
	// the chain, which Chronicle cannot tell from deletion. That happens for
	// purges from before retention records existed that were never
	// backfilled, for an enforcer built without a chain recorder, and for a
	// record that does not verify under the chain's pin. Such a purged
	// sequence reads as a gap. The event after it is checked against its own
	// declared predecessor, so an unrecorded purge alone does not mark it
	// tampered.
	//
	// A chain is one (app, tenant). A policy purges it when the policy's
	// app is the chain's app and the policy's tenant is either empty (the
	// stores apply an app-level policy to every tenant in the app) or the
	// chain's own tenant. A policy with no app at all, which only trusted
	// in-process code can create, is not counted.
	//
	// It counts the policies configured NOW, so purges made under policies
	// that have since been deleted are not reflected. -1 means unknown:
	// listing the policies failed, and that is not allowed to fail the
	// verification itself. It is also -1 on a verification embedded in a
	// stored report (reports.detail), where no count was taken. No omitempty,
	// because zero is an answer the page needs.
	RetentionPolicies int `json:"retentionPolicies"`
}

// VerifyInput bounds the range. Both zero means genesis to head, which is
// the whole chain. The React page sends an explicit bounded window by
// default, because VerifyChain holds every event in the range in memory at
// once; the server enforces that bound too, through Deps.MaxVerifySpan,
// because a client that forgot to bound its request must not be able to
// crash the server.
//
// StreamID optionally names the chain to verify. Empty means the viewer's own
// chain (its exact app and tenant). An app-wide viewer passes a tenant's
// chain ID, taken from streams.list, to verify that tenant's history. A chain
// the viewer does not own answers NOT_FOUND.
type VerifyInput struct {
	StreamID string `json:"streamId,omitempty"`
	FromSeq  uint64 `json:"fromSeq,omitempty"`
	ToSeq    uint64 `json:"toSeq,omitempty"`
}

// VerifyResponse carries NoChain rather than only a nil Report, because
// "the selected scope has never recorded an event" and "verification
// produced nothing" are different answers and the page says which.
//
// NoChain is about one scope. Chronicle keeps a chain per app and tenant, so
// an app-wide viewer whose events all sit under tenants gets NoChain for its
// own app-level scope while each tenant's chain, listed by streams.list, has
// events and can be verified by naming it.
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
// HashScheme is the event's own recorded scheme, verbatim, which can be
// empty, and what an empty one means depends on where the event sits.
// Below the stream's pin (or on a chain with no pin) it means the row
// predates schemes being recorded: its digest was resolved by the tolerant,
// pre-migration fallback (trying the historical unkeyed schemes in turn)
// rather than checked against a claimed one, and Keyed is false for it. At or
// above the pin an empty scheme is not history, since clearing the column is
// how a downgrade would buy the tolerant path, so it comes back Valid false.
//
// Two further limits bound what a caller may conclude from Valid, and
// neither can be recovered from the response:
//
//   - On an unkeyed chain, Valid true does not rule out a rewrite. The
//     digest is reproducible by anyone who can write to the store, so a
//     rewritten event that also recomputed its own hash and PrevHash passes
//     this check the same as an untouched one.
//   - This checks only the event's own digest against its claimed PrevHash,
//     never whether that PrevHash matches the event actually stored before
//     it. It says nothing about the event's place in the chain. Chain
//     linkage needs verify.run over a range around the event.
//
// A downgrade (an event claiming a weaker scheme than its stream pins at
// that sequence, which verify.Report surfaces as its own Downgrades list)
// has no representation here at all: it can only come back as Valid false,
// indistinguishable from ordinary edited content. Telling the two apart
// needs verify.run over a range around the event, not this intent.
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

// newVerifier builds the verifier the same way the admin API does. The two
// answer the same question and must not disagree about what evidence they
// consulted. Checkpoints and signer travel together or not at all: a checkpoint store without a signer proves
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

// projectReport copies every field of a verify.Report onto its wire type.
// The scalar and slice fields are copied as they are, and the coverage,
// retained and checkpoint entries are converted one by one into their wire
// types. RetentionPolicies is not part of a verify.Report, so it is left at
// zero here and filled in by the handler. It is written out field by field
// on purpose, not as a loop over reflected fields: a report field added later
// without a matching line here is easy to spot, not a silent drop.
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

	for _, rg := range r.Retained {
		out.Retained = append(out.Retained, RetainedRangeDTO{
			FromSeq:   rg.FromSeq,
			ToSeq:     rg.ToSeq,
			RecordSeq: rg.RecordSeq,
			PolicyID:  rg.PolicyID,
			Backfill:  rg.Backfill,
		})
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
		v, err := scopeFromPrincipal(p, deps)
		if err != nil {
			return VerifyResponse{}, err
		}

		st, err := selectStream(ctx, deps, "verify.run", v, in.StreamID)
		if err != nil {
			return VerifyResponse{}, err
		}
		if st == nil {
			return VerifyResponse{NoChain: true}, nil
		}

		fromSeq, toSeq := resolveVerifySpan(in, st.HeadSeq)

		// Refuse a reversed range only when the CALLER supplied an explicit
		// ToSeq that resolved below fromSeq -- that is a mistake in the
		// request. A ToSeq resolved from the stream's own head must never be
		// refused this way, even when the head is 0: that is a wiped chain,
		// exactly the case checkClaimedHead exists to catch (a signed
		// checkpoint still asserting events the head no longer claims). The
		// resolved span there is 0, so memory is never at risk, and refusing
		// it here as "toSeq < fromSeq" would hide the headline tamper case
		// behind a generic bad-request error before VerifyChain ever runs.
		if in.ToSeq != 0 && toSeq < fromSeq {
			return VerifyResponse{}, &fcontract.Error{
				Code:    fcontract.CodeBadRequest,
				Message: "toSeq cannot be less than fromSeq",
			}
		}

		// A range that resolved with toSeq below fromSeq (the wiped-chain
		// case above, or an explicit FromSeq past a shorter head) covers no
		// sequences; span stays 0 rather than underflowing the subtraction.
		var span uint64
		if toSeq >= fromSeq {
			span = toSeq - fromSeq + 1
		}
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
		// keyed chain plain and walk past every downgrade check. The scope
		// is the chain's own, not the viewer's: an app-wide viewer verifying
		// a tenant's chain reads that tenant's events.
		report, err := newVerifier(deps).VerifyChain(ctx, &verify.Input{
			StreamID: st.ID,
			FromSeq:  in.FromSeq,
			ToSeq:    in.ToSeq,
			AppID:    st.AppID,
			TenantID: st.TenantID,
			Pin:      hash.Pin{Scheme: hash.Scheme(st.Scheme), Since: st.SchemeSince},
			HeadSeq:  st.HeadSeq,
			HeadHash: st.HeadHash,
		})
		if err != nil {
			return VerifyResponse{}, deps.mapStoreError("verify.run", err)
		}

		out := VerifyResponse{Report: projectReport(report)}
		if out.Report != nil {
			out.Report.RetentionPolicies = verifyRetentionPolicyCount(ctx, deps, st.AppID, st.TenantID)
		}
		return out, nil
	}
}

// verifyRetentionPolicyCount counts the policies that can purge the chain
// (appID, tenantID), for VerifyReport.RetentionPolicies. It lists the whole
// app, because an app-level policy (empty TenantID) covers every tenant's
// chain and a tenant viewer's own scope would miss it; then it keeps the
// app-level policies and the chain's own tenant's. A sibling tenant's policy
// never touches this chain, so counting it would read a real deletion as a
// possible purge. A store error is logged and answered as -1 ("unknown"):
// the report is still true without this number.
func verifyRetentionPolicyCount(ctx context.Context, deps Deps, appID, tenantID string) int {
	policies, err := deps.Store.ListPolicies(ctx, retention.ListPoliciesOpts{
		Scope: retention.Scope{AppID: appID},
		Limit: -1,
	})
	if err != nil {
		deps.logger().Error("chronicle/contract: count retention policies for verify.run failed",
			log.String("contributor", contributorName),
			log.String("op", "verify.run"),
			log.Error(err),
		)
		return -1
	}

	n := 0
	for _, p := range policies {
		// AppID is checked again here rather than trusted to the listing:
		// the stores read an empty AppID as every app.
		if p != nil && p.AppID == appID && (p.TenantID == "" || p.TenantID == tenantID) {
			n++
		}
	}
	return n
}

func verifyEventHandler(deps Deps) func(context.Context, VerifyEventInput, fcontract.Principal) (VerifyEventResponse, error) {
	return func(ctx context.Context, in VerifyEventInput, p fcontract.Principal) (VerifyEventResponse, error) {
		v, err := scopeFromPrincipal(p, deps)
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
		if event == nil {
			return VerifyEventResponse{}, errNotFound()
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

		// Chronicle.VerifyEvent resolves the event's stream itself, with a raw
		// GetStreamByScope(event.AppID, event.TenantID) that carries none of
		// scopedStream's collision guard. store/redis builds its scope key as
		// appID + ":" + tenantID, so app "a:b"/tenant "c" and app "a"/tenant
		// "b:c" can resolve to the same row on that backend; handed the wrong
		// stream, VerifyEvent checks the event against the wrong pin, and a
		// downgraded event can come back valid:true under a pin that never
		// should have applied to it. Re-resolve the event's own scope through
		// scopedStream here, and refuse before ever calling VerifyEvent if it
		// does not land on the event's own stream.
		eventScope := viewScope{AppID: event.AppID, TenantID: event.TenantID}
		st, err := scopedStream(ctx, deps, "verify.event", eventScope)
		if err != nil {
			return VerifyEventResponse{}, err
		}
		if st == nil || st.ID != event.StreamID {
			resolvedID := "none"
			if st != nil {
				resolvedID = st.ID.String()
			}
			deps.logger().Error("chronicle/contract: verify.event resolved a chain that does not match the event's own",
				log.String("op", "verify.event"),
				log.String("event_id", event.ID.String()),
				log.String("event_stream_id", event.StreamID.String()),
				log.String("resolved_stream_id", resolvedID),
			)
			return VerifyEventResponse{}, &fcontract.Error{
				Code:    fcontract.CodeInternal,
				Message: "the audit store returned a chain outside this event's scope",
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
