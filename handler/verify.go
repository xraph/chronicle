package handler

import (
	"fmt"
	"net/http"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/verify"
)

// newVerifier builds the verifier POST /v1/verify runs, checking signed
// checkpoints when this deployment configured both a store to hold them and
// a signer to check them under, and falling back to plain chain verification
// when it did not.
//
// Both have to be present. A checkpoint store on its own gives a verifier
// rows it cannot authenticate, and the extension only ever sets the pair
// together, so the guard is a real "checkpoints are configured here" test
// rather than defensive noise. Without them this route reports no
// checkpoints and its coverage ladder tops out at keyed, which is what every
// deployment that has not turned checkpointing on should see.
func (a *API) newVerifier() *verify.Verifier {
	if a.deps.CheckpointStore == nil || a.deps.CheckpointSigner == nil {
		return verify.NewVerifierWithChain(a.deps.VerifyStore, a.deps.HashChain)
	}
	return verify.NewVerifierWithCheckpoints(
		a.deps.VerifyStore, a.deps.HashChain, a.deps.CheckpointStore, a.deps.CheckpointSigner)
}

// verifyChain handles POST /v1/verify.
func (a *API) verifyChain(ctx forge.Context, req *VerifyChainRequest) (*verify.Report, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if req.StreamID == "" {
		return nil, forge.BadRequest("stream_id is required")
	}

	streamID, err := parseStreamID(req.StreamID)
	if err != nil {
		return nil, forge.BadRequest("invalid stream_id")
	}

	c, span := a.tracer.Start(c, "chronicle.verifyChain",
		trace.WithAttributes(
			attribute.String("stream_id", req.StreamID),
			attribute.String("from_seq", fmt.Sprintf("%d", req.FromSeq)),
			attribute.String("to_seq", fmt.Sprintf("%d", req.ToSeq)),
		))
	defer span.End()

	// Security-critical: confirm the caller owns the stream. Without this, any
	// caller could verify another tenant's chain, learning its event count,
	// sequence range and integrity status.
	if a.deps.StreamStore == nil {
		return nil, forge.NewHTTPError(
			http.StatusServiceUnavailable,
			"stream store not configured; chain verification cannot confirm stream ownership",
		)
	}

	st, err := a.deps.StreamStore.GetStream(c, streamID)
	if err != nil {
		return nil, mapStoreError(err)
	}
	if !ownedByCaller(c, st.AppID, st.TenantID) {
		return nil, forge.NotFound("stream not found")
	}

	input := &verify.Input{
		StreamID: streamID,
		FromSeq:  req.FromSeq,
		ToSeq:    req.ToSeq,
		Pin:      hash.Pin{Scheme: hash.Scheme(st.Scheme), Since: st.SchemeSince},
		HeadSeq:  st.HeadSeq,
		HeadHash: st.HeadHash,
	}

	report, err := a.newVerifier().VerifyChain(c, input)
	if err != nil {
		a.deps.Logger.Error("failed to verify chain", log.String("stream_id", req.StreamID), log.Error(err))
		return nil, fmt.Errorf("verify chain: %w", err)
	}

	return report, nil
}
