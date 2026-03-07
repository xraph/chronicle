package handler

import (
	"fmt"
	"net/http"

	"github.com/xraph/forge"
	log "github.com/xraph/go-utils/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle/verify"
)

// verifyChain handles POST /v1/verify.
func (a *API) verifyChain(ctx forge.Context, req *VerifyChainRequest) (*verify.Report, error) {
	c := scopedContext(ctx)
	if err := requireScope(c); err != nil {
		return nil, err
	}

	if req.StreamID == "" {
		return nil, forge.BadRequest("stream_id is required")
	}
	if req.ToSeq == 0 {
		return nil, forge.BadRequest("to_seq must be greater than 0")
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

	input := &verify.Input{
		StreamID: streamID,
		FromSeq:  req.FromSeq,
		ToSeq:    req.ToSeq,
	}

	verifier := verify.NewVerifier(a.deps.VerifyStore)
	report, err := verifier.VerifyChain(c, input)
	if err != nil {
		a.deps.Logger.Error("failed to verify chain", log.String("stream_id", req.StreamID), log.Error(err))
		return nil, fmt.Errorf("verify chain: %w", err)
	}

	return report, ctx.JSON(http.StatusOK, report)
}
