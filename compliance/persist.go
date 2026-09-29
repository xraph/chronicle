package compliance

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/xraph/chronicle/verify"
)

// reportBody is the part of a Report a backend stores in its single data
// column: everything that is not a scalar column of its own.
//
// Backends used to store Sections alone there, so Stats and Verification were
// dropped on save and every report read back through GetReport, which is what
// the export route does, came out without them. One shared shape keeps every
// backend storing the same thing.
type reportBody struct {
	Sections          []Section          `json:"sections"`
	Stats             *Stats             `json:"stats,omitempty"`
	Verification      *verify.Report     `json:"verification,omitempty"`
	VerificationScope *VerificationScope `json:"verification_scope,omitempty"`
}

// EncodeReportBody serialises the parts of r a backend keeps in its data
// column. DecodeReportBody reverses it.
func EncodeReportBody(r *Report) ([]byte, error) {
	data, err := json.Marshal(reportBody{
		Sections:          r.Sections,
		Stats:             r.Stats,
		Verification:      r.Verification,
		VerificationScope: r.VerificationScope,
	})
	if err != nil {
		return nil, fmt.Errorf("compliance: encode report body: %w", err)
	}
	return data, nil
}

// DecodeReportBody fills r's Sections, Stats, Verification and
// VerificationScope from data written by EncodeReportBody.
//
// It also reads the older form, a bare JSON array of sections. A report
// stored that way never kept its stats or verification, so those stay nil and
// the report reads as unverified, which is what it is.
func DecodeReportBody(data []byte, r *Report) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &r.Sections); err != nil {
			return fmt.Errorf("compliance: decode report sections: %w", err)
		}
		return nil
	}

	var body reportBody
	if err := json.Unmarshal(trimmed, &body); err != nil {
		return fmt.Errorf("compliance: decode report body: %w", err)
	}
	r.Sections = body.Sections
	r.Stats = body.Stats
	r.Verification = body.Verification
	r.VerificationScope = body.VerificationScope
	return nil
}
