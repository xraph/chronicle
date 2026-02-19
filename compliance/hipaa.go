package compliance

import (
	"context"
	"fmt"
)

// HIPAAInput defines inputs for HIPAA audit report generation.
type HIPAAInput struct {
	Period      DateRange `json:"period"`
	AppID       string    `json:"app_id" optional:"true"`
	TenantID    string    `json:"tenant_id,omitempty" optional:"true"`
	GeneratedBy string    `json:"generated_by" optional:"true"`
}

// hipaaSections defines the standard HIPAA audit report sections.
var hipaaSections = []sectionDef{
	{
		title:      "PHI Access",
		categories: []string{"data"},
		notes:      "Protected Health Information access events including patient and health data interactions.",
	},
	{
		title:      "Authentication Logs",
		categories: []string{"auth"},
		notes:      "Authentication events for all users accessing the system.",
	},
	{
		title:    "Security Incidents",
		severity: []string{"warning", "critical"},
		notes:    "Security incidents that may indicate unauthorized access or data breaches.",
	},
	{
		title:   "Data Disposition",
		actions: []string{"delete", "purge"},
		notes:   "Data deletion and purge events related to PHI lifecycle management.",
	},
}

// buildHIPAA generates a HIPAA compliance report.
func (e *Engine) buildHIPAA(ctx context.Context, input *HIPAAInput) ([]Section, error) {
	sections := make([]Section, 0, len(hipaaSections))

	for _, def := range hipaaSections {
		section, err := e.buildSection(ctx, def, input.Period, input.AppID, input.TenantID)
		if err != nil {
			return nil, fmt.Errorf("building section %q: %w", def.title, err)
		}
		sections = append(sections, section)
	}

	return sections, nil
}
