package compliance

import (
	"context"
	"fmt"
)

// EUAIActInput defines inputs for EU AI Act transparency report generation.
type EUAIActInput struct {
	Period      DateRange `json:"period"`
	AppID       string    `json:"app_id" optional:"true"`
	TenantID    string    `json:"tenant_id,omitempty" optional:"true"`
	GeneratedBy string    `json:"generated_by" optional:"true"`
}

// euaiActSections defines the standard EU AI Act transparency report sections.
var euaiActSections = []sectionDef{
	{
		title:      "AI System Inventory",
		categories: []string{"ai", "ml"},
		notes:      "Inventory of AI and machine learning system events.",
	},
	{
		title:   "AI Decision Log",
		actions: []string{"decision", "prediction"},
		notes:   "Automated decision-making and prediction events requiring transparency.",
	},
	{
		title:      "AI Incidents",
		categories: []string{"ai"},
		severity:   []string{"warning", "critical"},
		notes:      "AI-related incidents including warnings and critical failures.",
	},
	{
		title:      "Data Governance",
		categories: []string{"data"},
		notes:      "Data governance events covering data processing and management.",
	},
	{
		title:   "Human Oversight",
		actions: []string{"review", "override"},
		notes:   "Human oversight events including manual reviews and decision overrides.",
	},
}

// buildEUAIAct generates an EU AI Act transparency report.
func (e *Engine) buildEUAIAct(ctx context.Context, input *EUAIActInput) ([]Section, error) {
	sections := make([]Section, 0, len(euaiActSections))

	for _, def := range euaiActSections {
		section, err := e.buildSection(ctx, def, input.Period, input.AppID, input.TenantID)
		if err != nil {
			return nil, fmt.Errorf("building section %q: %w", def.title, err)
		}
		sections = append(sections, section)
	}

	return sections, nil
}
