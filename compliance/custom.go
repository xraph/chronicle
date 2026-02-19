package compliance

import (
	"context"
	"fmt"
)

// CustomInput defines inputs for a custom compliance report.
type CustomInput struct {
	Title       string          `json:"title"`
	Period      DateRange       `json:"period"`
	AppID       string          `json:"app_id" optional:"true"`
	TenantID    string          `json:"tenant_id,omitempty" optional:"true"`
	GeneratedBy string          `json:"generated_by" optional:"true"`
	Sections    []CustomSection `json:"sections"`
}

// CustomSection defines a section in a custom compliance report.
type CustomSection struct {
	Title      string   `json:"title"`
	Categories []string `json:"categories,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	Severity   []string `json:"severity,omitempty"`
	Notes      string   `json:"notes,omitempty"`
}

// buildCustom generates a custom compliance report from user-defined sections.
func (e *Engine) buildCustom(ctx context.Context, input *CustomInput) ([]Section, error) {
	sections := make([]Section, 0, len(input.Sections))

	for _, cs := range input.Sections {
		def := sectionDef{
			title:      cs.Title,
			categories: cs.Categories,
			actions:    cs.Actions,
			severity:   cs.Severity,
			notes:      cs.Notes,
		}

		section, err := e.buildSection(ctx, def, input.Period, input.AppID, input.TenantID)
		if err != nil {
			return nil, fmt.Errorf("building custom section %q: %w", cs.Title, err)
		}
		sections = append(sections, section)
	}

	return sections, nil
}
