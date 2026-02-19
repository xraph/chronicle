package compliance

import (
	"context"
	"fmt"

	"github.com/xraph/chronicle/audit"
)

// SOC2Input defines inputs for SOC2 Type II report generation.
type SOC2Input struct {
	Period      DateRange `json:"period"`
	AppID       string    `json:"app_id" optional:"true"`
	TenantID    string    `json:"tenant_id,omitempty" optional:"true"`
	GeneratedBy string    `json:"generated_by" optional:"true"`
}

// soc2Sections defines the standard SOC2 Type II report sections.
var soc2Sections = []sectionDef{
	{
		title:      "CC6.1 Logical Access",
		categories: []string{"auth", "access"},
		actions:    []string{"login", "logout", "access.grant", "access.revoke"},
		notes:      "Logical access controls including user authentication and authorization events.",
	},
	{
		title:      "CC6.2 Authentication Events",
		categories: []string{"auth"},
		notes:      "Authentication events including success and failure rates.",
	},
	{
		title:      "CC6.3 Data Access",
		categories: []string{"data"},
		actions:    []string{"read", "write", "delete"},
		notes:      "Data access events including reads, writes, and deletions.",
	},
	{
		title:    "CC7.2 Security Incidents",
		severity: []string{"warning", "critical"},
		notes:    "Security incidents including warnings and critical events.",
	},
	{
		title:      "CC8.1 Change Management",
		categories: []string{"config", "deployment"},
		notes:      "Change management events including configuration and deployment changes.",
	},
}

// buildSOC2 generates a SOC2 Type II compliance report.
func (e *Engine) buildSOC2(ctx context.Context, input *SOC2Input) ([]Section, error) {
	sections := make([]Section, 0, len(soc2Sections))

	for _, def := range soc2Sections {
		section, err := e.buildSection(ctx, def, input.Period, input.AppID, input.TenantID)
		if err != nil {
			return nil, fmt.Errorf("building section %q: %w", def.title, err)
		}
		sections = append(sections, section)
	}

	return sections, nil
}

// sectionDef is an internal definition for a report section template.
type sectionDef struct {
	title      string
	categories []string
	actions    []string
	severity   []string
	notes      string
}

// buildSection queries audit data and assembles a single report section.
func (e *Engine) buildSection(ctx context.Context, def sectionDef, period DateRange, appID, tenantID string) (Section, error) {
	q := &audit.Query{
		After:      period.From,
		Before:     period.To,
		AppID:      appID,
		TenantID:   tenantID,
		Categories: def.categories,
		Actions:    def.actions,
		Severity:   def.severity,
		Limit:      1000,
		Order:      "asc",
	}

	result, err := e.auditStore.Query(ctx, q)
	if err != nil {
		return Section{}, fmt.Errorf("querying events: %w", err)
	}

	// Build aggregate stats for the section.
	aggQ := &audit.AggregateQuery{
		After:    period.From,
		Before:   period.To,
		AppID:    appID,
		TenantID: tenantID,
		GroupBy:  []string{"outcome", "severity"},
	}

	aggResult, err := e.auditStore.Aggregate(ctx, aggQ)
	if err != nil {
		return Section{}, fmt.Errorf("aggregating events: %w", err)
	}

	return Section{
		Title:  def.title,
		Events: result.Events,
		Stats:  aggResult,
		Notes:  def.notes,
	}, nil
}
