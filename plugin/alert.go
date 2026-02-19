package plugin

// AlertRule defines criteria for triggering alerts.
type AlertRule struct {
	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`
	Action   string `json:"action,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
}
