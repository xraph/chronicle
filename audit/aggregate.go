package audit

import (
	"errors"
	"fmt"
)

// Errors returned when validating an aggregate query's grouping fields.
var (
	// ErrEmptyGroupBy is returned when an aggregate query names no fields.
	ErrEmptyGroupBy = errors.New("aggregate query requires at least one group_by field")

	// ErrUnsupportedGroupBy is returned when a group_by field is not one of the
	// fields an aggregate query is allowed to group on.
	ErrUnsupportedGroupBy = errors.New("unsupported group_by field")

	// ErrDuplicateGroupBy is returned when the same field is named twice.
	ErrDuplicateGroupBy = errors.New("duplicate group_by field")
)

// groupByColumns maps each accepted group_by field to the physical column name
// the SQL backends may interpolate.
//
// Security-critical: SQL backends build their SELECT and GROUP BY clauses by
// string interpolation, which no placeholder can protect (an identifier is not
// a bindable value). The values in this map are compile-time constants, so
// interpolating a *resolved* column can never carry caller-supplied bytes.
// Callers must interpolate what ResolveGroupBy returns, never their own input.
var groupByColumns = map[string]string{
	"category": "category",
	"action":   "action",
	"outcome":  "outcome",
	"severity": "severity",
	"resource": "resource",
}

// ResolveGroupBy validates the requested group_by fields and returns the
// physical column names to group on, in the order requested.
//
// Validation happens before any query is built. Matching is exact: no trimming
// and no case folding, so a field either is a known identifier or is rejected.
func ResolveGroupBy(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return nil, ErrEmptyGroupBy
	}

	columns := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))

	for _, field := range fields {
		column, ok := groupByColumns[field]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedGroupBy, field)
		}
		if _, dup := seen[field]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateGroupBy, field)
		}
		seen[field] = struct{}{}
		columns = append(columns, column)
	}

	return columns, nil
}

// AssignGroupValue sets the AggregateGroup field named by field to value.
// It returns ErrUnsupportedGroupBy for any field outside the whitelist.
func AssignGroupValue(g *AggregateGroup, field, value string) error {
	target, err := groupFieldPointer(g, field)
	if err != nil {
		return err
	}
	*target = value
	return nil
}

// GroupFieldPointer returns a pointer to the AggregateGroup field named by
// field, for use as a row-scan destination.
func GroupFieldPointer(g *AggregateGroup, field string) (*string, error) {
	return groupFieldPointer(g, field)
}

func groupFieldPointer(g *AggregateGroup, field string) (*string, error) {
	switch field {
	case "category":
		return &g.Category, nil
	case "action":
		return &g.Action, nil
	case "outcome":
		return &g.Outcome, nil
	case "severity":
		return &g.Severity, nil
	case "resource":
		return &g.Resource, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedGroupBy, field)
	}
}
