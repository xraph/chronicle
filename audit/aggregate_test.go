package audit

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveGroupByAcceptsWhitelistedFields(t *testing.T) {
	for _, field := range []string{"category", "action", "outcome", "severity", "resource"} {
		cols, err := ResolveGroupBy([]string{field})
		if err != nil {
			t.Fatalf("ResolveGroupBy(%q): unexpected error: %v", field, err)
		}
		if len(cols) != 1 || cols[0] != field {
			t.Fatalf("ResolveGroupBy(%q) = %v, want [%s]", field, cols, field)
		}
	}
}

func TestResolveGroupByRejectsInjection(t *testing.T) {
	payloads := []string{
		"category, (SELECT COUNT(*) FROM chronicle_streams)",
		"category; DROP TABLE chronicle_events",
		"category)--",
		"CAST((SELECT hash FROM chronicle_events LIMIT 1) AS int)",
		"*",
		"1",
		"user_id",
		"subject_id",
		"metadata",
		"category.nested",
		"CATEGORY",
		" category",
		"category ",
		"",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			cols, err := ResolveGroupBy([]string{payload})
			if err == nil {
				t.Fatalf("ResolveGroupBy(%q) accepted the payload, returned %v", payload, cols)
			}
			if !errors.Is(err, ErrUnsupportedGroupBy) {
				t.Fatalf("ResolveGroupBy(%q) error = %v, want ErrUnsupportedGroupBy", payload, err)
			}
			if !strings.Contains(err.Error(), "unsupported group_by field") {
				t.Fatalf("ResolveGroupBy(%q) message = %q, want it to mention the unsupported field", payload, err)
			}
			if cols != nil {
				t.Fatalf("ResolveGroupBy(%q) returned columns %v alongside an error", payload, cols)
			}
		})
	}
}

func TestResolveGroupByRequiresAtLeastOneField(t *testing.T) {
	_, err := ResolveGroupBy(nil)
	if err == nil {
		t.Fatal("ResolveGroupBy(nil) should fail")
	}
	if !errors.Is(err, ErrEmptyGroupBy) {
		t.Fatalf("error = %v, want ErrEmptyGroupBy", err)
	}
}

func TestResolveGroupByRejectsDuplicates(t *testing.T) {
	_, err := ResolveGroupBy([]string{"category", "category"})
	if err == nil {
		t.Fatal("ResolveGroupBy should reject a duplicated field")
	}
	if !errors.Is(err, ErrDuplicateGroupBy) {
		t.Fatalf("error = %v, want ErrDuplicateGroupBy", err)
	}
}

// TestResolveGroupByReturnsConstantColumns is the property that makes the SQL
// backends safe: the returned strings come from the package's own table, so no
// caller-supplied byte can ever reach an interpolated query.
func TestResolveGroupByReturnsConstantColumns(t *testing.T) {
	cols, err := ResolveGroupBy([]string{"resource", "category"})
	if err != nil {
		t.Fatalf("ResolveGroupBy: %v", err)
	}
	if len(cols) != 2 {
		t.Fatalf("expected 2 columns, got %d", len(cols))
	}
	for _, col := range cols {
		if !isBareIdentifier(col) {
			t.Fatalf("resolved column %q is not a bare identifier", col)
		}
	}
}

func isBareIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '_' && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

func TestAssignGroupValuePopulatesTheMatchingField(t *testing.T) {
	tests := []struct {
		field string
		check func(g AggregateGroup) string
	}{
		{"category", func(g AggregateGroup) string { return g.Category }},
		{"action", func(g AggregateGroup) string { return g.Action }},
		{"outcome", func(g AggregateGroup) string { return g.Outcome }},
		{"severity", func(g AggregateGroup) string { return g.Severity }},
		{"resource", func(g AggregateGroup) string { return g.Resource }},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			var g AggregateGroup
			if err := AssignGroupValue(&g, tt.field, "value"); err != nil {
				t.Fatalf("AssignGroupValue: %v", err)
			}
			if got := tt.check(g); got != "value" {
				t.Fatalf("field %s = %q, want %q", tt.field, got, "value")
			}
		})
	}
}

func TestGroupFieldPointerRejectsUnknownField(t *testing.T) {
	var g AggregateGroup
	if err := AssignGroupValue(&g, "user_id", "attacker"); err == nil {
		t.Fatal("AssignGroupValue should reject a non-whitelisted field")
	}
}

func TestResolveGroupByAcceptsTimeBuckets(t *testing.T) {
	for _, field := range []string{"day", "hour"} {
		cols, err := ResolveGroupBy([]string{field})
		if err != nil {
			t.Fatalf("ResolveGroupBy(%q): %v", field, err)
		}
		if len(cols) != 1 {
			t.Fatalf("ResolveGroupBy(%q) returned %d columns, want 1", field, len(cols))
		}
	}
}

func TestResolveGroupByStillRejectsUnknownFields(t *testing.T) {
	// "week" is deliberately not supported. The whitelist is what keeps
	// group_by out of the SQL string, so widening it by accident is a
	// injection surface and not merely a feature.
	if _, err := ResolveGroupBy([]string{"week"}); !errors.Is(err, ErrUnsupportedGroupBy) {
		t.Fatalf("ResolveGroupBy(week) error = %v, want ErrUnsupportedGroupBy", err)
	}
}

func TestResolveGroupByRejectsDuplicateBucket(t *testing.T) {
	if _, err := ResolveGroupBy([]string{"day", "day"}); !errors.Is(err, ErrDuplicateGroupBy) {
		t.Fatalf("ResolveGroupBy(day,day) error = %v, want ErrDuplicateGroupBy", err)
	}
}

func TestResolveGroupByPreservesRequestOrder(t *testing.T) {
	// The store backends zip the returned columns against the requested fields
	// to recover which bucket unit was asked for, because "day" and "hour"
	// share the "timestamp" column. That zip is only valid if order is preserved
	// one-for-one, so this test is what makes it safe to rely on.
	//
	// The field order below is deliberately NOT alphabetical ("outcome",
	// "day", "category" rather than "category", "day", "outcome"). An
	// implementation that sorted fields before resolving them would produce
	// the same output as a correct one on an already-sorted input, which
	// would make the test pass for the wrong reason. Don't "tidy" this back
	// into alphabetical order.
	fields := []string{"outcome", "day", "category"}
	cols, err := ResolveGroupBy(fields)
	if err != nil {
		t.Fatalf("ResolveGroupBy: %v", err)
	}
	if len(cols) != len(fields) {
		t.Fatalf("got %d columns for %d fields; the zip in every backend assumes one-for-one",
			len(cols), len(fields))
	}
	if cols[0] != "outcome" || cols[1] != "timestamp" || cols[2] != "category" {
		t.Fatalf("columns = %v, want [outcome timestamp category] in request order", cols)
	}
}

func TestResolveGroupByRejectsMultipleBucketFields(t *testing.T) {
	// "day" and "hour" are distinct field names, so the exact-duplicate check
	// does not catch this, but both map to the "timestamp" column and both
	// route through groupFieldPointer to the same &g.Bucket. Without this
	// check, the second assignment would silently overwrite the first.
	if _, err := ResolveGroupBy([]string{"day", "hour"}); !errors.Is(err, ErrMultipleBucketFields) {
		t.Fatalf("ResolveGroupBy(day,hour) error = %v, want ErrMultipleBucketFields", err)
	}
}

func TestResolveGroupByAcceptsSingleBucketWithDimension(t *testing.T) {
	// Guards against the multiple-bucket check over-rejecting: one bucket
	// field alongside an ordinary dimension is perfectly expressible and
	// must still succeed.
	cols, err := ResolveGroupBy([]string{"day", "category"})
	if err != nil {
		t.Fatalf("ResolveGroupBy(day,category): unexpected error: %v", err)
	}
	if len(cols) != 2 || cols[0] != "timestamp" || cols[1] != "category" {
		t.Fatalf("columns = %v, want [timestamp category]", cols)
	}
}
