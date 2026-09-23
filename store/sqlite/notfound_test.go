package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
)

// Every getter that maps a missing row through groveError has to return the
// sentinel a caller can test for.
//
// It did not. grove hands sqlite's driver error straight through, and that
// error is database/sql's "sql: no rows in result set". groveError matched the
// bare "no rows in result set", which is pgx's wording, so on sqlite every
// single one of these returned the raw driver error instead. A caller asking
// errors.Is(err, chronicle.ErrEventNotFound) got false and had to treat a
// perfectly ordinary miss as an internal failure.
func TestMissingRowsReturnTheNotFoundSentinels(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, tc := range []struct {
		name string
		call func() error
		want error
	}{
		{"Get", func() error { _, err := s.Get(ctx, id.NewAuditID()); return err }, chronicle.ErrEventNotFound},
		{"GetStream", func() error { _, err := s.GetStream(ctx, id.NewStreamID()); return err }, chronicle.ErrStreamNotFound},
		{"GetPolicy", func() error { _, err := s.GetPolicy(ctx, id.NewPolicyID()); return err }, chronicle.ErrPolicyNotFound},
		{"GetReport", func() error { _, err := s.GetReport(ctx, id.NewReportID()); return err }, chronicle.ErrReportNotFound},
		{"GetErasure", func() error { _, err := s.GetErasure(ctx, id.NewErasureID()); return err }, chronicle.ErrErasureNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatalf("%s on a missing row returned no error", tc.name)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("%s returned %v, want it to wrap %v", tc.name, err, tc.want)
			}
		})
	}
}
