package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
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
//
// The two checkpoint getters joined the table when store/sqlite/checkpoint.go
// stopped keeping its own copy of the mapping. That copy was written to route
// around the bug above and so was never affected by it, which is exactly why
// nothing here noticed the bug on the checkpoint path. Now that both packages
// share one mapper, every caller of it is listed in one place.
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
		{"GetStreamByScope", func() error { _, err := s.GetStreamByScope(ctx, "no-such-app", ""); return err }, chronicle.ErrStreamNotFound},
		{"GetPolicy", func() error { _, err := s.GetPolicy(ctx, id.NewPolicyID()); return err }, chronicle.ErrPolicyNotFound},
		{"GetReport", func() error { _, err := s.GetReport(ctx, id.NewReportID()); return err }, chronicle.ErrReportNotFound},
		{"GetErasure", func() error { _, err := s.GetErasure(ctx, id.NewErasureID()); return err }, chronicle.ErrErasureNotFound},
		{"LatestCheckpoint", func() error { _, err := s.LatestCheckpoint(ctx, id.NewStreamID()); return err }, checkpoint.ErrNotFound},
		{"GetCheckpoint", func() error { _, err := s.GetCheckpoint(ctx, id.NewCheckpointID()); return err }, checkpoint.ErrNotFound},
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
