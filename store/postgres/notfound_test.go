package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// Every getter that maps a missing row through groveError has to return the
// sentinel a caller can test for. Same table as the sqlite side, because the
// two backends owe callers the same contract: a row that is not there is a
// miss, not an internal failure.
//
// This is the one the postgres package was missing entirely. groveError here
// is character for character the mapping in store/sqlite/store.go, and the
// sqlite copy is pinned by TestMissingRowsReturnTheNotFoundSentinels over
// there. Until this existed, the claim that the same three checks also catch a
// pgx miss rested on reading pgx's source, never on a run against a database.
//
// Keep the rows in step with the sqlite copy. The point of two identical
// tables is that a getter added to one backend and forgotten in the other
// shows up as a diff between these two files.
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

// A pgx miss has to satisfy errors.Is against sql.ErrNoRows, not merely say so
// in its message.
//
// groveError's third check is a strings.Contains on "no rows in result set",
// and that is a loose net: any error whose text happens to contain the phrase
// becomes a not-found sentinel, including one that came back from a query that
// did find rows and then failed for some other reason. The only reason the
// check is safe to delete is that the two errors.Is checks ahead of it already
// cover every driver in the tree. pgx v5 defines ErrNoRows as a proxy error
// wrapping database/sql's, which is what makes the sql.ErrNoRows check catch
// it, and that is a property of pgx rather than of anything in this repo. So
// pin it. If a pgx upgrade ever stops proxying, this fails here instead of
// quietly demoting every postgres miss to a raw driver error the day the
// fallback goes.
//
// No database needed, so it runs everywhere the rest of the file skips.
func TestPgxNoRowsProxiesDatabaseSQL(t *testing.T) {
	if !errors.Is(pgx.ErrNoRows, sql.ErrNoRows) {
		t.Fatalf("errors.Is(pgx.ErrNoRows, sql.ErrNoRows) is false; groveError's sql.ErrNoRows check no longer catches a pgx miss")
	}
}
