package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/internal/acceptancetest"
	"github.com/xraph/chronicle/sink"
	"github.com/xraph/chronicle/store"
)

func TestAcceptance(t *testing.T) {
	acceptancetest.Run(t, func(t *testing.T) store.Store { return openMigratedPostgres(t) })
}

func TestAcceptanceRollback(t *testing.T) {
	s := openMigratedPostgres(t)
	ctx := context.Background()
	// Fail the final receipt insertion, after stream/event/head writes.
	if _, err := s.pg.NewRaw(`CREATE FUNCTION refuse_acceptance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'receipt rejected'; END $$; CREATE TRIGGER refuse_acceptance BEFORE INSERT ON chronicle_acceptances FOR EACH ROW EXECUTE FUNCTION refuse_acceptance();`).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := s.Accept(ctx, acceptancetest.Request(), &hash.Chain{}, nil); err == nil || r != nil {
		t.Fatalf("got %+v %v", r, err)
	}
	for _, table := range []string{"chronicle_events", "chronicle_streams", "chronicle_acceptances"} {
		var count int
		if err := s.pg.NewRaw("SELECT count(*) FROM "+table).Scan(ctx, &count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
	if _, err := s.pg.NewRaw("DROP TRIGGER refuse_acceptance ON chronicle_acceptances").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	receipt, err := s.Accept(ctx, acceptancetest.Request(), &hash.Chain{}, nil)
	if err != nil || receipt.Sequence != 1 {
		t.Fatalf("retry: %+v %v", receipt, err)
	}
	// The caller loses its acknowledgement and retries with a nil hasher and
	// failing prepare: an existing receipt must precede both dependencies.
	recovered, err := s.Accept(ctx, acceptancetest.Request(), nil, func(*audit.Event) error { return errors.New("unavailable") })
	if err != nil || recovered.EventID != receipt.EventID {
		t.Fatalf("recovery: %+v %v", recovered, err)
	}
}

func TestAcceptanceScheme(t *testing.T) { acceptancetest.Scheme(t, openMigratedPostgres(t)) }

func TestAcceptanceArchiveRestoresExactMetadata(t *testing.T) {
	s := openMigratedPostgres(t)
	ctx := context.Background()
	receipt, err := s.Accept(ctx, acceptancetest.Request(), &hash.Chain{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	event, err := s.Get(ctx, receipt.EventID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.PurgeEvents(ctx, []id.ID{event.ID}); err != nil {
		t.Fatal(err)
	}
	if err = sink.DecodeArchive(bytes.NewReader(encoded), "snapshot", func(e *audit.Event, _ string) error { return s.AppendBatch(ctx, []*audit.Event{e}) }); err != nil {
		t.Fatal(err)
	}
	restored, err := s.Get(ctx, receipt.EventID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (&hash.Chain{}).VerifyWithPin(ctx, restored.PrevHash, restored, hash.Pin{Scheme: hash.SchemePlainV4, Since: 1})
	if err != nil || !result.OK {
		t.Fatalf("restored exact metadata: %+v %v", restored.Metadata, err)
	}
	replay, err := s.Accept(ctx, acceptancetest.Request(), nil, nil)
	if err != nil || replay.EventID != receipt.EventID {
		t.Fatalf("restored receipt: %+v %v", replay, err)
	}
}
