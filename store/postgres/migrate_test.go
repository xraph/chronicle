package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestMigrateOnACurrentSchemaTakesNoTableLocks is the regression test for
// Migrate deadlocking against live writers. It used to run every migration's
// ALTER TABLE on each call, and ALTER TABLE waits for an ACCESS EXCLUSIVE lock
// even when the column is already there. A process starting up next to one
// that was appending could deadlock with it.
//
// The transaction below holds the lock an INSERT takes on chronicle_events, the
// way an append in flight does. A second Migrate on a schema that is already
// current has nothing to apply and must return without waiting on it.
func TestMigrateOnACurrentSchemaTakesNoTableLocks(t *testing.T) {
	s, dsn := openLivePostgres(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `LOCK TABLE chronicle_events IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock chronicle_events: %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.Migrate(waitCtx); err != nil {
		if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
			t.Fatalf("second Migrate blocked behind a writer's lock on chronicle_events: %v", err)
		}
		t.Fatalf("second Migrate: %v", err)
	}
}

// Several processes starting at once all migrate the same fresh database. One
// applies the migrations and the rest wait for it, then find nothing to do.
func TestConcurrentMigrateOnAFreshSchema(t *testing.T) {
	s, _ := openLivePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const n = 4
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Migrate(ctx)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("Migrate %d: %v", i, err)
		}
	}

	var applied int
	if err := s.pg.QueryRow(ctx, `SELECT count(*) FROM grove_migrations WHERE "group" = 'chronicle'`).Scan(&applied); err != nil {
		t.Fatalf("count applied migrations: %v", err)
	}
	if want := len(Migrations.Migrations()); applied != want {
		t.Errorf("grove_migrations holds %d chronicle migrations, want %d (each applied once)", applied, want)
	}
}
