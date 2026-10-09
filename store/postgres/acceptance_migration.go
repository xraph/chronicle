package postgres

import (
	"context"
	"errors"

	"github.com/xraph/grove/migrate"
)

func init() {
	Migrations.MustRegister(&migrate.Migration{
		Name: "add_acceptance_tombstones", Version: "20261009000001",
		Up: func(ctx context.Context, exec migrate.Executor) error {
			_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS chronicle_acceptances (
 source_identity TEXT PRIMARY KEY,
 receipt JSONB NOT NULL
);
ALTER TABLE chronicle_events ADD COLUMN IF NOT EXISTS lossless_metadata BOOLEAN NOT NULL DEFAULT FALSE;`)
			return err
		},
		// Tombstones have no event foreign key or expiry. Payload erasure and
		// retention must never reopen an accepted source delivery.
		Down: func(context.Context, migrate.Executor) error {
			return errors.New("chronicle: acceptance tombstones require coordinated publisher retirement before removal")
		},
	})
}
