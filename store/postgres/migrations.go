package postgres

import (
	"context"

	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Chronicle store.
var Migrations = migrate.NewGroup("chronicle")

func init() {
	Migrations.MustRegister(
		&migrate.Migration{
			Name:    "create_streams_table",
			Version: "20240101000000",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_streams (
    id          TEXT PRIMARY KEY,
    app_id      TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT '',
    head_hash   TEXT NOT NULL DEFAULT '',
    head_seq    BIGINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(app_id, tenant_id)
);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS chronicle_streams CASCADE;`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_events_table",
			Version: "20240101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_events (
    id              TEXT PRIMARY KEY,
    stream_id       TEXT NOT NULL REFERENCES chronicle_streams(id),
    sequence        BIGINT NOT NULL,
    hash            TEXT NOT NULL,
    prev_hash       TEXT NOT NULL DEFAULT '',

    -- Scope
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    user_id         TEXT NOT NULL DEFAULT '',
    ip              TEXT NOT NULL DEFAULT '',

    -- What
    action          TEXT NOT NULL,
    resource        TEXT NOT NULL,
    category        TEXT NOT NULL,
    resource_id     TEXT NOT NULL DEFAULT '',
    metadata        JSONB DEFAULT '{}',
    outcome         TEXT NOT NULL DEFAULT 'success',
    severity        TEXT NOT NULL DEFAULT 'info',
    reason          TEXT NOT NULL DEFAULT '',

    -- GDPR
    subject_id          TEXT NOT NULL DEFAULT '',
    encryption_key_id   TEXT NOT NULL DEFAULT '',
    erased              BOOLEAN NOT NULL DEFAULT FALSE,
    erased_at           TIMESTAMPTZ,
    erasure_id          TEXT,

    timestamp       TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(stream_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_scope
    ON chronicle_events (app_id, tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_category
    ON chronicle_events (category, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_action
    ON chronicle_events (action, outcome, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_user
    ON chronicle_events (user_id, timestamp DESC)
    WHERE user_id != '';
CREATE INDEX IF NOT EXISTS idx_chronicle_events_subject
    ON chronicle_events (subject_id)
    WHERE subject_id != '';
CREATE INDEX IF NOT EXISTS idx_chronicle_events_severity
    ON chronicle_events (severity, timestamp DESC)
    WHERE severity IN ('warning', 'critical');
CREATE INDEX IF NOT EXISTS idx_chronicle_events_resource
    ON chronicle_events (resource, resource_id, timestamp DESC);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS chronicle_events CASCADE;`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_erasures_table",
			Version: "20240101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_erasures (
    id              TEXT PRIMARY KEY,
    subject_id      TEXT NOT NULL,
    reason          TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    events_affected BIGINT NOT NULL DEFAULT 0,
    key_destroyed   BOOLEAN NOT NULL DEFAULT FALSE,
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chronicle_erasures_subject ON chronicle_erasures (subject_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS chronicle_erasures CASCADE;`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_retention_tables",
			Version: "20240101000003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_retention_policies (
    id          TEXT PRIMARY KEY,
    category    TEXT NOT NULL UNIQUE,
    duration    BIGINT NOT NULL,
    archive     BOOLEAN NOT NULL DEFAULT FALSE,
    app_id      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS chronicle_archives (
    id              TEXT PRIMARY KEY,
    policy_id       TEXT NOT NULL,
    category        TEXT NOT NULL,
    event_count     BIGINT NOT NULL,
    from_timestamp  TIMESTAMPTZ NOT NULL,
    to_timestamp    TIMESTAMPTZ NOT NULL,
    sink_name       TEXT NOT NULL,
    sink_ref        TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
DROP TABLE IF EXISTS chronicle_archives CASCADE;
DROP TABLE IF EXISTS chronicle_retention_policies CASCADE;
`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_reports_table",
			Version: "20240101000004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_reports (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    type        TEXT NOT NULL,
    period_from TIMESTAMPTZ NOT NULL,
    period_to   TIMESTAMPTZ NOT NULL,
    app_id      TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT '',
    format      TEXT NOT NULL DEFAULT 'json',
    data        JSONB NOT NULL,
    generated_by TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chronicle_reports_scope ON chronicle_reports (app_id, tenant_id, created_at DESC);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS chronicle_reports CASCADE;`)
				return err
			},
		},
	)
}
