package sqlite

import (
	"context"

	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Chronicle SQLite store.
var Migrations = func() *migrate.Group {
	g := migrate.NewGroup("chronicle")
	g.MustRegister(
		&migrate.Migration{
			Name:    "create_streams_table",
			Version: "20240101000000",
			Comment: "Create chronicle_streams table",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_streams (
    id          TEXT PRIMARY KEY,
    app_id      TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT '',
    head_hash   TEXT NOT NULL DEFAULT '',
    head_seq    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(app_id, tenant_id)
);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS chronicle_streams;`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_events_table",
			Version: "20240101000001",
			Comment: "Create chronicle_events table with hash chain columns",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_events (
    id              TEXT PRIMARY KEY,
    stream_id       TEXT NOT NULL REFERENCES chronicle_streams(id),
    sequence        INTEGER NOT NULL,
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
    metadata        TEXT DEFAULT '{}',
    outcome         TEXT NOT NULL DEFAULT 'success',
    severity        TEXT NOT NULL DEFAULT 'info',
    reason          TEXT NOT NULL DEFAULT '',

    -- GDPR
    subject_id          TEXT NOT NULL DEFAULT '',
    encryption_key_id   TEXT NOT NULL DEFAULT '',
    erased              INTEGER NOT NULL DEFAULT 0,
    erased_at           TEXT,
    erasure_id          TEXT,

    timestamp       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(stream_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_scope
    ON chronicle_events (app_id, tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_category
    ON chronicle_events (category, timestamp);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_action
    ON chronicle_events (action, outcome, timestamp);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_user
    ON chronicle_events (user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_subject
    ON chronicle_events (subject_id);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_severity
    ON chronicle_events (severity, timestamp);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_resource
    ON chronicle_events (resource, resource_id, timestamp);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS chronicle_events;`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_erasures_table",
			Version: "20240101000002",
			Comment: "Create chronicle_erasures table",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_erasures (
    id              TEXT PRIMARY KEY,
    subject_id      TEXT NOT NULL,
    reason          TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    events_affected INTEGER NOT NULL DEFAULT 0,
    key_destroyed   INTEGER NOT NULL DEFAULT 0,
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_chronicle_erasures_subject ON chronicle_erasures (subject_id);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS chronicle_erasures;`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_retention_tables",
			Version: "20240101000003",
			Comment: "Create chronicle_retention_policies and chronicle_archives tables",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_retention_policies (
    id          TEXT PRIMARY KEY,
    category    TEXT NOT NULL UNIQUE,
    duration    INTEGER NOT NULL,
    archive     INTEGER NOT NULL DEFAULT 0,
    app_id      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chronicle_archives (
    id              TEXT PRIMARY KEY,
    policy_id       TEXT NOT NULL,
    category        TEXT NOT NULL,
    event_count     INTEGER NOT NULL,
    from_timestamp  TEXT NOT NULL,
    to_timestamp    TEXT NOT NULL,
    sink_name       TEXT NOT NULL,
    sink_ref        TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
DROP TABLE IF EXISTS chronicle_archives;
DROP TABLE IF EXISTS chronicle_retention_policies;
`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_reports_table",
			Version: "20240101000004",
			Comment: "Create chronicle_reports table",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
CREATE TABLE IF NOT EXISTS chronicle_reports (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    type        TEXT NOT NULL,
    period_from TEXT NOT NULL,
    period_to   TEXT NOT NULL,
    app_id      TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT '',
    format      TEXT NOT NULL DEFAULT 'json',
    data        TEXT NOT NULL,
    generated_by TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_chronicle_reports_scope ON chronicle_reports (app_id, tenant_id, created_at);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS chronicle_reports;`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "scope_retention_to_app_and_tenant",
			Version: "20240101000005",
			Comment: "Key retention policies per (app_id, tenant_id, category) and scope archives",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				// chronicle_retention_policies declared `category TEXT NOT NULL
				// UNIQUE` inline, which SQLite cannot drop with ALTER TABLE, so
				// the table is rebuilt. The INSERT names the pre-migration
				// columns explicitly; tenant_id takes its default. Any column
				// added to this table in a later migration must be appended to
				// the new CREATE TABLE, never to this copy list.
				_, err := exec.Exec(ctx, `
CREATE TABLE chronicle_retention_policies_new (
    id          TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    duration    INTEGER NOT NULL,
    archive     INTEGER NOT NULL DEFAULT 0,
    app_id      TEXT NOT NULL DEFAULT '',
    tenant_id   TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(app_id, tenant_id, category)
);

INSERT INTO chronicle_retention_policies_new
    (id, category, duration, archive, app_id, created_at, updated_at)
SELECT id, category, duration, archive, app_id, created_at, updated_at
FROM chronicle_retention_policies;

DROP TABLE chronicle_retention_policies;

ALTER TABLE chronicle_retention_policies_new RENAME TO chronicle_retention_policies;

ALTER TABLE chronicle_archives ADD COLUMN app_id TEXT NOT NULL DEFAULT '';
ALTER TABLE chronicle_archives ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_chronicle_archives_scope
    ON chronicle_archives (app_id, tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_chronicle_events_retention
    ON chronicle_events (app_id, tenant_id, category, timestamp);
`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `
DROP INDEX IF EXISTS idx_chronicle_events_retention;
DROP INDEX IF EXISTS idx_chronicle_archives_scope;

CREATE TABLE chronicle_archives_old (
    id              TEXT PRIMARY KEY,
    policy_id       TEXT NOT NULL,
    category        TEXT NOT NULL,
    event_count     INTEGER NOT NULL,
    from_timestamp  TEXT NOT NULL,
    to_timestamp    TEXT NOT NULL,
    sink_name       TEXT NOT NULL,
    sink_ref        TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO chronicle_archives_old
    (id, policy_id, category, event_count, from_timestamp, to_timestamp, sink_name, sink_ref, created_at)
SELECT id, policy_id, category, event_count, from_timestamp, to_timestamp, sink_name, sink_ref, created_at
FROM chronicle_archives;
DROP TABLE chronicle_archives;
ALTER TABLE chronicle_archives_old RENAME TO chronicle_archives;

CREATE TABLE chronicle_retention_policies_old (
    id          TEXT PRIMARY KEY,
    category    TEXT NOT NULL UNIQUE,
    duration    INTEGER NOT NULL,
    archive     INTEGER NOT NULL DEFAULT 0,
    app_id      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO chronicle_retention_policies_old
    (id, category, duration, archive, app_id, created_at, updated_at)
SELECT id, category, duration, archive, app_id, created_at, updated_at
FROM chronicle_retention_policies
GROUP BY category;
DROP TABLE chronicle_retention_policies;
ALTER TABLE chronicle_retention_policies_old RENAME TO chronicle_retention_policies;
`)
				return err
			},
		},
	)
	return g
}()
