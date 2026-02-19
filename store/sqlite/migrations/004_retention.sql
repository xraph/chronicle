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
