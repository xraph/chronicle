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
