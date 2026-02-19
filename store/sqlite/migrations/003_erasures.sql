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
