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
    ON chronicle_events (app_id, tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_category
    ON chronicle_events (category, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_action
    ON chronicle_events (action, outcome, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_user
    ON chronicle_events (user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_subject
    ON chronicle_events (subject_id);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_severity
    ON chronicle_events (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_chronicle_events_resource
    ON chronicle_events (resource, resource_id, timestamp DESC);
