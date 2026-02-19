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
