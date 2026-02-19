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
