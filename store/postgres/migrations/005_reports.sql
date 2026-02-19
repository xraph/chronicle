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
