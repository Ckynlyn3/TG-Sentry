-- +goose Up
CREATE TABLE records (
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    id TEXT COLLATE "C" NOT NULL,
    -- Preserve JSON text bytes and literal payload-search semantics from SQLite.
    payload TEXT NOT NULL CHECK (payload IS JSON),
    PRIMARY KEY (tenant_id, kind, id)
);
CREATE INDEX idx_records_reviews_created ON records
    (tenant_id, kind, ((payload::json->>'createdAt') COLLATE "C") DESC NULLS LAST, id COLLATE "C");

-- +goose Down
DROP TABLE records;
