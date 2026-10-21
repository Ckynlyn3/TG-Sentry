-- +goose Up
-- Existing tenant-scoped records remain the source of truth. Index the existing
-- hash lookup rather than adding a second credential/enrollment store.
CREATE INDEX idx_records_client_credential_hash ON records
    (tenant_id, ((payload::json->>'tokenHash') COLLATE "C"))
    WHERE kind = 'client_nodes';

-- +goose Down
DROP INDEX idx_records_client_credential_hash;
