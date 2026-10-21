-- +goose Up
-- Pool-model isolation: https://aws.amazon.com/blogs/database/multi-tenant-data-isolation-with-postgresql-row-level-security/
-- Owner bypass and FORCE: https://www.postgresql.org/docs/16/ddl-rowsecurity.html
-- Permissive OR / restrictive AND, USING / WITH CHECK:
-- https://www.postgresql.org/docs/16/sql-createpolicy.html
-- The operator provisions tg_sentry_app; migrations never create login credentials.
-- Expand-contract: retain the existing keys, indexes and payload bytes.
ALTER TABLE records ENABLE ROW LEVEL SECURITY;
ALTER TABLE records FORCE ROW LEVEL SECURITY;
CREATE POLICY records_base ON records AS PERMISSIVE FOR ALL
    USING (true) WITH CHECK (true);
CREATE POLICY records_tenant ON records AS RESTRICTIVE FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));
-- NULLIF also denies the empty custom-setting placeholder after pool reuse.
-- +goose StatementBegin
DO $$ BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO tg_sentry_app', current_schema());
END $$;
-- +goose StatementEnd
GRANT SELECT, INSERT, UPDATE, DELETE ON records TO tg_sentry_app;

-- +goose Down
-- Stop runtime traffic first: down deliberately removes the isolation boundary.
-- Retain data, schema USAGE and the externally provisioned cluster-wide role.
REVOKE SELECT, INSERT, UPDATE, DELETE ON records FROM tg_sentry_app;
DROP POLICY records_tenant ON records;
DROP POLICY records_base ON records;
ALTER TABLE records NO FORCE ROW LEVEL SECURITY;
ALTER TABLE records DISABLE ROW LEVEL SECURITY;
