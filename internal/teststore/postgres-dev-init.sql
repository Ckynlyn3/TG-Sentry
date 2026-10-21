-- Disposable local/CI role only. Production credentials are provisioned externally.
-- Official image init mechanism: https://hub.docker.com/_/postgres#initialization-scripts
DO $$ BEGIN
    CREATE ROLE tg_sentry_app LOGIN PASSWORD 'dev-only'
        NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
EXCEPTION WHEN duplicate_object THEN
    NULL; -- Never silently alter an existing role's attributes or credentials.
END $$;
