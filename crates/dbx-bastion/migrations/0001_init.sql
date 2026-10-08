-- DB Bastion initial schema (0001_init).
--
-- Applied exactly once per database file, guarded by the `schema_migrations`
-- table (created by the storage layer, not by this file). Every statement is
-- also written defensively with IF NOT EXISTS so a re-run is harmless.
--
-- IDs are UUID strings (TEXT). Timestamps are RFC3339 UTC strings (TEXT).

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name    TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS roles (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description     TEXT NOT NULL DEFAULT '',
    system_role     INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id         TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- A Bastion asset is "who may access this database". It maps to exactly one
-- DBX connection id ("how to connect"). Ordinary users only ever see asset_id;
-- raw host/port/username/password never leave the server.
CREATE TABLE IF NOT EXISTS assets (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    environment         TEXT NOT NULL CHECK (environment IN ('development', 'test', 'staging', 'production')),
    db_type             TEXT NOT NULL,
    dbx_connection_id   TEXT NOT NULL UNIQUE,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS permissions (
    id                  TEXT PRIMARY KEY,
    role_id             TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    effect              TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    action              TEXT NOT NULL CHECK (action IN ('connect', 'select', 'insert', 'update', 'delete', 'ddl', 'execute', 'export', 'import')),
    asset_id            TEXT NULL REFERENCES assets(id) ON DELETE CASCADE,
    database_pattern    TEXT NULL,
    schema_pattern      TEXT NULL,
    table_pattern       TEXT NULL,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_permissions_role_action
    ON permissions(role_id, action);

-- Sessions store only the token *hash*. Raw session tokens never hit the disk.
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    login_ip        TEXT NULL,
    user_agent      TEXT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    revoked_at      TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_token
    ON sessions(token_hash);

CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON sessions(user_id, expires_at);

CREATE TABLE IF NOT EXISTS approval_requests (
    id              TEXT PRIMARY KEY,
    requester_id    TEXT NOT NULL REFERENCES users(id),
    asset_id        TEXT NOT NULL REFERENCES assets(id),
    database_name   TEXT NULL,
    schema_name     TEXT NULL,
    sql_text        TEXT NOT NULL,
    sql_hash        TEXT NOT NULL,
    risk_level      TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'expired')),
    reason          TEXT NOT NULL DEFAULT '',
    requested_at    TEXT NOT NULL,
    decided_at      TEXT NULL,
    decided_by      TEXT NULL REFERENCES users(id)
);

-- Execution tickets are one-time consumable and bound to
-- user + asset + database + schema + exact SQL hash + expiry.
CREATE TABLE IF NOT EXISTS execution_tickets (
    id                  TEXT PRIMARY KEY,
    approval_request_id TEXT NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    asset_id            TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    database_name       TEXT NULL,
    schema_name         TEXT NULL,
    sql_hash            TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    consumed_at         TEXT NULL,
    created_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_execution_tickets_lookup
    ON execution_tickets(id, user_id, asset_id, expires_at, consumed_at);

-- Audit events are append-only evidence. Ordinary users must never be able to
-- modify them; enforcement lives in the service layer (later TASK).
CREATE TABLE IF NOT EXISTS audit_events (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    session_id          TEXT NOT NULL,
    asset_id            TEXT NOT NULL,
    database_name       TEXT NULL,
    schema_name         TEXT NULL,
    sql_text            TEXT NOT NULL,
    sql_kind            TEXT NOT NULL,
    risk_level          TEXT NOT NULL,
    source_ip           TEXT NULL,
    client_request_id   TEXT NULL,
    status              TEXT NOT NULL,
    success             INTEGER NULL,
    duration_ms         INTEGER NULL,
    error_message       TEXT NULL,
    started_at          TEXT NOT NULL,
    finished_at         TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_started
    ON audit_events(started_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_user
    ON audit_events(user_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_asset
    ON audit_events(asset_id, started_at DESC);
