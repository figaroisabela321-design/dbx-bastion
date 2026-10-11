-- 0004_rbac: user groups, grant expiry, asset-group-scoped grants.
--
-- V1 scope rule: every permission row binds EXACTLY ONE of
-- asset_id / asset_group_id (XOR). There is no "all assets" grant.
--
-- UPGRADE SAFETY (fail closed): historical rows with asset_id IS NULL
-- (the 0001 "all assets" meaning) violate the new CHECK during the copy
-- below, which aborts this migration: the transaction rolls back, the
-- version is NOT recorded, and the database stays usable at 0003.
-- Nothing is silently deleted or broadened.
--
-- Offline diagnosis and repair (run BEFORE upgrading):
--   1. Find offending rows:
--        SELECT id, role_id, effect, action
--          FROM permissions WHERE asset_id IS NULL;
--   2. For each row, explicitly re-create the grant scoped to a concrete
--      asset or asset group (there is no automatic conversion: mapping
--      "all assets" to anything else would silently change semantics).
--   3. Delete the NULL-scope rows:
--        DELETE FROM permissions WHERE asset_id IS NULL;
--   4. Re-run the application; the migration will be retried automatically.
--
-- Fresh databases have an empty permissions table and migrate trivially.

CREATE TABLE IF NOT EXISTS user_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS user_group_members (
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id  TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    added_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS group_roles (
    group_id  TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    role_id   TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    added_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (group_id, role_id)
);

-- Rebuild permissions: add asset_group_id + expires_at, enforce the XOR
-- scope rule, and harden delete behavior.
--
-- SQLite cannot add a CHECK constraint or a column with a non-constant
-- default via ALTER TABLE, so the table is rebuilt. `permissions` is a
-- leaf table (nothing references it), making the rebuild safe.
--
-- Delete policy is ON DELETE RESTRICT on BOTH asset references: deleting
-- an asset or an asset group that still has grants fails loudly instead
-- of silently wiping rows — especially DENY rows, whose silent
-- disappearance would be a privilege escalation (fail open). Grant
-- removal is always an explicit management action
-- (GrantService::revoke_grant / revoke_grants_for_group /
-- revoke_grants_for_asset). Assets are normally soft-deleted, which does
-- not touch these rows at all.
CREATE TABLE permissions_new (
    id                  TEXT PRIMARY KEY,
    role_id             TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    effect              TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    action              TEXT NOT NULL CHECK (action IN
        ('connect', 'select', 'insert', 'update', 'delete',
         'ddl', 'execute', 'export', 'import')),
    asset_id            TEXT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    asset_group_id      TEXT NULL REFERENCES asset_groups(id) ON DELETE RESTRICT,
    database_pattern    TEXT NULL,
    schema_pattern      TEXT NULL,
    table_pattern       TEXT NULL,
    expires_at          TEXT NULL,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((asset_id IS NULL) != (asset_group_id IS NULL))
);

INSERT INTO permissions_new
    (id, role_id, effect, action, asset_id, asset_group_id,
     database_pattern, schema_pattern, table_pattern, expires_at, created_at)
SELECT id, role_id, effect, action, asset_id, NULL,
       database_pattern, schema_pattern, table_pattern, NULL, created_at
FROM permissions;

DROP TABLE permissions;
ALTER TABLE permissions_new RENAME TO permissions;

CREATE INDEX IF NOT EXISTS idx_permissions_role_action ON permissions(role_id, action);
CREATE INDEX IF NOT EXISTS idx_permissions_asset ON permissions(asset_id);
CREATE INDEX IF NOT EXISTS idx_permissions_asset_group ON permissions(asset_group_id);
CREATE INDEX IF NOT EXISTS idx_user_group_members_user ON user_group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_group_roles_group ON group_roles(group_id);
