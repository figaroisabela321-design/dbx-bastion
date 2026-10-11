-- 0003_assets: asset groups, soft delete, description and connection-test status.
--
-- NOTE: SQLite ALTER TABLE ... ADD COLUMN only accepts constant defaults
-- (no parenthesized expressions) and cannot add PRIMARY KEY / UNIQUE
-- constraints. New uniqueness needs are therefore enforced with
-- CREATE UNIQUE INDEX.

-- Asset groups form an optional hierarchy via parent_id. Group names are
-- globally unique (simpler and unambiguous for V1).
CREATE TABLE IF NOT EXISTS asset_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    parent_id   TEXT NULL REFERENCES asset_groups(id) ON DELETE RESTRICT,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Many-to-many asset <-> group membership.
CREATE TABLE IF NOT EXISTS asset_group_members (
    asset_id  TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    group_id  TEXT NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    added_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (asset_id, group_id)
);

-- Soft delete: deleted rows stay for audit/work-order history but are
-- hidden from listings and never resolved for new operations.
ALTER TABLE assets ADD COLUMN deleted_at TEXT NULL;

ALTER TABLE assets ADD COLUMN description TEXT NOT NULL DEFAULT '';

ALTER TABLE assets ADD COLUMN last_tested_at TEXT NULL;

ALTER TABLE assets ADD COLUMN last_test_status TEXT NULL
    CHECK (last_test_status IN ('success', 'failure'));

-- Asset names are unique (service also validates; the index is the race-safe
-- enforcement, including soft-deleted rows so history stays linkable).
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_name_unique ON assets(name);

CREATE INDEX IF NOT EXISTS idx_assets_deleted ON assets(deleted_at);
CREATE INDEX IF NOT EXISTS idx_asset_groups_parent ON asset_groups(parent_id);
CREATE INDEX IF NOT EXISTS idx_asset_group_members_group ON asset_group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_asset_group_members_asset ON asset_group_members(asset_id);
