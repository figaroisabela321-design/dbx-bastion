-- 0002_auth: session activity tracking + persistent bootstrap marker.
--
-- NOTE: SQLite ALTER TABLE ... ADD COLUMN does not accept parenthesized
-- expression defaults (e.g. DEFAULT (strftime(...))). The new column is
-- therefore added NULL-able and existing rows are backfilled from the
-- already-present `created_at` value. The service layer always writes
-- `last_active_at` explicitly for new sessions and treats NULL as
-- `created_at` defensively.

ALTER TABLE sessions ADD COLUMN last_active_at TEXT NULL;

UPDATE sessions SET last_active_at = created_at WHERE last_active_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_sessions_user_active
    ON sessions(user_id, revoked_at, expires_at);

-- One-row table recording that the initial admin bootstrap has completed.
-- Checked inside the bootstrap transaction; prevents a second initial admin
-- from ever being created, even under concurrent execution.
CREATE TABLE IF NOT EXISTS bootstrap_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    initialized_at  TEXT NOT NULL,
    initialized_by  TEXT NOT NULL DEFAULT ''
);
