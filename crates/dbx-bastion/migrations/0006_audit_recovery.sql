-- TASK-005E P0-2: append-only audit recovery events.
--
-- The old triage model overwrote `started`/`unknown_interrupted` rows as
-- `failed`, fabricating an unknown execution result as a failure and
-- destroying the original evidence. The new model:
--
-- - `audit_events` rows are NEVER modified by triage. The original
--   status (`started` / `unknown_interrupted`) and all fields are
--   preserved as the historical record.
-- - Each triage appends ONE row here. The table is append-only in
--   practice: rows are never UPDATED or DELETED (UNIQUE on
--   audit_event_id enforces at most one triage per audit event).
-- - `conclusion` distinguishes the operator's finding:
--   - `confirmed_committed`: evidence proves the SQL committed.
--   - `confirmed_not_executed`: evidence proves it never executed.
--   - `still_unknown`: outcome remains unknown; execution stays blocked.
-- - Only `confirmed_committed` / `confirmed_not_executed` lift the
--   execution block. `still_unknown` (or no triage) keeps refusing.
--
-- Compatible with existing databases: the table is new, no existing
-- rows are touched, and historical `failed` rows written by the old
-- triage remain as-is (their original status is unrecoverable, which
-- is why the old model was wrong — new triages must use this table).

CREATE TABLE IF NOT EXISTS audit_recovery_events (
    id               TEXT PRIMARY KEY,
    audit_event_id   TEXT NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    triaged_by       TEXT NOT NULL,
    triaged_at       TEXT NOT NULL,
    original_status  TEXT NOT NULL CHECK (original_status IN ('started', 'unknown_interrupted')),
    conclusion       TEXT NOT NULL CHECK (conclusion IN ('confirmed_committed', 'confirmed_not_executed', 'still_unknown')),
    reason           TEXT NOT NULL CHECK (length(reason) >= 1 AND length(reason) <= 2000),
    evidence         TEXT NOT NULL CHECK (length(evidence) <= 10000),
    UNIQUE(audit_event_id)
);

CREATE INDEX IF NOT EXISTS idx_recovery_audit_event ON audit_recovery_events(audit_event_id);
