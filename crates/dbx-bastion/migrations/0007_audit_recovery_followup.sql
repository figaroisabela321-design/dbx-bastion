-- TASK-005E follow-up: allow follow-up triage after still_unknown.
--
-- Migration 0006's UNIQUE(audit_event_id) permitted only one recovery
-- event per audit record. If the first triage concluded `still_unknown`,
-- later evidence (e.g. DBA confirms the transaction committed) could not
-- be recorded.
--
-- New model (append-only, history preserved):
-- - Multiple recovery events per audit_event_id are allowed.
-- - The LATEST event (by rowid) determines the effective conclusion.
-- - `still_unknown` may be followed by `confirmed_*` with evidence.
-- - Once a `confirmed_committed` / `confirmed_not_executed` conclusion
--   exists, no further triage is allowed (enforced in application logic;
--   confirmed conclusions are irreversible).
-- - All history remains queryable; nothing is overwritten or deleted.
--
-- SQLite cannot DROP a UNIQUE constraint; recreate the table without it.

CREATE TABLE audit_recovery_events_new (
    id               TEXT PRIMARY KEY,
    audit_event_id   TEXT NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    triaged_by       TEXT NOT NULL,
    triaged_at       TEXT NOT NULL,
    original_status  TEXT NOT NULL CHECK (original_status IN ('started', 'unknown_interrupted')),
    conclusion       TEXT NOT NULL CHECK (conclusion IN ('confirmed_committed', 'confirmed_not_executed', 'still_unknown')),
    reason           TEXT NOT NULL CHECK (length(reason) >= 1 AND length(reason) <= 2000),
    evidence         TEXT NOT NULL CHECK (length(evidence) <= 10000)
);

INSERT INTO audit_recovery_events_new
    SELECT id, audit_event_id, triaged_by, triaged_at, original_status, conclusion, reason, evidence
    FROM audit_recovery_events;

DROP TABLE audit_recovery_events;

ALTER TABLE audit_recovery_events_new RENAME TO audit_recovery_events;

CREATE INDEX idx_recovery_audit_event ON audit_recovery_events(audit_event_id);
