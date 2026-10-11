-- TASK-005F P2-002: Database-level append-only protection for audit_recovery_events.
--
-- Until now, append-only was enforced only by application code
-- (triage_interruption only INSERTs; confirmed irreversibility is checked
-- in Rust). A direct SQL UPDATE/DELETE (DBA mistake, code regression, or
-- SQL injection) could rewrite history.
--
-- This migration adds BEFORE UPDATE / BEFORE DELETE triggers that abort
-- the statement. INSERT and SELECT are unaffected.
--
-- Convention for future migrations: if a later migration must rebuild
-- audit_recovery_events (e.g. schema change), it MUST DROP these triggers
-- first, rebuild the table, then re-create the triggers — all inside the
-- same migration transaction.

CREATE TRIGGER trg_recovery_events_no_update
BEFORE UPDATE ON audit_recovery_events
BEGIN
    SELECT RAISE(ABORT, 'audit_recovery_events is append-only: UPDATE forbidden');
END;

CREATE TRIGGER trg_recovery_events_no_delete
BEFORE DELETE ON audit_recovery_events
BEGIN
    SELECT RAISE(ABORT, 'audit_recovery_events is append-only: DELETE forbidden');
END;
