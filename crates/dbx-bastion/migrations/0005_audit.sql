-- 0005_audit: gateway audit event log (TASK-005B).
--
-- 0001 created an `audit_events` placeholder that was never written
-- (no audit implementation existed before TASK-005B). This migration
-- adds the columns the gateway audit service needs. `sql_text` holds
-- gateway-redacted SQL (literals masked); the SHA-256 of the exact SQL
-- is stored in `sql_hash` for tamper-evident correlation. Result rows
-- are never stored.

ALTER TABLE audit_events ADD COLUMN sql_hash TEXT;
ALTER TABLE audit_events ADD COLUMN action TEXT;
ALTER TABLE audit_events ADD COLUMN policy_decision TEXT;
ALTER TABLE audit_events ADD COLUMN row_count INTEGER;

CREATE INDEX IF NOT EXISTS idx_audit_events_status ON audit_events(status);
CREATE INDEX IF NOT EXISTS idx_audit_events_asset_time ON audit_events(asset_id, started_at);
