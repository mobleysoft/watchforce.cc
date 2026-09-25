CREATE TABLE IF NOT EXISTS monitors (
  id TEXT PRIMARY KEY,
  owner_email TEXT NOT NULL,
  url TEXT NOT NULL,
  label TEXT,
  check_interval_minutes INTEGER NOT NULL DEFAULT 5,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_status TEXT,
  last_reachable INTEGER,
  last_checked_at TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id TEXT NOT NULL,
  checked_at TEXT NOT NULL DEFAULT (datetime('now')),
  reachable INTEGER NOT NULL,
  status_code INTEGER,
  response_ms INTEGER,
  error TEXT
);

CREATE INDEX IF NOT EXISTS idx_checks_monitor ON checks(monitor_id, checked_at);

CREATE TABLE IF NOT EXISTS entitlements (
  owner_email TEXT PRIMARY KEY,
  monitor_slots INTEGER NOT NULL DEFAULT 0,
  stripe_customer_id TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- MCCOMB Screening Audit Trail (2026-09-20): this table already exists in
-- production watchforce_db (created via an ad-hoc `wrangler d1 execute`
-- migration, never previously captured in this schema file) - added here
-- so a fresh D1 provision from this file wouldn't silently omit it.
CREATE TABLE IF NOT EXISTS screenings (
  id TEXT PRIMARY KEY,
  query TEXT NOT NULL,
  match_count INTEGER NOT NULL DEFAULT 0,
  matched_names TEXT,
  screened_at TEXT NOT NULL DEFAULT (datetime('now'))
);
