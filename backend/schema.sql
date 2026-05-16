PRAGMA foreign_keys = ON;

-- =========================
-- USERS
-- =========================
CREATE TABLE IF NOT EXISTS users (
  user_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  name           TEXT NOT NULL,
  email          TEXT NOT NULL UNIQUE,
  password_hash  TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'ACTIVE'
                 CHECK (status IN ('ACTIVE','DISABLED','PENDING')),
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- =========================
-- TARGETS (supertype)
-- =========================
-- Note: the target_type column is intentionally kept loose. The specialization
-- table (url_targets / apk_files / code_targets / pe_files) is what actually
-- disambiguates the row at SELECT time via LEFT JOIN. Keeping target_type to
-- just URL/APK/HOST lets old databases upgrade in place without rebuilding the
-- table.
CREATE TABLE IF NOT EXISTS targets (
  target_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL,
  target_type  TEXT NOT NULL CHECK (target_type IN ('URL','APK','HOST')),
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- URL specialization (same target_id)
CREATE TABLE IF NOT EXISTS url_targets (
  target_id  INTEGER PRIMARY KEY,
  url        TEXT NOT NULL UNIQUE,
  url_type   TEXT NOT NULL DEFAULT 'WEB' CHECK (url_type IN ('WEB','API')),
  protocol   TEXT,
  domain     TEXT,
  path       TEXT,
  FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE CASCADE
);

-- APK specialization (same target_id)
CREATE TABLE IF NOT EXISTS apk_files (
  target_id     INTEGER PRIMARY KEY,
  file_name     TEXT NOT NULL,
  file_size     INTEGER,
  package_name  TEXT,
  app_version   TEXT,
  permissions   TEXT,
  FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE CASCADE
);

-- Code / folder specialization (stored under HOST target_type for compatibility)
CREATE TABLE IF NOT EXISTS code_targets (
  target_id        INTEGER PRIMARY KEY,
  folder_name      TEXT NOT NULL,
  file_count       INTEGER NOT NULL DEFAULT 0,
  total_size       INTEGER NOT NULL DEFAULT 0,
  root_path_hint   TEXT,
  summary_json     TEXT,
  FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE CASCADE
);

-- Windows PE specialization (.exe / .dll / .sys malware-scan targets)
CREATE TABLE IF NOT EXISTS pe_files (
  target_id     INTEGER PRIMARY KEY,
  file_name     TEXT NOT NULL,
  file_size     INTEGER,
  md5_hash      TEXT,
  verdict       TEXT,
  summary_json  TEXT,
  FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE CASCADE
);

-- =========================
-- SCANS
-- =========================
CREATE TABLE IF NOT EXISTS scans (
  scan_id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id          INTEGER NOT NULL,
  target_id        INTEGER NOT NULL,

  status           TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','COMPLETED','FAILED')),
  started_at       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  finished_at      TEXT,
  error_message    TEXT,

  zap_spider_id    TEXT,
  zap_ascan_id     TEXT,

  total_findings   INTEGER NOT NULL DEFAULT 0,
  phase            TEXT,
  spider_progress  INTEGER DEFAULT 0,
  ascan_progress   INTEGER DEFAULT 0,

  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
  FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_scans_user_time ON scans(user_id, started_at);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);

-- =========================
-- FINDINGS
-- =========================
CREATE TABLE IF NOT EXISTS findings (
  finding_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id      INTEGER NOT NULL,

  -- for UI ordering within a scan (you compute it)
  finding_no   INTEGER NOT NULL,

  title        TEXT NOT NULL,
  severity     TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  cvss_score   REAL CHECK (cvss_score BETWEEN 0 AND 10),
  description  TEXT,
  owasp_code   INTEGER,
  cwe_id       INTEGER,
  detected_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),

  raw_json     TEXT,

  UNIQUE(scan_id, finding_no),
  FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

-- =========================
-- CHILD TABLES (reference finding_id, not composite)
-- =========================
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id     INTEGER NOT NULL,
  evidence_type  TEXT NOT NULL DEFAULT 'TEXT'
                 CHECK (evidence_type IN ('TEXT','REQUEST','RESPONSE','HEADER','PARAM','SCREENSHOT','OTHER')),
  url            TEXT,
  content        TEXT NOT NULL,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS remediations (
  remediation_id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id     INTEGER NOT NULL,
  source         TEXT,
  text           TEXT NOT NULL,
  reference_url  TEXT,
  created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS affected_endpoints (
  endpoint_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id    INTEGER NOT NULL,
  method        TEXT CHECK (method IN ('GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD')),
  path          TEXT NOT NULL,
  status_code   INTEGER,
  FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

-- =========================
-- REPORTS
-- =========================
CREATE TABLE IF NOT EXISTS reports (
  report_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id          INTEGER NOT NULL,
  report_type      TEXT NOT NULL CHECK (report_type IN ('HTML','PDF')),
  generated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  overall_severity TEXT CHECK (overall_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS report_items (
  report_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id      INTEGER NOT NULL,
  finding_id     INTEGER NOT NULL,
  item_no        INTEGER NOT NULL,
  status         TEXT NOT NULL DEFAULT 'OPEN'
                 CHECK (status IN ('OPEN','ACKED','FIXED','FALSE_POSITIVE')),
  UNIQUE(report_id, item_no),
  FOREIGN KEY (report_id) REFERENCES reports(report_id) ON DELETE CASCADE,
  FOREIGN KEY (finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

-- =========================
-- ANOMALY SCORE
-- =========================
CREATE TABLE IF NOT EXISTS anomaly_score (
  scan_id       INTEGER PRIMARY KEY,
  score         REAL NOT NULL,
  computed_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  model_version TEXT,
  FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

-- =========================
-- SCHEDULE + NOTIFICATIONS
-- =========================
CREATE TABLE IF NOT EXISTS schedule (
  schedule_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL,
  timezone    TEXT NOT NULL,
  status      TEXT NOT NULL CHECK (status IN ('ACTIVE','PAUSED','DISABLED')),
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
  notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id         INTEGER NOT NULL,
  event_type      TEXT NOT NULL,
  title           TEXT,
  message         TEXT,
  level           TEXT DEFAULT 'INFO',
  is_read         INTEGER NOT NULL DEFAULT 0,
  read_at         TEXT,
  scan_id         INTEGER,
  action_url      TEXT,
  metadata_json   TEXT,
  sent_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
  FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_time ON notifications(user_id, sent_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read, sent_at DESC);
