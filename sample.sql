PRAGMA foreign_keys = ON;

-- ---------------- USERS (PARENT) ----------------
INSERT INTO users (
    name, email, password_hash, status, created_at
) VALUES
('Admin User', 'admin@example.com', 'hash123admin', 'ACTIVE', '2026-01-01'),
('Normal User', 'user@example.com', 'hash123user', 'ACTIVE', '2026-01-02');


-- ---------------- URL TARGETS (PARENT) ----------------
INSERT INTO url_targets (
    target_id, url, url_type, protocol, domain, path
) VALUES
(101, 'https://example.com/login', 'WEB', 'HTTPS', 'example.com', '/login'),
(102, 'http://testsite.com/api', 'API', 'HTTP', 'testsite.com', '/api');


-- ---------------- SCANS (CHILD of users & targets) ----------------
INSERT INTO scans (
    user_id, target_id, profile_id, schedule_id,
    status, started_at, finished_at, duration, total_findings
) VALUES
(1, 101, 5, 10, 'COMPLETED',
 '2026-01-01 10:00', '2026-01-01 10:05', 5.0, 3),

(2, 102, 6, 11, 'RUNNING',
 '2026-01-02 11:00', NULL, NULL, 0);


-- ---------------- FINDINGS (CHILD of scans) ----------------
INSERT INTO findings (
    scan_id, finding_no, title, severity, cvss_score,
    description, owasp_code, cwe_id, detected_at
) VALUES
(1, 1, 'SQL Injection', 'High', 9.1,
 'User input not sanitized', 1, 89, '2026-01-01');
