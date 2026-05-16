import os
import json
import time
import socket
import sqlite3
import threading
import datetime
import ipaddress
import hashlib
import shutil
from urllib.parse import urlparse
from datetime import timedelta
from chatbot.chat_service import generate_chat_reply
from flask import Flask, request, jsonify, make_response, send_file
from werkzeug.exceptions import RequestEntityTooLarge
from flask_cors import CORS

from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)

from werkzeug.utils import secure_filename
try:
    from androguard.core.apk import APK
except ImportError:  
    from androguard.core.bytecodes.apk import APK
import re
from io import BytesIO

from db import get_conn
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, KeepTogether
from reportlab.graphics.shapes import Drawing, Rect, String, Line

# ZAP primitives ---------------------------------------------------------------------------------------------------
from zap_client import (
    zap_version,
    access_url,
    spider_scan, spider_status,
    ascan_scan, ascan_status,
    fetch_alerts
)

app = Flask(__name__)
app.url_map.strict_slashes = False

CORS(
    app,
    resources={r"/api/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-change-me")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
jwt = JWTManager(app)

ALLOWED_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}
ALLOW_PRIVATE_TARGETS = os.environ.get("ALLOW_PRIVATE_TARGETS", "0") == "1"

UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/data/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
CODE_UPLOAD_DIR = os.path.join(UPLOAD_DIR, "code")
os.makedirs(CODE_UPLOAD_DIR, exist_ok=True)

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "300"))
MAX_CODE_FILES = int(os.environ.get("MAX_CODE_FILES", "20000"))
MAX_CODE_TEXT_BYTES = int(os.environ.get("MAX_CODE_TEXT_BYTES", str(1024 * 1024)))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

def _column_exists(conn, table_name: str, column_name: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(r["name"] == column_name for r in rows)


def ensure_runtime_schema():
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    conn = get_conn()
    try:
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                try:
                    conn.executescript(f.read())
                except sqlite3.OperationalError:
                    
                    pass

        scan_cols = {r["name"] for r in conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "phase" not in scan_cols:
            conn.execute("ALTER TABLE scans ADD COLUMN phase TEXT")
        if "spider_progress" not in scan_cols:
            conn.execute("ALTER TABLE scans ADD COLUMN spider_progress INTEGER DEFAULT 0")
        if "ascan_progress" not in scan_cols:
            conn.execute("ALTER TABLE scans ADD COLUMN ascan_progress INTEGER DEFAULT 0")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS code_targets (
              target_id        INTEGER PRIMARY KEY,
              folder_name      TEXT NOT NULL,
              file_count       INTEGER NOT NULL DEFAULT 0,
              total_size       INTEGER NOT NULL DEFAULT 0,
              root_path_hint   TEXT,
              summary_json     TEXT,
              FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pe_files (
              target_id     INTEGER PRIMARY KEY,
              file_name     TEXT NOT NULL,
              file_size     INTEGER,
              md5_hash      TEXT,
              verdict       TEXT,
              summary_json  TEXT,
              FOREIGN KEY (target_id) REFERENCES targets(target_id) ON DELETE CASCADE
            )
            """
        )

        notif_cols = {r["name"] for r in conn.execute("PRAGMA table_info(notifications)").fetchall()}
        notif_alters = {
            "title": "ALTER TABLE notifications ADD COLUMN title TEXT",
            "message": "ALTER TABLE notifications ADD COLUMN message TEXT",
            "level": "ALTER TABLE notifications ADD COLUMN level TEXT DEFAULT 'INFO'",
            "is_read": "ALTER TABLE notifications ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0",
            "read_at": "ALTER TABLE notifications ADD COLUMN read_at TEXT",
            "scan_id": "ALTER TABLE notifications ADD COLUMN scan_id INTEGER",
            "action_url": "ALTER TABLE notifications ADD COLUMN action_url TEXT",
            "metadata_json": "ALTER TABLE notifications ADD COLUMN metadata_json TEXT",
        }
        for col, stmt in notif_alters.items():
            if col not in notif_cols:
                conn.execute(stmt)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user_time ON notifications(user_id, sent_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read, sent_at DESC)")
        conn.commit()
    finally:
        conn.close()


ensure_runtime_schema()


@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(_err):
    return jsonify({
        "error": f"Upload payload is too large. Keep the selected folder under about {MAX_UPLOAD_MB} MB after excluding node_modules, build output, and binaries."
    }), 413

# -----------------------------------------------------------------------------------------------------------------
# helpers

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def now_human_local():
   
    now = datetime.datetime.now()
    
    stamp = now.strftime("%b %d, %Y · %I:%M %p")
    
    stamp = stamp.replace(" 0", " ", 1) if " 0" in stamp[-9:] else stamp
    return stamp


def normalize_severity(zap_risk: str) -> str:
    r = (zap_risk or "").strip().lower()
    if "critical" in r:
        return "CRITICAL"
    if "high" in r:
        return "HIGH"
    if "medium" in r:
        return "MEDIUM"
    if "low" in r:
        return "LOW"
    return "INFO"

def _severity_rank(sev: str) -> int:
    order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
    return order.get((sev or "").upper(), 6)

def safe_update_scan(conn, scan_id: int, **fields):
   
    if not fields:
        return

    cols = []
    vals = []
    for k, v in fields.items():
        cols.append(f"{k}=?")
        vals.append(v)

    vals.append(scan_id)
    sql = f"UPDATE scans SET {', '.join(cols)} WHERE scan_id=?"

    try:
        conn.execute(sql, tuple(vals))
        conn.commit()
    except sqlite3.OperationalError as e:
        
        conn.execute(
            "UPDATE scans SET error_message=? WHERE scan_id=?",
            (f"PROGRESS_UPDATE_SKIPPED: {e}", scan_id),
        )
        conn.commit()


def get_or_create_url_target(conn, user_id: int, url: str) -> int:
    row = conn.execute("SELECT target_id FROM url_targets WHERE url=?", (url,)).fetchone()
    if row:
        return int(row["target_id"])

    conn.execute("INSERT INTO targets(user_id, target_type) VALUES(?, 'URL')", (user_id,))
    target_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    parsed = urlparse(url)
    protocol = parsed.scheme or None
    domain = parsed.hostname or None
    path = parsed.path or "/"

    conn.execute("""
        INSERT INTO url_targets(target_id, url, url_type, protocol, domain, path)
        VALUES(?, ?, 'WEB', ?, ?, ?)
    """, (target_id, url, protocol, domain, path))

    return int(target_id)

def create_apk_target(conn, user_id: int, file_name: str, file_size: int) -> int:
    
    conn.execute("INSERT INTO targets(user_id, target_type) VALUES(?, 'APK')", (user_id,))
    target_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    conn.execute("""
        INSERT INTO apk_files(target_id, file_name, file_size)
        VALUES(?, ?, ?)
    """, (target_id, file_name, int(file_size)))

    return int(target_id)


def create_code_target(conn, user_id: int, folder_name: str, file_count: int, total_size: int, root_path_hint: str | None = None) -> int:
    conn.execute("INSERT INTO targets(user_id, target_type) VALUES(?, 'HOST')", (user_id,))
    target_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        """
        INSERT INTO code_targets(target_id, folder_name, file_count, total_size, root_path_hint)
        VALUES(?, ?, ?, ?, ?)
        """,
        (target_id, folder_name, int(file_count), int(total_size), root_path_hint),
    )
    return int(target_id)


def create_pe_target(conn, user_id: int, file_name: str, file_size: int) -> int:
   
    conn.execute("INSERT INTO targets(user_id, target_type) VALUES(?, 'HOST')", (user_id,))
    target_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        """
        INSERT INTO pe_files(target_id, file_name, file_size)
        VALUES(?, ?, ?)
        """,
        (target_id, file_name, int(file_size)),
    )
    return int(target_id)


def create_notification(conn, user_id: int, event_type: str, title: str, message: str, level: str = "INFO", scan_id: int | None = None, action_url: str | None = "/reports", metadata: dict | None = None):
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(notifications)").fetchall()}
    payload = {
        "user_id": user_id,
        "event_type": event_type,
        "title": title,
        "message": message,
        "level": (level or "INFO").upper(),
        "scan_id": scan_id,
        "action_url": action_url,
        "metadata_json": json.dumps(metadata or {}, ensure_ascii=False),
    }

    if {"title", "message", "level", "is_read", "scan_id", "action_url", "metadata_json"}.issubset(cols):
        conn.execute(
            """
            INSERT INTO notifications(user_id, event_type, title, message, level, is_read, scan_id, action_url, metadata_json)
            VALUES(?, ?, ?, ?, ?, 0, ?, ?, ?)
            """,
            (
                payload["user_id"], payload["event_type"], payload["title"], payload["message"], payload["level"],
                payload["scan_id"], payload["action_url"], payload["metadata_json"],
            ),
        )
    else:
        conn.execute(
            "INSERT INTO notifications(user_id, event_type) VALUES(?, ?)",
            (user_id, event_type),
        )


def get_scan_notification_context(conn, scan_id: int) -> dict | None:
    row = conn.execute(
        """
        SELECT
            s.scan_id,
            s.user_id,
            CASE
                WHEN pf.target_id IS NOT NULL THEN 'MALWARE'
                WHEN ct.target_id IS NOT NULL THEN 'FOLDER'
                ELSE t.target_type
            END AS target_type,
            COALESCE(u.url, af.file_name, ct.folder_name, pf.file_name) AS target_name
        FROM scans s
        JOIN targets t ON t.target_id = s.target_id
        LEFT JOIN url_targets u ON u.target_id = t.target_id
        LEFT JOIN apk_files af ON af.target_id = t.target_id
        LEFT JOIN code_targets ct ON ct.target_id = t.target_id
        LEFT JOIN pe_files pf ON pf.target_id = t.target_id
        WHERE s.scan_id = ?
        """,
        (scan_id,),
    ).fetchone()
    return dict(row) if row else None

# ------------------------------------------------------------------------------------------------------------------
# SSRF guard (MVP-level safety)

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return True


def validate_target_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https URLs are allowed")
    if not parsed.netloc:
        raise ValueError("Invalid URL (missing host)")

    host = parsed.hostname
    if not host:
        raise ValueError("Invalid URL (missing hostname)")

    if not ALLOW_PRIVATE_TARGETS:
        if host.lower() in ("localhost",):
            raise ValueError("Refusing to scan localhost")

        try:
            ipaddress.ip_address(host)
            ip = host
            if _is_private_ip(ip):
                raise ValueError("Refusing to scan private/link-local/reserved IP targets")
            return
        except ValueError:
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                raise ValueError("Could not resolve hostname")

            if _is_private_ip(ip):
                raise ValueError("Refusing to scan targets resolving to private/link-local/reserved IPs")


# -----------------------------------------------------------------------------------------------------------------
# Streaming ingest (dedupe)

def _fingerprint(alert: dict, inst: dict) -> str:
    """
    Stable key so we don't insert duplicates every poll.
    Uses alert title + risk + instance url + param + method.
    """
    parts = [
        (alert.get("alert") or "").strip(),
        (alert.get("risk") or "").strip(),
        (inst.get("url") or inst.get("uri") or alert.get("url") or "").strip(),
        (inst.get("param") or "").strip(),
        (inst.get("method") or "").strip(),
    ]
    raw = "|".join(parts).encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


def ingest_alerts_incremental(conn, scan_id: int, alerts: list) -> int:
    
    existing = set()
    rows = conn.execute("SELECT raw_json FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
    for r in rows:
        try:
            obj = json.loads(r["raw_json"]) if r["raw_json"] else {}
            fp = obj.get("_fp")
            if fp:
                existing.add(fp)
        except Exception:
            pass

    next_no = conn.execute(
        "SELECT COALESCE(MAX(finding_no), 0) AS m FROM findings WHERE scan_id=?",
        (scan_id,)
    ).fetchone()["m"] or 0

    new_count = 0

    for a in (alerts or []):
        instances = a.get("instances")
        if not instances:
            instances = [{"url": a.get("url"), "method": None, "param": None, "evidence": None}]

        for inst in instances:
            fp = _fingerprint(a, inst)
            if fp in existing:
                continue

            existing.add(fp)
            next_no += 1
            new_count += 1

            title = (a.get("alert") or "Unknown").strip()
            severity = normalize_severity(a.get("risk"))

            desc = (a.get("desc") or "").strip()
            sol = (a.get("solution") or "").strip()
            if sol:
                desc = f"{desc}\n\nSolution:\n{sol}" if desc else f"Solution:\n{sol}"

            cwe = int(a.get("cweid") or 0) or None
            wasc = int(a.get("wascid") or 0) or None

            raw_obj = {"_fp": fp, "zap_alert": a, "zap_instance": inst}
            raw_json = json.dumps(raw_obj)

            conn.execute("""
                INSERT INTO findings(
                    scan_id, finding_no, title, severity, cvss_score,
                    description, owasp_code, cwe_id, raw_json
                )
                VALUES(?, ?, ?, ?, NULL, ?, ?, ?, ?)
            """, (scan_id, next_no, title, severity, desc, wasc, cwe, raw_json))

            finding_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            
            u = (inst.get("url") or inst.get("uri") or a.get("url") or "").strip()
            if u:
                conn.execute("""
                    INSERT INTO affected_endpoints(finding_id, method, path, status_code)
                    VALUES (?, ?, ?, NULL)
                """, (finding_id, inst.get("method"), u))

            # evidence best-effort
            ev = (
                inst.get("evidence")
                or a.get("evidence")
                or a.get("attack")
                or a.get("otherinfo")
                or a.get("param")
            )
            if ev:
                conn.execute("""
                    INSERT INTO evidence(finding_id, evidence_type, url, content)
                    VALUES (?, 'TEXT', ?, ?)
                """, (finding_id, u, str(ev).strip()))

            # remediation best-effort
            if sol:
                conn.execute("""
                    INSERT INTO remediations(finding_id, source, text, reference_url)
                    VALUES (?, 'ZAP', ?, ?)
                """, (finding_id, sol, a.get("reference")))

    if new_count:
        total = conn.execute("SELECT COUNT(*) AS c FROM findings WHERE scan_id=?", (scan_id,)).fetchone()["c"]
        conn.execute("UPDATE scans SET total_findings=? WHERE scan_id=?", (int(total), scan_id))

    return new_count


def _boolish(v):
    if v is None:
        return None
    return str(v).strip().lower() == "true"


def _apk_attr(apk_obj, tag: str, attribute: str, **attribute_filter):
    """
    Compatibility helper for Androguard 3.x/4.x attribute access.
    Uses modern get_attribute_value() when available and falls back to get_element().
    """
    attr = (attribute or "").replace("android:", "")

    if hasattr(apk_obj, "get_attribute_value"):
        try:
            return apk_obj.get_attribute_value(tag, attr, **attribute_filter)
        except TypeError:
            pass

    if hasattr(apk_obj, "get_element"):
        try:
            return apk_obj.get_element(tag, attr, **attribute_filter)
        except TypeError:
            return apk_obj.get_element(tag, attribute, **attribute_filter)

    return None


def analyze_apk_static(apk_path: str) -> dict:
    """
    Returns:
      {
        "meta": {package_name, app_version, permissions[list]},
        "findings": [ {title, severity, description, cwe_id, evidence_url, evidence_text, remediation_text, ref_url}, ... ]
      }
    """
    a = APK(apk_path)

    package_name = a.get_package() or None
    version_name = a.get_androidversion_name() or None
    version_code = a.get_androidversion_code() or None

    perms = sorted(set(a.get_permissions() or []))

    findings = []

    dbg = _boolish(_apk_attr(a, "application", "debuggable"))
    if dbg is True:
        findings.append({
            "title": "Debuggable build enabled (android:debuggable=true)",
            "severity": "HIGH",
            "description": (
                "The app is built with debugging enabled. This can expose internal behavior "
                "and can make reverse engineering / runtime inspection easier in production.\n"
                "Impact: attackers may abuse debug functionality, extract sensitive info, or weaken protections."
            ),
            "cwe_id": 489,  
            "evidence_url": "AndroidManifest.xml",
            "evidence_text": "android:debuggable=\"true\"",
            "remediation_text": "Disable debugging for release builds. Ensure release buildTypes set debuggable false.",
            "ref_url": "https://cwe.mitre.org/data/definitions/489.html",
        })

    allow_backup = _boolish(_apk_attr(a, "application", "allowBackup"))
    
    if allow_backup is True:
        findings.append({
            "title": "App backups enabled (android:allowBackup=true)",
            "severity": "MEDIUM",
            "description": (
                "Backups can allow an attacker with device access (or adb backup style flows, depending on Android version) "
                "to extract app data. If the app stores tokens/PII locally, this becomes a data theft risk."
            ),
            "cwe_id": None,
            "evidence_url": "AndroidManifest.xml",
            "evidence_text": "android:allowBackup=\"true\"",
            "remediation_text": (
                "If the app handles sensitive data, set android:allowBackup=\"false\" and/or use Android backup best practices."
            ),
            "ref_url": "https://developer.android.com/privacy-and-security/risks/backup-best-practices",
        })

    cleartext = _boolish(_apk_attr(a, "application", "usesCleartextTraffic"))
    if cleartext is True:
        findings.append({
            "title": "Cleartext traffic allowed (android:usesCleartextTraffic=true)",
            "severity": "HIGH",
            "description": (
                "Allowing cleartext traffic can permit sensitive data exposure over HTTP.\n"
                "Impact: network attackers (same Wi-Fi, ISP, compromised router) can sniff/modify traffic."
            ),
            "cwe_id": 319,  
            "evidence_url": "AndroidManifest.xml",
            "evidence_text": "android:usesCleartextTraffic=\"true\"",
            "remediation_text": "Disable cleartext traffic and enforce HTTPS with a proper Network Security Config.",
            "ref_url": "https://cwe.mitre.org/data/definitions/319.html",
        })

   
    def comp_exported(kind: str, name: str) -> bool:
        ex = _apk_attr(a, kind, "exported", name=name)
        if ex is None:
            
            try:
                if kind in {"activity", "service", "receiver"} and a.get_intent_filters(kind, name):
                    return True
            except Exception:
                pass
            return False
        return str(ex).strip().lower() == "true"

    def comp_permission(kind: str, name: str):
        return _apk_attr(a, kind, "permission", name=name)

    for kind, getter in [
        ("activity", a.get_activities),
        ("service", a.get_services),
        ("receiver", a.get_receivers),
    ]:
        for cname in (getter() or []):
            if comp_exported(kind, cname):
                perm = comp_permission(kind, cname)
                if not perm:
                    findings.append({
                        "title": f"Exported {kind} without permission restriction",
                        "severity": "HIGH",
                        "description": (
                            f"The component '{cname}' appears exported and does not declare an access permission.\n"
                            "Impact: other apps may invoke this component and potentially reach sensitive logic or data."
                        ),
                        "cwe_id": 926,  
                        "evidence_url": "AndroidManifest.xml",
                        "evidence_text": f"{kind} name=\"{cname}\" exported=true (or implied) without android:permission",
                        "remediation_text": (
                            "Set android:exported=\"false\" for internal components, or enforce a signature-level permission "
                            "for external entry points. Avoid unnecessary intent-filters on sensitive components."
                        ),
                        "ref_url": "https://cwe.mitre.org/data/definitions/926.html",
                    })

    
    dangerous = [p for p in perms if any(x in p for x in [
        "READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"
    ])]
    if dangerous:
        findings.append({
            "title": "Potentially sensitive permissions requested",
            "severity": "INFO",
            "description": (
                "The app requests sensitive permissions. This is not automatically a vulnerability, "
                "but it increases privacy/security risk and should be justified + protected."
            ),
            "cwe_id": None,
            "evidence_url": "AndroidManifest.xml",
            "evidence_text": ", ".join(dangerous),
            "remediation_text": "Minimize permissions. Use runtime permission prompts, least privilege, and justify usage.",
            "ref_url": None,
        })

    
    try:
        all_strings = " ".join(a.get_strings() or [])
        patterns = [
            (r"AKIA[0-9A-Z]{16}", "Possible AWS Access Key ID pattern"),
            (r"AIza[0-9A-Za-z\-_]{35}", "Possible Google API key pattern"),
            (r"-----BEGIN(.*?)PRIVATE KEY-----", "Possible embedded private key"),
        ]
        hits = []
        for pat, label in patterns:
            if re.search(pat, all_strings):
                hits.append(label)
        if hits:
            findings.append({
                "title": "Possible hardcoded secret material (heuristic)",
                "severity": "MEDIUM",
                "description": (
                    "Static string patterns suggest secrets may be embedded in the APK. "
                    "This can enable API abuse if keys are valid."
                ),
                "cwe_id": None,
                "evidence_url": "DEX strings",
                "evidence_text": "; ".join(hits),
                "remediation_text": "Never ship secrets in APK. Move secrets server-side or use short-lived tokens + attestation.",
                "ref_url": None,
            })
    except Exception:
        pass

    return {
        "meta": {
            "package_name": package_name,
            "app_version": version_name or (str(version_code) if version_code else None),
            "permissions": perms
        },
        "findings": findings
    }


IGNORED_CODE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "dist", "build",
    "target", "__pycache__", ".idea", ".vscode", ".next", ".turbo", ".cache"
}
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts", ".go", ".rb", ".php", ".cs", ".cpp", ".c",
    ".h", ".hpp", ".swift", ".scala", ".rs", ".sql", ".yaml", ".yml", ".json", ".xml", ".html", ".htm", ".css",
    ".scss", ".env", ".conf", ".config", ".properties", ".ini", ".md", ".txt", ".dockerfile", ".sh", ".bash", ".zsh"
}


def _guess_language(file_name: str) -> str:
    ext = os.path.splitext(file_name.lower())[1]
    mapping = {
        ".py": "Python", ".js": "JavaScript", ".jsx": "React", ".ts": "TypeScript", ".tsx": "React TS",
        ".java": "Java", ".kt": "Kotlin", ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#",
        ".cpp": "C++", ".c": "C", ".swift": "Swift", ".rs": "Rust", ".sql": "SQL", ".html": "HTML",
        ".css": "CSS", ".json": "JSON", ".xml": "XML", ".yaml": "YAML", ".yml": "YAML", ".sh": "Shell"
    }
    if os.path.basename(file_name).lower() == "dockerfile":
        return "Dockerfile"
    return mapping.get(ext, "Text")


def _is_probably_text_file(file_path: str) -> bool:
    base = os.path.basename(file_path).lower()
    if base in {"dockerfile", ".env", ".env.local", ".env.production"}:
        return True
    return os.path.splitext(base)[1] in TEXT_EXTENSIONS


def _safe_read_file(file_path: str) -> str:
    with open(file_path, "rb") as f:
        data = f.read(MAX_CODE_TEXT_BYTES)
    if b"\x00" in data:
        return ""
    return data.decode("utf-8", errors="ignore")


def _iter_match_lines(pattern: str, text: str, flags=0):
    for match in re.finditer(pattern, text, flags):
        yield match.start(), match.group(0)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def analyze_code_folder_static(root_dir: str) -> dict:
    findings = []
    languages = set()
    scanned_files = 0
    total_bytes = 0
    max_findings = 120

    def add_finding(title: str, severity: str, description: str, cwe_id: int | None, file_rel: str, line_no: int | None, snippet: str, remediation: str, ref_url: str | None = None):
        if len(findings) >= max_findings:
            return
        findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "cwe_id": cwe_id,
            "evidence_url": file_rel,
            "evidence_text": f"Line {line_no}: {snippet.strip()[:400]}" if line_no else snippet.strip()[:400],
            "remediation_text": remediation,
            "ref_url": ref_url,
        })

    for current_root, dir_names, file_names in os.walk(root_dir):
        dir_names[:] = [d for d in dir_names if d not in IGNORED_CODE_DIRS and not d.startswith(".")]
        for file_name in sorted(file_names):
            file_path = os.path.join(current_root, file_name)
            rel_path = os.path.relpath(file_path, root_dir).replace("\\", "/")
            total_bytes += os.path.getsize(file_path)
            if not _is_probably_text_file(file_path):
                continue
            try:
                text = _safe_read_file(file_path)
            except Exception:
                continue
            if not text.strip():
                continue

            scanned_files += 1
            languages.add(_guess_language(file_name))
            lowered = text.lower()

            generic_patterns = [
                (r"-----BEGIN[ A-Z]*PRIVATE KEY-----", "Possible embedded private key material", "HIGH", 798,
                 "A private key appears to be stored directly in source or configuration files. This can lead to credential theft and signing abuse.",
                 "Remove private keys from the repository. Load secrets from secure secret-management infrastructure.",
                 "https://cwe.mitre.org/data/definitions/798.html"),
                (r"AKIA[0-9A-Z]{16}", "Possible hardcoded AWS access key", "HIGH", 798,
                 "An AWS access key identifier was detected in project files, indicating that credentials may be embedded in code.",
                 "Rotate the credential immediately and move it to a vault or environment-based secret store.",
                 "https://cwe.mitre.org/data/definitions/798.html"),
                (r"AIza[0-9A-Za-z\-_]{35}", "Possible hardcoded Google API key", "MEDIUM", 798,
                 "A Google-style API key pattern was detected in the uploaded codebase.",
                 "Restrict the key, rotate it, and move secret material out of source control.",
                 "https://cwe.mitre.org/data/definitions/798.html"),
                (r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"\'][^\"\']{8,}[\"\']", "Possible hardcoded secret assignment", "MEDIUM", 798,
                 "A variable that appears to store a password, token, or API key directly in code was detected.",
                 "Use environment variables, secret managers, or server-side token exchange instead of literal credentials.",
                 "https://cwe.mitre.org/data/definitions/798.html"),
            ]
            for pattern, title, severity, cwe_id, description, remediation, ref_url in generic_patterns:
                for offset, snippet in _iter_match_lines(pattern, text):
                    add_finding(title, severity, description, cwe_id, rel_path, _line_number(text, offset), snippet, remediation, ref_url)
                    break

            js_sink_patterns = [
                (r"\beval\s*\(", "Dynamic code execution via eval()", "HIGH", 95,
                 "Use of eval() can enable arbitrary code execution or DOM-based injection when fed attacker-controlled input.",
                 "Eliminate eval(). Prefer safe parsing, explicit dispatch tables, or structured data formats like JSON.",
                 "https://cwe.mitre.org/data/definitions/95.html"),
                (r"innerHTML\s*=", "DOM write through innerHTML", "MEDIUM", 79,
                 "Writing unsanitized data through innerHTML can create DOM-based XSS if attacker input reaches the sink.",
                 "Prefer textContent or sanitized templating libraries before rendering untrusted data.",
                 "https://cwe.mitre.org/data/definitions/79.html"),
                (r"document\.write\s*\(", "Use of document.write()", "MEDIUM", 79,
                 "document.write() is an unsafe HTML injection sink that can open the door to cross-site scripting flaws.",
                 "Remove document.write() and render content through safe DOM APIs.",
                 "https://cwe.mitre.org/data/definitions/79.html"),
            ]
            if any(rel_path.endswith(ext) for ext in (".js", ".jsx", ".ts", ".tsx", ".html")):
                for pattern, title, severity, cwe_id, description, remediation, ref_url in js_sink_patterns:
                    for offset, snippet in _iter_match_lines(pattern, text, re.IGNORECASE):
                        add_finding(title, severity, description, cwe_id, rel_path, _line_number(text, offset), snippet, remediation, ref_url)
                        break

            python_patterns = [
                (r"subprocess\.(run|Popen|call)\([^\n]{0,180}shell\s*=\s*True", "Command execution with shell=True", "HIGH", 78,
                 "Spawning shell commands with shell=True increases command injection risk if any part of the command is influenced by external input.",
                 "Use argument arrays with shell=False and validate command parameters strictly.",
                 "https://cwe.mitre.org/data/definitions/78.html"),
                (r"pickle\.loads\s*\(", "Unsafe deserialization with pickle.loads()", "HIGH", 502,
                 "pickle.loads() on untrusted data can result in arbitrary code execution during deserialization.",
                 "Do not deserialize untrusted pickle payloads. Use safe serialization formats such as JSON.",
                 "https://cwe.mitre.org/data/definitions/502.html"),
                (r"yaml\.load\s*\(", "Potentially unsafe YAML loading", "MEDIUM", 502,
                 "yaml.load() may construct arbitrary Python objects depending on the loader in use.",
                 "Use yaml.safe_load() unless a trusted custom loader is strictly required.",
                 "https://cwe.mitre.org/data/definitions/502.html"),
                (r"app\.run\([^\n]{0,140}debug\s*=\s*True", "Flask debug mode enabled", "MEDIUM", 489,
                 "Running Flask with debug=True in a deployed context can expose stack traces and an interactive debugger.",
                 "Disable debug mode in non-development environments and move configuration to environment variables.",
                 "https://cwe.mitre.org/data/definitions/489.html"),
            ]
            if rel_path.endswith(".py"):
                for pattern, title, severity, cwe_id, description, remediation, ref_url in python_patterns:
                    for offset, snippet in _iter_match_lines(pattern, text, re.IGNORECASE):
                        add_finding(title, severity, description, cwe_id, rel_path, _line_number(text, offset), snippet, remediation, ref_url)
                        break
                if 'execute(f"' in text or "execute(f'" in text or ('.execute("SELECT' in text and '+' in text):
                    add_finding(
                        "Potential SQL query construction with string interpolation",
                        "HIGH",
                        "The code appears to build SQL statements with string formatting or concatenation, which can lead to SQL injection if user input is inserted directly.",
                        89,
                        rel_path,
                        None,
                        "Database execute(...) appears to use concatenated or interpolated SQL.",
                        "Use parameterized queries or ORM binding APIs instead of interpolating values into SQL strings.",
                        "https://cwe.mitre.org/data/definitions/89.html",
                    )

            tls_patterns = [
                (r"verify\s*=\s*False", "TLS certificate verification disabled", "HIGH", 295,
                 "The code disables TLS certificate verification, which allows man-in-the-middle interception of traffic.",
                 "Enable certificate verification and trust only valid CA chains or pinned certificates.",
                 "https://cwe.mitre.org/data/definitions/295.html"),
                (r"rejectUnauthorized\s*:\s*false", "TLS verification disabled in HTTP client", "HIGH", 295,
                 "The HTTP client explicitly disables server certificate validation.",
                 "Set rejectUnauthorized to true and fix certificate trust handling properly.",
                 "https://cwe.mitre.org/data/definitions/295.html"),
                (r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"\']0[\"\']", "Global Node TLS verification disabled", "HIGH", 295,
                 "Disabling NODE_TLS_REJECT_UNAUTHORIZED globally weakens every HTTPS request from that process.",
                 "Remove the override and resolve trust issues with proper certificates.",
                 "https://cwe.mitre.org/data/definitions/295.html"),
                (r"_create_unverified_context\s*\(", "Creation of unverified SSL context", "HIGH", 295,
                 "An SSL context without certificate verification was detected.",
                 "Create verified contexts and enforce hostname validation.",
                 "https://cwe.mitre.org/data/definitions/295.html"),
            ]
            for pattern, title, severity, cwe_id, description, remediation, ref_url in tls_patterns:
                for offset, snippet in _iter_match_lines(pattern, text, re.IGNORECASE):
                    add_finding(title, severity, description, cwe_id, rel_path, _line_number(text, offset), snippet, remediation, ref_url)
                    break

            if rel_path.endswith((".env", ".yaml", ".yml", ".json", ".ini", ".properties")) and "debug=true" in lowered:
                add_finding(
                    "Debug configuration enabled in project settings",
                    "LOW",
                    "The uploaded folder contains configuration that appears to enable debug mode.",
                    489,
                    rel_path,
                    None,
                    "debug=true",
                    "Disable debug mode outside development and keep environment-specific secure defaults.",
                    "https://cwe.mitre.org/data/definitions/489.html",
                )

    folder_name = os.path.basename(root_dir.rstrip("/")) or "Uploaded Folder"
    return {
        "meta": {
            "folder_name": folder_name,
            "file_count": scanned_files,
            "total_size": total_bytes,
            "languages": sorted(languages),
        },
        "findings": findings,
    }

# ----------------------------------------------------------------------------------------------------------------
# worker

def scan_worker(scan_id: int, target_url: str):
    conn = get_conn()
    try:
        safe_update_scan(
            conn, scan_id,
            error_message="WORKER_STARTED",
            phase="INIT",
            spider_progress=0,
            ascan_progress=0
        )

        # Retry wrapper 
        last_err = None
        for attempt in range(1, 6):
            try:
                # seed
                safe_update_scan(conn, scan_id, phase="SEED", error_message="ACCESS_URL")
                access_url(target_url)

                # SPIDER 
                safe_update_scan(conn, scan_id, phase="SPIDER", spider_progress=0, error_message="SPIDER_START")
                sid = spider_scan(target_url)
                safe_update_scan(conn, scan_id, zap_spider_id=sid)

                while True:
                    pct = int(spider_status(sid))
                    safe_update_scan(conn, scan_id, spider_progress=pct, error_message=f"SPIDER {pct}%")

                    # STREAM: fetch & ingest while spider runs
                    alerts = fetch_alerts(target_url)
                    conn.execute("BEGIN")
                    ingest_alerts_incremental(conn, scan_id, alerts)
                    conn.execute("COMMIT")
                    conn.commit()

                    if pct >= 100:
                        break
                    time.sleep(5)

                # ACTIVE SCAN 
                safe_update_scan(conn, scan_id, phase="ASCAN", ascan_progress=0, error_message="ASCAN_START")
                aid = ascan_scan(target_url)
                safe_update_scan(conn, scan_id, zap_ascan_id=aid)

                while True:
                    pct = int(ascan_status(aid))
                    safe_update_scan(conn, scan_id, ascan_progress=pct, error_message=f"ASCAN {pct}%")

                    # STREAM: fetch & ingest while ascan runs
                    alerts = fetch_alerts(target_url)
                    conn.execute("BEGIN")
                    ingest_alerts_incremental(conn, scan_id, alerts)
                    conn.execute("COMMIT")
                    conn.commit()

                    if pct >= 100:
                        break
                    time.sleep(5)

                # final fetch 
                safe_update_scan(conn, scan_id, phase="FINALIZE", error_message="FINAL_FETCH_ALERTS")
                alerts = fetch_alerts(target_url)
                conn.execute("BEGIN")
                ingest_alerts_incremental(conn, scan_id, alerts)
                conn.execute("COMMIT")
                conn.commit()

                last_err = None
                break

            except Exception as e:
                last_err = e
                safe_update_scan(
                    conn,
                    scan_id,
                    phase="RETRY",
                    error_message=f"ZAP_RETRY_{attempt}: {type(e).__name__}: {e}"
                )
                time.sleep(2 * attempt)

        if last_err is not None:
            raise last_err

        # mark done
        safe_update_scan(conn, scan_id, phase="DONE", spider_progress=100, ascan_progress=100, error_message=None)
        conn.execute("""
            UPDATE scans
            SET status='COMPLETED',
                finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE scan_id=?
        """, (scan_id,))
        ctx = get_scan_notification_context(conn, scan_id) or {}
        if ctx.get("user_id"):
            create_notification(
                conn,
                int(ctx["user_id"]),
                "SCAN_COMPLETED",
                "Scan completed",
                f"{ctx.get('target_type', 'Target')} scan finished for {ctx.get('target_name') or 'your target'}. Report is ready.",
                level="SUCCESS",
                scan_id=scan_id,
                action_url="/reports",
                metadata={"target_type": ctx.get("target_type"), "target_name": ctx.get("target_name")},
            )
        conn.commit()

    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass

        safe_update_scan(
            conn,
            scan_id,
            status="FAILED",
            finished_at=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            phase="FAILED",
            error_message=f"{type(e).__name__}: {e}"
        )
        ctx = get_scan_notification_context(conn, scan_id) or {}
        if ctx.get("user_id"):
            create_notification(
                conn,
                int(ctx["user_id"]),
                "SCAN_FAILED",
                "Scan failed",
                f"{ctx.get('target_type', 'Target')} scan failed for {ctx.get('target_name') or 'your target'}. Check scan logs for details.",
                level="ERROR",
                scan_id=scan_id,
                action_url="/reports",
                metadata={"target_type": ctx.get("target_type"), "target_name": ctx.get("target_name"), "error": str(e)},
            )
            conn.commit()

    finally:
        conn.close()


def apk_scan_worker(scan_id: int, target_id: int, apk_path: str):
    conn = get_conn()
    try:
        safe_update_scan(
            conn,
            scan_id,
            phase="APK_INIT",
            spider_progress=0,
            ascan_progress=5,
            error_message="APK_WORKER_STARTED"
        )

        safe_update_scan(
            conn,
            scan_id,
            phase="APK_ANALYZE",
            spider_progress=0,
            ascan_progress=55,
            error_message="PARSING_APK"
        )
        report = analyze_apk_static(apk_path)

        meta = report["meta"]
        perms_json = json.dumps(meta.get("permissions") or [])

        conn.execute("""
            UPDATE apk_files
            SET package_name=?, app_version=?, permissions=?
            WHERE target_id=?
        """, (meta.get("package_name"), meta.get("app_version"), perms_json, target_id))
        conn.commit()

        # insert findings
        next_no = conn.execute(
            "SELECT COALESCE(MAX(finding_no), 0) AS m FROM findings WHERE scan_id=?",
            (scan_id,)
        ).fetchone()["m"] or 0

        inserted = 0
        for f in report["findings"]:
            next_no += 1
            inserted += 1

            raw_json = json.dumps({"apk_check": True, "data": f}, ensure_ascii=False)

            conn.execute("""
                INSERT INTO findings(
                    scan_id, finding_no, title, severity, cvss_score,
                    description, owasp_code, cwe_id, raw_json
                )
                VALUES(?, ?, ?, ?, NULL, ?, NULL, ?, ?)
            """, (
                scan_id, next_no,
                f["title"], f["severity"],
                f.get("description"),
                f.get("cwe_id"),
                raw_json
            ))

            finding_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            # evidence
            ev_url = f.get("evidence_url")
            ev_text = f.get("evidence_text")
            if ev_text:
                conn.execute("""
                    INSERT INTO evidence(finding_id, evidence_type, url, content)
                    VALUES (?, 'TEXT', ?, ?)
                """, (finding_id, ev_url, str(ev_text)))

            # remediation
            rem = f.get("remediation_text")
            if rem:
                conn.execute("""
                    INSERT INTO remediations(finding_id, source, text, reference_url)
                    VALUES (?, 'APK_STATIC', ?, ?)
                """, (finding_id, rem, f.get("ref_url")))

        conn.execute("UPDATE scans SET total_findings=? WHERE scan_id=?", (inserted, scan_id))
        conn.execute("""
            UPDATE scans
            SET status='COMPLETED',
                phase='DONE',
                spider_progress=100,
                ascan_progress=100,
                finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                error_message=NULL
            WHERE scan_id=?
        """, (scan_id,))
        ctx = get_scan_notification_context(conn, scan_id) or {}
        if ctx.get("user_id"):
            create_notification(
                conn,
                int(ctx["user_id"]),
                "APK_SCAN_COMPLETED",
                "APK scan completed",
                f"APK analysis finished for {ctx.get('target_name') or 'your file'}. Review the generated findings.",
                level="SUCCESS",
                scan_id=scan_id,
                action_url="/reports",
                metadata={"target_type": "APK", "target_name": ctx.get("target_name")},
            )
        conn.commit()

    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass

        safe_update_scan(
            conn,
            scan_id,
            status="FAILED",
            finished_at=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            phase="FAILED",
            error_message=f"{type(e).__name__}: {e}"
        )
        ctx = get_scan_notification_context(conn, scan_id) or {}
        if ctx.get("user_id"):
            create_notification(
                conn,
                int(ctx["user_id"]),
                "APK_SCAN_FAILED",
                "APK scan failed",
                f"APK analysis failed for {ctx.get('target_name') or 'your file'}.",
                level="ERROR",
                scan_id=scan_id,
                action_url="/reports",
                metadata={"target_type": "APK", "target_name": ctx.get("target_name"), "error": str(e)},
            )
            conn.commit()
    finally:
        conn.close()

def code_scan_worker(scan_id: int, target_id: int, root_dir: str):
    conn = get_conn()
    try:
        safe_update_scan(
            conn,
            scan_id,
            phase="CODE_INIT",
            spider_progress=5,
            ascan_progress=5,
            error_message="CODE_WORKER_STARTED"
        )

        safe_update_scan(
            conn,
            scan_id,
            phase="CODE_INDEX",
            spider_progress=25,
            ascan_progress=25,
            error_message="INDEXING_FILES"
        )
        report = analyze_code_folder_static(root_dir)

        meta = report["meta"]
        existing_target = conn.execute(
            "SELECT folder_name FROM code_targets WHERE target_id=?",
            (target_id,),
        ).fetchone()
        display_folder_name = (existing_target["folder_name"] if existing_target and existing_target["folder_name"] else None) \
            or meta.get("folder_name") \
            or os.path.basename(root_dir)
        meta["folder_name"] = display_folder_name

        conn.execute(
            """
            UPDATE code_targets
            SET folder_name=?, file_count=?, total_size=?, summary_json=?, root_path_hint=?
            WHERE target_id=?
            """,
            (
                display_folder_name,
                int(meta.get("file_count") or 0),
                int(meta.get("total_size") or 0),
                json.dumps(meta, ensure_ascii=False),
                root_dir,
                target_id,
            ),
        )
        conn.commit()

        safe_update_scan(
            conn,
            scan_id,
            phase="CODE_ANALYZE",
            spider_progress=50,
            ascan_progress=75,
            error_message="ANALYZING_CODE"
        )

        next_no = conn.execute(
            "SELECT COALESCE(MAX(finding_no), 0) AS m FROM findings WHERE scan_id=?",
            (scan_id,),
        ).fetchone()["m"] or 0

        inserted = 0
        for f in report["findings"]:
            next_no += 1
            inserted += 1
            raw_json = json.dumps({"code_check": True, "data": f}, ensure_ascii=False)
            conn.execute(
                """
                INSERT INTO findings(
                    scan_id, finding_no, title, severity, cvss_score,
                    description, owasp_code, cwe_id, raw_json
                )
                VALUES(?, ?, ?, ?, NULL, ?, NULL, ?, ?)
                """,
                (
                    scan_id, next_no,
                    f["title"], f["severity"],
                    f.get("description"),
                    f.get("cwe_id"),
                    raw_json,
                ),
            )
            finding_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            if f.get("evidence_text"):
                conn.execute(
                    """
                    INSERT INTO evidence(finding_id, evidence_type, url, content)
                    VALUES (?, 'TEXT', ?, ?)
                    """,
                    (finding_id, f.get("evidence_url"), str(f.get("evidence_text"))),
                )
            if f.get("remediation_text"):
                conn.execute(
                    """
                    INSERT INTO remediations(finding_id, source, text, reference_url)
                    VALUES (?, 'CODE_STATIC', ?, ?)
                    """,
                    (finding_id, f.get("remediation_text"), f.get("ref_url")),
                )

        conn.execute("UPDATE scans SET total_findings=? WHERE scan_id=?", (inserted, scan_id))
        conn.execute(
            """
            UPDATE scans
            SET status='COMPLETED',
                phase='DONE',
                spider_progress=100,
                ascan_progress=100,
                finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                error_message=NULL
            WHERE scan_id=?
            """,
            (scan_id,),
        )
        ctx = get_scan_notification_context(conn, scan_id) or {}
        if ctx.get("user_id"):
            create_notification(
                conn,
                int(ctx["user_id"]),
                "CODE_SCAN_COMPLETED",
                "Folder scan completed",
                f"Code folder analysis finished for {ctx.get('target_name') or 'your uploaded folder'}.",
                level="SUCCESS",
                scan_id=scan_id,
                action_url="/reports",
                metadata={"target_type": "FOLDER", "target_name": ctx.get("target_name"), "files": meta.get("file_count")},
            )
        conn.commit()

    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        safe_update_scan(
            conn,
            scan_id,
            status="FAILED",
            finished_at=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            phase="FAILED",
            error_message=f"{type(e).__name__}: {e}"
        )
        ctx = get_scan_notification_context(conn, scan_id) or {}
        if ctx.get("user_id"):
            create_notification(
                conn,
                int(ctx["user_id"]),
                "CODE_SCAN_FAILED",
                "Folder scan failed",
                f"Code folder analysis failed for {ctx.get('target_name') or 'your uploaded folder'}.",
                level="ERROR",
                scan_id=scan_id,
                action_url="/reports",
                metadata={"target_type": "FOLDER", "target_name": ctx.get("target_name"), "error": str(e)},
            )
            conn.commit()
    finally:
        conn.close()


def malware_scan_worker(scan_id: int, target_id: int, pe_path: str, display_name: str):
    """
    Background worker for PE-binary malware scans.

    Runs the three trained classifiers (LightGBM, Random Forest, XGBoost) over
    the uploaded `.exe` / `.dll` / `.sys`, projects each model's output into
    VSAWA's findings/evidence/remediation schema, and stores an aggregated
    verdict on the `pe_files` row.

    Phases reported via `phase` column for the ScanPage progress bar:
        PE_INIT          – worker entered, file present
        PE_FEATURES      – feature extraction in progress (slowest phase)
        PE_PREDICT       – running the 3 classifiers
        PE_PERSIST       – writing findings to the DB
        DONE / FAILED    – terminal
    """
    
    from malware_scan.scanner import scan_pe_file

    conn = get_conn()
    try:
        safe_update_scan(
            conn, scan_id,
            phase="PE_INIT", spider_progress=0, ascan_progress=5,
            error_message="MALWARE_WORKER_STARTED",
        )

        safe_update_scan(
            conn, scan_id,
            phase="PE_FEATURES", spider_progress=15, ascan_progress=25,
            error_message="EXTRACTING_FEATURES",
        )

     
        safe_update_scan(
            conn, scan_id,
            phase="PE_PREDICT", spider_progress=40, ascan_progress=60,
            error_message="RUNNING_CLASSIFIERS",
        )
        report = scan_pe_file(pe_path, original_name=display_name)

        safe_update_scan(
            conn, scan_id,
            phase="PE_PERSIST", spider_progress=80, ascan_progress=90,
            error_message="PERSISTING_FINDINGS",
        )

       
        summary_json = json.dumps({
            "overall_prediction": report["overall_prediction"],
            "malicious_votes":    report["malicious_votes"],
            "total_models":       report["total_models"],
            "size_bytes":         report["size_bytes"],
            "size_human":         report["size_human"],
            "model_results":      report["model_results"],
        }, ensure_ascii=False, default=str)

        conn.execute(
            """
            UPDATE pe_files
            SET md5_hash = ?, verdict = ?, summary_json = ?
            WHERE target_id = ?
            """,
            (report["md5"], report["overall_prediction"], summary_json, target_id),
        )

        # Insert each finding into the standard findings/evidence/remediations
        # tables so the existing PDF generator and Reports page can render
        # malware findings with zero special-casing.
        next_no = conn.execute(
            "SELECT COALESCE(MAX(finding_no), 0) AS m FROM findings WHERE scan_id=?",
            (scan_id,),
        ).fetchone()["m"] or 0

        inserted = 0
        for f in report["vsawa_findings"]:
            next_no += 1
            inserted += 1

            raw_json = json.dumps(
                {"malware_check": True, "model": f.get("model"), "data": f},
                ensure_ascii=False,
                default=str,
            )

            conn.execute(
                """
                INSERT INTO findings(
                    scan_id, finding_no, title, severity, cvss_score,
                    description, owasp_code, cwe_id, raw_json
                ) VALUES(?, ?, ?, ?, NULL, ?, NULL, ?, ?)
                """,
                (
                    scan_id, next_no,
                    f["title"], f["severity"],
                    f.get("description"),
                    f.get("cwe_id"),
                    raw_json,
                ),
            )

            finding_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            if f.get("evidence_text"):
                conn.execute(
                    """
                    INSERT INTO evidence(finding_id, evidence_type, url, content)
                    VALUES (?, 'TEXT', NULL, ?)
                    """,
                    (finding_id, str(f["evidence_text"])),
                )

            if f.get("remediation_text"):
                conn.execute(
                    """
                    INSERT INTO remediations(finding_id, source, text, reference_url)
                    VALUES (?, 'MALWARE_ML', ?, NULL)
                    """,
                    (finding_id, f["remediation_text"]),
                )

        conn.execute("UPDATE scans SET total_findings=? WHERE scan_id=?", (inserted, scan_id))
        conn.execute(
            """
            UPDATE scans
            SET status='COMPLETED', phase='DONE',
                spider_progress=100, ascan_progress=100,
                finished_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                error_message=NULL
            WHERE scan_id=?
            """,
            (scan_id,),
        )

        ctx = get_scan_notification_context(conn, scan_id) or {}
        if ctx.get("user_id"):
            verdict = report["overall_prediction"]
            create_notification(
                conn, int(ctx["user_id"]),
                "MALWARE_SCAN_COMPLETED",
                f"Malware scan: {verdict}",
                f"PE analysis of {display_name} finished — verdict: {verdict}.",
                level="WARNING" if verdict == "Malicious" else "SUCCESS",
                scan_id=scan_id,
                action_url="/reports",
                metadata={
                    "target_type": "MALWARE",
                    "target_name": display_name,
                    "verdict": verdict,
                    "malicious_votes": report["malicious_votes"],
                    "total_models": report["total_models"],
                },
            )
        conn.commit()

        
        try:
            if os.path.exists(pe_path):
                os.remove(pe_path)
        except Exception:
            pass

    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass

        safe_update_scan(
            conn, scan_id,
            status="FAILED",
            finished_at=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            phase="FAILED",
            error_message=f"{type(e).__name__}: {e}",
        )
        ctx = get_scan_notification_context(conn, scan_id) or {}
        if ctx.get("user_id"):
            create_notification(
                conn, int(ctx["user_id"]),
                "MALWARE_SCAN_FAILED",
                "Malware scan failed",
                f"PE binary analysis failed for {display_name}.",
                level="ERROR",
                scan_id=scan_id,
                action_url="/reports",
                metadata={"target_type": "MALWARE", "target_name": display_name, "error": str(e)},
            )
            conn.commit()
    finally:
        conn.close()


def _load_scan_report_data(conn, user_id: int, scan_id: int):
    scan = conn.execute(
        """
        SELECT
            s.scan_id,
            s.user_id,
            s.status,
            s.phase,
            s.total_findings,
            s.started_at,
            s.finished_at,
            s.error_message,
            CASE
                WHEN pf.target_id IS NOT NULL THEN 'MALWARE'
                WHEN ct.target_id IS NOT NULL THEN 'FOLDER'
                ELSE t.target_type
            END AS target_type,
            COALESCE(u.url, af.file_name, ct.folder_name, pf.file_name) AS target_name,
            af.package_name,
            af.app_version,
            ct.file_count AS folder_file_count,
            ct.total_size AS folder_total_size,
            ct.summary_json AS folder_summary_json,
            pf.file_name   AS pe_file_name,
            pf.file_size   AS pe_file_size,
            pf.md5_hash    AS pe_md5,
            pf.verdict     AS pe_verdict,
            pf.summary_json AS pe_summary_json
        FROM scans s
        JOIN targets t ON t.target_id = s.target_id
        LEFT JOIN url_targets u ON u.target_id = t.target_id
        LEFT JOIN apk_files af ON af.target_id = t.target_id
        LEFT JOIN code_targets ct ON ct.target_id = t.target_id
        LEFT JOIN pe_files pf ON pf.target_id = t.target_id
        WHERE s.scan_id = ? AND s.user_id = ?
        """,
        (scan_id, user_id),
    ).fetchone()

    if not scan:
        return None

    findings_rows = conn.execute(
        """
        SELECT
            finding_id,
            finding_no,
            title,
            severity,
            description,
            cwe_id,
            owasp_code
        FROM findings
        WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                WHEN 'INFO' THEN 5
                ELSE 6
            END,
            finding_no ASC
        """,
        (scan_id,),
    ).fetchall()

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    findings = []

    for row in findings_rows:
        finding = dict(row)
        sev = (finding.get("severity") or "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

        evidence_rows = conn.execute(
            "SELECT url, content FROM evidence WHERE finding_id = ? LIMIT 3",
            (finding["finding_id"],),
        ).fetchall()
        remediation_rows = conn.execute(
            "SELECT text, reference_url FROM remediations WHERE finding_id = ? LIMIT 3",
            (finding["finding_id"],),
        ).fetchall()

        finding["evidence"] = [dict(r) for r in evidence_rows]
        finding["remediations"] = [dict(r) for r in remediation_rows]
        findings.append(finding)

    scan_dict = dict(scan)
    try:
        scan_dict["folder_summary"] = json.loads(scan_dict.get("folder_summary_json") or "{}")
    except Exception:
        scan_dict["folder_summary"] = {}
    try:
        scan_dict["pe_summary"] = json.loads(scan_dict.get("pe_summary_json") or "{}")
    except Exception:
        scan_dict["pe_summary"] = {}

    return {
        "scan": scan_dict,
        "severity_counts": severity_counts,
        "findings": findings,
    }


# -----------------------------------------------------------------------------------------------------------------
# routes

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        origin = request.headers.get("Origin", "")
        resp = make_response("", 204)

        if origin in ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin

        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = request.headers.get(
            "Access-Control-Request-Headers", "Content-Type, Authorization"
        )
        return resp


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "zap_version": zap_version()})


@app.post("/api/auth/signup")
def signup():
    body = request.get_json(force=True, silent=True) or {}

    name = (body.get("name") or "").strip()
    email = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "")

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not email or "@" not in email:
        return jsonify({"error": "valid email is required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    pw_hash = generate_password_hash(password, method="pbkdf2:sha256")

    conn = get_conn()
    try:
        try:
            conn.execute(
                "INSERT INTO users(name, email, password_hash, status) VALUES(?, ?, ?, 'ACTIVE')",
                (name, email, pw_hash),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "email already exists"}), 409

        user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return jsonify({"user_id": int(user_id), "name": name, "email": email}), 201
    finally:
        conn.close()


@app.post("/api/auth/login")
def login():
    body = request.get_json(force=True, silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "")

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT user_id, name, email, password_hash, status FROM users WHERE email=?",
            (email,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "invalid credentials"}), 401
    if row["status"] != "ACTIVE":
        return jsonify({"error": "account not active"}), 403
    if not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401

    access_token = create_access_token(identity=str(row["user_id"]))

    return jsonify({
        "access_token": access_token,
        "user": {"user_id": int(row["user_id"]), "name": row["name"], "email": row["email"]}
    }), 200


@app.get("/api/auth/me")
@jwt_required()
def me():
    user_id = int(get_jwt_identity())
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT user_id, name, email, status, created_at FROM users WHERE user_id=?",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "user not found"}), 404
    return jsonify(dict(row)), 200


@app.post("/api/scans")
@jwt_required()
def create_scan():
    user_id = int(get_jwt_identity())
    body = request.get_json(force=True, silent=True) or {}

    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    try:
        validate_target_url(url)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    conn = get_conn()
    try:
        target_id = get_or_create_url_target(conn, user_id, url)

        conn.execute("""
            INSERT INTO scans(user_id, target_id, status, phase, spider_progress, ascan_progress, error_message)
            VALUES(?, ?, 'RUNNING', 'QUEUED', 0, 0, 'QUEUED')
        """, (user_id, target_id))

        scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        create_notification(
            conn,
            user_id,
            "SCAN_QUEUED",
            "Web scan started",
            f"Web scan queued for {url}.",
            level="INFO",
            scan_id=int(scan_id),
            action_url="/reports",
            metadata={"target_type": "URL", "target_name": url},
        )
        conn.commit()
    finally:
        conn.close()

    t = threading.Thread(target=scan_worker, args=(scan_id, url), daemon=True)
    t.start()

    return jsonify({"scan_id": int(scan_id), "status": "RUNNING"}), 202

@app.post("/api/apk-scans")
@jwt_required()
def create_apk_scan():
    user_id = int(get_jwt_identity())

    if "apk" not in request.files:
        return jsonify({"error": "apk file field is required (multipart/form-data, field name: apk)"}), 400

    f = request.files["apk"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400

    filename = secure_filename(f.filename)
    if not filename.lower().endswith(".apk"):
        return jsonify({"error": "only .apk files are allowed"}), 400

    # Save file
    save_path = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{filename}")
    f.save(save_path)

    file_size = os.path.getsize(save_path)

    conn = get_conn()
    try:
        target_id = create_apk_target(conn, user_id, filename, file_size)

        conn.execute("""
            INSERT INTO scans(user_id, target_id, status, phase, spider_progress, ascan_progress, error_message)
            VALUES(?, ?, 'RUNNING', 'QUEUED', 0, 0, 'QUEUED')
        """, (user_id, target_id))

        scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        create_notification(
            conn,
            user_id,
            "APK_SCAN_QUEUED",
            "APK scan started",
            f"APK upload accepted for {filename}. Static analysis is running.",
            level="INFO",
            scan_id=int(scan_id),
            action_url="/reports",
            metadata={"target_type": "APK", "target_name": filename, "file_size": file_size},
        )
        conn.commit()
    finally:
        conn.close()

    t = threading.Thread(target=apk_scan_worker, args=(scan_id, target_id, save_path), daemon=True)
    t.start()

    return jsonify({"scan_id": int(scan_id), "status": "RUNNING"}), 202

@app.post("/api/folder-scans")
@jwt_required()
def create_folder_scan():
    user_id = int(get_jwt_identity())
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "folder files are required (multipart/form-data field name: files)"}), 400
    if len(files) > MAX_CODE_FILES:
        return jsonify({"error": f"Too many files uploaded. Limit is {MAX_CODE_FILES}. Exclude node_modules, dist, build, coverage, and other generated folders before uploading."}), 400

    rel_paths = []
    raw_paths = request.form.get("relative_paths")
    if raw_paths:
        try:
            rel_paths = json.loads(raw_paths)
        except Exception:
            rel_paths = []
    if rel_paths and len(rel_paths) != len(files):
        return jsonify({"error": "relative_paths count does not match uploaded file count"}), 400

    folder_label = (request.form.get("folder_name") or "uploaded-folder").strip() or "uploaded-folder"
    folder_label = secure_filename(folder_label) or "uploaded-folder"
    root_dir = os.path.join(CODE_UPLOAD_DIR, f"{int(time.time())}_{folder_label}")
    os.makedirs(root_dir, exist_ok=True)

    saved_count = 0
    total_size = 0
    for idx, f in enumerate(files):
        incoming_name = rel_paths[idx] if idx < len(rel_paths) else f.filename
        safe_rel = incoming_name.replace("\\", "/").lstrip("/")
        safe_parts = []
        for part in safe_rel.split("/"):
            if not part or part in {".", ".."}:
                continue
            safe_parts.append(secure_filename(part))
        if not safe_parts:
            continue
        dest_path = os.path.join(root_dir, *safe_parts)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        f.save(dest_path)
        saved_count += 1
        total_size += os.path.getsize(dest_path)

    if saved_count == 0:
        shutil.rmtree(root_dir, ignore_errors=True)
        return jsonify({"error": "No valid files were found in uploaded folder."}), 400

    conn = get_conn()
    try:
        target_id = create_code_target(conn, user_id, folder_label, saved_count, total_size, root_dir)
        conn.execute(
            """
            INSERT INTO scans(user_id, target_id, status, phase, spider_progress, ascan_progress, error_message)
            VALUES(?, ?, 'RUNNING', 'QUEUED', 0, 0, 'QUEUED')
            """,
            (user_id, target_id),
        )
        scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        create_notification(
            conn,
            user_id,
            "CODE_SCAN_QUEUED",
            "Folder scan started",
            f"Folder upload accepted for {folder_label}. Static source analysis is running.",
            level="INFO",
            scan_id=int(scan_id),
            action_url="/reports",
            metadata={"target_type": "FOLDER", "target_name": folder_label, "file_count": saved_count},
        )
        conn.commit()
    finally:
        conn.close()

    t = threading.Thread(target=code_scan_worker, args=(scan_id, target_id, root_dir), daemon=True)
    t.start()

    return jsonify({"scan_id": int(scan_id), "status": "RUNNING", "file_count": saved_count}), 202


MAX_PE_UPLOAD_MB = int(os.environ.get("MAX_PE_UPLOAD_MB", "60"))
ALLOWED_PE_EXTS = {".exe", ".dll", ".sys"}


@app.post("/api/malware-scans")
@jwt_required()
def create_malware_scan():
    """
    Upload a Windows PE binary (.exe / .dll / .sys) and queue an ML
    malware scan over it. Runs the LightGBM, Random Forest, and XGBoost
    classifiers trained on EMBER-style static features.

    Returns:
        202 {scan_id, status: "RUNNING"}
        400 if file missing / wrong extension / size limit exceeded
    """
    user_id = int(get_jwt_identity())

    if "file" not in request.files:
        return jsonify({
            "error": "PE file field is required (multipart/form-data field name: file)"
        }), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400

    filename = secure_filename(f.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_PE_EXTS:
        return jsonify({
            "error": f"Unsupported extension '{ext}'. "
                     f"Allowed PE extensions: {', '.join(sorted(ALLOWED_PE_EXTS))}"
        }), 400

   
    save_path = os.path.join(UPLOAD_DIR, f"{int(time.time())}_pe_{filename}")
    f.save(save_path)

    file_size = os.path.getsize(save_path)
    if file_size > MAX_PE_UPLOAD_MB * 1024 * 1024:
        try:
            os.remove(save_path)
        except Exception:
            pass
        return jsonify({
            "error": f"PE binary is too large. Limit is {MAX_PE_UPLOAD_MB} MB."
        }), 413

    conn = get_conn()
    try:
        target_id = create_pe_target(conn, user_id, filename, file_size)

        conn.execute("""
            INSERT INTO scans(user_id, target_id, status, phase, spider_progress, ascan_progress, error_message)
            VALUES(?, ?, 'RUNNING', 'QUEUED', 0, 0, 'QUEUED')
        """, (user_id, target_id))

        scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        create_notification(
            conn, user_id,
            "MALWARE_SCAN_QUEUED",
            "Malware scan started",
            f"PE binary '{filename}' is being analysed by the ML classifiers.",
            level="INFO",
            scan_id=int(scan_id),
            action_url="/reports",
            metadata={"target_type": "MALWARE", "target_name": filename, "file_size": file_size},
        )
        conn.commit()
    finally:
        conn.close()

    t = threading.Thread(
        target=malware_scan_worker,
        args=(scan_id, target_id, save_path, filename),
        daemon=True,
    )
    t.start()

    return jsonify({"scan_id": int(scan_id), "status": "RUNNING"}), 202


@app.get("/api/scans/<int:scan_id>")
@jwt_required()
def get_scan(scan_id: int):
    user_id = int(get_jwt_identity())
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id=? AND user_id=?",
            (scan_id, user_id)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row)), 200


@app.get("/api/scans/<int:scan_id>/findings")
@jwt_required()
def get_findings(scan_id: int):
    user_id = int(get_jwt_identity())
    conn = get_conn()
    try:
        scan = conn.execute(
            "SELECT 1 FROM scans WHERE scan_id=? AND user_id=?",
            (scan_id, user_id)
        ).fetchone()
        if not scan:
            return jsonify({"error": "not found"}), 404

        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY finding_no ASC",
            (scan_id,)
        ).fetchall()
    finally:
        conn.close()

    return jsonify([dict(r) for r in rows]), 200


@app.put("/api/auth/password")
@jwt_required()
def change_password():
    user_id = int(get_jwt_identity())
    body = request.get_json(force=True, silent=True) or {}
    current_pw = body.get("current_password", "")
    new_pw = body.get("new_password", "")

    if not current_pw or not new_pw:
        return jsonify({"error": "current_password and new_password are required"}), 400
    if len(new_pw) < 12:
        return jsonify({"error": "New password must be at least 12 characters"}), 400

    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404
        if not check_password_hash(row["password_hash"], current_pw):
            return jsonify({"error": "Current password is incorrect"}), 401

        new_hash = generate_password_hash(new_pw, method="pbkdf2:sha256")
        conn.execute(
            "UPDATE users SET password_hash=? WHERE user_id=?", (new_hash, user_id)
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "Password updated successfully"}), 200


@app.delete("/api/auth/account")
@jwt_required()
def delete_account():
    user_id = int(get_jwt_identity())
    body = request.get_json(force=True, silent=True) or {}
    password = body.get("password", "")

    if not password:
        return jsonify({"error": "password is required to confirm deletion"}), 400

    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404
        if not check_password_hash(row["password_hash"], password):
            return jsonify({"error": "Incorrect password"}), 401

        conn.execute("DELETE FROM users WHERE user_id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "Account deleted"}), 200


@app.get("/api/scans")
@jwt_required()
def list_scans():
    """Return all scans for the logged-in user, newest first, with target info."""
    user_id = int(get_jwt_identity())
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT
                s.scan_id,
                s.status,
                s.phase,
                s.total_findings,
                s.started_at,
                s.finished_at,
                s.error_message,
                CASE
                    WHEN pf.target_id IS NOT NULL THEN 'MALWARE'
                    WHEN ct.target_id IS NOT NULL THEN 'FOLDER'
                    ELSE t.target_type
                END AS target_type,
                COALESCE(u.url, af.file_name, ct.folder_name, pf.file_name) AS target_name,
                pf.verdict AS pe_verdict
            FROM scans s
            JOIN targets t ON t.target_id = s.target_id
            LEFT JOIN url_targets u ON u.target_id = t.target_id
            LEFT JOIN apk_files af ON af.target_id = t.target_id
            LEFT JOIN code_targets ct ON ct.target_id = t.target_id
            LEFT JOIN pe_files pf ON pf.target_id = t.target_id
            WHERE s.user_id = ?
            ORDER BY s.started_at DESC
        """, (user_id,)).fetchall()
    finally:
        conn.close()

    return jsonify([dict(r) for r in rows]), 200


@app.get("/api/dashboard/stats")
@jwt_required()
def dashboard_stats():
    """Aggregate stats for the dashboard: scan counts, vuln breakdown, trend, top threats."""
    user_id = int(get_jwt_identity())
    conn = get_conn()
    try:
        total_scans = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE user_id=?", (user_id,)
        ).fetchone()["c"]

        today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
        scans_today = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE user_id=? AND started_at LIKE ?",
            (user_id, f"{today}%")
        ).fetchone()["c"]

        total_vulns = conn.execute("""
            SELECT COALESCE(SUM(s.total_findings), 0) AS c
            FROM scans s WHERE s.user_id=?
        """, (user_id,)).fetchone()["c"]

        sev_rows = conn.execute("""
            SELECT f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON s.scan_id = f.scan_id
            WHERE s.user_id = ?
            GROUP BY f.severity
        """, (user_id,)).fetchall()
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in sev_rows:
            if r["severity"] in severity_counts:
                severity_counts[r["severity"]] = r["cnt"]

        critical_count = severity_counts["CRITICAL"] + severity_counts["HIGH"]

        def weighted_score(counts):
            high_n = counts["HIGH"]
            med_n = counts["MEDIUM"]
            low_n = counts["LOW"]

            high_penalty = (
                min(high_n, 5) * 8 +
                min(max(high_n - 5, 0), 5) * 4 +
                max(high_n - 10, 0) * 1
            )
            med_penalty = min(med_n, 10) * 1 + max(med_n - 10, 0) * 0.5
            low_penalty = min(low_n, 20) * 0.25

            total_penalty = high_penalty + med_penalty + low_penalty
            raw = 100 - total_penalty
            return max(1, min(100, round(raw)))

        security_score = weighted_score(severity_counts) if total_scans > 0 else None

        time_rows = conn.execute("""
            SELECT started_at, finished_at FROM scans
            WHERE user_id=? AND status='COMPLETED'
              AND finished_at IS NOT NULL AND started_at IS NOT NULL
        """, (user_id,)).fetchall()
        avg_scan_secs = None
        if time_rows:
            deltas = []
            for r in time_rows:
                try:
                    s = datetime.datetime.fromisoformat(r["started_at"].rstrip("Z"))
                    f = datetime.datetime.fromisoformat(r["finished_at"].rstrip("Z"))
                    deltas.append((f - s).total_seconds())
                except Exception:
                    pass
            if deltas:
                avg_scan_secs = int(sum(deltas) / len(deltas))

        OWASP_PATTERNS = {
            "A01": ["access control", "broken access", "idor", "privilege"],
            "A02": ["cryptograph", "sensitive data", "weak cipher", "ssl", "tls", "hash"],
            "A03": ["injection", "sql", "xss", "cross-site script", "command injection", "ldap"],
            "A04": ["insecure design", "design flaw"],
            "A05": ["misconfigur", "security misconfigur", "default credential", "directory listing", "x-frame", "csp"],
            "A06": ["vulnerable component", "outdated", "known vuln"],
            "A07": ["authentication", "session", "credential", "brute force", "weak password"],
            "A08": ["integrity", "deserialization", "software integrity"],
            "A09": ["logging", "monitoring", "log", "audit"],
            "A10": ["server-side request", "ssrf"],
        }
        owasp_map = {k: 0 for k in OWASP_PATTERNS}

        finding_rows = conn.execute("""
            SELECT f.title, f.description
            FROM findings f
            JOIN scans s ON s.scan_id = f.scan_id
            WHERE s.user_id=?
        """, (user_id,)).fetchall()

        for row in finding_rows:
            text = ((row["title"] or "") + " " + (row["description"] or "")).lower()
            matched = False
            for code, keywords in OWASP_PATTERNS.items():
                if any(kw in text for kw in keywords):
                    owasp_map[code] += 1
                    matched = True
                    break
            if not matched:
                owasp_map["A05"] += 1

        trend_rows = conn.execute("""
            SELECT strftime('%Y-%m', s.started_at) AS month,
                   COALESCE(SUM(s.total_findings), 0) AS total
            FROM scans s
            WHERE s.user_id=?
              AND s.started_at >= date('now', '-6 months')
            GROUP BY month
            ORDER BY month ASC
        """, (user_id,)).fetchall()
        trend = [{"month": r["month"], "total": r["total"]} for r in trend_rows]

        threat_rows = conn.execute("""
            SELECT f.title,
                   f.severity,
                   f.owasp_code,
                   f.cwe_id,
                   f.description,
                   COALESCE(u.url, af.file_name, ct.folder_name, pf.file_name) AS target_name,
                   COUNT(*) AS occurrence_count
            FROM findings f
            JOIN scans s ON s.scan_id = f.scan_id
            JOIN targets t ON t.target_id = s.target_id
            LEFT JOIN url_targets u ON u.target_id = t.target_id
            LEFT JOIN apk_files af ON af.target_id = t.target_id
            LEFT JOIN code_targets ct ON ct.target_id = t.target_id
            LEFT JOIN pe_files pf ON pf.target_id = t.target_id
            WHERE s.user_id = ?
            GROUP BY f.title, f.severity
            ORDER BY
                CASE f.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    WHEN 'INFO' THEN 5
                    ELSE 6
                END ASC,
                MAX(f.finding_id) DESC
            LIMIT 5
        """, (user_id,)).fetchall()
        top_threats = [dict(r) for r in threat_rows]

        recent_rows = conn.execute("""
            SELECT
                s.scan_id,
                s.status,
                s.total_findings,
                s.started_at,
                COALESCE(u.url, af.file_name, ct.folder_name, pf.file_name) AS target_name,
                CASE
                    WHEN pf.target_id IS NOT NULL THEN 'MALWARE'
                    WHEN ct.target_id IS NOT NULL THEN 'FOLDER'
                    ELSE t.target_type
                END AS target_type
            FROM scans s
            JOIN targets t ON t.target_id = s.target_id
            LEFT JOIN url_targets u ON u.target_id = t.target_id
            LEFT JOIN apk_files af ON af.target_id = t.target_id
            LEFT JOIN code_targets ct ON ct.target_id = t.target_id
            LEFT JOIN pe_files pf ON pf.target_id = t.target_id
            WHERE s.user_id=?
            ORDER BY s.started_at DESC
            LIMIT 5
        """, (user_id,)).fetchall()
        recent_scans = [dict(r) for r in recent_rows]
    finally:
        conn.close()

    return jsonify({
        "total_scans": total_scans,
        "scans_today": scans_today,
        "total_vulns": total_vulns,
        "critical_count": critical_count,
        "security_score": security_score,
        "avg_scan_secs": avg_scan_secs,
        "severity_counts": severity_counts,
        "owasp_map": owasp_map,
        "trend": trend,
        "top_threats": top_threats,
        "recent_scans": recent_scans,
    }), 200

@app.get("/api/notifications")
@jwt_required()
def list_notifications():
    user_id = int(get_jwt_identity())
    limit = min(max(int(request.args.get("limit", 12)), 1), 50)
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                n.notification_id,
                n.event_type,
                COALESCE(n.title, n.event_type) AS title,
                COALESCE(n.message, '') AS message,
                COALESCE(n.level, 'INFO') AS level,
                COALESCE(n.is_read, 0) AS is_read,
                n.read_at,
                n.sent_at,
                n.scan_id,
                n.action_url,
                n.metadata_json,
                COALESCE(u.url, af.file_name, ct.folder_name, pf.file_name) AS target_name,
                CASE
                    WHEN pf.target_id IS NOT NULL THEN 'MALWARE'
                    WHEN ct.target_id IS NOT NULL THEN 'FOLDER'
                    ELSE t.target_type
                END AS target_type
            FROM notifications n
            LEFT JOIN scans s ON s.scan_id = n.scan_id
            LEFT JOIN targets t ON t.target_id = s.target_id
            LEFT JOIN url_targets u ON u.target_id = t.target_id
            LEFT JOIN apk_files af ON af.target_id = t.target_id
            LEFT JOIN code_targets ct ON ct.target_id = t.target_id
            LEFT JOIN pe_files pf ON pf.target_id = t.target_id
            WHERE n.user_id = ?
            ORDER BY n.sent_at DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        unread_count = conn.execute(
            "SELECT COUNT(*) AS c FROM notifications WHERE user_id=? AND COALESCE(is_read,0)=0",
            (user_id,),
        ).fetchone()["c"]
    finally:
        conn.close()

    items = []
    for row in rows:
        item = dict(row)
        try:
            item["metadata"] = json.loads(item.get("metadata_json") or "{}")
        except Exception:
            item["metadata"] = {}
        item.pop("metadata_json", None)
        items.append(item)
    return jsonify({"items": items, "unread_count": unread_count}), 200


@app.post("/api/notifications/<int:notification_id>/read")
@jwt_required()
def mark_notification_read(notification_id: int):
    user_id = int(get_jwt_identity())
    conn = get_conn()
    try:
        cur = conn.execute(
            """
            UPDATE notifications
            SET is_read=1, read_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE notification_id=? AND user_id=?
            """,
            (notification_id, user_id),
        )
        conn.commit()
    finally:
        conn.close()
    if cur.rowcount == 0:
        return jsonify({"error": "notification not found"}), 404
    return jsonify({"ok": True}), 200


@app.post("/api/notifications/read-all")
@jwt_required()
def mark_all_notifications_read():
    user_id = int(get_jwt_identity())
    conn = get_conn()
    try:
        conn.execute(
            """
            UPDATE notifications
            SET is_read=1, read_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE user_id=? AND COALESCE(is_read,0)=0
            """,
            (user_id,),
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True}), 200


@app.post("/api/chat")
@jwt_required()
def chat():
    user_id = int(get_jwt_identity())
    body = request.get_json(force=True, silent=True) or {}
    message = (body.get("message") or "").strip()

    if not message:
        return jsonify({"error": "message is required"}), 400

    try:
        reply = generate_chat_reply(user_id=user_id, user_message=message)
        return jsonify({"reply": reply}), 200
    except Exception as e:
        return jsonify({"error": f"chat failed: {type(e).__name__}: {e}"}), 500



@app.get("/api/kb/owasp")
@jwt_required()
def kb_owasp():
    from chatbot.kb_service import KNOWLEDGE, estimate_severity

    categories = []
    for kb in sorted(KNOWLEDGE, key=lambda x: (x.get("owasp_id") or "ZZZ")):
        cwes = []
        worst_severity = "LOW"
        sev_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        for cwe in kb.get("cwes", []):
            sev = estimate_severity(cwe.get("impact", ""))
            if sev_order.get(sev, 0) > sev_order.get(worst_severity, 0):
                worst_severity = sev
            cwes.append({
                "cwe_id":      cwe.get("cwe_id"),
                "name":        cwe.get("name"),
                "description": cwe.get("description"),
                "impact":      cwe.get("impact"),
                
                "prevention":  cwe.get("prevention") if isinstance(cwe.get("prevention"), list) else [cwe.get("prevention")] if cwe.get("prevention") else [],
                "fixation":    cwe.get("fixation")   if isinstance(cwe.get("fixation"),   list) else [cwe.get("fixation")]   if cwe.get("fixation")   else [],
                "mitigation":  cwe.get("mitigation") if isinstance(cwe.get("mitigation"), list) else [cwe.get("mitigation")] if cwe.get("mitigation") else [],
                "severity":    sev,
            })
        categories.append({
            "owasp_id":         kb.get("owasp_id"),
            "category":         kb.get("category"),
            "summary":          kb.get("summary") or kb.get("description") or "",
            "cwes":             cwes,
            "cwe_count":        len(cwes),
            "highest_severity": worst_severity,
        })

    return jsonify({"categories": categories}), 200


@app.get("/api/scans/<int:scan_id>/report")
@jwt_required()
def get_scan_report(scan_id):
    user_id = int(get_jwt_identity())
    conn = get_conn()
    try:
        payload = _load_scan_report_data(conn, user_id, scan_id)
        if not payload:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify(payload), 200
    finally:
        conn.close()



@app.get("/api/scans/<int:scan_id>/report/pdf")
@jwt_required()
def download_pdf(scan_id):
    user_id = int(get_jwt_identity())
    conn = get_conn()
    try:
        payload = _load_scan_report_data(conn, user_id, scan_id)
        if not payload:
            return jsonify({"error": "Scan not found"}), 404

        scan = payload["scan"]
        findings = payload["findings"]
        severity_counts = payload["severity_counts"]
        folder_summary = scan.get("folder_summary") or {}
        pe_summary = scan.get("pe_summary") or {}

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=38 * mm,
            bottomMargin=18 * mm,
            title=f"VSAWA Security Report #{scan_id}",
            author="VSAWA Vulnerability Scanner",
        )


        theme = {
            "page":      colors.HexColor("#ffffff"),
            "ink":       colors.HexColor("#0f172a"),  # body text
            "ink_soft":  colors.HexColor("#334155"),  # secondary text
            "muted":     colors.HexColor("#64748b"),  # captions
            "rule":      colors.HexColor("#e2e8f0"),  # hairlines
            "panel":     colors.HexColor("#f8fafc"),  # block backgrounds
            "panel_alt": colors.HexColor("#f1f5f9"),  # alt block bg
            "brand":     colors.HexColor("#0e7490"),  # cyan-700 (header band)
            "brand_alt": colors.HexColor("#155e75"),  # cyan-800
            "accent":    colors.HexColor("#0891b2"),  # cyan-600 (section rule)
            "critical":  colors.HexColor("#b91c1c"),
            "high":      colors.HexColor("#dc2626"),
            "medium":    colors.HexColor("#d97706"),
            "low":       colors.HexColor("#16a34a"),
            "info":      colors.HexColor("#2563eb"),
        }

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="VS_Body",        parent=styles["Normal"], fontName="Helvetica",       fontSize=10,  leading=14, textColor=theme["ink"]))
        styles.add(ParagraphStyle(name="VS_BodyJ",       parent=styles["Normal"], fontName="Helvetica",       fontSize=10,  leading=14, textColor=theme["ink"], alignment=4))  # justified
        styles.add(ParagraphStyle(name="VS_Muted",       parent=styles["Normal"], fontName="Helvetica",       fontSize=9,   leading=12, textColor=theme["muted"]))
        styles.add(ParagraphStyle(name="VS_Caption",     parent=styles["Normal"], fontName="Helvetica-Oblique", fontSize=8.5, leading=11, textColor=theme["muted"]))
        styles.add(ParagraphStyle(name="VS_H1",          parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=theme["ink"], spaceBefore=4, spaceAfter=8))
        styles.add(ParagraphStyle(name="VS_H2",          parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=theme["brand_alt"], spaceBefore=10, spaceAfter=6))
        styles.add(ParagraphStyle(name="VS_H3",          parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=10.5, leading=13, textColor=theme["ink"], spaceBefore=4, spaceAfter=3))
        styles.add(ParagraphStyle(name="VS_FieldLabel",  parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=10, textColor=theme["muted"], spaceAfter=1))
        styles.add(ParagraphStyle(name="VS_FieldValue",  parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=13, textColor=theme["ink"]))
        styles.add(ParagraphStyle(name="VS_Mono",        parent=styles["Normal"], fontName="Courier",         fontSize=8.5, leading=11, textColor=theme["ink_soft"]))
        styles.add(ParagraphStyle(name="VS_Badge",       parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=10, alignment=1, textColor=colors.white))
        styles.add(ParagraphStyle(name="VS_FindingTitle",parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=theme["ink"]))

        def sev_color(sev):
            return {
                "CRITICAL": theme["critical"],
                "HIGH":     theme["high"],
                "MEDIUM":   theme["medium"],
                "LOW":      theme["low"],
                "INFO":     theme["info"],
            }.get((sev or "INFO").upper(), theme["info"])

        def p(text, style="VS_Body"):
            return Paragraph(escape(str(text or "—")).replace("\n", "<br/>"), styles[style])

        def format_bytes(num):
            num = int(num or 0)
            if num <= 0:
                return "—"
            value, idx = float(num), 0
            units = ["B", "KB", "MB", "GB", "TB"]
            while value >= 1024 and idx < len(units) - 1:
                value /= 1024.0
                idx += 1
            return (f"{int(value)} " if idx == 0 else f"{value:.2f} ") + units[idx]

        def parse_iso(ts):
            if not ts:
                return None
            ts = ts.replace("Z", "+00:00")
            try:
                return datetime.datetime.fromisoformat(ts)
            except Exception:
                return None

        def format_duration(start_ts, finish_ts):
            sd, ed = parse_iso(start_ts), parse_iso(finish_ts)
            if not sd or not ed:
                return "—"
            total = max(int((ed - sd).total_seconds()), 0)
            m, s = divmod(total, 60)
            h, m = divmod(m, 60)
            if h:
                return f"{h}h {m}m {s}s"
            if m:
                return f"{m}m {s}s"
            return f"{s}s"

        def highest_severity(counts):
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if counts.get(sev, 0):
                    return sev
            return "NONE"

        def security_score(counts):
            score = 100
            score -= counts.get("CRITICAL", 0) * 30
            score -= counts.get("HIGH", 0) * 18
            score -= counts.get("MEDIUM", 0) * 10
            score -= counts.get("LOW", 0) * 4
            score -= counts.get("INFO", 0) * 1
            return max(0, min(100, score))

        def score_band(score):
            if score >= 85:
                return "Good"
            if score >= 65:
                return "Caution"
            if score >= 40:
                return "Elevated Risk"
            return "High Risk"

        target_label = scan.get("target_name") or "Unknown target"
        target_type = (scan.get("target_type") or "Unknown").upper()
        highest = highest_severity(severity_counts)
        score = security_score(severity_counts)
        duration = format_duration(scan.get("started_at"), scan.get("finished_at"))
        total_findings = int(scan.get("total_findings") or 0)

        
        def target_lens_text():
            if target_type == "URL":
                return (
                    "This assessment performed a dynamic security scan against a live web target. "
                    "Findings reflect runtime vulnerabilities, misconfigurations, and weaknesses "
                    "observed during automated crawling and active testing of the web application."
                )
            if target_type == "APK":
                return (
                    "This assessment performed static analysis of an Android application package. "
                    "Findings focus on manifest configuration, exported components, dangerous "
                    "permissions, and other high-signal mobile security weaknesses."
                )
            if target_type == "FOLDER":
                return (
                    "This assessment performed static source-code analysis of an uploaded project "
                    "folder. Findings focus on insecure code patterns, hard-coded secrets, risky "
                    "configuration, and source-level weaknesses likely to surface as exploitable bugs."
                )
            if target_type == "MALWARE":
                return (
                    "This assessment ran an ML-based malware analysis over a Windows PE binary. "
                    "Three independent classifiers (LightGBM, Random Forest, XGBoost) trained on "
                    "EMBER-style static features evaluated the file. Findings reflect each model's "
                    "verdict plus an aggregated ensemble decision."
                )
            return "Static review of recorded scan data."

        # summary paragraph
        def overview_text():
            if total_findings == 0:
                return (
                    "No findings were recorded for this scan. Based on the stored results the "
                    "target currently appears clean from the perspective of the selected scan "
                    "module. Remember that a clean automated scan is not a guarantee of security; "
                    "it should be supplemented by manual review on high-risk assets."
                )
            crit_hi = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)
            return (
                f"This assessment recorded <b>{total_findings}</b> finding{'s' if total_findings != 1 else ''}. "
                f"The highest observed risk level is <b>{highest}</b>, and VSAWA assigns a posture "
                f"score of <b>{score}/100</b> ({score_band(score)}). "
                f"Remediation should prioritise the <b>{crit_hi}</b> critical/high-risk "
                f"item{'s' if crit_hi != 1 else ''} first; medium-risk items should be queued "
                f"shortly afterwards because they often become exploitable when chained."
            )

        #  cover header 
        def draw_page(canvas, _doc):
            canvas.saveState()
            width, height = A4

           
            canvas.setFillColor(theme["page"])
            canvas.rect(0, 0, width, height, stroke=0, fill=1)

            band_h = 24 * mm
            canvas.setFillColor(theme["brand"])
            canvas.rect(0, height - band_h, width, band_h, stroke=0, fill=1)

            
            canvas.setFillColor(theme["accent"])
            canvas.rect(0, height - band_h - 1.4 * mm, width, 1.4 * mm, stroke=0, fill=1)

            
            canvas.setFillColor(colors.white)
            canvas.setFont("Helvetica-Bold", 16)
            canvas.drawString(18 * mm, height - 14 * mm, "VSAWA")
            canvas.setFont("Helvetica", 9.5)
            canvas.drawString(18 * mm, height - 19.5 * mm, "Security Assessment Report")

            
            canvas.setFont("Helvetica", 9)
            canvas.drawRightString(width - 18 * mm, height - 14 * mm,
                                   f"Report #{scan_id}  •  {target_type}")
            canvas.setFont("Helvetica", 8)
            
            canvas.drawRightString(width - 18 * mm, height - 19.5 * mm,
                                   f"Generated {now_human_local()}")

        
            canvas.setStrokeColor(theme["rule"])
            canvas.setLineWidth(0.6)
            canvas.line(18 * mm, 12 * mm, width - 18 * mm, 12 * mm)
            canvas.setFillColor(theme["muted"])
            canvas.setFont("Helvetica", 8)
            canvas.drawString(18 * mm, 7.5 * mm,
                              "Confidential — VSAWA Vulnerability Scanner output")
            canvas.drawRightString(width - 18 * mm, 7.5 * mm,
                                   f"Page {_doc.page}")
            canvas.restoreState()

       
        def severity_chart(counts):
            chart_w = 174 * mm
            chart_h = 56 * mm
            d = Drawing(chart_w, chart_h)
            # Panel
            d.add(Rect(0, 0, chart_w, chart_h, rx=4, ry=4,
                       fillColor=theme["panel"], strokeColor=theme["rule"], strokeWidth=0.6))
            # Title row
            d.add(String(8, chart_h - 12, "Severity Distribution",
                         fontName="Helvetica-Bold", fontSize=10.5, fillColor=theme["ink"]))
            d.add(String(8, chart_h - 23, "Bar length is proportional to finding count within this scan.",
                         fontName="Helvetica", fontSize=8, fillColor=theme["muted"]))

            max_count = max(max(counts.values()), 1)
            order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            bar_track_w = 108 * mm
            bar_x = 36 * mm
            y = chart_h - 36
            for sev in order:
                count = counts.get(sev, 0)
                fill_w = (count / max_count) * bar_track_w if count else 0
                # Severity label
                d.add(String(8, y + 1.5, sev,
                             fontName="Helvetica-Bold", fontSize=8.5,
                             fillColor=theme["ink_soft"]))
                # Empty track
                d.add(Rect(bar_x, y, bar_track_w, 7,
                           fillColor=colors.HexColor("#e2e8f0"), strokeColor=None))
                # Filled portion
                if fill_w > 0:
                    d.add(Rect(bar_x, y, fill_w, 7,
                               fillColor=sev_color(sev), strokeColor=None))
                # Count
                d.add(String(bar_x + bar_track_w + 4, y + 1.5, str(count),
                             fontName="Helvetica-Bold", fontSize=8.5,
                             fillColor=theme["ink"]))
                y -= 8 * mm
            return d

   
        def score_gauge(score_val):
            w = 174 * mm
            h = 22 * mm
            d = Drawing(w, h)
            d.add(Rect(0, 0, w, h, rx=4, ry=4,
                       fillColor=theme["panel"], strokeColor=theme["rule"], strokeWidth=0.6))
            d.add(String(8, h - 11, "Security Posture Score",
                         fontName="Helvetica-Bold", fontSize=10.5, fillColor=theme["ink"]))
            d.add(String(8, 4, score_band(score_val),
                         fontName="Helvetica", fontSize=8.5, fillColor=theme["muted"]))
            track_x = 56 * mm
            track_w = 96 * mm
            d.add(Rect(track_x, 6, track_w, 5,
                       fillColor=colors.HexColor("#e2e8f0"), strokeColor=None))
            fill_w = (max(0, min(score_val, 100)) / 100.0) * track_w
            score_color = (theme["low"]    if score_val >= 65 else
                           theme["medium"] if score_val >= 40 else
                           theme["high"])
            d.add(Rect(track_x, 6, fill_w, 5, fillColor=score_color, strokeColor=None))
            d.add(String(w - 8, 5, f"{score_val}/100",
                         fontName="Helvetica-Bold", fontSize=11,
                         fillColor=theme["ink"], textAnchor="end"))
            return d

        
        def kpi_card(label, value, accent):
            tbl = Table(
                [[Paragraph(escape(label), styles["VS_FieldLabel"])],
                 [Paragraph(escape(str(value)), styles["VS_FieldValue"])]],
                colWidths=[None],
            )
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), theme["panel"]),
                ("BOX",        (0, 0), (-1, -1), 0.6, theme["rule"]),
                ("LINEBEFORE", (0, 0), (0, -1), 2.6, accent),
                ("LEFTPADDING",   (0, 0), (-1, -1), 9),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 9),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]))
            return tbl

        # ----- priority table (top 5)
        def priority_table(items):
            rows = [[
                p("#", "VS_FieldLabel"),
                p("Severity", "VS_FieldLabel"),
                p("Finding", "VS_FieldLabel"),
                p("CWE", "VS_FieldLabel"),
            ]]
            for idx, finding in enumerate(items[:5], start=1):
                sev = (finding.get("severity") or "INFO").upper()
                rows.append([
                    p(str(idx)),
                    Paragraph(escape(sev), styles["VS_Badge"]),
                    p(finding.get("title") or f"Finding {idx}"),
                    p(str(finding.get("cwe_id") or "—")),
                ])
            tbl = Table(rows, colWidths=[10 * mm, 22 * mm, 122 * mm, 20 * mm])
            cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), theme["panel_alt"]),
                ("TEXTCOLOR",  (0, 0), (-1, -1), theme["ink"]),
                ("BOX",        (0, 0), (-1, -1), 0.6, theme["rule"]),
                ("LINEABOVE",  (0, 1), (-1, 1), 0.6, theme["rule"]),
                ("INNERGRID",  (0, 0), (-1, -1), 0.4, theme["rule"]),
                ("LEFTPADDING",   (0, 0), (-1, -1), 7),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]
            for ridx in range(1, len(rows)):
                sev = rows[ridx][1].getPlainText()
                cmds.append(("BACKGROUND", (1, ridx), (1, ridx), sev_color(sev)))
                if ridx % 2 == 0:
                    cmds.append(("BACKGROUND", (0, ridx), (0, ridx), theme["panel"]))
                    cmds.append(("BACKGROUND", (2, ridx), (-1, ridx), theme["panel"]))
            tbl.setStyle(TableStyle(cmds))
            return tbl

        # ----- per-finding block ------------------------------------------------
        def evidence_block(evidence_rows):
            if not evidence_rows:
                return p("No explicit evidence snippet was captured for this finding.", "VS_Muted")
            cells = []
            for ev in evidence_rows[:3]:
                line = (ev.get("content") or "").strip()
                if ev.get("url"):
                    line = f"{ev['url']} :: {line}" if line else ev["url"]
                cells.append([Paragraph(escape(line[:600] or "—").replace("\n", "<br/>"),
                                        styles["VS_Mono"])])
            tbl = Table(cells, colWidths=[170 * mm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), theme["panel"]),
                ("BOX",           (0, 0), (-1, -1), 0.5, theme["rule"]),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            return tbl

        def remediation_block(rem_rows):
            if not rem_rows:
                return p("No remediation guidance was recorded for this finding.", "VS_Muted")
            paras = []
            for rem in rem_rows[:3]:
                part = (rem.get("text") or "").strip()
                ref  = (rem.get("reference_url") or "").strip()
                if ref:
                    part = (f"{part}\nReference: {ref}" if part else f"Reference: {ref}")
                paras.append(Paragraph(
                    f"&bull;&nbsp; {escape(part[:700]).replace(chr(10), '<br/>')}",
                    styles["VS_Body"],
                ))
            tbl = Table([[para] for para in paras], colWidths=[170 * mm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), theme["panel_alt"]),
                ("BOX",           (0, 0), (-1, -1), 0.5, theme["rule"]),
                ("LINEBEFORE",    (0, 0), (0, -1), 2.4, theme["low"]),
                ("LEFTPADDING",   (0, 0), (-1, -1), 9),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 9),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            return tbl

        def finding_block(idx, finding):
            sev = (finding.get("severity") or "INFO").upper()
            title = finding.get("title") or f"Finding {idx}"

            # Title row: number + title + severity badge.
            header = Table(
                [[Paragraph(escape(f"#{idx}  {title}"), styles["VS_FindingTitle"]),
                  Paragraph(escape(sev), styles["VS_Badge"])]],
                colWidths=[148 * mm, 22 * mm],
            )
            header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), theme["panel_alt"]),
                ("BACKGROUND", (1, 0), (1, 0), sev_color(sev)),
                ("BOX",        (0, 0), (-1, -1), 0.6, theme["rule"]),
                ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING",   (0, 0), (-1, -1), 9),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 9),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]))

            cwe   = finding.get("cwe_id") or "—"
            owasp = finding.get("owasp_code") or "—"
            ev_first = (finding.get("evidence") or [{}])[0].get("url") or "—"

            meta = Table(
                [[p(f"CWE: {cwe}", "VS_Muted"),
                  p(f"OWASP: {owasp}", "VS_Muted"),
                  p(f"Location: {ev_first}", "VS_Muted")]],
                colWidths=[26 * mm, 30 * mm, 114 * mm],
            )
            meta.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.5, theme["rule"]),
                ("LEFTPADDING",   (0, 0), (-1, -1), 9),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 9),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))

            description = finding.get("description") or "No description available."
            commentary = (
                "This issue should be addressed quickly — it represents a directly exploitable "
                "or high-business-impact weakness."
                if sev in {"CRITICAL", "HIGH"}
                else
                "This issue weakens the overall security posture and can combine with other "
                "weaknesses to increase exploitability."
            )

            return KeepTogether([
                header,
                meta,
                Spacer(1, 4),
                p("Description", "VS_H3"),
                p(description),
                p(commentary, "VS_Muted"),
                Spacer(1, 4),
                p("Observed Evidence", "VS_H3"),
                evidence_block(finding.get("evidence") or []),
                Spacer(1, 4),
                p("Recommended Remediation", "VS_H3"),
                remediation_block(finding.get("remediations") or []),
                Spacer(1, 10),
            ])

        # ----- meta rows: target-type-specific
        meta_rows = [
            [p("Target",     "VS_FieldLabel"), p(target_label)],
            [p("Scan Type",  "VS_FieldLabel"), p(target_type)],
            [p("Status",     "VS_FieldLabel"), p(scan.get("status") or "—")],
            [p("Duration",   "VS_FieldLabel"), p(duration)],
            [p("Started",    "VS_FieldLabel"), p(scan.get("started_at") or "—")],
            [p("Finished",   "VS_FieldLabel"), p(scan.get("finished_at") or "—")],
        ]
        if target_type == "APK":
            meta_rows.extend([
                [p("Package",  "VS_FieldLabel"), p(scan.get("package_name") or "—")],
                [p("Version",  "VS_FieldLabel"), p(scan.get("app_version") or "—")],
            ])
        elif target_type == "FOLDER":
            langs = ", ".join(folder_summary.get("languages") or []) or "—"
            meta_rows.extend([
                [p("Files Scanned",   "VS_FieldLabel"), p(str(scan.get("folder_file_count") or folder_summary.get("file_count") or 0))],
                [p("Folder Size",     "VS_FieldLabel"), p(format_bytes(scan.get("folder_total_size") or folder_summary.get("total_size") or 0))],
                [p("Languages",       "VS_FieldLabel"), p(langs)],
            ])
        elif target_type == "MALWARE":
            verdict = scan.get("pe_verdict") or pe_summary.get("overall_prediction") or "—"
            md5 = scan.get("pe_md5") or pe_summary.get("md5") or "—"
            file_size = scan.get("pe_file_size") or pe_summary.get("size_bytes") or 0
            votes = pe_summary.get("malicious_votes")
            total_models = pe_summary.get("total_models")
            votes_str = (f"{votes} / {total_models} models"
                         if votes is not None and total_models else "—")
            models_used = ", ".join(
                r.get("scanning_tool", "?") for r in (pe_summary.get("model_results") or [])
            ) or "LightGBM, Random Forest, XGBoost"
            meta_rows.extend([
                [p("File Name",       "VS_FieldLabel"), p(scan.get("pe_file_name") or target_label)],
                [p("File Size",       "VS_FieldLabel"), p(format_bytes(file_size))],
                [p("MD5",             "VS_FieldLabel"), Paragraph(escape(md5), styles["VS_Mono"])],
                [p("Verdict",         "VS_FieldLabel"), p(verdict)],
                [p("Malicious Votes", "VS_FieldLabel"), p(votes_str)],
                [p("Models Used",     "VS_FieldLabel"), p(models_used)],
            ])

        meta_table = Table(meta_rows, colWidths=[38 * mm, 136 * mm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
            ("BOX",           (0, 0), (-1, -1), 0.6, theme["rule"]),
            ("INNERGRID",     (0, 0), (-1, -1), 0.4, theme["rule"]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 9),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 9),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))

       
        kpi_grid = Table([
            [kpi_card("Total findings", total_findings,           theme["accent"]),
             kpi_card("Highest severity", highest,                sev_color(highest if highest != 'NONE' else 'INFO'))],
            [kpi_card("Security posture", f"{score}/100",         theme["accent"]),
             kpi_card("Scan target",       target_type.title(),   theme["brand"])],
        ], colWidths=[84 * mm, 84 * mm], rowHeights=[None, None])
        kpi_grid.setStyle(TableStyle([
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))

        
        story = []

        # Section 1: Executive Summary
        story.append(KeepTogether([
            Paragraph("Executive Summary", styles["VS_H2"]),
            Paragraph(overview_text(), styles["VS_BodyJ"]),
            Spacer(1, 6),
            kpi_grid,
        ]))
        story.append(Spacer(1, 6))
        story.append(score_gauge(score))
        story.append(Spacer(1, 12))

        # Section 2: Scan Scope
        story.append(KeepTogether([
            Paragraph("Scan Scope & Target Details", styles["VS_H2"]),
            Paragraph(target_lens_text(), styles["VS_BodyJ"]),
            Spacer(1, 5),
            meta_table,
        ]))
        story.append(Spacer(1, 12))

        # Section 3: Findings Overview
        story.append(KeepTogether([
            Paragraph("Findings Overview", styles["VS_H2"]),
            severity_chart(severity_counts),
        ]))
        story.append(Spacer(1, 10))

        # Section 4: Priority queue (top 5)
        if findings:
            story.append(KeepTogether([
                Paragraph("Top Priorities for Triage", styles["VS_H3"]),
                Paragraph(
                    "Items below are the highest-severity findings recorded for this scan and "
                    "should be the first to be acknowledged and remediated.",
                    styles["VS_Muted"],
                ),
                Spacer(1, 4),
                priority_table(findings),
            ]))
            story.append(Spacer(1, 12))

        # Section 5: Detailed findings
        if not findings:
            story.append(KeepTogether([
                Paragraph("Detailed Findings", styles["VS_H2"]),
                p(
                    "No findings were stored for this scan. The target appears clean "
                    "based on the recorded results."
                ),
            ]))
        else:
            story.append(KeepTogether([
                Paragraph("Detailed Findings", styles["VS_H2"]),
                finding_block(1, findings[0]),
            ]))
            for idx, finding in enumerate(findings[1:], start=2):
                story.append(finding_block(idx, finding))

        # Section 6: Recommendations / analyst notes
        recs = [
            "Treat Critical and High findings as release blockers until they are verified "
            "and remediated by the responsible engineering owner.",
            "Schedule Medium findings into the next sprint — they often chain with other "
            "weaknesses to become exploitable.",
            "After remediation, rerun the same scan module to confirm that the corresponding "
            "evidence and findings disappear from the report.",
            "Use this report alongside manual code/architecture review on high-value assets; "
            "automated scanners produce a strong baseline but do not replace human judgement.",
        ]
        if target_type == "MALWARE":
            recs.insert(0,
                "If any classifier flagged the binary as malicious, treat it as untrusted: "
                "quarantine the sample, hunt its MD5 across the fleet, and rotate any "
                "credentials it may have touched."
            )
        if scan.get("error_message"):
            recs.append(f"System note recorded by scanner: {scan.get('error_message')}")

       
        rec_paragraphs = [
            Paragraph(f"&bull;&nbsp; {escape(rec)}", styles["VS_Body"])
            for rec in recs
        ]
        first_chunk = [Paragraph("Recommendations", styles["VS_H2"])]
        for para in rec_paragraphs[:2]:
            first_chunk.append(para)
            first_chunk.append(Spacer(1, 2))
        story.append(KeepTogether(first_chunk))
        for para in rec_paragraphs[2:]:
            story.append(para)
            story.append(Spacer(1, 2))

        # ----- build
        try:
            doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
        except Exception as e:
            return jsonify({
                "error": f"PDF generation failed: {type(e).__name__}: {e}"
            }), 500

        buffer.seek(0)
        safe_name = f"vsawa_report_{scan_id}.pdf"
        return send_file(
            buffer,
            as_attachment=True,
            download_name=safe_name,
            mimetype="application/pdf",
        )
    finally:
        conn.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
