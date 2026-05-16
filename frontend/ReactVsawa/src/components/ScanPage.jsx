import React, { useEffect, useMemo, useRef, useState } from "react";
import "./ScanPage.css";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000").replace(/\/$/, "");

const PHASE_PROGRESS = {
  QUEUED: 5,
  INIT: 10,
  SEED: 20,
  SPIDER: null,
  ASCAN: null,
  FINALIZE: 92,
  APK_INIT: 15,
  APK_ANALYZE: 72,
  CODE_INIT: 12,
  CODE_INDEX: 35,
  CODE_ANALYZE: 78,
  PE_INIT: 10,
  PE_FEATURES: 30,
  PE_PREDICT: 65,
  PE_PERSIST: 90,
  DONE: 100,
  FAILED: 100,
};

// =============================================================================
// Module-specific phase descriptions for the live status panel.
//
// Originally the status panel always read "Phase: X · Spider: N% · Active Scan: N%"
// regardless of scan type. That's accurate for URL scans (which are powered by
// OWASP ZAP and really do have spider/active-scan phases) but flat wrong for
// APK, FOLDER and MALWARE scans -- those don't go through ZAP at all.
//
// MODULE_STATUS_INFO maps each module to:
//   - engine: human-readable tool/engine name shown in the status header
//   - phases: { backendPhaseCode: humanReadableLabel }
//   - metrics: ordered list of two metric blocks for the status row -- each
//              metric block tells the renderer which `progress.*` field to
//              read and what label to print next to it.
// =============================================================================
const MODULE_STATUS_INFO = {
  URL: {
    engine: "OWASP ZAP",
    phases: {
      QUEUED:    "Queued for scan engine",
      INIT:      "Initialising ZAP session",
      SEED:      "Seeding target into ZAP",
      SPIDER:    "Crawling target (spider)",
      ASCAN:     "Active vulnerability scan",
      FINALIZE:  "Finalising findings",
      DONE:      "Scan complete",
      FAILED:    "Scan failed",
    },
    metrics: [
      { key: "spider", label: "Spider" },
      { key: "ascan",  label: "Active Scan" },
    ],
  },
  APK: {
    engine: "Androguard",
    phases: {
      QUEUED:      "Queued for APK worker",
      APK_INIT:    "Loading APK with Androguard",
      APK_ANALYZE: "Manifest, permissions & component analysis",
      DONE:        "Analysis complete",
      FAILED:      "APK analysis failed",
    },
    // APK is single-phase work; we surface a synthetic split (Static / Manifest)
    // computed from overall progress so users still get two-channel feedback.
    metrics: [
      { key: "static",   label: "Static Analysis" },
      { key: "manifest", label: "Manifest Review" },
    ],
  },
  FOLDER: {
    engine: "LM Studio (static code review)",
    phases: {
      QUEUED:       "Queued for folder worker",
      CODE_INIT:    "Initialising static analyser",
      CODE_INDEX:   "Indexing source files",
      CODE_ANALYZE: "AI static code review (LM Studio)",
      DONE:         "Analysis complete",
      FAILED:       "Folder analysis failed",
    },
    metrics: [
      { key: "index",   label: "Indexing" },
      { key: "review",  label: "AI Review" },
    ],
  },
  MALWARE: {
    engine: "ML ensemble (LightGBM / Random Forest / XGBoost)",
    phases: {
      QUEUED:      "Queued for malware worker",
      PE_INIT:     "Loading PE binary",
      PE_FEATURES: "Feature extraction (LIEF + EMBER, 2381 dims)",
      PE_PREDICT:  "Running ML classifiers",
      PE_PERSIST:  "Persisting findings",
      DONE:        "Analysis complete",
      FAILED:      "Malware scan failed",
    },
    metrics: [
      { key: "features", label: "Feature Extraction" },
      { key: "predict",  label: "ML Classification" },
    ],
  },
};

// Default fallback so a scan whose module we somehow lost still renders
// something sensible (instead of falling back to the old ZAP-only line).
const DEFAULT_MODULE_INFO = MODULE_STATUS_INFO.URL;

// =============================================================================
// phaseChannelPct
//
// Helper for synthesising a 0-100 progress value for ONE channel of a
// two-channel status display when the backend only emits a single discrete
// phase code (which it does for APK / FOLDER / MALWARE -- only URL/ZAP scans
// emit real spider/ascan percentages).
//
// Inputs:
//   phase       - current backend phase code (e.g. "PE_FEATURES")
//   beforePhases - phases that finish before this channel even starts (-> 0%)
//   duringPhases - phases during which this channel ramps up (-> 50% midway)
//                  the final entry indicates "fully complete" (-> 100%)
//   completed   - true if the whole scan has hit COMPLETED status
//
// Rules:
//   - If completed, every channel is 100%.
//   - If phase is in beforePhases, channel is 0% (work hasn't reached us).
//   - If phase is the LAST duringPhase entry, channel is 100%.
//   - Otherwise, if phase is anywhere in duringPhases, channel is a smooth
//     ramp 25/50/75 based on the position in the list.
//   - Otherwise (unknown / failed / queued), channel is 0%.
// =============================================================================
function phaseChannelPct(phase, beforePhases, duringPhases, completed) {
  if (completed) return 100;
  if (!phase) return 0;
  if (beforePhases.includes(phase)) return 0;
  const idx = duringPhases.indexOf(phase);
  if (idx === -1) return 0;
  if (idx === duringPhases.length - 1) return 100;
  // Evenly distribute the partial percentages across the during-list.
  return Math.round(((idx + 1) / duringPhases.length) * 100);
}

const IGNORED_UPLOAD_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  ".nuxt",
  "coverage",
  ".vite",
  "target",
  "bin",
  "obj",
  "vendor",
  "Pods",
  ".idea",
  ".vs",
  "__pycache__",
  ".pytest_cache",
  "venv",
  ".venv",
  "env",
  ".mypy_cache",
]);

const SKIPPED_BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".mp3", ".wav", ".mp4", ".mov",
  ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar", ".jar", ".class", ".so", ".dll", ".exe", ".dmg",
  ".apk", ".ipa", ".bin", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map", ".min.js",
]);

function normalizeRelPath(file) {
  return (file?.webkitRelativePath || file?.name || "").replace(/\\/g, "/");
}

// =============================================================================
// Active-scan persistence
//
// Why this exists:
//   The original ScanPage held scan state (scanId, scanModule, status) in
//   React `useState`. When the user navigated away to Dashboard / Reports /
//   anywhere else, the ScanPage unmounted and its state was thrown away.
//   On return, the page rendered as if no scan had ever been started -- so
//   the user lost visibility into their in-flight scan, and worse, the
//   `isScanRunning` guard was reset, letting them queue a SECOND concurrent
//   scan from the same browser session.
//
// What this fixes:
//   We mirror the absolute minimum needed to resume polling -- the scan id
//   and the module that owns it -- into localStorage. On ScanPage mount we
//   read this back and rehydrate. The 4 startXxxScan() functions consult
//   `localStorage` (via getActiveScan()) before kicking off, so even if the
//   user reloads the page or comes back from another tab they cannot start
//   a second scan while one is still running. When the scan reaches
//   COMPLETED / FAILED, the entry is wiped.
//
// We deliberately do NOT mirror `progress.spider`, `progress.ascan`, or the
// human-readable `status` string -- those refresh from the backend within
// 1.5 seconds of the page being shown, and persisting them would just make
// stale "RUNNING 12%" data flash for one tick before the live poll
// replaces it.
// =============================================================================
const ACTIVE_SCAN_KEY = "vsawa.active_scan";

function getActiveScan() {
  try {
    const raw = localStorage.getItem(ACTIVE_SCAN_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || !parsed.scanId) return null;
    return parsed;
  } catch {
    return null;
  }
}

function setActiveScan(scanId, scanModule) {
  try {
    localStorage.setItem(
      ACTIVE_SCAN_KEY,
      JSON.stringify({ scanId, scanModule, startedAt: Date.now() }),
    );
  } catch {
    // localStorage can throw in incognito modes with quota exceeded; not
    // fatal -- we just lose persistence in that one session.
  }
}

function clearActiveScan() {
  try {
    localStorage.removeItem(ACTIVE_SCAN_KEY);
  } catch {
    // ignore
  }
}

function getClientSkipReason(file) {
  const rel = normalizeRelPath(file);
  const parts = rel.split("/").filter(Boolean);
  if (!parts.length) return "invalid path";

  const dirs = parts.slice(0, -1);
  if (dirs.some((segment) => IGNORED_UPLOAD_DIRS.has(segment) || segment.startsWith("."))) {
    return "generated/dependency folders";
  }

  const baseName = (parts[parts.length - 1] || "").toLowerCase();
  for (const ext of SKIPPED_BINARY_EXTENSIONS) {
    if (baseName.endsWith(ext)) {
      return "binary/assets";
    }
  }

  if ((file?.size || 0) > 5 * 1024 * 1024) {
    return "very large files";
  }

  return null;
}

const ScanPage = () => {
  const [activeForm, setActiveForm] = useState("web");
  const [url, setUrl] = useState("");
  const [apkFile, setApkFile] = useState(null);
  const [peFile, setPeFile] = useState(null);
  const [codeFiles, setCodeFiles] = useState([]);
  const [folderName, setFolderName] = useState("");
  const [folderSelectionMeta, setFolderSelectionMeta] = useState({ totalSelected: 0, kept: 0, skipped: 0, reasons: [] });
  const [status, setStatus] = useState("");
  const [scanId, setScanId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState({
    phase: "",
    spider: 0,
    ascan: 0,
    scanStatus: "",
  });
  // Which module owns the currently displayed status -- drives the
  // module-specific phase labels in the progress panel. Set when a scan
  // starts; cleared when the user switches scan types.
  // Values: "" | "URL" | "APK" | "FOLDER" | "MALWARE"
  const [scanModule, setScanModule] = useState("");

  const pollTimerRef = useRef(null);
  const folderInputRef = useRef(null);
  const isScanRunning = progress.scanStatus === "RUNNING";

  function getToken() {
    return localStorage.getItem("token") || localStorage.getItem("access_token");
  }

  function stopPolling() {
    if (pollTimerRef.current) {
      clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }

  function resetScanState(nextForm) {
    setActiveForm(nextForm);
    setStatus("");
    setScanId(null);
    setScanModule("");
    setProgress({ phase: "", spider: 0, ascan: 0, scanStatus: "" });
    if (nextForm !== "code") {
      setFolderSelectionMeta({ totalSelected: 0, kept: 0, skipped: 0, reasons: [] });
    }
  }

  // Shared "can I start a scan right now?" guard.
  //
  // This is the SINGLE source of truth for blocking concurrent scans. It
  // checks both the live React `isScanRunning` flag (covers the case where
  // the user clicks Start twice on this page) AND the persisted localStorage
  // lock (covers the case where another tab / a previous navigation started
  // one). The previous code only checked `isScanRunning`, which let a user
  // start a second scan after navigating away and back, because the React
  // state was reset on remount even though the backend was still working.
  //
  // Returns `true` if it's safe to proceed, `false` if a scan is already
  // in flight (in which case the user has already been alerted).
  function ensureNoActiveScan() {
    if (isScanRunning) {
      alert("A security scan is already in progress. Please wait for it to finish.");
      return false;
    }
    const persisted = getActiveScan();
    if (persisted) {
      alert(
        `Scan #${persisted.scanId} is still running in the background. ` +
        "Please wait for it to finish before starting a new one.",
      );
      // Rehydrate the in-flight scan so the user sees progress even if
      // they bypassed the mount-time restore (e.g., refreshed mid-action).
      setScanId(persisted.scanId);
      if (persisted.scanModule) setScanModule(persisted.scanModule);
      setProgress((prev) => ({ ...prev, scanStatus: "RUNNING" }));
      return false;
    }
    return true;
  }

  function getProgressPct() {
    if (progress.scanStatus === "COMPLETED") return 100;
    if (progress.phase === "SPIDER") return progress.spider ?? 0;
    if (progress.phase === "ASCAN") return progress.ascan ?? 0;
    return PHASE_PROGRESS[progress.phase] ?? Math.max(progress.spider ?? 0, progress.ascan ?? 0, 0);
  }

  async function pollScan(id) {
    const token = getToken();
    if (!token) {
      setStatus("You are not logged in. Please sign in again.");
      stopPolling();
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/scans/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setStatus(data?.error || `Failed to fetch scan status (HTTP ${res.status})`);
        if (res.status === 401) localStorage.removeItem("token");
        stopPolling();
        return;
      }

      const phase = data.phase || data.error_message || "";
      const spider = data.spider_progress ?? 0;
      const ascan = data.ascan_progress ?? 0;
      const scanStatus = data.status || "";

      setProgress({ phase, spider, ascan, scanStatus });

      if (scanStatus === "RUNNING") {
        setStatus(`RUNNING • ${phase || "WORKING..."}`);
      } else if (scanStatus === "COMPLETED") {
        setStatus("COMPLETED ✅ Report is available on the Reports page.");
        // Terminal state -- release the cross-page lock so the user can
        // queue a new scan from any page.
        clearActiveScan();
        stopPolling();
      } else if (scanStatus === "FAILED") {
        setStatus(`FAILED ❌ • ${data.error_message || "Unexpected scanner failure."}`);
        clearActiveScan();
        stopPolling();
      }
    } catch {
      setStatus("Network / Server error while checking scan status.");
      stopPolling();
    }
  }


  useEffect(() => {
    const input = folderInputRef.current;
    if (!input) return;
    input.setAttribute("webkitdirectory", "");
    input.setAttribute("directory", "");
  }, [activeForm]);

  // Rehydrate from localStorage on mount. If the user navigated away while a
  // scan was running, we re-attach to its scan_id and the existing poll
  // effect (below) will resume the live status feed within 1.5s.
  useEffect(() => {
    const persisted = getActiveScan();
    if (!persisted) return;

    setScanId(persisted.scanId);
    if (persisted.scanModule) setScanModule(persisted.scanModule);
    // Tell the user immediately that we're catching up; the next poll will
    // overwrite this with the real phase label.
    setStatus(`Resuming scan #${persisted.scanId}... waiting for status update.`);
    setProgress((prev) => ({ ...prev, scanStatus: "RUNNING" }));
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps

  // Cross-tab synchronisation. If a scan completes in another browser tab
  // (causing that tab to clear ACTIVE_SCAN_KEY), reflect the change here too
  // so the "scan in progress" badge clears even if the user never refreshes.
  useEffect(() => {
    const onStorage = (e) => {
      if (e.key !== ACTIVE_SCAN_KEY) return;
      if (!e.newValue) {
        // Active scan was cleared somewhere else -- but only release our
        // local UI lock if our own scan is the one that finished, to avoid
        // a race where two tabs talk over each other.
        setProgress((prev) =>
          prev.scanStatus === "RUNNING"
            ? prev   // we're still mid-scan locally; ignore foreign clear
            : { ...prev, scanStatus: prev.scanStatus || "COMPLETED" },
        );
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  useEffect(() => {
    stopPolling();
    if (!scanId) return;

    pollScan(scanId);
    pollTimerRef.current = setInterval(() => {
      pollScan(scanId);
    }, 1500);

    return () => stopPolling();
  }, [scanId]);

  async function startWebScan() {
    if (!ensureNoActiveScan()) return;

    const target = url.trim();
    if (!target) {
      setStatus("Please enter a target URL.");
      return;
    }

    const token = getToken();
    if (!token) {
      setStatus("You are not logged in. Please sign in again.");
      return;
    }

    try {
      setLoading(true);
      setStatus("Starting web scan...");
      setScanModule("URL");
      setProgress({ phase: "QUEUED", spider: 0, ascan: 0, scanStatus: "RUNNING" });

      const res = await fetch(`${API_BASE}/api/scans`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ url: target }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg = data?.error || `Failed to start scan (HTTP ${res.status})`;
        setStatus(msg);
        setProgress((prev) => ({ ...prev, scanStatus: "FAILED" }));
        if (res.status === 401) localStorage.removeItem("token");
        return;
      }

      setScanId(data.scan_id);
      // Persist the lock IMMEDIATELY after the backend acknowledges so the
      // window between "scan accepted" and "user navigates away" is covered.
      setActiveScan(data.scan_id, "URL");
      setStatus(`RUNNING (scan_id=${data.scan_id})`);
    } catch {
      setStatus("Network / Server error while uploading the folder. Re-select the project folder and try again. Large dependency/build folders are excluded automatically.");
      setProgress((prev) => ({ ...prev, scanStatus: "FAILED" }));
    } finally {
      setLoading(false);
    }
  }

  async function startApkScan() {
    if (!ensureNoActiveScan()) return;
    if (!apkFile) {
      setStatus("Please choose an APK file first.");
      return;
    }

    const token = getToken();
    if (!token) {
      setStatus("You are not logged in. Please sign in again.");
      return;
    }

    try {
      setLoading(true);
      setStatus("Uploading APK and starting analysis...");
      setScanModule("APK");
      setProgress({ phase: "QUEUED", spider: 0, ascan: 0, scanStatus: "RUNNING" });

      const formData = new FormData();
      formData.append("apk", apkFile);

      const res = await fetch(`${API_BASE}/api/apk-scans`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg = data?.error || `Failed to start APK scan (HTTP ${res.status})`;
        setStatus(msg);
        setProgress((prev) => ({ ...prev, scanStatus: "FAILED" }));
        if (res.status === 401) localStorage.removeItem("token");
        return;
      }

      setScanId(data.scan_id);
      setActiveScan(data.scan_id, "APK");
      setStatus(`RUNNING (scan_id=${data.scan_id})`);
    } catch {
      setStatus("Network / Server error.");
      setProgress((prev) => ({ ...prev, scanStatus: "FAILED" }));
    } finally {
      setLoading(false);
    }
  }

  async function startMalwareScan() {
    if (!ensureNoActiveScan()) return;
    if (!peFile) {
      setStatus("Please choose a PE file (.exe / .dll / .sys) first.");
      return;
    }

    const token = getToken();
    if (!token) {
      setStatus("You are not logged in. Please sign in again.");
      return;
    }

    try {
      setLoading(true);
      setStatus("Uploading PE binary and starting ML malware analysis...");
      setScanModule("MALWARE");
      setProgress({ phase: "QUEUED", spider: 0, ascan: 0, scanStatus: "RUNNING" });

      const formData = new FormData();
      formData.append("file", peFile);

      const res = await fetch(`${API_BASE}/api/malware-scans`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg = data?.error || `Failed to start malware scan (HTTP ${res.status})`;
        setStatus(msg);
        setProgress((prev) => ({ ...prev, scanStatus: "FAILED" }));
        if (res.status === 401) localStorage.removeItem("token");
        return;
      }

      setScanId(data.scan_id);
      setActiveScan(data.scan_id, "MALWARE");
      setStatus(`RUNNING (scan_id=${data.scan_id}) • Running LightGBM, Random Forest, and XGBoost classifiers`);
    } catch {
      setStatus("Network / Server error.");
      setProgress((prev) => ({ ...prev, scanStatus: "FAILED" }));
    } finally {
      setLoading(false);
    }
  }

  async function startCodeScan() {
    if (!ensureNoActiveScan()) return;
    if (!codeFiles.length) {
      setStatus("Please choose a project folder first. Dependency/build folders are ignored automatically.");
      return;
    }

    const token = getToken();
    if (!token) {
      setStatus("You are not logged in. Please sign in again.");
      return;
    }

    try {
      setLoading(true);
      setStatus(`Uploading ${codeFiles.length} filtered project files and preparing static analysis...`);
      setScanModule("FOLDER");
      setProgress({ phase: "QUEUED", spider: 0, ascan: 0, scanStatus: "RUNNING" });

      const formData = new FormData();
      const relativePaths = [];
      codeFiles.forEach((file) => {
        formData.append("files", file);
        relativePaths.push(file.webkitRelativePath || file.name);
      });
      formData.append("relative_paths", JSON.stringify(relativePaths));
      formData.append("folder_name", folderName || "uploaded-folder");

      const res = await fetch(`${API_BASE}/api/folder-scans`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg = data?.error || `Failed to start folder scan (HTTP ${res.status})`;
        setStatus(msg);
        setProgress((prev) => ({ ...prev, scanStatus: "FAILED" }));
        if (res.status === 401) localStorage.removeItem("token");
        return;
      }

      setScanId(data.scan_id);
      setActiveScan(data.scan_id, "FOLDER");
      setStatus(`RUNNING (scan_id=${data.scan_id}) • ${data.file_count || codeFiles.length} files uploaded`);
    } catch {
      setStatus("Network / Server error.");
      setProgress((prev) => ({ ...prev, scanStatus: "FAILED" }));
    } finally {
      setLoading(false);
    }
  }

  const displayPct = getProgressPct();
  const selectedFolderSummary = useMemo(() => {
    if (!codeFiles.length) return null;
    const totalBytes = codeFiles.reduce((sum, file) => sum + (file.size || 0), 0);
    const totalMb = (totalBytes / (1024 * 1024)).toFixed(totalBytes >= 1024 * 1024 ? 2 : 3);
    return {
      count: codeFiles.length,
      totalBytes,
      totalMb,
      summary: `${codeFiles.length} files • ${totalMb} MB`,
    };
  }, [codeFiles]);

  const scanTypes = [
    { id: "web", icon: "🌐", label: "Website URL", desc: "Dynamic scan of a live web target" },
    { id: "code", icon: "📁", label: "Code Folder", desc: "Static analysis of uploaded project files" },
    { id: "android", icon: "🤖", label: "Android App", desc: "APK security assessment" },
    { id: "malware", icon: "🦠", label: "Malware Scan", desc: "ML classification of Windows PE binaries" },
  ];

  return (
    <div className="scan-page">
      <div className="scan-header">
        <h1>New Security Scan</h1>
        <p>Analyze a live URL, uploaded source folder, or Android APK for security weaknesses.</p>
      </div>

      <div className="scan-type-row">
        {scanTypes.map(({ id, icon, label, desc }) => (
          <div
            key={id}
            className={`scan-type-card ${activeForm === id ? "active" : ""} ${isScanRunning ? "locked" : ""}`}
            onClick={() => {
              if (isScanRunning) {
                alert("Please wait for the current scan to finish before changing scan types.");
                return;
              }
              resetScanState(id);
            }}
          >
            <div className="scan-type-icon">{icon}</div>
            <div className="scan-type-text">
              <strong>{label}</strong>
              <span>{desc}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="scan-form-area">
        <p className="scan-form-title">⚡ Configure Scan</p>

        {isScanRunning && (
          <div className="scan-status-box" style={{ marginBottom: 18 }}>
            <div className="scan-status-line"><strong>Please do not start another scan.</strong></div>
            <div className="scan-status-line" style={{ marginBottom: 0 }}><strong>Do not navigate away from this page.</strong></div>
          </div>
        )}

        {activeForm === "web" && (
          <div className="scan-form-grid">
            <div className="scan-input-wrap">
              <label>Target URL</label>
              <input
                type="url"
                className="scan-input"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={isScanRunning}
              />
            </div>

            <div>
              <button
                className={`scan-btn ${isScanRunning || loading ? "scan-btn-muted" : ""}`}
                onClick={startWebScan}
                disabled={loading || isScanRunning}
              >
                {loading ? "Initializing..." : isScanRunning ? "Scan in Progress..." : "Start Security Scan"}
                <span style={{ fontSize: "16px" }}>→</span>
              </button>
            </div>
          </div>
        )}

        {activeForm === "code" && (
          <div className="scan-form-grid">
            <div className="scan-input-wrap">
              <label>Folder Name</label>
              <input
                className="scan-input"
                placeholder="e.g. VSAWA-Backend"
                value={folderName}
                onChange={(e) => setFolderName(e.target.value)}
                disabled={isScanRunning}
              />
            </div>
            <div className="scan-input-wrap">
              <label>Upload Project Folder</label>
              <input
                ref={folderInputRef}
                type="file"
                className="scan-input scan-input-folder"
                multiple
                disabled={isScanRunning}
                onChange={(e) => {
                  const allFiles = Array.from(e.target.files || []);
                  const keptFiles = [];
                  const reasons = new Set();
                  let skipped = 0;

                  allFiles.forEach((file) => {
                    const reason = getClientSkipReason(file);
                    if (reason) {
                      skipped += 1;
                      reasons.add(reason);
                      return;
                    }
                    keptFiles.push(file);
                  });

                  setCodeFiles(keptFiles);
                  setFolderSelectionMeta({
                    totalSelected: allFiles.length,
                    kept: keptFiles.length,
                    skipped,
                    reasons: Array.from(reasons),
                  });

                  const derivedFolder = allFiles[0]?.webkitRelativePath?.split("/")?.[0] || "";
                  if (derivedFolder) setFolderName(derivedFolder);
                }}
              />
              {folderSelectionMeta.totalSelected > 0 && (
                <>
                  <div className="scan-selection-chip">
                    <strong>{folderName || codeFiles[0]?.webkitRelativePath?.split("/")?.[0] || "Selected Folder"}</strong>
                    <span>
                      {selectedFolderSummary?.summary || "No uploadable source files detected"}
                      {folderSelectionMeta.skipped > 0
                        ? ` • ${folderSelectionMeta.skipped} file(s) ignored`
                        : ""}
                    </span>
                  </div>
                  <div className="scan-folder-note">
                    <strong>Upload filtering:</strong> {folderSelectionMeta.kept} kept out of {folderSelectionMeta.totalSelected} selected.
                    {folderSelectionMeta.skipped > 0
                      ? ` Ignored ${folderSelectionMeta.reasons.join(", ")} to keep the scan stable and focused on real source files.`
                      : " All selected files look uploadable."}
                  </div>
                </>
              )}
            </div>
            <div>
              <button
                className={`scan-btn ${isScanRunning || loading ? "scan-btn-muted" : ""}`}
                onClick={startCodeScan}
                disabled={loading || isScanRunning}
              >
                {loading ? "Uploading..." : isScanRunning ? "Scan in Progress..." : "Start Folder Scan"}
                <span style={{ fontSize: "16px" }}>→</span>
              </button>
            </div>
          </div>
        )}

        {activeForm === "android" && (
          <div className="scan-form-grid">
            <div className="scan-input-wrap">
              <label>Upload APK</label>
              <input
                type="file"
                accept=".apk"
                className="scan-input"
                disabled={isScanRunning}
                onChange={(e) => {
                  const file = e.target.files?.[0] || null;
                  setApkFile(file);
                }}
              />
              {apkFile && <small style={{ color: "#94a3b8", marginTop: 8, display: "block" }}>Selected: {apkFile.name}</small>}
            </div>
            <div>
              <button
                className={`scan-btn ${isScanRunning || loading ? "scan-btn-muted" : ""}`}
                onClick={startApkScan}
                disabled={loading || isScanRunning}
              >
                {loading ? "Uploading..." : isScanRunning ? "Scan in Progress..." : "Start APK Scan"}
                <span style={{ fontSize: "16px" }}>→</span>
              </button>
            </div>
          </div>
        )}

        {activeForm === "malware" && (
          <div className="scan-form-grid">
            <div className="scan-input-wrap">
              <label>Upload Windows PE Binary (.exe / .dll / .sys)</label>
              <input
                type="file"
                accept=".exe,.dll,.sys"
                className="scan-input"
                disabled={isScanRunning}
                onChange={(e) => {
                  const file = e.target.files?.[0] || null;
                  setPeFile(file);
                }}
              />
              {peFile && (
                <small style={{ color: "#94a3b8", marginTop: 8, display: "block" }}>
                  Selected: {peFile.name} ({(peFile.size / 1024 / 1024).toFixed(2)} MB)
                </small>
              )}
              <div className="scan-folder-note" style={{ marginTop: 10 }}>
                <strong>How it works:</strong> the binary is analysed by three independent ML
                classifiers (LightGBM, Random Forest, XGBoost) trained on EMBER-style static
                PE features. Each model returns a verdict and a confidence score, and the
                report aggregates them into an ensemble decision.
              </div>
            </div>
            <div>
              <button
                className={`scan-btn ${isScanRunning || loading ? "scan-btn-muted" : ""}`}
                onClick={startMalwareScan}
                disabled={loading || isScanRunning}
              >
                {loading ? "Uploading..." : isScanRunning ? "Scan in Progress..." : "Start Malware Scan"}
                <span style={{ fontSize: "16px" }}>→</span>
              </button>
            </div>
          </div>
        )}

        {(status || scanId) && (
          <div className="scan-status-box" style={{ marginTop: 20 }}>
            {scanId && (() => {
              // Pick the module info to render. We prefer the explicit
              // scanModule state set when the scan started; if it's empty
              // (shouldn't happen during a running scan, but might if the
              // page was reloaded mid-scan) we fall back to the URL/ZAP
              // panel since that's the only module the backend reports
              // SPIDER/ASCAN percentages for.
              const moduleInfo = MODULE_STATUS_INFO[scanModule] || DEFAULT_MODULE_INFO;
              const phaseLabel = moduleInfo.phases[progress.phase] || progress.phase || "Working...";

              // Compute the two metric channels. For URL scans these are
              // the real ZAP spider/ascan percentages. For everything else
              // we synthesise them from the phase ladder defined in
              // PHASE_PROGRESS so the user still sees two progress signals.
              const overallPct = (() => {
                if (progress.scanStatus === "COMPLETED") return 100;
                if (progress.phase === "SPIDER") return progress.spider ?? 0;
                if (progress.phase === "ASCAN") return progress.ascan ?? 0;
                return PHASE_PROGRESS[progress.phase] ?? Math.max(progress.spider ?? 0, progress.ascan ?? 0, 0);
              })();

              // metric value resolver: keys defined per module above are
              // mapped to either real backend fields (spider/ascan) or to
              // computed slices of the overall phase progress.
              const metricValue = (key) => {
                if (key === "spider") return progress.spider ?? 0;
                if (key === "ascan")  return progress.ascan ?? 0;

                // Synthetic channels for APK / FOLDER / MALWARE. Each
                // channel is "filled" by certain phases:
                //   - APK static / manifest split tracks APK_INIT then APK_ANALYZE
                //   - FOLDER indexing / AI review split tracks CODE_INDEX then CODE_ANALYZE
                //   - MALWARE features / predict split tracks PE_FEATURES then PE_PREDICT+PERSIST
                const phase = progress.phase;
                const completed = progress.scanStatus === "COMPLETED";

                if (key === "static")   return phaseChannelPct(phase, ["APK_INIT"],   ["APK_ANALYZE", "DONE"], completed);
                if (key === "manifest") return phaseChannelPct(phase, [],             ["APK_ANALYZE", "DONE"], completed);

                if (key === "index")    return phaseChannelPct(phase, ["CODE_INIT"],  ["CODE_INDEX", "CODE_ANALYZE", "DONE"], completed);
                if (key === "review")   return phaseChannelPct(phase, ["CODE_INIT", "CODE_INDEX"], ["CODE_ANALYZE", "DONE"], completed);

                if (key === "features") return phaseChannelPct(phase, ["PE_INIT"],   ["PE_FEATURES", "PE_PREDICT", "PE_PERSIST", "DONE"], completed);
                if (key === "predict")  return phaseChannelPct(phase, ["PE_INIT", "PE_FEATURES"], ["PE_PREDICT", "PE_PERSIST", "DONE"], completed);

                return 0;
              };

              return (
                <>
                  <div className="scan-status-line">
                    Engine: <strong>{moduleInfo.engine}</strong>
                  </div>
                  <div className="scan-status-line">
                    Phase: <strong>{phaseLabel}</strong>
                    {moduleInfo.metrics.map((m) => (
                      <span key={m.key}>
                        &nbsp;&nbsp;{m.label}: <strong>{metricValue(m.key)}%</strong>
                      </span>
                    ))}
                  </div>

                  <div className="scan-progress-row">
                    <span className="scan-progress-label">Overall Progress</span>
                    <span className="scan-progress-pct">{overallPct}%</span>
                  </div>
                  <div className="scan-progress-track">
                    <div className="scan-progress-fill" style={{ width: `${overallPct}%` }} />
                  </div>
                </>
              );
            })()}

            {status && (
              <div className="scan-status-line" style={{ marginTop: scanId ? 12 : 0, marginBottom: 0 }}>
                {status}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanPage;
