import React, { useState, useEffect, useCallback } from "react";
import {
  Search,
  Globe,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Calendar,
  Smartphone,
  Download,
  Eye,
  RefreshCw,
  FolderOpen,
  ShieldAlert,
} from "lucide-react";
import "./ReportsPage.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";
const POLL_MS = 5000;

function getAuthToken() {
  return localStorage.getItem("token") || localStorage.getItem("access_token");
}

function formatDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

async function fetchPdfBlob(scanId) {
  const token = getAuthToken();
  if (!token) throw new Error("Not logged in.");

  const res = await fetch(`${API_BASE}/api/scans/${scanId}/report/pdf`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error || `PDF request failed (HTTP ${res.status})`);
  }

  const blob = await res.blob();
  const contentDisposition = res.headers.get("Content-Disposition") || "";
  const match = contentDisposition.match(/filename\*?=(?:UTF-8''|\")?([^\";]+)/i);
  const filename = match ? decodeURIComponent(match[1].replace(/"/g, "")) : `scan_report_${scanId}.pdf`;

  return { blob, filename };
}

async function previewPdf(scanId) {
  const { blob } = await fetchPdfBlob(scanId);
  const blobUrl = URL.createObjectURL(blob);
  window.open(blobUrl, "_blank", "noopener,noreferrer");
  setTimeout(() => URL.revokeObjectURL(blobUrl), 60_000);
}

async function downloadPdf(scanId) {
  const { blob, filename } = await fetchPdfBlob(scanId);
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(blobUrl);
}

function getDisplayName(scan) {
  if (scan.target_type === "APK") return scan.target_name || "APK File";
  if (scan.target_type === "FOLDER") return scan.target_name || "Code Folder";
  if (scan.target_type === "MALWARE") return scan.target_name || "PE Binary";
  try {
    return new URL(scan.target_name).hostname;
  } catch {
    return scan.target_name || "Unknown target";
  }
}

function getScanTypeMeta(scan) {
  switch (scan.target_type) {
    case "APK":
      return { Icon: Smartphone, label: "APK Scan" };
    case "FOLDER":
      return { Icon: FolderOpen, label: "Folder Scan" };
    case "MALWARE":
      return { Icon: ShieldAlert, label: "Malware Scan" };
    default:
      return { Icon: Globe, label: "URL Scan" };
  }
}

function ScanRow({ scan, onPreview, onDownload }) {
  const [busyAction, setBusyAction] = useState("");
  const isCompleted = scan.status === "COMPLETED";

  // For URL/APK/FOLDER a "secure" verdict means zero findings.
  // For MALWARE the ML aggregate finding always exists (info or critical), so
  // we read `pe_verdict` directly from the backend and translate "Malicious"
  // into the same vulnerable-styling we use elsewhere.
  const isMalware = scan.target_type === "MALWARE";
  const isSecure = isMalware
    ? (scan.pe_verdict || "").toLowerCase() !== "malicious"
    : !scan.total_findings;

  const { Icon: TypeIcon, label: typeLabel } = getScanTypeMeta(scan);

  const handlePreview = async (e) => {
    e.stopPropagation();
    if (!isCompleted) return;
    try {
      setBusyAction("preview");
      await onPreview(scan.scan_id);
    } catch (err) {
      alert(err.message || "Failed to open PDF preview.");
    } finally {
      setBusyAction("");
    }
  };

  const handleDownload = async (e) => {
    e.stopPropagation();
    if (!isCompleted) return;
    try {
      setBusyAction("download");
      await onDownload(scan.scan_id);
    } catch (err) {
      alert(err.message || "Failed to download PDF.");
    } finally {
      setBusyAction("");
    }
  };

  const handleRowClick = async () => {
    if (!isCompleted) return;
    try {
      setBusyAction("preview");
      await onPreview(scan.scan_id);
    } catch (err) {
      alert(err.message || "Failed to open PDF preview.");
    } finally {
      setBusyAction("");
    }
  };

  return (
    <div className="reports-table-row" onClick={handleRowClick} style={{ cursor: isCompleted ? "pointer" : "default" }}>
      <div className="scan-name-cell">
        <strong>{getDisplayName(scan)}</strong>
        <span>{scan.target_name || "—"}</span>
      </div>

      <div className="reports-date">
        <Calendar size={12} style={{ marginRight: 6 }} />
        {formatDateTime(scan.started_at)}
      </div>

      <div className={`reports-vulns ${scan.total_findings > 0 ? "has-vulns" : ""}`}>
        {scan.total_findings > 0 ? <AlertTriangle size={14} /> : <ShieldCheck size={14} />}
        {scan.total_findings} {scan.total_findings === 1 ? "Issue" : "Issues"}
      </div>

      <div>
        <span
          className="badge-secure"
          style={!isSecure ? {
            color: "#f87171",
            borderColor: "#f87171",
            background: "rgba(248,113,113,0.05)",
          } : {}}
        >
          {isMalware
            ? (isSecure ? "Clean" : "Malicious")
            : (isSecure ? "Secure" : "Vulnerable")}
        </span>
        {scan.status !== "COMPLETED" && (
          <span
            style={{
              marginLeft: 6,
              fontSize: 10,
              color: "#f59e0b",
              background: "rgba(245,158,11,0.1)",
              border: "1px solid rgba(245,158,11,0.3)",
              borderRadius: 3,
              padding: "1px 5px",
            }}
          >
            {scan.status}
          </span>
        )}
      </div>

      <div className="reports-type">
        <TypeIcon size={14} />
        {typeLabel}
      </div>

      <div className="reports-actions" onClick={(e) => e.stopPropagation()}>
        {isCompleted ? (
          <>
            <button className="report-action-btn report-action-btn--view" onClick={handlePreview} title="Preview PDF report">
              {busyAction === "preview" ? <span className="report-action-spinner" /> : <Eye size={13} />}
              {busyAction === "preview" ? "…" : "View"}
            </button>
            <button className="report-action-btn report-action-btn--pdf" onClick={handleDownload} title="Download PDF report">
              {busyAction === "download" ? <span className="report-action-spinner" /> : <Download size={13} />}
              {busyAction === "download" ? "…" : "PDF"}
            </button>
          </>
        ) : (
          <span style={{ fontSize: 11, color: "#475569" }}>
            {scan.status === "RUNNING" ? "⏳ Scanning" : scan.status}
          </span>
        )}
      </div>
    </div>
  );
}

export default function ReportsPage() {
  const [searchTerm, setSearchTerm] = useState("");
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const fetchScans = useCallback(async (isRefresh = false) => {
    const token = getAuthToken();
    if (!token) {
      setError("You need to log in to view reports.");
      setLoading(false);
      return;
    }

    if (isRefresh) setRefreshing(true);
    try {
      const res = await fetch(`${API_BASE}/api/scans`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err?.error || `Server error ${res.status}`);
      }
      const data = await res.json();
      setScans(Array.isArray(data) ? data : []);
      setError("");
    } catch (err) {
      setError(err.message || "Failed to load reports.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchScans(false);
    const id = setInterval(() => fetchScans(true), POLL_MS);
    return () => clearInterval(id);
  }, [fetchScans]);

  const filtered = scans.filter((s) => (s.target_name || "").toLowerCase().includes(searchTerm.toLowerCase()));

  return (
    <div className="reports-page">
      <div className="reports-header">
        <h1>All Scan Reports</h1>
        <p>Review scan history for the logged-in user. Completed scans can be previewed as PDF and downloaded.</p>
      </div>

      <div className="reports-card">
        <div className="reports-card-header">
          <h2>
            <FileText size={18} color="#00f2fe" />
            Audit History
            <span style={{ color: "#475569", fontWeight: 500, fontSize: 12 }}>
              ({loading ? "…" : `${filtered.length} Total`})
            </span>
          </h2>

          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <button
              className="report-action-btn report-action-btn--view"
              onClick={() => fetchScans(true)}
              style={{ padding: "10px 12px" }}
              title="Refresh report list"
            >
              <RefreshCw size={13} className={refreshing ? "spin-icon" : ""} />
              Refresh
            </button>

            <div className="reports-search-wrap">
              <Search className="reports-search-icon" size={16} />
              <input
                className="reports-search"
                placeholder="Search by URL or file name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className="reports-table">
          <div className="reports-table-head">
            <span>Asset Detail</span>
            <span>Audit Date</span>
            <span>Findings</span>
            <span>Status</span>
            <span>Method</span>
            <span>Actions</span>
          </div>

          {loading ? (
            <div className="reports-empty">
              <div style={{ color: "#475569", fontSize: 14 }}>Loading scans…</div>
            </div>
          ) : error ? (
            <div className="reports-empty" style={{ color: "#f87171" }}>⚠ {error}</div>
          ) : filtered.length === 0 ? (
            <div className="reports-empty">
              <AlertTriangle size={48} strokeWidth={1} />
              <div className="reports-empty-text">
                {scans.length === 0
                  ? "No scans yet. Run your first scan to generate user-specific reports."
                  : "No report records found matching your query."}
              </div>
            </div>
          ) : (
            filtered.map((scan) => (
              <ScanRow
                key={scan.scan_id}
                scan={scan}
                onPreview={previewPdf}
                onDownload={downloadPdf}
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
