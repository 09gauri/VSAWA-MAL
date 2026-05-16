import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Chart as ChartJS,
  ArcElement,
  BarElement,
  LineElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
  PointElement,
} from "chart.js";
import { Doughnut, Bar, Line } from "react-chartjs-2";
import { useNavigate } from "react-router-dom";
import "./Dashboard.css";

ChartJS.register(
  ArcElement,
  BarElement,
  LineElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
  PointElement
);

const API_BASE =
  (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000").replace(/\/$/, "");

const POLL_INTERVAL_MS = 5000;
const OWASP_LABELS = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"];

const OWASP_TITLES = {
  A01: "Broken Access Control",
  A02: "Cryptographic Failures",
  A03: "Injection",
  A04: "Insecure Design",
  A05: "Security Misconfiguration",
  A06: "Vulnerable and Outdated Components",
  A07: "Identification and Authentication Failures",
  A08: "Software and Data Integrity Failures",
  A09: "Security Logging and Monitoring Failures",
  A10: "Server-Side Request Forgery",
};

function formatDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  }) +
    ", " +
    d.toLocaleTimeString(undefined, {
      hour: "numeric",
      minute: "2-digit",
    });
}

function formatAvgScanTime(seconds) {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return secs ? `${mins}m ${secs}s` : `${mins}m`;
}

function shortenTargetName(value, maxLen = 26) {
  if (!value) return "—";
  try {
    const url = new URL(value);
    const compact = `${url.hostname}${url.pathname !== "/" ? url.pathname : ""}`;
    return compact.length > maxLen ? `${compact.slice(0, maxLen)}…` : compact;
  } catch {
    return value.length > maxLen ? `${value.slice(0, maxLen)}…` : value;
  }
}

function scoreColor(score) {
  if (score == null) return undefined;
  if (score >= 80) return "#22c55e";
  if (score >= 50) return "#f59e0b";
  return "#ef4444";
}

function severityTone(severity) {
  switch ((severity || "").toUpperCase()) {
    case "CRITICAL":
      return { bg: "rgba(255,63,63,0.18)", color: "#ff6b6b", border: "rgba(255,63,63,0.45)" };
    case "HIGH":
      return { bg: "rgba(239,68,68,0.18)", color: "#f87171", border: "rgba(239,68,68,0.45)" };
    case "MEDIUM":
      return { bg: "rgba(245,158,11,0.18)", color: "#fbbf24", border: "rgba(245,158,11,0.45)" };
    case "LOW":
      return { bg: "rgba(34,211,238,0.18)", color: "#22d3ee", border: "rgba(34,211,238,0.45)" };
    default:
      return { bg: "rgba(148,163,184,0.18)", color: "#cbd5e1", border: "rgba(148,163,184,0.35)" };
  }
}

const Dashboard = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchStats = useCallback(async (signal) => {
    const token = localStorage.getItem("token");
    if (!token) {
      setLoading(false);
      setStats(null);
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/api/dashboard/stats`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        signal,
      });

      if (!response.ok) {
        throw new Error(`Dashboard request failed (${response.status})`);
      }

      const data = await response.json();
      setStats(data);
      setError("");
    } catch (err) {
      if (err.name === "AbortError") return;
      setError(err.message || "Failed to load dashboard data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetchStats(controller.signal);

    const intervalId = window.setInterval(() => {
      fetchStats();
    }, POLL_INTERVAL_MS);

    return () => {
      controller.abort();
      window.clearInterval(intervalId);
    };
  }, [fetchStats]);

  const severityData = useMemo(() => {
    if (!stats) return null;

    const counts = stats.severity_counts || {};
    const labels = [];
    const data = [];
    const backgroundColor = [];

    const ordered = [
      { label: "Low", value: counts.LOW || 0, color: "#00f2fe" },
      { label: "Medium", value: counts.MEDIUM || 0, color: "#00bfff" },
      { label: "High", value: counts.HIGH || 0, color: "#ff9800" },
      { label: "Critical", value: counts.CRITICAL || 0, color: "#ff3f3f" },
    ];

    ordered.forEach((item) => {
      if (item.value > 0) {
        labels.push(item.label);
        data.push(item.value);
        backgroundColor.push(item.color);
      }
    });

    if (data.length === 0) return null;

    return {
      labels,
      datasets: [
        {
          data,
          backgroundColor,
          borderColor: backgroundColor,
          borderWidth: 2,
        },
      ],
    };
  }, [stats]);

  const owaspData = useMemo(() => {
    if (!stats) return null;

    return {
      labels: OWASP_LABELS,
      datasets: [
        {
          data: OWASP_LABELS.map((key) => stats.owasp_map?.[key] || 0),
          backgroundColor: OWASP_LABELS.map((key) =>
            (stats.owasp_map?.[key] || 0) > 0 ? "#00f2fe" : "rgba(0,242,254,0.20)"
          ),
        },
      ],
    };
  }, [stats]);

  const trendData = useMemo(() => {
    if (!stats || !Array.isArray(stats.trend) || stats.trend.length === 0) return null;

    return {
      labels: stats.trend.map((item) => {
        const [year, month] = (item.month || "").split("-");
        if (!year || !month) return item.month;
        return new Date(Number(year), Number(month) - 1, 1).toLocaleDateString(undefined, {
          month: "short",
          year: "2-digit",
        });
      }),
      datasets: [
        {
          label: "Vulnerabilities",
          data: stats.trend.map((item) => item.total || 0),
          borderColor: "#00f2fe",
          backgroundColor: "rgba(0,242,254,0.10)",
          tension: 0.4,
        },
      ],
    };
  }, [stats]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: "white" },
      },
    },
    scales: {
      x: {
        ticks: { color: "white" },
        grid: { color: "rgba(255,255,255,0.1)" },
      },
      y: {
        ticks: { color: "white" },
        grid: { color: "rgba(255,255,255,0.1)" },
      },
    },
  };

  const owaspOptions = {
    ...chartOptions,
    plugins: {
      ...chartOptions.plugins,
      tooltip: {
        callbacks: {
          title: (items) => {
            const key = OWASP_LABELS[items[0].dataIndex];
            return `${key}: ${OWASP_TITLES[key] || ""}`;
          },
        },
      },
    },
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: "white" },
      },
    },
  };

  const noData = !loading && !error && (!stats || stats.total_scans === 0);

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div className="header-content">
          <h1>Security Command Center</h1>
          <p>Monitor, analyze, and secure your applications</p>
        </div>

        <div className="header-actions">
          <button
            className="action-btn new-scan-btn"
            onClick={() => navigate("/scan")}
          >
            New Security Scan
          </button>
          <button
            className="action-btn view-report-btn"
            onClick={() => navigate("/reports")}
          >
            View Reports
          </button>
        </div>
      </div>

      {error && (
        <div
          style={{
            marginBottom: 20,
            padding: 14,
            borderRadius: 12,
            background: "rgba(239,68,68,0.12)",
            border: "1px solid rgba(239,68,68,0.30)",
            color: "#fca5a5",
          }}
        >
          Unable to load live dashboard data: {error}
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card cyber-glow">
          <div className="stat-card-content">
            <div className="stat-info">
              <div className="stat-text">
                <p className="stat-label">Total Scans</p>
                <h3 className="stat-value total-scans">
                  {loading ? "…" : stats?.total_scans ?? 0}
                </h3>
                <p className="stat-note green">
                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="stat-icon">
                    <polyline points="22 7 13.5 15.5 8.5 10.5 2 17"></polyline>
                    <polyline points="16 7 22 7 22 13"></polyline>
                  </svg>
                  {loading ? "Loading…" : `${stats?.scans_today ?? 0} today`}
                </p>
              </div>
              <div className="stat-icon-container blue">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="icon-large">
                  <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"></path>
                </svg>
              </div>
            </div>
          </div>
        </div>

        <div className="stat-card cyber-glow">
          <div className="stat-card-content">
            <div className="stat-info">
              <div className="stat-text">
                <p className="stat-label">Vulnerabilities</p>
                <h3 className="stat-value vulnerabilities">
                  {loading ? "…" : stats?.total_vulns ?? 0}
                </h3>
                <p className="stat-note red">
                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="stat-icon">
                    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"></path>
                    <path d="M12 9v4"></path>
                    <path d="M12 17h.01"></path>
                  </svg>
                  {loading ? "Loading…" : `${stats?.critical_count ?? 0} high severity`}
                </p>
              </div>
              <div className="stat-icon-container red">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="icon-large">
                  <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"></path>
                  <path d="M12 9v4"></path>
                  <path d="M12 17h.01"></path>
                </svg>
              </div>
            </div>
          </div>
        </div>

        <div className="stat-card cyber-glow">
          <div className="stat-card-content">
            <div className="stat-info">
              <div className="stat-text">
                <p className="stat-label">Security Score</p>
                <h3
                  className="stat-value security-score"
                  style={{ color: scoreColor(stats?.security_score) }}
                >
                  {loading
                    ? "…"
                    : stats?.security_score == null
                    ? "—"
                    : `${stats.security_score}%`}
                </h3>
                <p className="stat-note">
                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="stat-icon">
                    <path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"></path>
                  </svg>
                  Live telemetry
                </p>
              </div>
              <div className="stat-icon-container green">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="icon-large">
                  <polyline points="22 7 13.5 15.5 8.5 10.5 2 17"></polyline>
                  <polyline points="16 7 22 7 22 13"></polyline>
                </svg>
              </div>
            </div>
          </div>
        </div>

        <div className="stat-card cyber-glow">
          <div className="stat-card-content">
            <div className="stat-info">
              <div className="stat-text">
                <p className="stat-label">Avg Scan Time</p>
                <h3 className="stat-value scan-time">
                  {loading ? "…" : formatAvgScanTime(stats?.avg_scan_secs)}
                </h3>
                <p className="stat-note blue">
                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="stat-icon">
                    <circle cx="12" cy="12" r="10"></circle>
                    <polyline points="12 6 12 12 16 14"></polyline>
                  </svg>
                  Refreshed every 5s
                </p>
              </div>
              <div className="stat-icon-container blue">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="icon-large">
                  <circle cx="12" cy="12" r="10"></circle>
                  <polyline points="12 6 12 12 16 14"></polyline>
                </svg>
              </div>
            </div>
          </div>
        </div>
      </div>

      {noData && (
        <div
          style={{
            marginBottom: 24,
            padding: 16,
            borderRadius: 14,
            background: "rgba(14,165,233,0.10)",
            border: "1px solid rgba(14,165,233,0.24)",
            color: "#bae6fd",
          }}
        >
          No scans found for this account yet. Run your first scan to populate the dashboard.
        </div>
      )}

      <div className="dashboard-content">
        <div className="charts-column">
          <div className="chart-card">
            <h5>Vulnerability Severity Distribution</h5>
            <div className="chart-container">
              {severityData ? (
                <Doughnut data={severityData} options={doughnutOptions} />
              ) : (
                <div style={{ color: "#94a3b8", display: "flex", alignItems: "center", justifyContent: "center", height: "100%" }}>
                  No severity data yet
                </div>
              )}
            </div>
          </div>

          <div className="chart-card">
            <h5>OWASP Top 10 Distribution</h5>
            <div className="chart-container">
              {owaspData ? (
                <Bar data={owaspData} options={owaspOptions} />
              ) : (
                <div style={{ color: "#94a3b8", display: "flex", alignItems: "center", justifyContent: "center", height: "100%" }}>
                  No OWASP mapping available yet
                </div>
              )}
            </div>
          </div>

          <div className="chart-card">
            <h5>Vulnerability Detection Trend</h5>
            <div className="chart-container">
              {trendData ? (
                <Line data={trendData} options={chartOptions} />
              ) : (
                <div style={{ color: "#94a3b8", display: "flex", alignItems: "center", justifyContent: "center", height: "100%" }}>
                  Trend data will appear after scans accumulate
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="activity-column">
          <div className="activity-card">
            <div className="activity-header">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="activity-icon warning">
                <path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"></path>
              </svg>
              <h3>Critical Threats</h3>
            </div>
            <p className="activity-subtitle">Highest priority vulnerabilities</p>
            <div className="threats-list">
              {stats?.top_threats?.length ? (
                stats.top_threats.map((threat, index) => {
                  const tone = severityTone(threat.severity);
                  return (
                    <div className="threat-item" key={`${threat.title}-${index}`}>
                      <div className="threat-header">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="threat-icon">
                          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"></path>
                          <path d="M12 9v4"></path>
                          <path d="M12 17h.01"></path>
                        </svg>
                        <div className="threat-info">
                          <h4>{threat.title || "Untitled finding"}</h4>
                          <p>
                            {threat.cwe_id
                              ? `CWE-${threat.cwe_id}`
                              : shortenTargetName(threat.target_name || "Security finding", 38)}
                          </p>
                        </div>
                      </div>
                      <div className="threat-tags">
                        <span
                          className="tag"
                          style={{
                            background: tone.bg,
                            color: tone.color,
                            border: `1px solid ${tone.border}`,
                            textTransform: "lowercase",
                          }}
                        >
                          {(threat.severity || "info").toLowerCase()}
                        </span>
                        <span className="confidence">
                          {threat.occurrence_count || 1} occurrence{(threat.occurrence_count || 1) > 1 ? "s" : ""}
                        </span>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div style={{ color: "#94a3b8", fontStyle: "italic" }}>
                  No high-priority findings yet
                </div>
              )}
            </div>
          </div>

          <div className="activity-card">
            <div className="activity-header">
              <h3>Recent Security Scans</h3>
              <button className="view-all-btn" onClick={() => navigate("/reports")}>View All →</button>
            </div>
            <div className="scans-list">
              {stats?.recent_scans?.length ? (
                stats.recent_scans.map((scan) => (
                  <div className="scan-item" key={scan.scan_id}>
                    <div className="scan-icon">
                      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path>
                        <path d="M2 12h20"></path>
                      </svg>
                    </div>
                    <div className="scan-info">
                      <div className="scan-name">{shortenTargetName(scan.target_name)}</div>
                      <div className="scan-date">{formatDateTime(scan.started_at)}</div>
                    </div>
                    <div className="scan-status">
                      <span className={`status ${(scan.status || "unknown").toLowerCase()}`}>
                        {(scan.status || "UNKNOWN").toLowerCase()}
                      </span>
                      <span className="vuln-count">{scan.total_findings || 0} vulns</span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ color: "#94a3b8", fontStyle: "italic" }}>
                  No recent scans yet
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
