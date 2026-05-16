import React, { useEffect, useMemo, useState } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Sidebar from './components/Sidebar.jsx';
import Dashboard from './components/Dashboard.jsx';
import ScanPage from './components/ScanPage.jsx';
import ReportsPage from './components/ReportsPage.jsx';
import AuthPage from './components/AuthPage.jsx';
import ProfilePage from './components/ProfilePage.jsx';
import VulnerabilityDB from './components/VulnerabilityDB.jsx';
import FloatingChatbot from "./components/FloatingChatbot";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000").replace(/\/$/, "");

const App = () => {
  const location = useLocation();
  const [authStatus, setAuthStatus] = useState("checking");

  useEffect(() => {
    let cancelled = false;

    async function bootstrapSession() {
      const token = localStorage.getItem("token") || localStorage.getItem("access_token");
      if (!token) {
        if (!cancelled) setAuthStatus("guest");
        return;
      }

      try {
        const res = await fetch(`${API_BASE}/api/auth/me`, {
          method: "GET",
          headers: { Authorization: `Bearer ${token}` },
        });

        if (!res.ok) throw new Error("Session expired");

        if (!cancelled) setAuthStatus("authenticated");
      } catch {
        localStorage.removeItem("token");
        localStorage.removeItem("access_token");
        localStorage.removeItem("user");
        if (!cancelled) setAuthStatus("guest");
      }
    }

    bootstrapSession();
    return () => {
      cancelled = true;
    };
  }, []);

  const setIsLoggedIn = (value) => {
    setAuthStatus(value ? "authenticated" : "guest");
  };

  const isLoggedIn = authStatus === "authenticated";
  const isPublicRoute = location.pathname === "/" || location.pathname.startsWith("/auth");
  const showSidebar = isLoggedIn && !isPublicRoute;

  const shellStyles = useMemo(() => `
    *, *::before, *::after { box-sizing: border-box; }

    body {
      margin: 0;
      /* Inter has tighter, more readable rendering than DM Sans at small
         sizes; keep DM Sans as a fallback for any leftover component still
         requesting it explicitly. */
      font-family: 'Inter', 'DM Sans', system-ui, -apple-system, sans-serif;
      background: #020617;
      color: white;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      font-size: 15px;
      line-height: 1.6;
      text-rendering: optimizeLegibility;
    }

    /* ---- READABILITY BUMPS ----------------------------------------------
       The component CSS files were originally written with very small text
       (10-13 px) and aggressive UPPERCASE + letter-spacing on micro-labels,
       which produced an "AI dashboard" look that strained the eye over long
       sessions. Rather than rewrite every component, we floor small text to
       legible sizes via cascade overrides. Components that genuinely need
       compact text (badge widgets, code-only readouts) can still go smaller
       via more specific selectors.
       ------------------------------------------------------------------- */
    .right-panel p,
    .right-panel li,
    .right-panel td,
    .right-panel th {
      font-size: 14.5px;
      line-height: 1.6;
    }

    /* Convert tiny ALL-CAPS labels into normal-case 13.5px copy. We keep
       the rule narrow (only labels that are 11 px or smaller and uppercase)
       so we don't disturb intentional badges. */
    .right-panel label,
    .right-panel .vuln-section-label,
    .right-panel .label-small {
      font-size: 13.5px;
      text-transform: none;
      letter-spacing: 0;
    }
    /* ---- end readability bumps ---------------------------------------- */

    .app-shell {
      min-height: 100vh;
      display: flex;
      background: #020617;
    }

    .sidebar {
      width: 256px;
      min-width: 256px;
      background: #080f1e;
      display: flex;
      flex-direction: column;
      border-right: 1px solid rgba(255,255,255,0.06);
      position: sticky;
      top: 0;
      height: 100vh;
      overflow-y: auto;
    }

    .sidebar-header {
      padding: 24px 20px 20px;
      font-size: 17px;
      font-weight: 700;
      color: #00f2fe;
      display: flex;
      gap: 10px;
      align-items: center;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      font-family: 'Space Grotesk', sans-serif;
      letter-spacing: -0.3px;
    }

    .menu-section {
      padding: 16px 12px;
      flex: 1;
    }

    .menu-item {
      padding: 10px 14px;
      display: flex;
      gap: 11px;
      align-items: center;
      cursor: pointer;
      color: #94a3b8;
      border-radius: 8px;
      margin-bottom: 2px;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.2s ease;
      letter-spacing: 0.1px;
      text-decoration: none;
    }

    .menu-item:hover {
      background: rgba(255,255,255,0.05);
      color: #e2e8f0;
    }

    .menu-item.active {
      background: linear-gradient(135deg, rgba(0,242,254,0.12), rgba(79,172,254,0.08));
      color: #00f2fe;
      border: 1px solid rgba(0,242,254,0.15);
    }

    .menu-item i {
      width: 16px;
      text-align: center;
      font-size: 13px;
    }

    .metrics-section {
      padding: 16px 12px 12px;
      border-top: 1px solid rgba(255,255,255,0.06);
    }

    .metrics-section h4 {
      color: rgba(255,255,255,0.3);
      font-size: 10px;
      font-weight: 700;
      margin-bottom: 16px;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      padding: 0 6px;
    }

    .metric-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 7px 6px;
      border-radius: 6px;
      margin-bottom: 2px;
    }

    .metric-row:hover {
      background: rgba(255,255,255,0.03);
    }

    .profile-section {
      padding: 12px;
      border-top: 1px solid rgba(255,255,255,0.06);
    }

    .right-panel {
      flex: 1;
      min-width: 0;
      overflow-x: hidden;
    }

    .app-loading-screen {
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: radial-gradient(circle at top, rgba(0,242,254,0.09), transparent 38%), #020617;
      color: #cbd5e1;
      font-family: 'DM Sans', sans-serif;
    }

    .app-loading-card {
      padding: 24px 28px;
      border-radius: 18px;
      background: rgba(11, 23, 40, 0.92);
      border: 1px solid rgba(255,255,255,0.08);
      box-shadow: 0 18px 48px rgba(0, 0, 0, 0.35);
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .app-loading-spinner {
      width: 18px;
      height: 18px;
      border-radius: 50%;
      border: 2px solid rgba(0,242,254,0.2);
      border-top-color: #00f2fe;
      animation: app-spin 1s linear infinite;
    }

    @keyframes app-spin {
      to { transform: rotate(360deg); }
    }

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
  `, []);

  if (authStatus === "checking") {
    return (
      <>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" />
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=DM+Sans:wght@300;400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
        <style>{shellStyles}</style>
        <div className="app-loading-screen">
          <div className="app-loading-card">
            <div className="app-loading-spinner" />
            <div>Preparing VSAWA session…</div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" />
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" />
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=DM+Sans:wght@300;400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
      <style>{shellStyles}</style>

      <div className="app-shell">
        {showSidebar && <Sidebar />}
        <div className="right-panel">
          <Routes>
            <Route path="/" element={<AuthPage setIsLoggedIn={setIsLoggedIn} />} />
            <Route path="/auth" element={<AuthPage setIsLoggedIn={setIsLoggedIn} />} />
            <Route path="/dashboard" element={isLoggedIn ? <Dashboard /> : <Navigate to="/" replace />} />
            <Route path="/scan" element={isLoggedIn ? <ScanPage /> : <Navigate to="/" replace />} />
            <Route path="/reports" element={isLoggedIn ? <ReportsPage /> : <Navigate to="/" replace />} />
            <Route path="/vulnerability" element={isLoggedIn ? <VulnerabilityDB /> : <Navigate to="/" replace />} />
            <Route path="/profile" element={isLoggedIn ? <ProfilePage setIsLoggedIn={setIsLoggedIn} /> : <Navigate to="/" replace />} />
            <Route path="*" element={<Navigate to={isLoggedIn ? "/dashboard" : "/"} replace />} />
          </Routes>
        </div>
      </div>

      {showSidebar && <FloatingChatbot />}
    </>
  );
};

export default App;
