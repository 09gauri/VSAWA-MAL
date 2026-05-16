import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import NotificationBell from './NotificationBell.jsx';

const API_BASE =
  (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000').replace(/\/$/, '');

const POLL_INTERVAL_MS = 5000;

const Sidebar = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const [metrics, setMetrics] = useState({
    scans_today: 0,
    total_vulns: 0,
  });
  const [isOnline, setIsOnline] = useState(true);

  const fetchMetrics = useCallback(async (signal) => {
    const token = localStorage.getItem('token') || localStorage.getItem('access_token');
    if (!token) {
      setMetrics({ scans_today: 0, total_vulns: 0 });
      setIsOnline(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/api/dashboard/stats`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
        signal,
      });

      if (!response.ok) {
        throw new Error(`Sidebar metrics request failed (${response.status})`);
      }

      const data = await response.json();
      setMetrics({
        scans_today: data.scans_today || 0,
        total_vulns: data.total_vulns || 0,
      });
      setIsOnline(true);
    } catch (err) {
      if (err.name === 'AbortError') return;
      setIsOnline(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetchMetrics(controller.signal);

    const intervalId = window.setInterval(() => {
      fetchMetrics();
    }, POLL_INTERVAL_MS);

    return () => {
      controller.abort();
      window.clearInterval(intervalId);
    };
  }, [fetchMetrics, location.pathname]);

  const isActive = (id) => {
    if ((id === 'dashboard' || id === '/dashboard') && (location.pathname === '/' || location.pathname === '/dashboard')) {
      return true;
    }
    return location.pathname.includes(id);
  };

  const menuItems = [
    { id: 'dashboard', icon: 'fas fa-chart-line', label: 'Dashboard', path: '/dashboard' },
    { id: 'scan', icon: 'fas fa-search', label: 'New Scan', path: '/scan' },
    { id: 'reports', icon: 'fas fa-file-alt', label: 'Reports', path: '/reports' },
    { id: 'vulnerability', icon: 'fas fa-database', label: 'Vulnerability DB', path: '/vulnerability' },
  ];

  const profileInitial = useMemo(() => {
    try {
      const raw = localStorage.getItem('user');
      if (!raw) return 'U';
      const user = JSON.parse(raw);
      const first = (user?.name || user?.email || 'U').trim().charAt(0).toUpperCase();
      return first || 'U';
    } catch {
      return 'U';
    }
  }, []);

  return (
    <div
      className="sidebar"
      style={{
        position: 'sticky',
        top: 0,
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        background: '#050a17',
      }}
    >
      <div className="sidebar-header">
        <i className="fas fa-shield-halved" style={{ fontSize: '24px' }}></i>

        <span
          style={{
            fontSize: '22px',
            fontWeight: '900',
            letterSpacing: '.5px',
            color: '#ffffff',
            textTransform: 'uppercase',
            textShadow: '0 0 10px rgba(0, 242, 254, 0.3)',
          }}
        >
          VSAWA
        </span>
        <span
          style={{
            marginLeft: 'auto',
            fontSize: '10px',
            background: 'rgba(0,242,254,0.12)',
            color: '#00f2fe',
            padding: '2px 8px',
            borderRadius: '4px',
            fontWeight: '600',
            letterSpacing: '0.5px',
            border: '1px solid rgba(0,242,254,0.2)',
          }}
        >
          PRO
        </span>
        <NotificationBell />
      </div>

      <div className="menu-section">
        <p
          style={{
            fontSize: '10px',
            fontWeight: '700',
            color: 'rgba(255,255,255,0.25)',
            letterSpacing: '1.5px',
            textTransform: 'uppercase',
            padding: '8px 8px 12px',
            margin: 0,
          }}
        >
          Navigation
        </p>

        {menuItems.map((item) => (
          <div
            key={item.id}
            className={`menu-item ${isActive(item.id) ? 'active' : ''}`}
            onClick={() => navigate(item.path)}
          >
            <i className={item.icon}></i>
            <span>{item.label}</span>
            {isActive(item.id) && (
              <span
                style={{
                  marginLeft: 'auto',
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  background: '#00f2fe',
                  boxShadow: '0 0 8px #00f2fe',
                }}
              />
            )}
          </div>
        ))}
      </div>

      <div className="metrics-section">
        <h4>Security Metrics</h4>

        <div className="metric-row">
          <div style={{ display: 'flex', alignItems: 'center', gap: '9px' }}>
            <span
              style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                background: isOnline ? '#10b981' : '#ef4444',
                boxShadow: isOnline ? '0 0 6px #10b981' : '0 0 6px #ef4444',
                flexShrink: 0,
              }}
            ></span>
            <span style={{ color: '#94a3b8', fontSize: '13px' }}>System Status</span>
          </div>
          <span
            style={{
              color: isOnline ? '#0ea5e9' : '#f87171',
              fontWeight: '600',
              fontSize: '12px',
            }}
          >
            {isOnline ? 'Online' : 'Offline'}
          </span>
        </div>

        <div className="metric-row">
          <div style={{ display: 'flex', alignItems: 'center', gap: '9px' }}>
            <i className="fas fa-search" style={{ color: '#8b5cf6', fontSize: '11px', width: '7px' }}></i>
            <span style={{ color: '#94a3b8', fontSize: '13px', marginLeft: '2px' }}>Scans Today</span>
          </div>
          <span style={{ color: '#e2e8f0', fontWeight: '600', fontSize: '13px' }}>{metrics.scans_today}</span>
        </div>

        <div className="metric-row">
          <div style={{ display: 'flex', alignItems: 'center', gap: '9px' }}>
            <i className="fas fa-bug" style={{ color: '#ef4444', fontSize: '11px', width: '7px' }}></i>
            <span style={{ color: '#94a3b8', fontSize: '13px', marginLeft: '2px' }}>Vulns Found</span>
          </div>
          <span style={{ color: '#e2e8f0', fontWeight: '600', fontSize: '13px' }}>{metrics.total_vulns}</span>
        </div>
      </div>

      <div className="profile-section">
        <div
          className={`menu-item ${location.pathname === '/profile' ? 'active' : ''}`}
          onClick={() => navigate('/profile')}
        >
          <div
            style={{
              width: '26px',
              height: '26px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '11px',
              fontWeight: '700',
              color: 'white',
              flexShrink: 0,
            }}
          >
            {profileInitial}
          </div>
          <span>Profile</span>
          <i className="fas fa-chevron-right" style={{ marginLeft: 'auto', fontSize: '10px', opacity: 0.4 }}></i>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
