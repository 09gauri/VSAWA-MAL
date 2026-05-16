import React, { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Bell, CheckCheck } from "lucide-react";
import { useNavigate } from "react-router-dom";
import "./NotificationBell.css";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000").replace(/\/$/, "");
const POLL_MS = 5000;
const PANEL_WIDTH = 380;

function getToken() {
  return localStorage.getItem("token") || localStorage.getItem("access_token");
}

function formatTime(iso) {
  if (!iso) return "Now";
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return iso;
  return dt.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function clampPanelLeft(left) {
  const gutter = 12;
  const maxLeft = Math.max(gutter, window.innerWidth - PANEL_WIDTH - gutter);
  return Math.min(Math.max(left, gutter), maxLeft);
}

export default function NotificationBell() {
  const navigate = useNavigate();
  const wrapRef = useRef(null);
  const panelRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [panelStyle, setPanelStyle] = useState({ top: 58, left: 12, width: PANEL_WIDTH });

  async function fetchNotifications() {
    const token = getToken();
    if (!token) {
      setItems([]);
      setUnreadCount(0);
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/notifications?limit=12`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`Notification fetch failed (${res.status})`);
      const data = await res.json();
      setItems(Array.isArray(data.items) ? data.items : []);
      setUnreadCount(Number(data.unread_count || 0));
    } catch {
      // Preserve the last successfully fetched items so transient backend issues
      // do not make the panel look empty.
    } finally {
      setLoading(false);
    }
  }

  function positionPanel() {
    const trigger = wrapRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const top = rect.bottom + 10;
    const left = clampPanelLeft(rect.right - PANEL_WIDTH);
    setPanelStyle({ top, left, width: PANEL_WIDTH });
  }

  useEffect(() => {
    fetchNotifications();
    const id = window.setInterval(fetchNotifications, POLL_MS);
    return () => window.clearInterval(id);
  }, []);

  useLayoutEffect(() => {
    if (!open) return;
    positionPanel();
    const handleViewportChange = () => positionPanel();
    window.addEventListener("resize", handleViewportChange);
    window.addEventListener("scroll", handleViewportChange, true);
    return () => {
      window.removeEventListener("resize", handleViewportChange);
      window.removeEventListener("scroll", handleViewportChange, true);
    };
  }, [open]);

  useEffect(() => {
    function onDocClick(e) {
      const insideTrigger = wrapRef.current?.contains(e.target);
      const insidePanel = panelRef.current?.contains(e.target);
      if (!insideTrigger && !insidePanel) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, []);

  async function markOneRead(notificationId) {
    const token = getToken();
    if (!token) return;
    const targetItem = items.find((item) => item.notification_id === notificationId);
    const wasUnread = targetItem && !Number(targetItem.is_read);
    try {
      await fetch(`${API_BASE}/api/notifications/${notificationId}/read`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      setItems((prev) => prev.map((item) => (
        item.notification_id === notificationId ? { ...item, is_read: 1 } : item
      )));
      if (wasUnread) {
        setUnreadCount((prev) => Math.max(0, prev - 1));
      }
    } catch {
      // ignore soft failure; next poll will re-sync
    }
  }

  async function markAllRead() {
    const token = getToken();
    if (!token || !unreadCount) return;
    try {
      await fetch(`${API_BASE}/api/notifications/read-all`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      setItems((prev) => prev.map((item) => ({ ...item, is_read: 1 })));
      setUnreadCount(0);
    } catch {
      // ignore soft failure
    }
  }

  async function openNotification(item) {
    if (!Number(item.is_read)) {
      await markOneRead(item.notification_id);
    }
    setOpen(false);
    navigate(item.action_url || "/reports");
  }

  const panel = open ? createPortal(
    <div className="notif-panel notif-panel-floating" ref={panelRef} style={panelStyle}>
      <div className="notif-panel-head">
        <div>
          <strong>Notifications</strong>
          <span>{unreadCount} unread</span>
        </div>
        <button type="button" onClick={markAllRead} disabled={!unreadCount}>
          <CheckCheck size={14} />
          Mark all read
        </button>
      </div>

      <div className="notif-list">
        {loading ? (
          <div className="notif-empty">Loading notifications…</div>
        ) : items.length === 0 ? (
          <div className="notif-empty">No notifications yet.</div>
        ) : (
          items.map((item) => (
            <button
              type="button"
              key={item.notification_id}
              className={`notif-item ${Number(item.is_read) ? "read" : "unread"}`}
              onClick={() => openNotification(item)}
            >
              <div className={`notif-dot level-${(item.level || "INFO").toLowerCase()}`}></div>
              <div className="notif-body">
                <div className="notif-title-row">
                  <strong>{item.title || item.event_type}</strong>
                  <span>{formatTime(item.sent_at)}</span>
                </div>
                <p>{item.message || "System event"}</p>
                {item.target_name && (
                  <small>{item.target_type || "Target"}: {item.target_name}</small>
                )}
              </div>
            </button>
          ))
        )}
      </div>
    </div>,
    document.body
  ) : null;

  return (
    <>
      <div className="notif-wrap" ref={wrapRef}>
        <button
          type="button"
          className={`notif-bell ${open ? "open" : ""}`}
          onClick={() => {
            if (!open) positionPanel();
            setOpen((v) => !v);
          }}
          title="Notifications"
          aria-label="Open notifications"
          aria-expanded={open}
        >
          <Bell size={17} strokeWidth={2.2} />
          {unreadCount > 0 && <span className="notif-count">{unreadCount > 9 ? "9+" : unreadCount}</span>}
        </button>
      </div>
      {panel}
    </>
  );
}
