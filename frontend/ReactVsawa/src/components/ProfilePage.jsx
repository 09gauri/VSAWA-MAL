import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "./ProfilePage.css";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000").replace(/\/$/, "");

// Helper to make the date look professional
function formatJoinedDate(isoString) {
  if (!isoString) return "—";
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return isoString;
  return d.toLocaleDateString(undefined, { 
    month: "short", 
    day: "2-digit", 
    year: "numeric" 
  });
}



const ProfilePage = ({ setIsLoggedIn }) => {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("info");

  useEffect(() => {
    const controller = new AbortController();

    async function loadMe() {
      setLoading(true);
      setError("");
      const token = localStorage.getItem("token");

      // Safety check: if no token, flip state and let App.jsx redirect
      if (!token) {
        setLoading(false);
        if (setIsLoggedIn) setIsLoggedIn(false);
        return;
      }

      try {
        const res = await fetch(`${API_BASE}/api/auth/me`, {
          method: "GET",
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });

        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
          // If token is invalid or expired
          if (res.status === 401 || res.status === 422) {
            localStorage.removeItem("token");
            if (setIsLoggedIn) setIsLoggedIn(false);
            return;
          }
          throw new Error(data.error || `Failed to load profile`);
        }

        setUser({
          name: data.name,
          email: data.email,
          joinedDate: formatJoinedDate(data.created_at),
          status: data.status || "ACTIVE"
        });
      } catch (e) {
        if (e.name !== "AbortError") {
          setError(e.message || "Connection error.");
        }
      } finally {
        setLoading(false);
      }
    }

    loadMe();
    return () => controller.abort();
  }, [setIsLoggedIn]);

  // --- THE LOGOUT HANDLER ---
  const handleLogout = () => {
  // 1. Clear the token
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  
  // 2. Update the state so Sidebar disappears
  setIsLoggedIn(false); 
  
  // 3. Force the URL to /auth
  navigate("/auth"); 
};

  // Logic for UI display
  const displayName = loading ? "Loading..." : (user?.name || "Admin User");
  const displayEmail = loading ? "Loading..." : (user?.email || "—");
  const displayJoined = loading ? "Loading..." : (user?.joinedDate || "—");
  const status = loading ? "LOADING" : (user?.status || "—");
  
  // Create initials for avatar (e.g., "John Doe" -> "JD")
  const initials = !loading && user?.name 
    ? user.name.split(" ").map(n => n[0]).join("").slice(0, 2).toUpperCase()
    : "U";

  const tabs = [
    { id: "info", label: "Profile Info", icon: "👤" },
    { id: "password", label: "Security", icon: "🔒" },
    { id: "danger", label: "Danger Zone", icon: "⚠️" },
  ];

  return (
    <div className="profile-page">
      {/* HEADER SECTION */}
      <div className="profile-header-section">
        <div className="profile-avatar">
          {loading ? "..." : initials}
        </div>
        <div className="profile-header-text">
          <h3>Account Settings</h3>
          <p>Manage your enterprise security profile and credentials</p>
        </div>
      </div>

      {/* NAVIGATION TABS */}
      <div className="profile-tabs">
        {tabs.map(({ id, label, icon }) => (
          <div
            key={id}
            className={`profile-tab ${id === "danger" ? "danger-tab" : ""} ${activeTab === id ? "active" : ""}`}
            onClick={() => setActiveTab(id)}
          >
            <span>{icon}</span>
            {label}
          </div>
        ))}
      </div>

      <div className="profile-content">
        {error && <div className="error-banner">{error}</div>}

        {/* TAB 1: INFORMATION */}
        {activeTab === "info" && (
          <div className="fade-in">
            <div className="section-title">General Information</div>
            <div className="info-bar">
              <div className="info-label">Full Name</div>
              <div className="info-value">{displayName}</div>
            </div>
            <div className="info-bar">
              <div className="info-label">Email Address</div>
              <div className="info-value">{displayEmail}</div>
            </div>
            <div className="info-bar">
              <div className="info-label">Member Since</div>
              <div className="info-value">{displayJoined}</div>
            </div>
            <div className="info-bar">
              <div className="info-label">System Status</div>
              <div className={`info-value status-active`}>{status}</div>
            </div>
            
            <div style={{ marginTop: "32px" }}>
              <button 
                className="btn btn-primary" 
                onClick={handleLogout}
                
              >
                Sign Out
              </button>
            </div>
          </div>
        )}

        {/* TAB 2: PASSWORD */}
{activeTab === "password" && (
  <div className="fade-in">
    <div className="section-title">Update Security Credentials</div>
    
    <div className="info-bar">
      <div className="info-label">Current Password</div>
      <input 
        type="password" 
        className="input-field" 
        placeholder="••••••••••••" 
      />
    </div>

    <div className="info-bar">
      <div className="info-label">New Password</div>
      <input 
        type="password" 
        className="input-field" 
        placeholder="Enter new password" 
      />
    </div>

    {/* NEW: Confirm Password Field */}
    <div className="info-bar">
      <div className="info-label">Confirm New Password</div>
      <input 
        type="password" 
        className="input-field" 
        placeholder="Repeat new password" 
      />
    </div>

    <div style={{ marginTop: "24px" }}>
      <button className="btn btn-primary">
        Update Password
      </button>
      <p style={{ fontSize: '12px', color: '#64748b', marginTop: '10px' }}>
        Ensure your password is at least 8 characters long with numbers and symbols.
      </p>
    </div>
  </div>
)}

        {/* TAB 3: DANGER */}
        {activeTab === "danger" && (
          <div className="fade-in">
            <div className="section-title">Danger Zone</div>
            <div className="info-bar" style={{ borderColor: "rgba(239, 68, 68, 0.2)" }}>
              <div className="info-label" style={{ color: "#ef4444" }}>Delete Account</div>
              <div className="info-value" style={{ fontSize: "13px", color: "#64748b", flex: 1, marginRight: "20px" }}>
                Permanently remove your account and all history.
              </div>
              <button className="btn btn-danger">Delete Now</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProfilePage;