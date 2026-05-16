import React, { useEffect, useState } from "react";
import { Shield, Globe, Server, Zap, AlertCircle, ChevronRight } from "lucide-react";
import { useNavigate } from "react-router-dom"; // Added for routing
import "./AuthPage.css";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000").replace(/\/$/, "");

const AuthPage = ({ setIsLoggedIn }) => {
  const navigate = useNavigate(); // Initialize navigation
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function restoreSession() {
      const token = localStorage.getItem("token") || localStorage.getItem("access_token");
      if (!token) return;
      try {
        const res = await fetch(`${API_BASE}/api/auth/me`, {
          method: "GET",
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error("Session expired");
        setIsLoggedIn(true);
      } catch {
        localStorage.removeItem("token");
        localStorage.removeItem("access_token");
        localStorage.removeItem("user");
        setIsLoggedIn(false);
      }
    }
    restoreSession();
  }, [setIsLoggedIn]);

  const handleTabChange = (signUpMode) => {
    setIsSignUp(signUpMode);
    setError("");
    setPassword(""); 
    setConfirmPassword("");
  };

  const handleAuth = async (e) => {
    e.preventDefault();
    setError("");
    
    if (isSignUp) {
      if (!name.trim()) { setError("Name is required"); return; }
      if (password !== confirmPassword) { setError("Passwords do not match"); return; }
    }
    if (password.length < 12) { setError("Password must be 12+ chars"); return; }

    setLoading(true);
    try {
      const endpoint = isSignUp ? "/api/auth/signup" : "/api/auth/login";
      const payload = isSignUp 
        ? { name, email, password } 
        : { email, password };

      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Action failed");

      if (isSignUp) {
        setIsSignUp(false); 
        setPassword("");    
        setConfirmPassword("");
        setError("Account created! Now enter your password to sign in.");
      } else {
        localStorage.setItem("token", data.access_token);
        localStorage.setItem("user", JSON.stringify(data.user || { email }));
        setIsLoggedIn(true);
        navigate("/dashboard"); // Route user to dashboard on login
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const features = [
    { icon: Globe, label: "Web Scanning" },
    { icon: Server, label: "Server Analysis" },
    { icon: Zap, label: "APK Files" },
    { icon: AlertCircle, label: "Compliance" },
  ];

  return (
    <div className="auth-root">
      <div className="auth-orb-1" />
      <div className="auth-orb-2" />

      <div className="auth-wrap">
        <nav className="auth-nav">
          <Shield size={32} color="#00f2fe" strokeWidth={2.5} />
          <span className="auth-nav-brand">VSAWA</span>
          <span className="auth-nav-badge">ENTERPRISE</span>
        </nav>

        <main className="auth-main">
          <div className="auth-hero">
            <div className="auth-hero-eyebrow">
              <span />
              Enterprise-Grade Security
            </div>
            <h1>
              Vulnerability scans,<br />
              <em>without the hassle.</em>
            </h1>
            <p>
              Enterprise-grade security scanning for modern web applications. 
              Detect OWASP Top 10 vulnerabilities before attackers do.
            </p>
            <div className="auth-features">
              {features.map(({ icon: Icon, label }) => (
                <div className="auth-feature-item" key={label}>
                  <div className="auth-feature-icon">
                    <Icon size={16} color="#00f2fe" />
                  </div>
                  <span>{label}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="auth-card">
            <div className="auth-tabs">
              <button
                type="button"
                className={`auth-tab ${!isSignUp ? "active" : ""}`}
                onClick={() => handleTabChange(false)}
              >
                Sign In
              </button>
              <button
                type="button"
                className={`auth-tab ${isSignUp ? "active" : ""}`}
                onClick={() => handleTabChange(true)}
              >
                Sign Up
              </button>
            </div>

            <h3 className="auth-card-title">
              {isSignUp ? "Create Account" : "Welcome Back"}
            </h3>
            <p className="auth-card-sub">
              {isSignUp ? "Start securing your applications today." : "Access the vulnerability dashboard."}
            </p>

            {error && <div className="auth-error">{error}</div>}

            <form onSubmit={handleAuth} autoComplete="off">
              {isSignUp && (
                <div className="auth-field">
                  <label>Full Name</label>
                  <input
                    type="text"
                    name="fullname"
                    placeholder="Harry Potter"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    autoComplete="off"
                  />
                </div>
              )}

              <div className="auth-field">
                <label>Email Address</label>
                <input
                  type="email"
                  name="email"
                  placeholder="email@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email" 
                />
              </div>

              <div className="auth-field">
                <label>Password</label>
                <input
                  type="password"
                  name="password"
                  autoComplete="new-password"
                  placeholder="Min. 12 characters"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>

              {isSignUp && (
                <div className="auth-field">
                  <label>Confirm Password</label>
                  <input
                    type="password"
                    name="confirm-password"
                    autoComplete="new-password"
                    placeholder="Repeat password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                  />
                </div>
              )}

              <button type="submit" className="auth-submit" disabled={loading}>
                {loading ? "Processing..." : isSignUp ? "Get Started" : "Sign In"}
                <ChevronRight size={16} />
              </button>
            </form>
          </div>
        </main>
      </div>

      <footer className="auth-footer">
        <div className="auth-footer-inner">
          <p className="auth-footer-copy">© 2026 VulnScan Security, Inc.</p>
          <a href="/" className="auth-footer-brand">
            <Shield size={22} color="#00f2fe" />
            VSAWA
          </a>
          <a href="mailto:gauriupadhyay090605@gmail.com" className="auth-footer-link">
            Contact - gauriupadhyay090605@gmail.com
          </a>
        </div>
      </footer>
    </div>
  );
};

export default AuthPage;