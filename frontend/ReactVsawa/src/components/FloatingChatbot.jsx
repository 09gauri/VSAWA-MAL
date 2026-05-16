import React, { useEffect, useRef, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

function FloatingChatbot() {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [chat, setChat] = useState([
    {
      sender: "bot",
      text: "VSAWA Shield active. How can I assist with your scan today?",
    },
  ]);

  const chatBodyRef = useRef(null);

  useEffect(() => {
    if (chatBodyRef.current) {
      chatBodyRef.current.scrollTop = chatBodyRef.current.scrollHeight;
    }
  }, [chat, open]);

  const sendMessage = async () => {
    if (!message.trim() || sending) return;

    const token = localStorage.getItem("token") || localStorage.getItem("access_token");
    const currentMsg = message.trim();

    const userMsg = { sender: "user", text: currentMsg };
    setChat((prev) => [...prev, userMsg]);
    setMessage("");
    setSending(true);

    try {
      if (!token) {
        setChat((prev) => [
          ...prev,
          {
            sender: "bot",
            text: "You need to be logged in before I can access your scan results.",
          },
        ]);
        return;
      }

      const res = await fetch(`${API_BASE}/api/chat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ message: currentMsg }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(
          data?.error ||
            (res.status === 401
              ? "Your session expired. Please log in again."
              : `HTTP ${res.status}`)
        );
      }

      setChat((prev) => [
        ...prev,
        {
          sender: "bot",
          text: data?.reply || "I could not generate a response right now.",
        },
      ]);
    } catch (err) {
      console.error("Chat request failed:", err);
      setChat((prev) => [
        ...prev,
        {
          sender: "bot",
          text: `Chat error: ${err?.message || "Unknown error"}`,
        },
      ]);
    } finally {
      setSending(false);
    }
  };

  return (
    <>
      <style>{`
        .chatbot-wrapper {
          position: fixed;
          bottom: 30px;
          right: 30px;
          z-index: 9999;
          font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        }

        .chat-toggle {
          width: 60px;
          height: 60px;
          background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
          border-radius: 14px;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
          box-shadow: 0 10px 20px rgba(0, 242, 254, 0.2);
        }

        .chat-toggle:hover {
          transform: scale(1.05) translateY(-5px);
          box-shadow: 0 0 20px rgba(0, 242, 254, 0.6), 0 0 40px rgba(79, 172, 254, 0.3);
        }

        .icon-msg {
          width: 22px;
          height: 18px;
          border: 2.5px solid #020617;
          border-radius: 4px;
          position: relative;
        }

        .icon-msg::after {
          content: '';
          position: absolute;
          bottom: -7px;
          left: 3px;
          border-left: 7px solid #020617;
          border-bottom: 7px solid transparent;
        }

        .chat-window {
          width: 370px;
          height: 520px;
          background: #0f172a;
          border-radius: 20px;
          margin-bottom: 15px;
          display: flex;
          flex-direction: column;
          overflow: hidden;
          border: 1px solid rgba(255, 255, 255, 0.1);
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
          animation: slideUp 0.3s ease-out;
        }

        @keyframes slideUp {
          from { opacity: 0; transform: translateY(30px); }
          to { opacity: 1; transform: translateY(0); }
        }

        .chat-header {
          background: linear-gradient(90deg, #1e293b, #0f172a);
          color: #00f2fe;
          padding: 16px 20px;
          font-weight: 700;
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
          font-size: 14.5px;
          letter-spacing: 0;
          text-transform: none;
        }

        .chat-body {
          flex: 1;
          padding: 20px;
          overflow-y: auto;
          background: #0f172a;
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .msg-container {
          padding: 12px 16px;
          font-size: 14.5px;
          line-height: 1.6;
          max-width: 85%;
          white-space: pre-wrap;
        }

        .user {
          align-self: flex-end;
          background: #00f2fe;
          color: #020617;
          border-radius: 15px 15px 2px 15px;
          font-weight: 500;
        }

        .bot {
          align-self: flex-start;
          background: rgba(255, 255, 255, 0.05);
          color: #e2e8f0;
          border-radius: 15px 15px 15px 2px;
          border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .typing {
          opacity: 0.8;
          font-style: italic;
        }

        .chat-footer {
          padding: 15px;
          background: #1e293b;
          display: flex;
          gap: 10px;
        }

        .chat-footer input {
          flex: 1;
          background: rgba(15, 23, 42, 0.8);
          border: 1px solid rgba(255, 255, 255, 0.1);
          padding: 10px 15px;
          border-radius: 8px;
          color: white;
          outline: none;
        }

        .chat-footer input:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .send-btn {
          background: #00f2fe;
          border: none;
          width: 40px;
          border-radius: 8px;
          cursor: pointer;
          color: #020617;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: background 0.2s;
        }

        .send-btn:hover {
          background: #4facfe;
        }

        .send-btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }
      `}</style>

      <div className="chatbot-wrapper">
        {open && (
          <div className="chat-window">
            <div className="chat-header">
              <span>VSAWA SHIELD AI</span>
              <span
                style={{ cursor: "pointer", fontSize: "18px" }}
                onClick={() => setOpen(false)}
              >
                ✕
              </span>
            </div>

            <div className="chat-body" ref={chatBodyRef}>
              {chat.map((msg, i) => (
                <div key={i} className={`msg-container ${msg.sender}`}>
                  {msg.text}
                </div>
              ))}

              {sending && (
                <div className="msg-container bot typing">Analyzing your scan data...</div>
              )}
            </div>

            <div className="chat-footer">
              <input
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Type your security query..."
                disabled={sending}
                onKeyDown={(e) => e.key === "Enter" && sendMessage()}
              />
              <button className="send-btn" onClick={sendMessage} disabled={sending}>
                <span style={{ transform: "rotate(-45deg)", display: "block", marginBottom: "2px" }}>
                  ➤
                </span>
              </button>
            </div>
          </div>
        )}

        <div className="chat-toggle" onClick={() => setOpen(!open)}>
          {open ? (
            <span style={{ color: "#020617", fontWeight: "bold", fontSize: "20px" }}>✕</span>
          ) : (
            <div className="icon-msg"></div>
          )}
        </div>
      </div>
    </>
  );
}

export default FloatingChatbot;
