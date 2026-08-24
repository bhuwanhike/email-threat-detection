import { useState } from "react";
import Icon from "../components/Icon";
import { dash } from "../App";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const ACCENT = {
  coral: { bg: "#fcedea", fg: "#c85344" },
  amber: { bg: "#faf0dd", fg: "#a8762a" },
  mint:  { bg: "#e5f3ec", fg: "#3d8266" },
  blue:  { bg: "#e8eff4", fg: "#4a7186" },
};

export default function Workspaces({ workspaces, activeWs, onOpen, onReset, onChanged }) {
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function addWorkspace(e) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError("");
    try {
      const res = await fetch(`${API}/workspaces`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description: desc }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || "Could not create threat domain");
      setName("");
      setDesc("");
      await onChanged();
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  }

  async function removeWorkspace(ws) {
    setError("");
    try {
      const res = await fetch(`${API}/workspaces/${ws.id}`, { method: "DELETE" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || "Could not remove this domain");
      await onChanged();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div>
      <section className="welcome">
        <div>
          <p className="eyebrow"><span className="pulse" /> THREAT INTELLIGENCE HUB</p>
          <h1>Threat Domains</h1>
          <p className="lede">
            Every analyzed email is automatically classified into a shared threat domain.
            Open the domain matching your work environment — cases, metrics and indicators
            are filtered to it across the whole platform.
          </p>
        </div>
      </section>

      {error && (
        <p className="scan-error" style={{ marginBottom: 16 }}>
          <Icon name="alert" size={13} /> {error}
        </p>
      )}

      <button
        className={`filter-tab ${!activeWs ? "active" : ""}`}
        onClick={onReset}
        style={{ marginBottom: 18 }}
      >
        <Icon name="globe" size={12} /> All domains (global view)
      </button>

      <div className="ti-grid" style={{ gridTemplateColumns: "repeat(auto-fill,minmax(280px,1fr))", gap: 14 }}>
        {workspaces.map(ws => {
          const acc = ACCENT[ws.accent] || ACCENT.blue;
          const active = activeWs === ws.slug;
          return (
            <div key={ws.id} className="metric" style={{
              minHeight: 0, flexDirection: "column", alignItems: "stretch", gap: 11,
              borderColor: active ? "var(--coral)" : "var(--line)",
              boxShadow: active ? "0 8px 24px rgba(233,104,86,.15)" : "var(--shadow)",
            }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: 11 }}>
                <span style={{
                  width: 36, height: 36, borderRadius: 9, background: acc.bg, color: acc.fg,
                  display: "grid", placeItems: "center", flex: "0 0 auto",
                }}>
                  <Icon name={ws.icon} size={17} />
                </span>
                <div style={{ minWidth: 0 }}>
                  <b style={{ fontSize: 14.5, display: "block", letterSpacing: "-.2px" }}>{ws.name}</b>
                  <small style={{
                    fontFamily: "'Space Mono',monospace", fontSize: 8.5, letterSpacing: ".8px",
                    color: "var(--muted)", textTransform: "uppercase",
                  }}>
                    {ws.is_custom ? "Community contributed" : "Core domain"}
                  </small>
                </div>
                {active && (
                  <span className="ioc-type-badge" style={{ background: "#eaf6f0", color: "#34745b", marginLeft: "auto" }}>● OPEN</span>
                )}
              </div>

              <p style={{ fontSize: 11.5, color: "var(--muted)", margin: 0, lineHeight: 1.55, minHeight: 32 }}>
                {dash(ws.description)}
              </p>

              <div style={{ display: "flex", gap: 14, fontFamily: "'Space Mono',monospace", fontSize: 9.5, color: "var(--muted)", letterSpacing: ".5px" }}>
                <span><b style={{ color: ws.open_cases ? "#c85344" : "var(--ink)", fontSize: 12 }}>{ws.open_cases}</b> OPEN</span>
                <span><b style={{ color: "var(--ink)", fontSize: 12 }}>{ws.total_cases}</b> ANALYZED</span>
                <span><b style={{ color: "var(--ink)", fontSize: 12 }}>{ws.threats}</b> HIGH-RISK</span>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {!active && (
                  <button className="location-button" onClick={() => onOpen(ws)}>
                    Open workspace <Icon name="chevron" size={12} />
                  </button>
                )}
                <span style={{ marginLeft: "auto" }} />
                {ws.is_custom && !ws.total_cases && (
                  <button title="Remove community domain" onClick={() => removeWorkspace(ws)}
                    style={{ background: "none", border: "1px solid var(--line)", borderRadius: 5, color: "#c85344", padding: "6px 9px", fontSize: 11, fontWeight: 700, cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 5 }}>
                    <Icon name="x" size={11} /> Remove
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <section style={{ marginTop: 34 }}>
        <p className="ti-section-label">CONTRIBUTE A NEW THREAT DOMAIN</p>
        <form onSubmit={addWorkspace} className="queue-toolbar">
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="Domain name — e.g. QR-code Phishing"
            maxLength={60}
            style={{ flex: "1 1 240px", maxWidth: 300, background: "var(--surface)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--ink)", padding: "10px 12px", fontSize: 13, outline: "none" }}
          />
          <input
            value={desc}
            onChange={e => setDesc(e.target.value)}
            placeholder="Short description for the community…"
            maxLength={200}
            style={{ flex: "2 1 320px", background: "var(--surface)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--ink)", padding: "10px 12px", fontSize: 13, outline: "none" }}
          />
          <button className="scan-button" type="submit" disabled={busy || !name.trim()}>
            <Icon name="zap" size={14} /> {busy ? "Adding…" : "Add domain"}
          </button>
        </form>
        <p className="lede" style={{ marginTop: -8, fontSize: 11.5 }}>
          Core domains are shared by everyone; community domains can be removed while empty.
        </p>
      </section>
    </div>
  );
}
