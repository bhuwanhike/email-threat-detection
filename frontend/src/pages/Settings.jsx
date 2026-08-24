import { useEffect, useState } from "react";
import Icon from "../components/Icon";
import { dash } from "../App";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

export default function Settings({ setNotice }) {
  const [config, setConfig] = useState(null);
  const [retentionDays, setRetentionDays] = useState(90);
  const [maskPii, setMaskPii] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API}/privacy-config`)
      .then(res => {
        if (!res.ok) throw new Error("failed");
        return res.json();
      })
      .then(data => {
        setConfig(data);
        if (typeof data.retention_days === "number") setRetentionDays(data.retention_days);
        if (typeof data.mask_pii === "boolean") setMaskPii(data.mask_pii);
      })
      .catch(() => setError("Could not load settings. Is the backend running on port 8000?"));
  }, []);

  async function save(e) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      const res = await fetch(`${API}/privacy-config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          retention_days: parseInt(retentionDays) || 90,
          mask_pii: maskPii,
        }),
      });
      if (!res.ok) throw new Error("save failed");
      const data = await res.json();
      setConfig(data.config);
      setNotice("Settings saved.");
    } catch {
      setError("Failed to save settings — backend unreachable.");
    }
    setSaving(false);
  }

  return (
    <div>
      <section className="welcome" style={{ marginBottom: 28 }}>
        <div>
          <p className="eyebrow">SYSTEM</p>
          <h1>Settings</h1>
          <p className="lede">Privacy and data-governance controls applied to every analysis.</p>
        </div>
      </section>

      {error && (
        <p style={{ padding: "14px", color: "var(--coral)", fontSize: 13, border: "1px dashed var(--coral)", borderRadius: 8, marginBottom: 16 }}>
          {error}
        </p>
      )}

      {!config && !error && (
        <p style={{ color: "var(--muted)", fontSize: 13 }}>Loading settings…</p>
      )}

      {config && (
        <form onSubmit={save} style={{ maxWidth: 560, display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="sr-card" style={{ padding: 16 }}>
            <p className="ti-section-label"><Icon name="eye" size={12} /> PII MASKING</p>
            <label style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, cursor: "pointer" }}>
              <span style={{ fontSize: 12, color: "var(--ink)" }}>
                Mask emails, phone numbers, card numbers, SSN/Aadhaar/PAN in stored bodies and previews
                <small style={{ display: "block", color: "var(--muted)", marginTop: 2 }}>
                  Currently: {maskPii ? "enabled (GDPR/DPDP)" : "disabled"}
                </small>
              </span>
              <input type="checkbox" checked={maskPii} onChange={e => setMaskPii(e.target.checked)} style={{ width: 18, height: 18, accentColor: "#56a987" }} />
            </label>
          </div>

          <div className="sr-card" style={{ padding: 16 }}>
            <p className="ti-section-label"><Icon name="clock" size={12} /> DATA RETENTION</p>
            <label style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              <span style={{ fontSize: 12, color: "var(--ink)" }}>
                Retain analyzed cases for (days)
                <small style={{ display: "block", color: "var(--muted)", marginTop: 2 }}>
                  Current value: {dash(config.retention_days)} days
                </small>
              </span>
              <input
                type="number"
                min={1}
                max={3650}
                value={retentionDays}
                onChange={e => setRetentionDays(e.target.value)}
                style={{ width: 90, padding: "8px 10px", background: "var(--surface)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--ink)", fontFamily: "'Space Mono',monospace" }}
              />
            </label>
          </div>

          <div className="sr-card" style={{ padding: 16 }}>
            <p className="ti-section-label"><Icon name="shield" size={12} /> EVIDENCE HASH ALGORITHM</p>
            <span style={{ fontSize: 12, color: "var(--muted)", fontFamily: "'Space Mono',monospace" }}>{dash(config.evidence_hash_algo)}</span>
          </div>

          <div className="modal-actions">
            <button className="scan-button" type="submit" disabled={saving}>
              <Icon name="check" size={15} /> {saving ? "Saving..." : "Save changes"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
