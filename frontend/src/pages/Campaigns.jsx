import { useEffect, useState } from "react";
import Icon from "../components/Icon";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

export default function Campaigns({ campaigns: propCampaigns }) {
  const [data, setData] = useState(propCampaigns || null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (propCampaigns) {
      setData(propCampaigns);
      return;
    }
    fetch(`${API}/campaigns`)
      .then(r => r.json())
      .then(d => setData(d))
      .catch(() => setData([]));
  }, [propCampaigns]);

  const list = data || [];

  const openCase = caseId => {
    setSelected(caseId);
    const ev = new CustomEvent("navigate-case", { detail: caseId });
    window.dispatchEvent(ev);
  };

  return (
    <div>
      <section className="welcome" style={{ marginBottom: 28 }}>
        <div>
          <p className="eyebrow">CAMPAIGN ANALYSIS</p>
          <h1>Threat Campaign Clusters</h1>
          <p className="lede">
            Grouped emails with shared IOCs, TTPs, or sender infrastructure. {list.length} active campaign clusters tracked.
          </p>
        </div>
      </section>

      <div className="ti-grid">
        <div className="ti-stat-card">
          <span className="metric-icon coral" style={{ width: 32, height: 32 }}>
            <Icon name="radar" size={16} />
          </span>
          <div>
            <small>ACTIVE CAMPAIGNS</small>
            <strong>{list.length}</strong>
          </div>
        </div>
        <div className="ti-stat-card">
          <span className="metric-icon amber" style={{ width: 32, height: 32 }}>
            <Icon name="zap" size={16} />
          </span>
          <div>
            <small>CRITICAL / HIGH</small>
            <strong>{list.filter(c => c.accent === "red" || c.accent === "orange").length}</strong>
          </div>
        </div>
        <div className="ti-stat-card">
          <span className="metric-icon blue" style={{ width: 32, height: 32 }}>
            <Icon name="inbox" size={16} />
          </span>
          <div>
            <small>TOTAL EMAILS</small>
            <strong>{list.reduce((a, c) => a + (c.count || 0), 0)}</strong>
          </div>
        </div>
        <div className="ti-stat-card">
          <span className="metric-icon mint" style={{ width: 32, height: 32 }}>
            <Icon name="map" size={16} />
          </span>
          <div>
            <small>UNIQUE IOCS</small>
            <strong>{Array.from(new Set(list.flatMap(c => c.iocs || []))).length}</strong>
          </div>
        </div>
      </div>

      <div className="ti-section-label" style={{ marginTop: 28 }}>
        CAMPAIGN CLUSTERS · Grouped by shared infrastructure / TTPs
      </div>

      {list.length === 0 && (
        <p style={{ padding: "20px", color: "var(--muted)", fontSize: 13, border: "1px dashed var(--line)", borderRadius: 8 }}>
          No campaigns detected yet — clusters form automatically when analyzed emails share infrastructure or TTPs.
        </p>
      )}

      <div style={{ display: "grid", gap: 14, gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))" }}>
        {list.map(c => (
          <div key={c.id} className="sr-card" style={{ borderLeft: `4px solid var(--${c.accent})`, cursor: "pointer" }} onClick={() => setSelected(selected === c.id ? null : c.id)}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
              <div>
                <span className="ioc-type-badge" style={{ marginRight: 6 }}>{c.id.split("-")[1]}</span>
                <span className={`severity ${c.accent}`}>{c.risk}</span>
                <p style={{ fontSize: 12, fontWeight: 700, marginTop: 6, color: "var(--ink)" }}>{c.name}</p>
              </div>
              <div style={{ textAlign: "right" }}>
                <small style={{ color: "var(--muted)" }}>Emails</small>
                <b style={{ display: "block", fontFamily: "'Space Mono',monospace", fontSize: 15 }}>{c.count}</b>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--muted)", marginBottom: 10 }}>
              <span>First seen: {c.first_seen}</span>
              <span>Avg score: <b style={{ color: c.avg_risk_score > 70 ? "var(--coral)" : "var(--ink)" }}>{Math.round(c.avg_risk_score || 0)}</b></span>
            </div>

            {c.ttps?.length > 0 && (
              <div style={{ marginBottom: 8 }}>
                <small style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.5 }}>TTPs</small>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 4 }}>
                  {c.ttps.map(t => <span key={t} className="hi-ttp-id" style={{ fontSize: 9 }}>{t}</span>)}
                </div>
              </div>
            )}

            {c.iocs?.length > 0 && (
              <div style={{ marginBottom: 8 }}>
                <small style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.5 }}>Shared IOCs ({c.iocs.length})</small>
                <div style={{ marginTop: 4, maxHeight: selected === c.id ? 200 : 42, overflow: "hidden", transition: "max-height 0.2s" }}>
                  {c.iocs.map(i => (
                    <div key={i} style={{ fontFamily: "'Space Mono',monospace", fontSize: 10, color: "var(--ink)", padding: "2px 0" }}>
                      {i}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selected === c.id && c.related_case_ids?.length > 0 && (
              <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--line)" }}>
                <small style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.5 }}>Related Cases</small>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
                  {c.related_case_ids.map(cid => (
                    <button
                      key={cid}
                      onClick={e => { e.stopPropagation(); openCase(cid); }}
                      style={{
                        fontFamily: "'Space Mono',monospace",
                        fontSize: 11,
                        padding: "4px 8px",
                        background: "var(--line)",
                        color: "var(--ink)",
                        border: "none",
                        borderRadius: 4,
                        cursor: "pointer",
                        fontWeight: 700,
                      }}
                    >
                      {cid}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <small style={{ fontSize: 10, color: "var(--muted)", marginTop: 6, display: "block" }}>
              Click to {selected === c.id ? "collapse" : "expand"} · Last seen: {c.last_seen}
            </small>
          </div>
        ))}
      </div>
    </div>
  );
}
