import Icon from "../components/Icon";

export default function CaseHistory({ history }) {
  const closedCases = history || [];
  const analystsActive = new Set(closedCases.map(h => h.analyst).filter(Boolean)).size;

  return (
    <div>
      <section className="welcome" style={{ marginBottom: 28 }}>
        <div>
          <p className="eyebrow">CASE HISTORY</p>
          <h1>Resolved investigations</h1>
          <p className="lede">{closedCases.length} cases closed · Active forensic log</p>
        </div>
      </section>
      <div className="ti-grid">
        <div className="ti-stat-card"><span className="metric-icon coral" style={{ width: 32, height: 32 }}><Icon name="shield" size={16} /></span><div><small>TOTAL CLOSED</small><strong>{closedCases.length}</strong></div></div>
        <div className="ti-stat-card"><span className="metric-icon amber" style={{ width: 32, height: 32 }}><Icon name="alert" size={16} /></span><div><small>CRITICAL RESOLVED</small><strong>{closedCases.filter(h => h.label === "CRITICAL").length}</strong></div></div>
        <div className="ti-stat-card"><span className="metric-icon mint" style={{ width: 32, height: 32 }}><Icon name="check" size={16} /></span><div><small>AVG SCORE</small><strong>{closedCases.length > 0 ? Math.round(closedCases.reduce((a, h) => a + h.score, 0) / closedCases.length) : 0}</strong></div></div>
        <div className="ti-stat-card"><span className="metric-icon blue" style={{ width: 32, height: 32 }}><Icon name="clock" size={16} /></span><div><small>ANALYSTS ACTIVE</small><strong>{analystsActive || "—"}</strong></div></div>
      </div>
      <div className="ti-section-label">CLOSED CASES</div>
      <div className="queue-table">
        <div className="queue-head" style={{ gridTemplateColumns: "90px 1fr 1fr 80px 1fr 50px" }}>
          <span>CASE ID</span><span>SENDER</span><span>SUBJECT</span><span>SCORE</span><span>RESOLUTION</span><span>BY</span>
        </div>
        {closedCases.length === 0 && (
          <p style={{ padding: "20px", color: "var(--muted)", fontSize: 13 }}>No resolved cases yet — resolve a case from the overview to record it here.</p>
        )}
        {closedCases.map(h => (
          <div key={h.id} className="queue-row" style={{ gridTemplateColumns: "90px 1fr 1fr 80px 1fr 50px" }}>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 10 }}>{h.id}<br /><span style={{ color: "var(--muted)" }}>{h.closed}</span></span>
            <span style={{ fontSize: 11 }}>{h.sender || "—"}</span>
            <span style={{ fontSize: 11, color: "var(--muted)" }}>{h.subject || "—"}</span>
            <span className={`queue-score ${h.accent}`}>{h.score ?? "—"}</span>
            <span style={{ fontSize: 11 }}>{h.resolution}</span>
            <span className="workspace-avatar" style={{ width: 24, height: 24, fontSize: 9, borderRadius: "50%" }}>{h.analyst || "AS"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
