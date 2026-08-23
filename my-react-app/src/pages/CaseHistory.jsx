import Icon from "../components/Icon";

const history = [
  { id: "INC-2455", sender: "payroll@fake-hr-portal.com", subject: "Payroll update required", closed: "22 Aug 2026", score: 91, label: "CRITICAL", accent: "red", resolution: "Blocked · Reported to IT", analyst: "AS" },
  { id: "INC-2441", sender: "cfo@acme-corp-finance.net", subject: "Wire transfer authorization", closed: "21 Aug 2026", score: 87, label: "CRITICAL", accent: "red", resolution: "Blocked · Legal notified", analyst: "RK" },
  { id: "INC-2430", sender: "support@dropbox-verify.co", subject: "Your Dropbox storage is full", closed: "20 Aug 2026", score: 63, label: "MEDIUM", accent: "yellow", resolution: "Quarantined · User warned", analyst: "AS" },
  { id: "INC-2418", sender: "noreply@linkedin-jobs.net", subject: "You have a new job offer", closed: "19 Aug 2026", score: 44, label: "MEDIUM", accent: "yellow", resolution: "Marked suspicious · Monitored", analyst: "PD" },
  { id: "INC-2400", sender: "newsletter@techcrunch.com", subject: "Weekly tech digest", closed: "18 Aug 2026", score: 6, label: "LOW", accent: "green", resolution: "Cleared · Legitimate", analyst: "AS" },
  { id: "INC-2388", sender: "billing@aws-invoice-alert.com", subject: "Your AWS bill is ready", closed: "17 Aug 2026", score: 79, label: "HIGH", accent: "orange", resolution: "Blocked · Domain reported", analyst: "RK" },
];

export default function CaseHistory() {
  return (
    <div>
      <section className="welcome" style={{ marginBottom: 28 }}>
        <div>
          <p className="eyebrow">CASE HISTORY</p>
          <h1>Resolved investigations</h1>
          <p className="lede">{history.length} cases closed · Showing last 7 days</p>
        </div>
      </section>
      <div className="ti-grid">
        <div className="ti-stat-card"><span className="metric-icon coral" style={{ width: 32, height: 32 }}><Icon name="shield" size={16} /></span><div><small>TOTAL CLOSED</small><strong>{history.length}</strong></div></div>
        <div className="ti-stat-card"><span className="metric-icon amber" style={{ width: 32, height: 32 }}><Icon name="alert" size={16} /></span><div><small>CRITICAL RESOLVED</small><strong>{history.filter(h => h.label === "CRITICAL").length}</strong></div></div>
        <div className="ti-stat-card"><span className="metric-icon mint" style={{ width: 32, height: 32 }}><Icon name="check" size={16} /></span><div><small>AVG SCORE</small><strong>{Math.round(history.reduce((a, h) => a + h.score, 0) / history.length)}</strong></div></div>
        <div className="ti-stat-card"><span className="metric-icon blue" style={{ width: 32, height: 32 }}><Icon name="clock" size={16} /></span><div><small>ANALYSTS ACTIVE</small><strong>3</strong></div></div>
      </div>
      <div className="ti-section-label">CLOSED CASES</div>
      <div className="queue-table">
        <div className="queue-head" style={{ gridTemplateColumns: "90px 1fr 1fr 80px 1fr 50px" }}>
          <span>CASE ID</span><span>SENDER</span><span>SUBJECT</span><span>SCORE</span><span>RESOLUTION</span><span>BY</span>
        </div>
        {history.map(h => (
          <div key={h.id} className="queue-row" style={{ gridTemplateColumns: "90px 1fr 1fr 80px 1fr 50px" }}>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 9 }}>{h.id}<br /><span style={{ color: "var(--muted)" }}>{h.closed}</span></span>
            <span style={{ fontSize: 10 }}>{h.sender}</span>
            <span style={{ fontSize: 10, color: "var(--muted)" }}>{h.subject}</span>
            <span className={`queue-score ${h.accent}`}>{h.score}</span>
            <span style={{ fontSize: 10 }}>{h.resolution}</span>
            <span className="workspace-avatar" style={{ width: 24, height: 24, fontSize: 8, borderRadius: "50%" }}>{h.analyst}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
