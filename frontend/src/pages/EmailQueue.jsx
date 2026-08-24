import { useState } from "react";
import Icon from "../components/Icon";

export default function EmailQueue({ cases = [], onSelectCase, onAnalyze }) {
  const [filter, setFilter] = useState("All");
  const [query, setQuery] = useState("");
  const filters = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

  const visible = cases.filter(e =>
    (filter === "All" || e.label === filter) &&
    `${e.sender} ${e.subject}`.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div>
      <section className="welcome">
        <div>
          <p className="eyebrow">EMAIL QUEUE</p>
          <h1>Incoming emails</h1>
          <p className="lede">{cases.length} emails in queue · {cases.filter(e => e.label === "CRITICAL").length} critical</p>
        </div>
        <button className="scan-button" onClick={onAnalyze}><Icon name="upload" size={17} /> Analyze email</button>
      </section>
      <div className="queue-toolbar">
        <div className="search" style={{ maxWidth: 280 }}>
          <Icon name="search" size={15} />
          <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search sender or subject" />
        </div>
        <div className="filter-tabs">
          {filters.map(f => <button key={f} className={`filter-tab ${filter === f ? "active" : ""}`} onClick={() => setFilter(f)}>{f}</button>)}
        </div>
      </div>
      <div className="queue-table">
        <div className="queue-head"><span>SENDER</span><span>SUBJECT</span><span>TIME</span><span>SCORE</span><span>RISK</span></div>
        {visible.map(e => (
          <div
            key={e.id}
            className="queue-row"
            onClick={() => onSelectCase && onSelectCase(e)}
            style={{ cursor: "pointer" }}
          >
            <span className="queue-sender"><span className={`case-avatar ${e.accent}`} style={{ width: 26, height: 26, fontSize: 8 }}>{e.initials || "EM"}</span><span>{e.sender}</span></span>
            <span className="queue-subject">{e.subject}<small>{e.id}</small></span>
            <span className="queue-time">{e.time || "recent"}</span>
            <span className={`queue-score ${e.accent}`}>{e.score}</span>
            <span className={`severity ${e.accent}`}>{e.label}</span>
          </div>
        ))}
        {visible.length === 0 && <p style={{ padding: "20px", color: "var(--muted)", fontSize: 12 }}>No emails match your filter.</p>}
      </div>
    </div>
  );
}
