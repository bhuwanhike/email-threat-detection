import { useState } from "react";
import Icon from "../components/Icon";

const allEmails = [
  { id: "INC-2481", sender: "accounts-payable@micros0ft.com", subject: "Urgent: invoice overdue - action required", time: "12m ago", score: 94, label: "CRITICAL", accent: "red", initials: "AP" },
  { id: "INC-2479", sender: "ceo.office@northstar-holdings.co", subject: "Confidential acquisition request", time: "38m ago", score: 81, label: "HIGH", accent: "orange", initials: "CO" },
  { id: "INC-2476", sender: "support@cloud-storage-verify.net", subject: "Your storage is almost full", time: "1h ago", score: 67, label: "MEDIUM", accent: "yellow", initials: "CS" },
  { id: "INC-2472", sender: "newsletter@security-weekly.com", subject: "Weekly threat briefing", time: "2h ago", score: 12, label: "LOW", accent: "green", initials: "NW" },
  { id: "INC-2470", sender: "hr@corp-benefits-update.net", subject: "Important: Update your benefits enrollment", time: "3h ago", score: 78, label: "HIGH", accent: "orange", initials: "HR" },
  { id: "INC-2468", sender: "it-support@helpdesk-verify.com", subject: "Your password expires in 24 hours", time: "4h ago", score: 88, label: "CRITICAL", accent: "red", initials: "IT" },
  { id: "INC-2465", sender: "billing@invoice-portal.co", subject: "Invoice #4421 requires your approval", time: "5h ago", score: 61, label: "MEDIUM", accent: "yellow", initials: "BI" },
  { id: "INC-2460", sender: "admin@company.com", subject: "Team meeting rescheduled to Friday", time: "6h ago", score: 8, label: "LOW", accent: "green", initials: "AD" },
];

export default function EmailQueue({ onAnalyze }) {
  const [filter, setFilter] = useState("All");
  const [query, setQuery] = useState("");
  const filters = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const visible = allEmails.filter(e =>
    (filter === "All" || e.label === filter) &&
    `${e.sender} ${e.subject}`.toLowerCase().includes(query.toLowerCase())
  );
  return (
    <div>
      <section className="welcome">
        <div>
          <p className="eyebrow">EMAIL QUEUE</p>
          <h1>Incoming emails</h1>
          <p className="lede">{allEmails.length} emails in queue · {allEmails.filter(e => e.label === "CRITICAL").length} critical</p>
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
          <div key={e.id} className="queue-row">
            <span className="queue-sender"><span className={`case-avatar ${e.accent}`} style={{ width: 26, height: 26, fontSize: 8 }}>{e.initials}</span><span>{e.sender}</span></span>
            <span className="queue-subject">{e.subject}<small>{e.id}</small></span>
            <span className="queue-time">{e.time}</span>
            <span className={`queue-score ${e.accent}`}>{e.score}</span>
            <span className={`severity ${e.accent}`}>{e.label}</span>
          </div>
        ))}
        {visible.length === 0 && <p style={{ padding: "20px", color: "var(--muted)", fontSize: 12 }}>No emails match your filter.</p>}
      </div>
    </div>
  );
}
