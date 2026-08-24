import Icon from "../components/Icon";

const iocs = [
  { type: "DOMAIN", value: "micros0ft.com", threat: "Lookalike · BEC", detections: 14, vt: 8, status: "MALICIOUS", accent: "red" },
  { type: "DOMAIN", value: "northstar-holdings.co", threat: "BEC · CEO fraud", detections: 6, vt: 5, status: "MALICIOUS", accent: "red" },
  { type: "DOMAIN", value: "cloud-storage-verify.net", threat: "Phishing kit", detections: 200, vt: 3, status: "SUSPICIOUS", accent: "orange" },
  { type: "IP", value: "185.23.45.10", threat: "Open relay · Agra IN", detections: 9, vt: 2, status: "SUSPICIOUS", accent: "orange" },
  { type: "IP", value: "41.58.120.77", threat: "Residential proxy · Lagos NG", detections: 4, vt: 1, status: "SUSPICIOUS", accent: "orange" },
  { type: "IP", value: "95.216.44.22", threat: "Hetzner VPS · Frankfurt DE", detections: 3, vt: 0, status: "WATCHLIST", accent: "yellow" },
  { type: "URL", value: "http://secure-example-login.test/verify", threat: "Credential harvesting", detections: 7, vt: 11, status: "MALICIOUS", accent: "red" },
  { type: "HASH", value: "d41d8cd98f00b204e9800998ecf8427e", threat: "Macro dropper · Invoice_8831.xlsm", detections: 2, vt: 6, status: "MALICIOUS", accent: "red" },
];

const ttps = [
  { id: "T1566.001", name: "Spearphishing Attachment", count: 3 },
  { id: "T1566.002", name: "Spearphishing via Link", count: 5 },
  { id: "T1036.005", name: "Match Legitimate Name", count: 4 },
  { id: "T1078", name: "Valid Accounts", count: 2 },
  { id: "T1534", name: "Internal Spearphishing", count: 1 },
  { id: "T1657", name: "Financial Theft (BEC)", count: 2 },
];

export default function ThreatIntel() {
  return (
    <div>
      <section className="welcome" style={{ marginBottom: 28 }}>
        <div>
          <p className="eyebrow">THREAT INTELLIGENCE</p>
          <h1>IOC & TTP Registry</h1>
          <p className="lede">Aggregated indicators of compromise and MITRE ATT&CK techniques from all cases.</p>
        </div>
      </section>
      <div className="ti-grid">
        <div className="ti-stat-card"><span className="metric-icon coral" style={{ width: 32, height: 32 }}><Icon name="link" size={16} /></span><div><small>MALICIOUS IOCS</small><strong>{iocs.filter(i => i.status === "MALICIOUS").length}</strong></div></div>
        <div className="ti-stat-card"><span className="metric-icon amber" style={{ width: 32, height: 32 }}><Icon name="alert" size={16} /></span><div><small>SUSPICIOUS</small><strong>{iocs.filter(i => i.status === "SUSPICIOUS").length}</strong></div></div>
        <div className="ti-stat-card"><span className="metric-icon blue" style={{ width: 32, height: 32 }}><Icon name="zap" size={16} /></span><div><small>MITRE TTPS</small><strong>{ttps.length}</strong></div></div>
        <div className="ti-stat-card"><span className="metric-icon mint" style={{ width: 32, height: 32 }}><Icon name="radar" size={16} /></span><div><small>VT DETECTIONS</small><strong>{iocs.reduce((a, i) => a + i.vt, 0)}</strong></div></div>
      </div>
      <div className="ti-section-label">INDICATORS OF COMPROMISE</div>
      <div className="queue-table">
        <div className="queue-head" style={{ gridTemplateColumns: "90px 1fr 1fr 70px 80px 90px" }}>
          <span>TYPE</span><span>VALUE</span><span>THREAT</span><span>HITS</span><span>VT FLAGS</span><span>STATUS</span>
        </div>
        {iocs.map(ioc => (
          <div key={ioc.value} className="queue-row" style={{ gridTemplateColumns: "90px 1fr 1fr 70px 80px 90px" }}>
            <span><span className="ioc-type-badge">{ioc.type}</span></span>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 9, color: "var(--ink)" }}>{ioc.value}</span>
            <span style={{ fontSize: 10, color: "var(--muted)" }}>{ioc.threat}</span>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 10 }}>{ioc.detections}</span>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 10, color: ioc.vt > 0 ? "var(--coral)" : "var(--muted)" }}>{ioc.vt > 0 ? `${ioc.vt} engines` : "—"}</span>
            <span className={`severity ${ioc.accent}`}>{ioc.status}</span>
          </div>
        ))}
      </div>
      <div className="ti-section-label" style={{ marginTop: 28 }}>MITRE ATT&CK TECHNIQUES OBSERVED</div>
      <div className="ttp-grid">
        {ttps.map(t => (
          <div key={t.id} className="ttp-card">
            <span className="hi-ttp-id" style={{ fontSize: 9 }}>{t.id}</span>
            <b>{t.name}</b>
            <span>{t.count} case{t.count > 1 ? "s" : ""}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
