import Icon from "../components/Icon";

export default function ThreatIntel({ data }) {
  const iocs = data?.iocs || [];
  const ttps = data?.ttps || [];

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
        <div className="ti-stat-card"><span className="metric-icon mint" style={{ width: 32, height: 32 }}><Icon name="radar" size={16} /></span><div><small>VT DETECTIONS</small><strong>{iocs.reduce((a, i) => a + (i.vt || 0), 0)}</strong></div></div>
      </div>
      <div className="ti-section-label">INDICATORS OF COMPROMISE</div>
      <div className="queue-table">
        <div className="queue-head" style={{ gridTemplateColumns: "90px 1fr 1fr 70px 80px 90px" }}>
          <span>TYPE</span><span>VALUE</span><span>THREAT</span><span>HITS</span><span>VT FLAGS</span><span>STATUS</span>
        </div>
        {iocs.length === 0 && <p style={{ padding: "20px", color: "var(--muted)", fontSize: 13 }}>No indicators of compromise yet — they are aggregated automatically as emails are analyzed.</p>}
        {iocs.map(ioc => (
          <div key={ioc.value} className="queue-row" style={{ gridTemplateColumns: "90px 1fr 1fr 70px 80px 90px" }}>
            <span><span className="ioc-type-badge">{ioc.type}</span></span>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 10, color: "var(--ink)" }}>{ioc.value}</span>
            <span style={{ fontSize: 11, color: "var(--muted)" }}>{ioc.threat}</span>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 11 }}>{ioc.detections}</span>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 11, color: ioc.vt > 0 ? "var(--coral)" : "var(--muted)" }}>{ioc.vt > 0 ? `${ioc.vt} engines` : "—"}</span>
            <span className={`severity ${ioc.accent}`}>{ioc.status}</span>
          </div>
        ))}
      </div>
      {ttps.length > 0 && (
        <>
          <div className="ti-section-label" style={{ marginTop: 28 }}>MITRE ATT&CK TECHNIQUES OBSERVED</div>
          <div className="ttp-grid">
            {ttps.map(t => (
              <div key={t.id} className="ttp-card">
                <span className="hi-ttp-id" style={{ fontSize: 10 }}>{t.id}</span>
                <b>{t.name}</b>
                <span>{t.count} case{t.count > 1 ? "s" : ""}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
