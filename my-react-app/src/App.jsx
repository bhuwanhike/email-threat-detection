import { useState } from "react";
import "./App.css";

function Icon({ name, size = 18 }) {
  const icons = {
    grid: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
    inbox: "M4 5h16v14H4zM4 13h4l2 2h4l2-2h4",
    radar: "M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l6-6",
    map: "M3 6l6-3 6 3 6-3v15l-6 3-6-3-6 3zM9 3v15M15 6v15",
    clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
    settings: "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM19 13.5l2 1-2 3-2-1a7 7 0 0 1-2 1l-.3 2.2h-3.4L11 17.5a7 7 0 0 1-2-1l-2 1-2-3 2-1a7 7 0 0 1 0-3L5 9.5l2-3 2 1a7 7 0 0 1 2-1L11.3 4h3.4L15 6.5a7 7 0 0 1 2 1l2-1 2 3-2 1a7 7 0 0 1 0 3z",
    search: "m20 20-4-4M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z",
    upload: "M12 16V4m0 0L7 9m5-5 5 5M4 20h16",
    chevron: "m9 18 6-6-6-6",
    more: "M5 12h.01M12 12h.01M19 12h.01",
    shield: "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z",
    link: "M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1M14 11a5 5 0 0 0-7.1-.1l-2 2a5 5 0 0 0 7.1 7.1l1.1-1.1",
    file: "M6 3h8l4 4v14H6zM14 3v5h5M9 13h6M9 17h4",
    copy: "M8 8V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-3M4 9h9a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2z",
    server: "M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01",
  };
  return <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={icons[name] || icons.grid} /></svg>;
}

const cases = [
  { id: "INC-2481", sender: "accounts-payable@micros0ft.com", subject: "Urgent: invoice overdue - action required", time: "12m ago", score: 94, label: "CRITICAL", accent: "red", initials: "AP" },
  { id: "INC-2479", sender: "ceo.office@northstar-holdings.co", subject: "Confidential acquisition request", time: "38m ago", score: 81, label: "HIGH", accent: "orange", initials: "CO" },
  { id: "INC-2476", sender: "support@cloud-storage-verify.net", subject: "Your storage is almost full", time: "1h ago", score: 67, label: "MEDIUM", accent: "yellow", initials: "CS" },
  { id: "INC-2472", sender: "newsletter@security-weekly.com", subject: "Weekly threat briefing", time: "2h ago", score: 12, label: "LOW", accent: "green", initials: "NW" },
];
const indicators = [
  { type: "DOMAIN", value: "micros0ft.com", note: "Lookalike domain · 3 detections", icon: "link", tone: "red" },
  { type: "IP ADDRESS", value: "185.23.45.10", note: "Hosting provider · Agra, IN", icon: "map", tone: "orange" },
  { type: "ATTACHMENT", value: "Invoice_8831.xlsm", note: "Macro-enabled · sandbox pending", icon: "file", tone: "yellow" },
];
function ScoreRing({ score }) { return <div className="score-ring" style={{ "--score": `${score * 3.6}deg` }}><strong>{score}</strong><span>/ 100</span></div>; }

function App() {
  const [active, setActive] = useState("Overview");
  const [selected, setSelected] = useState(cases[0]);
  const [query, setQuery] = useState("");
  const [scanOpen, setScanOpen] = useState(false);
  const [scanText, setScanText] = useState("");
  const [notice, setNotice] = useState("");
  const [location, setLocation] = useState(null);
  const [locationStatus, setLocationStatus] = useState("idle");
  const visibleCases = cases.filter((item) => `${item.sender} ${item.subject}`.toLowerCase().includes(query.toLowerCase()));
  function runScan(event) { event.preventDefault(); setScanOpen(false); setNotice(scanText.trim() ? "Evidence queued for analysis" : "Paste an email or upload a .eml file to begin"); setScanText(""); }
  function locateAnalyst() {
    if (!navigator.geolocation) {
      setLocationStatus("error");
      setNotice("Geolocation is not supported by this browser");
      return;
    }
    setLocationStatus("loading");
    navigator.geolocation.getCurrentPosition(
      ({ coords }) => {
        setLocation({ latitude: coords.latitude, longitude: coords.longitude, accuracy: Math.round(coords.accuracy) });
        setLocationStatus("ready");
        setNotice("Your current location is ready");
      },
      () => {
        setLocationStatus("error");
        setNotice("Location permission was unavailable");
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 300000 },
    );
  }
  const nav = [{ label: "Overview", icon: "grid" }, { label: "Email Queue", icon: "inbox", count: 8 }, { label: "Threat Intel", icon: "radar" }, { label: "Infrastructure", icon: "map" }, { label: "Case History", icon: "clock" }];
  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><span className="brand-mark"><Icon name="shield" size={22} /></span><span>trace<span className="brand-dot">.</span>ai<small>FORENSIC INTELLIGENCE</small></span></div><div className="workspace"><span className="workspace-avatar">SA</span><span><b>Security Analysis</b><small>Enterprise workspace</small></span><Icon name="chevron" size={14} /></div><p className="nav-label">WORKSPACE</p><nav>{nav.map((item) => <button key={item.label} className={active === item.label ? "nav-item active" : "nav-item"} onClick={() => setActive(item.label)}><Icon name={item.icon} size={17} /><span>{item.label}</span>{item.count && <em>{item.count}</em>}</button>)}</nav><p className="nav-label lower">SYSTEM</p><button className="nav-item"><Icon name="settings" size={17} /><span>Settings</span></button><div className="sidebar-footer"><span className="online-dot" /><div><b>All systems operational</b><small>Last synced 2 min ago</small></div></div></aside>
    <main className="main"><header className="topbar"><div><span className="crumb">SECURITY OPERATIONS</span><span className="slash">/</span><b>{active}</b></div><div className="top-actions"><span className="live"><i /> Live monitoring</span><button className="avatar">AS</button></div></header><div className="content">
      <section className="welcome"><div><p className="eyebrow">SUNDAY, 23 AUGUST 2026 <span className="pulse" /></p><h1>Good afternoon, Alex.</h1><p className="lede">Here is what your intelligence workspace has surfaced today.</p></div><button className="scan-button" onClick={() => setScanOpen(true)}><Icon name="upload" size={17} /> Analyze email</button></section>
      {notice && <div className="notice" onClick={() => setNotice("")}><Icon name="shield" size={16} />{notice}{location && <small className="location-coordinates">{location.latitude.toFixed(5)}, {location.longitude.toFixed(5)} · ±{location.accuracy}m</small>}<span>Dismiss</span></div>}
      <section className="metric-grid"><div className="metric"><span className="metric-icon coral"><Icon name="inbox" size={17} /></span><div><small>EMAILS ANALYZED</small><strong>1,284</strong><p><b>+18.4%</b> vs last week</p></div><span className="spark coral-spark" /></div><div className="metric"><span className="metric-icon amber"><Icon name="radar" size={17} /></span><div><small>THREATS DETECTED</small><strong>37</strong><p><b>+6</b> new in 24 hours</p></div><span className="spark amber-spark" /></div><div className="metric"><span className="metric-icon mint"><Icon name="shield" size={17} /></span><div><small>CASES RESOLVED</small><strong>92.1%</strong><p><b>+4.2%</b> resolution rate</p></div><span className="spark mint-spark" /></div><div className="metric"><span className="metric-icon blue"><Icon name="map" size={17} /></span><div><small>IOC MATCHES</small><strong>146</strong><p><b>12</b> high-confidence hits</p></div><span className="spark blue-spark" /></div></section>
      <section className="section-head"><div><p className="eyebrow">PRIORITY QUEUE</p><h2>Recent investigations</h2></div><div className="section-actions"><button className="location-button" onClick={locateAnalyst} disabled={locationStatus === "loading"}><Icon name="map" size={14} />{locationStatus === "loading" ? "Locating..." : location ? "Location ready" : "Locate me"}</button><button className="text-button" onClick={() => setActive("Email Queue")}>View all cases <Icon name="chevron" size={14} /></button></div></section>
      <section className="investigation-layout"><div className="case-list"><div className="list-tools"><div className="search"><Icon name="search" size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search sender or subject" /></div><button className="filter">All risks <Icon name="chevron" size={13} /></button></div>{visibleCases.map((item) => <button key={item.id} className={`case-row ${selected.id === item.id ? "selected" : ""}`} onClick={() => setSelected(item)}><span className={`case-avatar ${item.accent}`}>{item.initials}</span><span className="case-info"><b>{item.sender}</b><span>{item.subject}</span><small>{item.id} · {item.time}</small></span><span className={`severity ${item.accent}`}>{item.label}</span><span className="row-score">{item.score}</span><Icon name="more" size={17} /></button>)}</div>
      <article className="detail-panel"><div className="detail-top"><div><p className="eyebrow">SELECTED INVESTIGATION · {selected.id}</p><h2>{selected.subject}</h2><p className="from">From <b>{selected.sender}</b> <span>·</span> received today at 13:44 IST</p></div><ScoreRing score={selected.score} /></div><div className="risk-summary"><span className="status-pill"><i /> {selected.label} RISK</span><span>Confidence <b>96%</b></span><span>3 detection rules triggered</span></div><div className="detail-section"><div className="subhead"><b>Relay path reconstruction</b><span>3 hops · suspicious origin</span></div><div className="relay"><div className="node"><span className="node-icon safe"><Icon name="inbox" size={16} /></span><small>ORIGIN</small><b>mail.company.in</b><em>Internal gateway</em></div><div className="connector"><i /><span>SPF pass</span></div><div className="node"><span className="node-icon warn"><Icon name="server" size={16} /></span><small>RELAY 01</small><b>mail-relay.pro</b><em>185.23.45.10</em></div><div className="connector danger"><i /><span>ASN flagged</span></div><div className="node"><span className="node-icon danger"><Icon name="radar" size={16} /></span><small>ORIGIN LIKELY</small><b>Agra, India</b><em>Hosting · AS12345</em></div></div></div><div className="detail-section"><div className="subhead"><b>Extracted indicators</b><button className="text-button">View all <Icon name="chevron" size={13} /></button></div><div className="indicator-grid">{indicators.map((item) => <div className="indicator" key={item.value}><span className={`indicator-icon ${item.tone}`}><Icon name={item.icon} size={15} /></span><div><small>{item.type}</small><b>{item.value}</b><span>{item.note}</span></div><button title="Copy indicator" onClick={() => { navigator.clipboard?.writeText(item.value); setNotice(`${item.value} copied to clipboard`); }}><Icon name="copy" size={14} /></button></div>)}</div></div></article></section>
    </div></main>
    {scanOpen && <div className="modal-backdrop" onClick={() => setScanOpen(false)}><form className="scan-modal" onSubmit={runScan} onClick={(e) => e.stopPropagation()}><button type="button" className="modal-close" onClick={() => setScanOpen(false)}>x</button><p className="eyebrow">NEW INVESTIGATION</p><h2>Analyze an email</h2><p>Paste raw headers and body to extract indicators, validate authentication, and build a case.</p><textarea value={scanText} onChange={(e) => setScanText(e.target.value)} placeholder="Paste email content or headers here..." /><div className="modal-actions"><button type="button" className="cancel" onClick={() => setScanOpen(false)}>Cancel</button><button className="scan-button" type="submit"><Icon name="radar" size={16} /> Start analysis</button></div></form></div>}
  </div>;
}

export default App;
