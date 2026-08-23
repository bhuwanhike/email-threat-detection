import { useState } from "react";
import "./App.css";
import Icon from "./components/Icon";
import EmailQueue from "./pages/EmailQueue";
import ThreatIntel from "./pages/ThreatIntel";
import Infrastructure from "./pages/Infrastructure";
import CaseHistory from "./pages/CaseHistory";

const hackerData = {
  "INC-2481": { actor: "TA-PHANTOM-09", origin: "Agra, Uttar Pradesh, India", asn: "AS12345 · BulkHosting Ltd", infra: ["micros0ft.com (reg. 3 days ago)", "185.23.45.10 (open relay)", "Invoice_8831.xlsm (macro dropper)"], ttps: [{ id: "T1566.001", label: "Spearphishing Attachment", detail: "Macro-enabled XLSM used as initial access vector" }, { id: "T1036.005", label: "Match Legitimate Name", detail: "Domain lookalike micros0ft.com mimics Microsoft brand" }, { id: "T1078", label: "Valid Accounts", detail: "Likely harvesting credentials via fake invoice portal" }], campaign: "INVOICE-STORM · 14 similar emails in 72h", evasion: ["SPF pass via compromised relay", "DKIM absent — forged Return-Path", "Display name spoofing: 'Microsoft Accounts'"], recommendation: "Block AS12345 at perimeter. Quarantine all .xlsm from micros0ft.com. Submit macro to sandbox. Notify finance team.", confidence: 96 },
  "INC-2479": { actor: "TA-EXEC-GHOST", origin: "Lagos, Nigeria", asn: "AS37148 · MainOne Cable", infra: ["northstar-holdings.co (reg. 11 days ago)", "41.58.120.77 (residential proxy)", "Reply-To mismatch detected"], ttps: [{ id: "T1566.002", label: "Spearphishing via Link", detail: "Embedded redirect to credential harvesting page" }, { id: "T1534", label: "Internal Spearphishing", detail: "Impersonates CEO to trigger wire transfer" }, { id: "T1657", label: "Financial Theft", detail: "BEC pattern — payment diversion attempt" }], campaign: "CEO-WIRE-01 · 6 targets in same org", evasion: ["Lookalike domain with valid TLS cert", "Reply-To redirects to attacker mailbox", "Sent during business hours IST"], recommendation: "Alert CFO and finance. Block northstar-holdings.co. Preserve headers for legal. Initiate BEC incident response.", confidence: 81 },
  "INC-2476": { actor: "UNKNOWN · Commodity Phishing Kit", origin: "Frankfurt, Germany (VPS)", asn: "AS24940 · Hetzner Online", infra: ["cloud-storage-verify.net (reg. 6 days ago)", "95.216.44.22 (Hetzner VPS)", "Phishing kit v3.2 fingerprint"], ttps: [{ id: "T1566.002", label: "Spearphishing via Link", detail: "Fake storage warning redirects to credential page" }, { id: "T1598.003", label: "Phishing for Info", detail: "Harvests cloud account credentials" }], campaign: "CLOUD-LURE-22 · 200+ targets globally", evasion: ["Hetzner IP not yet blacklisted", "HTTPS lure page with valid cert", "Urgency language to bypass user scrutiny"], recommendation: "Block cloud-storage-verify.net. Warn users. Submit URL to threat intel feeds.", confidence: 67 },
  "INC-2472": { actor: "N/A · Legitimate sender", origin: "San Francisco, CA, USA", asn: "AS15169 · Google LLC", infra: ["security-weekly.com (reg. 4 years ago)", "Mailchimp ESP · authenticated"], ttps: [], campaign: "No campaign association", evasion: [], recommendation: "No action required. Mark as trusted sender.", confidence: 12 },
};

const STATIC_CASES = [
  { id: "INC-2481", sender: "accounts-payable@micros0ft.com", subject: "Urgent: invoice overdue - action required", time: "12m ago", score: 94, label: "CRITICAL", accent: "red", initials: "AP" },
  { id: "INC-2479", sender: "ceo.office@northstar-holdings.co", subject: "Confidential acquisition request", time: "38m ago", score: 81, label: "HIGH", accent: "orange", initials: "CO" },
  { id: "INC-2476", sender: "support@cloud-storage-verify.net", subject: "Your storage is almost full", time: "1h ago", score: 67, label: "MEDIUM", accent: "yellow", initials: "CS" },
  { id: "INC-2472", sender: "newsletter@security-weekly.com", subject: "Weekly threat briefing", time: "2h ago", score: 12, label: "LOW", accent: "green", initials: "NW" },
];

const STATIC_INDICATORS = [
  { type: "DOMAIN", value: "micros0ft.com", note: "Lookalike domain · 3 detections", icon: "link", tone: "red" },
  { type: "IP ADDRESS", value: "185.23.45.10", note: "Hosting provider · Agra, IN", icon: "map", tone: "orange" },
  { type: "ATTACHMENT", value: "Invoice_8831.xlsm", note: "Macro-enabled · sandbox pending", icon: "file", tone: "yellow" },
];

function ScoreRing({ score }) {
  return (
    <div className="score-ring" style={{ "--score": `${score * 3.6}deg` }}>
      <strong>{score}</strong><span>/ 100</span>
    </div>
  );
}

function HackerInsightsModal({ case_, onClose }) {
  const d = hackerData[case_.id] || hackerData["INC-2472"];
  const isSafe = case_.score < 20;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="hacker-modal" onClick={e => e.stopPropagation()}>
        <button type="button" className="modal-close" onClick={onClose}>✕</button>
        <div className="hacker-modal-header">
          <span className="hacker-skull-icon"><Icon name="skull" size={20} /></span>
          <div><p className="eyebrow">ADVERSARY INTELLIGENCE · {case_.id}</p><h2>Hacker Insights</h2></div>
          <span className={`hi-confidence-badge ${case_.accent}`}>{d.confidence}% confidence</span>
        </div>
        <div className="hi-grid">
          <div className="hi-card"><p className="hi-card-label"><Icon name="target" size={12} /> ATTRIBUTED ACTOR</p><b className="hi-actor">{d.actor}</b><span className="hi-sub">{d.origin}</span><span className="hi-sub muted">{d.asn}</span></div>
          <div className="hi-card"><p className="hi-card-label"><Icon name="radar" size={12} /> CAMPAIGN</p><b className="hi-actor">{d.campaign}</b></div>
        </div>
        {d.ttps.length > 0 && <div className="hi-section"><p className="hi-section-label"><Icon name="zap" size={12} /> MITRE ATT&CK TTPs</p><div className="hi-ttp-list">{d.ttps.map(t => <div className="hi-ttp" key={t.id}><span className="hi-ttp-id">{t.id}</span><div><b>{t.label}</b><span>{t.detail}</span></div></div>)}</div></div>}
        <div className="hi-section"><p className="hi-section-label"><Icon name="server" size={12} /> MALICIOUS INFRASTRUCTURE</p><ul className="hi-infra-list">{d.infra.map(item => <li key={item}>{item}</li>)}</ul></div>
        {d.evasion.length > 0 && <div className="hi-section"><p className="hi-section-label"><Icon name="eye" size={12} /> EVASION TECHNIQUES</p><ul className="hi-infra-list evasion">{d.evasion.map(item => <li key={item}>{item}</li>)}</ul></div>}
        <div className={`hi-recommendation ${isSafe ? "safe" : ""}`}><Icon name="alert" size={14} /><div><b>Analyst Recommendation</b><p>{d.recommendation}</p></div></div>
      </div>
    </div>
  );
}

function ScanModal({ onClose, onResult }) {
  const [scanText, setScanText] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState("");
  const [error, setError] = useState("");

  async function runScan(e) {
    e.preventDefault();
    if (!scanText.trim()) { setError("Paste email content or headers to begin."); return; }
    setError("");
    setLoading(true);
    const steps = ["Parsing headers...", "Validating SPF / DKIM / DMARC...", "Extracting IPs and relay hops...", "Running NLP threat scoring...", "Querying IP geolocation...", "Checking VirusTotal...", "WHOIS domain lookup..."];
    for (const s of steps) {
      setStep(s);
      await new Promise(r => setTimeout(r, 420));
    }
    try {
      const res = await fetch("http://localhost:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw: scanText }),
      });
      if (!res.ok) throw new Error("Backend error");
      const data = await res.json();
      onResult(data);
      onClose();
    } catch {
      setError("Backend offline. Run start.bat in the backend folder first.");
    }
    setLoading(false);
    setStep("");
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <form className="scan-modal" onSubmit={runScan} onClick={e => e.stopPropagation()}>
        <button type="button" className="modal-close" onClick={onClose}>✕</button>
        <p className="eyebrow">NEW INVESTIGATION</p>
        <h2>Analyze an email</h2>
        <p>Paste raw email headers and body. The backend will parse, score, geolocate, and check VirusTotal in real time.</p>
        <textarea value={scanText} onChange={e => setScanText(e.target.value)} placeholder="Paste full email content including headers here..." disabled={loading} />
        {step && <div className="scan-step"><span className="scan-spinner" />{step}</div>}
        {error && <div className="scan-error"><Icon name="alert" size={13} />{error}</div>}
        <div className="modal-actions">
          <button type="button" className="cancel" onClick={onClose} disabled={loading}>Cancel</button>
          <button className="scan-button" type="submit" disabled={loading}><Icon name="radar" size={16} />{loading ? "Analyzing..." : "Start analysis"}</button>
        </div>
      </form>
    </div>
  );
}

function downloadReport(result) {
  const lines = [
    "================================================================",
    "       trace.ai — FORENSIC INTELLIGENCE REPORT",
    "       CONFIDENTIAL — FOR AUTHORIZED USE ONLY",
    "================================================================",
    `Generated   : ${new Date().toISOString()}`,
    `Subject     : ${result.subject}`,
    `From        : ${result.from}`,
    `Reply-To    : ${result.reply_to || "—"}`,
    `Return-Path : ${result.return_path || "—"}`,
    `Message-ID  : ${result.message_id}`,
    `Date        : ${result.date}`,
    "",
    "── THREAT ASSESSMENT ──────────────────────────────────────────",
    `Risk Score  : ${result.score} / 100`,
    `Risk Label  : ${result.label}`,
    `Flags       : ${(result.flags || []).join(" | ") || "None"}`,
    "",
    "── AUTHENTICATION ─────────────────────────────────────────────",
    `SPF         : ${result.auth?.spf}`,
    `DKIM        : ${result.auth?.dkim}`,
    `DMARC       : ${result.auth?.dmarc}`,
    "",
    "── BEC PATTERNS ───────────────────────────────────────────────",
    Object.keys(result.bec || {}).length > 0
      ? Object.entries(result.bec).map(([k, v]) => `${k}: ${v.join(", ")}`).join("\n")
      : "None detected",
    "",
    "── RELAY HOPS ─────────────────────────────────────────────────",
    ...(result.hops || []).map((h, i) => `HOP ${i + 1}: ${h.host} [${h.ip || "no IP"}]`),
    "",
    "── GEOLOCATION ────────────────────────────────────────────────",
    ...(result.geo || []).filter(g => g.lat !== 0).map(g =>
      `${g.ip} → ${g.city}, ${g.region}, ${g.country} | ${g.org}${g.vpn ? " | VPN/HOSTING" : ""}${g.tor ? " | TOR EXIT" : ""}`
    ),
    "",
    "── WHOIS ──────────────────────────────────────────────────────",
    `Domain      : ${result.whois?.domain}`,
    `Registrar   : ${result.whois?.registrar}`,
    `Created     : ${result.whois?.creation_date} (${result.whois?.age_days ?? "?"}  days ago)`,
    "",
    "── DNS ────────────────────────────────────────────────────────",
    `MX Records  : ${(result.dns?.mx || []).join(", ") || "None"}`,
    `A Records   : ${(result.dns?.a || []).join(", ") || "None"}`,
    `Suspicious  : ${result.dns?.suspicious ? "YES — no MX records" : "No"}`,
    "",
    "── VIRUSTOTAL ─────────────────────────────────────────────────",
    `Domain      : ${result.vt_domain?.malicious} malicious, ${result.vt_domain?.suspicious} suspicious / ${result.vt_domain?.total} engines`,
    ...(result.vt_urls || []).map(v => `URL: ${v.url} → ${v.malicious} malicious`),
    "",
    "── ATTACHMENTS ────────────────────────────────────────────────",
    ...(result.attachments || []).length > 0
      ? (result.attachments || []).map(a => `${a.filename} (${a.content_type})${a.dangerous ? " ⚠ DANGEROUS" : ""}`)
      : ["None"],
    "",
    "── URLS ───────────────────────────────────────────────────────",
    ...(result.urls || []).length > 0 ? result.urls : ["None"],
    "",
    "── BODY PREVIEW ───────────────────────────────────────────────",
    result.body_preview || "(empty)",
    "",
    "── CHAIN OF CUSTODY ───────────────────────────────────────────",
    "Received by : trace.ai automated ingestion",
    "Analyzed by : AI Engine v1.0",
    "Evidence    : SHA-256 hash preserved at ingestion",
    "Retention   : 90 days per organizational policy",
    "================================================================",
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `forensic-report-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

function ScanResultModal({ result, onClose, onAddCase }) {
  const geoPoints = (result.geo || []).filter(g => g.lat !== 0);
  const becKeys = Object.keys(result.bec || {});
  const dangerousAttachments = (result.attachments || []).filter(a => a.dangerous);
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="scan-result-modal" onClick={e => e.stopPropagation()}>
        <button type="button" className="modal-close" onClick={onClose}>✕</button>
        <div className="sr-header">
          <div><p className="eyebrow">ANALYSIS COMPLETE</p><h2>{result.subject || "(No subject)"}</h2><p className="from">From <b>{result.from}</b></p></div>
          <ScoreRing score={result.score} />
        </div>
        <div className="risk-summary">
          <span className="status-pill"><i /> {result.label} RISK</span>
          <span>Score <b>{result.score}/100</b></span>
          <span className={`severity ${result.accent}`}>{result.label}</span>
        </div>
        <div className="sr-grid">
          <div className="sr-card"><p className="hi-card-label"><Icon name="shield" size={12} /> AUTH RESULTS</p>
            {["spf","dkim","dmarc"].map(k => <div key={k} className="sr-auth-row"><span className="ioc-type-badge">{k.toUpperCase()}</span><span className={`auth-val ${result.auth?.[k] === "pass" ? "pass" : "fail"}`}>{result.auth?.[k] || "unknown"}</span></div>)}
          </div>
          <div className="sr-card"><p className="hi-card-label"><Icon name="alert" size={12} /> FLAGS TRIGGERED</p>
            {(result.flags || []).length === 0 ? <span style={{ fontSize: 10, color: "var(--muted)" }}>No flags</span> : (result.flags || []).map(f => <div key={f} className="sr-flag">{f}</div>)}
          </div>
        </div>
        {becKeys.length > 0 && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="zap" size={12} /> BEC PATTERNS DETECTED</p>
            {becKeys.map(k => <div key={k} className="sr-hop"><span className="ioc-type-badge danger">{k.replace(/_/g, " ").toUpperCase()}</span><span style={{ fontSize: 9, color: "var(--coral)" }}>{result.bec[k].join(" · ")}</span></div>)}
          </div>
        )}
        {dangerousAttachments.length > 0 && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="file" size={12} /> DANGEROUS ATTACHMENTS</p>
            {dangerousAttachments.map(a => <div key={a.filename} className="sr-hop"><span className="ioc-type-badge danger">{a.extension.toUpperCase()}</span><span style={{ fontSize: 10, color: "var(--coral)" }}>{a.filename}</span></div>)}
          </div>
        )}
        {(result.hops || []).length > 0 && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="server" size={12} /> RELAY HOPS</p>
            {result.hops.map((h, i) => <div key={i} className="sr-hop"><span className="ioc-type-badge">HOP {i + 1}</span><span style={{ fontFamily: "'Space Mono',monospace", fontSize: 9 }}>{h.host} {h.ip ? `[${h.ip}]` : ""}</span></div>)}
          </div>
        )}
        {geoPoints.length > 0 && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="map" size={12} /> GEOLOCATION</p>
            {geoPoints.map(g => (
              <div key={g.ip} className="sr-hop">
                <span className={`ioc-type-badge ${g.tor ? "danger" : g.vpn ? "" : ""}`}>{g.tor ? "TOR" : g.vpn ? "VPN" : "IP"}</span>
                <span style={{ fontSize: 10 }}>{g.ip} · {g.city}, {g.country} · <span style={{ color: "var(--muted)" }}>{g.org}</span>{g.tor && <span style={{ color: "var(--coral)", marginLeft: 6 }}>⚠ TOR EXIT</span>}{g.vpn && <span style={{ color: "var(--amber)", marginLeft: 6 }}>⚠ VPN/Hosting</span>}</span>
              </div>
            ))}
          </div>
        )}
        {result.dns && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="globe" size={12} /> DNS RECORDS</p>
            <div className="sr-hop"><span className="ioc-type-badge">MX</span><span style={{ fontSize: 10 }}>{(result.dns.mx || []).join(", ") || "None"}{result.dns.suspicious && <span style={{ color: "var(--coral)", marginLeft: 6 }}>⚠ No MX — spoofed domain</span>}</span></div>
            <div className="sr-hop"><span className="ioc-type-badge">A</span><span style={{ fontSize: 10 }}>{(result.dns.a || []).join(", ") || "None"}</span></div>
          </div>
        )}
        {result.whois?.domain && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="hash" size={12} /> WHOIS · {result.whois.domain}</p>
            <div className="sr-hop"><span className="ioc-type-badge">REG</span><span style={{ fontSize: 10 }}>{result.whois.registrar} · Created {result.whois.creation_date}{result.whois.age_days != null ? ` (${result.whois.age_days} days ago)` : ""}</span></div>
          </div>
        )}
        {result.vt_domain?.domain && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="radar" size={12} /> VIRUSTOTAL · {result.vt_domain.domain}</p>
            <div className="sr-hop"><span className={`ioc-type-badge ${result.vt_domain.malicious > 0 ? "danger" : ""}`}>VT</span><span style={{ fontSize: 10 }}>{result.vt_domain.malicious} malicious · {result.vt_domain.suspicious} suspicious · {result.vt_domain.total} engines</span></div>
          </div>
        )}
        {(result.urls || []).length > 0 && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="link" size={12} /> URLS FOUND</p>
            {result.urls.map(u => <div key={u} className="sr-hop"><span className="ioc-type-badge">URL</span><span style={{ fontFamily: "'Space Mono',monospace", fontSize: 9, wordBreak: "break-all" }}>{u}</span></div>)}
          </div>
        )}
        <div className="modal-actions">
          <button type="button" className="cancel" onClick={onClose}>Close</button>
          <button type="button" className="report-btn" onClick={() => downloadReport(result)}><Icon name="file" size={14} /> Download Report</button>
          <button className="scan-button" onClick={() => { onAddCase(result); onClose(); }}><Icon name="inbox" size={15} /> Add to Queue</button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [active, setActive] = useState("Overview");
  const [cases, setCases] = useState(STATIC_CASES);
  const [selected, setSelected] = useState(STATIC_CASES[0]);
  const [query, setQuery] = useState("");
  const [scanOpen, setScanOpen] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [notice, setNotice] = useState("");
  const [location, setLocation] = useState(null);
  const [locationStatus, setLocationStatus] = useState("idle");
  const [hackerOpen, setHackerOpen] = useState(false);

  const visibleCases = cases.filter(item => `${item.sender} ${item.subject}`.toLowerCase().includes(query.toLowerCase()));

  function handleScanResult(data) {
    setScanResult(data);
  }

  function addCaseFromScan(data) {
    const newCase = {
      id: `INC-${2490 + cases.length}`,
      sender: data.from,
      subject: data.subject || "(No subject)",
      time: "just now",
      score: data.score,
      label: data.label,
      accent: data.accent,
      initials: (data.from || "??").slice(0, 2).toUpperCase(),
    };
    setCases(prev => [newCase, ...prev]);
    setSelected(newCase);
    setNotice(`New case added: ${newCase.id} · Score ${newCase.score}`);
    setActive("Overview");
  }

  function locateAnalyst() {
    if (!navigator.geolocation) { setNotice("Geolocation not supported"); return; }
    setLocationStatus("loading");
    navigator.geolocation.getCurrentPosition(
      ({ coords }) => { setLocation({ latitude: coords.latitude, longitude: coords.longitude, accuracy: Math.round(coords.accuracy) }); setLocationStatus("ready"); setNotice("Your current location is ready"); },
      () => { setLocationStatus("error"); setNotice("Location permission was unavailable"); },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 300000 }
    );
  }

  const nav = [
    { label: "Overview", icon: "grid" },
    { label: "Email Queue", icon: "inbox", count: cases.length },
    { label: "Threat Intel", icon: "radar" },
    { label: "Infrastructure", icon: "map" },
    { label: "Case History", icon: "clock" },
  ];

  const indicators = selected.id === "INC-2481" ? STATIC_INDICATORS :
    selected.id === "INC-2479" ? [{ type: "DOMAIN", value: "northstar-holdings.co", note: "BEC domain · 11 days old", icon: "link", tone: "red" }, { type: "IP ADDRESS", value: "41.58.120.77", note: "Residential proxy · Lagos, NG", icon: "map", tone: "orange" }] :
    selected.id === "INC-2476" ? [{ type: "DOMAIN", value: "cloud-storage-verify.net", note: "Phishing kit · 6 days old", icon: "link", tone: "orange" }, { type: "IP ADDRESS", value: "95.216.44.22", note: "Hetzner VPS · Frankfurt, DE", icon: "map", tone: "yellow" }] :
    [{ type: "DOMAIN", value: "security-weekly.com", note: "Legitimate · 4 years old", icon: "link", tone: "green" }];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark"><Icon name="shield" size={22} /></span><span>trace<span className="brand-dot">.</span>ai<small>FORENSIC INTELLIGENCE</small></span></div>
        <div className="workspace"><span className="workspace-avatar">SA</span><span><b>Security Analysis</b><small>Enterprise workspace</small></span><Icon name="chevron" size={14} /></div>
        <p className="nav-label">WORKSPACE</p>
        <nav>{nav.map(item => <button key={item.label} className={active === item.label ? "nav-item active" : "nav-item"} onClick={() => setActive(item.label)}><Icon name={item.icon} size={17} /><span>{item.label}</span>{item.count && <em>{item.count}</em>}</button>)}</nav>
        <p className="nav-label lower">SYSTEM</p>
        <button className="nav-item"><Icon name="settings" size={17} /><span>Settings</span></button>
        <div className="sidebar-footer"><span className="online-dot" /><div><b>All systems operational</b><small>Last synced 2 min ago</small></div></div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div><span className="crumb">SECURITY OPERATIONS</span><span className="slash">/</span><b>{active}</b></div>
          <div className="top-actions"><span className="live"><i /> Live monitoring</span><button className="avatar">AS</button></div>
        </header>
        <div className="content">
          {active !== "Overview" && (
            <div>
              {active === "Email Queue" && <EmailQueue onAnalyze={() => setScanOpen(true)} />}
              {active === "Threat Intel" && <ThreatIntel />}
              {active === "Infrastructure" && <Infrastructure />}
              {active === "Case History" && <CaseHistory />}
            </div>
          )}
          {active === "Overview" && (
            <div>
              <section className="welcome">
                <div><p className="eyebrow">SUNDAY, 23 AUGUST 2026 <span className="pulse" /></p><h1>Good afternoon, Alex.</h1><p className="lede">Here is what your intelligence workspace has surfaced today.</p></div>
                <button className="scan-button" onClick={() => setScanOpen(true)}><Icon name="upload" size={17} /> Analyze email</button>
              </section>
              {notice && <div className="notice" onClick={() => setNotice("")}><Icon name="shield" size={16} />{notice}{location && <small className="location-coordinates">{location.latitude.toFixed(5)}, {location.longitude.toFixed(5)} · ±{location.accuracy}m</small>}<span>Dismiss</span></div>}
              <section className="metric-grid">
                <div className="metric"><span className="metric-icon coral"><Icon name="inbox" size={17} /></span><div><small>EMAILS ANALYZED</small><strong>1,284</strong><p><b>+18.4%</b> vs last week</p></div><span className="spark coral-spark" /></div>
                <div className="metric"><span className="metric-icon amber"><Icon name="radar" size={17} /></span><div><small>THREATS DETECTED</small><strong>37</strong><p><b>+6</b> new in 24 hours</p></div><span className="spark amber-spark" /></div>
                <div className="metric"><span className="metric-icon mint"><Icon name="shield" size={17} /></span><div><small>CASES RESOLVED</small><strong>92.1%</strong><p><b>+4.2%</b> resolution rate</p></div><span className="spark mint-spark" /></div>
                <div className="metric"><span className="metric-icon blue"><Icon name="map" size={17} /></span><div><small>IOC MATCHES</small><strong>146</strong><p><b>12</b> high-confidence hits</p></div><span className="spark blue-spark" /></div>
              </section>
              <section className="section-head">
                <div><p className="eyebrow">PRIORITY QUEUE</p><h2>Recent investigations</h2></div>
                <div className="section-actions">
                  <button className="location-button" onClick={locateAnalyst} disabled={locationStatus === "loading"}><Icon name="map" size={14} />{locationStatus === "loading" ? "Locating..." : location ? "Location ready" : "Locate me"}</button>
                  <button className="text-button" onClick={() => setActive("Email Queue")}>View all cases <Icon name="chevron" size={14} /></button>
                </div>
              </section>
              <section className="investigation-layout">
                <div className="case-list">
                  <div className="list-tools">
                    <div className="search"><Icon name="search" size={15} /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search sender or subject" /></div>
                    <button className="filter">All risks <Icon name="chevron" size={13} /></button>
                  </div>
                  {visibleCases.map(item => (
                    <button key={item.id} className={`case-row ${selected.id === item.id ? "selected" : ""}`} onClick={() => setSelected(item)}>
                      <span className={`case-avatar ${item.accent}`}>{item.initials}</span>
                      <span className="case-info"><b>{item.sender}</b><span>{item.subject}</span><small>{item.id} · {item.time}</small></span>
                      <span className={`severity ${item.accent}`}>{item.label}</span>
                      <span className="row-score">{item.score}</span>
                      <Icon name="more" size={17} />
                    </button>
                  ))}
                </div>
                <article className="detail-panel">
                  <div className="detail-top">
                    <div><p className="eyebrow">SELECTED INVESTIGATION · {selected.id}</p><h2>{selected.subject}</h2><p className="from">From <b>{selected.sender}</b> <span>·</span> received today at 13:44 IST</p></div>
                    <ScoreRing score={selected.score} />
                  </div>
                  <div className="risk-summary">
                    <span className="status-pill"><i /> {selected.label} RISK</span>
                    <span>Confidence <b>96%</b></span>
                    <span>3 detection rules triggered</span>
                    <button className="hacker-insights-btn" onClick={() => setHackerOpen(true)}><Icon name="skull" size={14} /> Hacker Insights</button>
                  </div>
                  <div className="detail-section">
                    <div className="subhead"><b>Relay path reconstruction</b><span>3 hops · suspicious origin</span></div>
                    <div className="relay">
                      <div className="node"><span className="node-icon safe"><Icon name="inbox" size={16} /></span><small>ORIGIN</small><b>mail.company.in</b><em>Internal gateway</em></div>
                      <div className="connector"><i /><span>SPF pass</span></div>
                      <div className="node"><span className="node-icon warn"><Icon name="server" size={16} /></span><small>RELAY 01</small><b>mail-relay.pro</b><em>185.23.45.10</em></div>
                      <div className="connector danger"><i /><span>ASN flagged</span></div>
                      <div className="node"><span className="node-icon danger"><Icon name="radar" size={16} /></span><small>ORIGIN LIKELY</small><b>Agra, India</b><em>Hosting · AS12345</em></div>
                    </div>
                  </div>
                  <div className="detail-section">
                    <div className="subhead"><b>Extracted indicators</b><button className="text-button">View all <Icon name="chevron" size={13} /></button></div>
                    <div className="indicator-grid">
                      {indicators.map(item => (
                        <div className="indicator" key={item.value}>
                          <span className={`indicator-icon ${item.tone}`}><Icon name={item.icon} size={15} /></span>
                          <div><small>{item.type}</small><b>{item.value}</b><span>{item.note}</span></div>
                          <button title="Copy" onClick={() => { navigator.clipboard?.writeText(item.value); setNotice(`${item.value} copied`); }}><Icon name="copy" size={14} /></button>
                        </div>
                      ))}
                    </div>
                  </div>
                </article>
              </section>
            </div>
          )}
        </div>
      </main>

      {scanOpen && <ScanModal onClose={() => setScanOpen(false)} onResult={handleScanResult} />}
      {scanResult && <ScanResultModal result={scanResult} onClose={() => setScanResult(null)} onAddCase={addCaseFromScan} />}
      {hackerOpen && <HackerInsightsModal case_={selected} onClose={() => setHackerOpen(false)} />}
    </div>
  );
}
