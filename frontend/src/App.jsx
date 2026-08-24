import { useState, useEffect, useRef, Fragment } from "react";
import "./App.css";
import Icon from "./components/Icon";
import EmailQueue from "./pages/EmailQueue";
import ThreatIntel from "./pages/ThreatIntel";
import Infrastructure from "./pages/Infrastructure";
import CaseHistory from "./pages/CaseHistory";
import Campaigns from "./pages/Campaigns";
import Settings from "./pages/Settings";
import Workspaces from "./pages/Workspaces";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

export const dash = v => (v === null || v === undefined || v === "" ? "—" : v);

export function timeAgo(iso) {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

export async function apiGet(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`GET ${path} failed`);
  return res.json();
}

function ScoreRing({ score }) {
  return (
    <div className="score-ring" style={{ "--score": `${(score || 0) * 3.6}deg` }}>
      <strong>{score ?? "—"}</strong><span>/ 100</span>
    </div>
  );
}

function HackerInsightsModal({ case_, analysisOverride, onClose }) {
  const [analysis, setAnalysis] = useState(analysisOverride || null);
  const [error, setError] = useState(false);

  useEffect(() => {
    if (analysisOverride || analysis) return;
    apiGet(`/analysis/${case_.id}`)
      .then(setAnalysis)
      .catch(() => setError(true));
  }, [case_.id]);

  if (!analysis) {
    return (
      <div className="modal-backdrop" onClick={onClose}>
        <div className="hacker-modal" onClick={e => e.stopPropagation()}>
          <button type="button" className="modal-close" onClick={onClose}>✕</button>
          {error ? (
            <p style={{ color: "var(--muted)", fontSize: 12 }}>No forensic analysis is stored for this case yet.</p>
          ) : (
            <p style={{ color: "var(--muted)", fontSize: 12 }}><span className="scan-spinner" style={{ width: 14, height: 14, display: "inline-block", verticalAlign: "middle", marginRight: 8 }} />Loading adversary intelligence…</p>
          )}
        </div>
      </div>
    );
  }

  const origin = analysis.origin_attribution || {};
  const camp = analysis.campaign || {};
  const geo = (analysis.geo || []).find(g => g.lat !== 0);
  const graph = analysis.correlation_graph;
  const displaySpoof = analysis.display_name_spoofing || {};
  const ev = analysis.evidence_hash || {};
  const urlAnalysis = analysis.url_analysis || [];

  const actor = (() => {
    const ot = origin.origin_type;
    if (ot === "spoofed_domain") return "TA · Brand Impersonation / Lookalike Domain";
    if (ot === "anonymized_infrastructure") return "TA · Anonymized Actor (VPN/TOR)";
    if (ot === "compromised_account") return "Likely Compromised Legitimate Account";
    if (ot === "direct_malicious_actor") return "Direct Malicious Infrastructure";
    return "—";
  })();

  const originText = geo ? `${geo.city}, ${geo.region || ""} ${geo.country} (${geo.org || ""})` : null;
  const confidence = origin.confidence;
  const isSafe = (case_.score ?? 0) < 20;

  const ttps = analysis.ttps || [];
  const evasion = [
    ...(displaySpoof.is_spoofed ? (displaySpoof.techniques || []) : []),
    ...urlAnalysis.filter(u => u.obfuscated).flatMap(u => (u.techniques || []).map(t => `${t} (${u.url?.slice(0, 40)}…)`)),
  ];
  const infra = [
    ...(geo ? [`Origin IP ${geo.ip} — ${geo.city || "Unknown"}, ${geo.country || "?"}${geo.vpn ? " · VPN/hosting ASN" : ""}${geo.tor ? " · TOR exit" : ""}`] : []),
    ...(analysis.attachments || []).filter(a => a.dangerous).map(a => `${a.filename} (${a.extension}) — dangerous attachment`),
    ...(urlAnalysis.filter(u => u.obfuscated).map(u => u.url)),
  ].filter(Boolean);
  const recommendations = analysis.recommendations || [];
  const origin_reasons = origin.reasons || [];

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="hacker-modal" onClick={e => e.stopPropagation()}>
        <button type="button" className="modal-close" onClick={onClose}>✕</button>
        <div className="hacker-modal-header">
          <span className="hacker-skull-icon"><Icon name="skull" size={20} /></span>
          <div><p className="eyebrow">ADVERSARY INTELLIGENCE · {case_.id}</p><h2>Hacker Insights</h2></div>
          <span className={`hi-confidence-badge ${case_.accent}`}>{confidence}% confidence</span>
        </div>
        <div className="hi-grid">
          <div className="hi-card">
            <p className="hi-card-label"><Icon name="target" size={12} /> ATTRIBUTED ACTOR / ORIGIN</p>
            <b className="hi-actor">{actor}</b>
            <span className="hi-sub">{dash(origin.origin_label || originText)}</span>
            <span className="hi-sub muted">{geo?.org || "—"}</span>
            {origin.origin_type && (
              <span className="hi-sub" style={{ marginTop: 4, fontSize: 9 }}>
                origin type: <b>{origin.origin_type.replace(/_/g, " ")}</b>
              </span>
            )}
          </div>
          <div className="hi-card">
            <p className="hi-card-label"><Icon name="radar" size={12} /> CAMPAIGN</p>
            <b className="hi-actor">{camp.campaign_name || "—"}</b>
            <span className="hi-sub muted" style={{ marginTop: 4 }}>
              {camp.matched ? `ID: ${camp.campaign_id}` : ""}
            </span>
            <span className="hi-sub">
              ~{camp.similar_emails_in_campaign ?? "—"} related emails · window: {camp.campaign_window || "unknown"}
            </span>
          </div>
        </div>

        {!origin_reasons.length && !ttps.length && !infra.length && !evasion.length && (
          <div className="hi-section">
            <p className="hi-section-label"><Icon name="shield" size={12} /> ADVERSARY INTELLIGENCE</p>
            <p style={{ fontSize: 10, color: "var(--muted)" }}>No adversary intelligence available for this case yet.</p>
          </div>
        )}

        {origin_reasons.length > 0 && (
          <div className="hi-section">
            <p className="hi-section-label"><Icon name="shield" size={12} /> ORIGIN EVIDENCE CHAIN</p>
            <ul className="hi-infra-list">{origin_reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
          </div>
        )}

        {graph?.nodes?.length > 0 && (
          <div className="hi-section">
            <p className="hi-section-label">
              <Icon name="target" size={12} /> CORRELATION GRAPH
              <span style={{ float: "right", fontSize: 9, color: "var(--muted)", fontWeight: 500 }}>
                {graph.summary?.total_nodes || 0} nodes · {graph.summary?.total_edges || 0} edges
              </span>
            </p>
            <CorrelationGraphView graph={graph} />
          </div>
        )}

        {ttps.length > 0 && <div className="hi-section"><p className="hi-section-label"><Icon name="zap" size={12} /> MITRE ATT&CK TTPs</p><div className="hi-ttp-list">{ttps.map(t => <div className="hi-ttp" key={t.id}><span className="hi-ttp-id">{t.id}</span><div><b>{t.label || t.name}</b><span>{t.detail}</span></div></div>)}</div></div>}
        {infra.length > 0 && <div className="hi-section"><p className="hi-section-label"><Icon name="server" size={12} /> MALICIOUS INFRASTRUCTURE</p><ul className="hi-infra-list">{infra.map(item => <li key={item}>{item}</li>)}</ul></div>}
        {evasion.length > 0 && <div className="hi-section"><p className="hi-section-label"><Icon name="eye" size={12} /> EVASION / OBFUSCATION TECHNIQUES</p><ul className="hi-infra-list evasion">{evasion.map((item, i) => <li key={i}>{item}</li>)}</ul></div>}

        {ev.sha256 && (
          <div className="hi-section">
            <p className="hi-section-label"><Icon name="hash" size={12} /> EVIDENCE CHAIN</p>
            <div style={{ fontFamily: "'Space Mono',monospace", fontSize: 9, wordBreak: "break-all", color: "var(--ink)", lineHeight: 1.6 }}>
              SHA-256: <b>{ev.sha256}</b><br />
              size: {dash(ev.size_bytes)} bytes · preserved: {ev.preserved_at || analysis.analyzed_at || "—"}
            </div>
          </div>
        )}

        <div className={`hi-recommendation ${isSafe ? "safe" : ""}`}><Icon name="alert" size={14} /><div>
          <b>Analyst Recommendation</b>
          {recommendations.length > 0
            ? recommendations.map((r, i) => <p key={i}>· {r}</p>)
            : <p>No recommendation available.</p>}
        </div></div>
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
      const res = await fetch(`${API}/analyze`, {
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
  const origin = result.origin_attribution || {};
  const originIp = result.originating_ip || {};
  const ev = result.evidence_hash || {};
  const spoof = result.display_name_spoofing || {};
  const camp = result.campaign || {};

  const lines = [
    "================================================================",
    "       MAILSHIELD — AI-POWERED FORENSIC INTELLIGENCE REPORT",
    "       CONFIDENTIAL — FOR AUTHORIZED INVESTIGATIVE USE ONLY",
    "================================================================",
    `Generated   : ${new Date().toISOString()}`,
    `Case ID     : ${result.case_id || "(new analysis)"}`,
    `Subject     : ${result.subject || "(no subject)"}`,
    `From        : ${result.from}`,
    `Display Name: ${result.from_display_name || "(none)"}`,
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
    "── SENDER AUTHENTICATION ──────────────────────────────────────",
    `SPF         : ${result.auth?.spf || "unknown"}`,
    `DKIM        : ${result.auth?.dkim || "unknown"}`,
    `DMARC       : ${result.auth?.dmarc || "unknown"}`,
    "",
    "── DISPLAY-NAME SPOOFING DETECTION ────────────────────────────",
    spoof.is_spoofed ? "⚠ SPOOFING DETECTED" : "None detected",
    ...(spoof.techniques || []).map(t => `  · ${t}`),
    "",
    "── BEC PATTERNS ───────────────────────────────────────────────",
    Object.keys(result.bec || {}).length > 0
      ? Object.entries(result.bec).map(([k, v]) => `${k}: ${v.join(", ")}`).join("\n")
      : "None detected",
    "",
    "── URL OBFUSCATION ANALYSIS ───────────────────────────────────",
    ...(result.url_analysis || []).map(u =>
      `${u.url.slice(0, 70)}${u.url.length > 70 ? "…" : ""}  ${u.obfuscated ? "[OBFUSCATED]" : "[clean]"} ${(u.techniques || []).join(" ; ")}`
    ),
    (result.url_analysis || []).length === 0 ? "No URLs" : "",
    "",
    "── ORIGIN TRACEABILITY ────────────────────────────────────────",
    `Earliest Origin IP: ${originIp.ip || "(unknown)"}  [via ${originIp.source || "—"}]`,
    `Origin Attribution: ${origin.origin_label || "—"}  (confidence ${origin.confidence || 0}%)`,
    `Origin Type Key   : ${origin.origin_type || "—"}`,
    ...(origin.reasons || []).slice(0, 5).map(r => `  · ${r}`),
    "",
    "── RELAY HOPS ─────────────────────────────────────────────────",
    ...(result.hops || []).map((h, i) => `HOP ${i + 1}: ${h.host} [${h.ip || "no IP"}]`),
    (result.hops || []).length === 0 ? "  (no Received headers)" : "",
    "",
    "── GEOLOCATION ────────────────────────────────────────────────",
    ...(result.geo || []).filter(g => g.lat !== 0).map(g =>
      `${g.ip} → ${g.city}, ${g.region}, ${g.country} | ${g.org}${g.vpn ? " | ⚠ VPN/HOSTING" : ""}${g.tor ? " | ⚠⚠ TOR EXIT NODE" : ""}`
    ),
    (result.geo || []).filter(g => g.lat !== 0).length === 0 ? "  (no geolocatable public IPs)" : "",
    "",
    "── DOMAIN INFRASTRUCTURE INTEL ────────────────────────────────",
    "—— WHOIS ——",
    `  Domain      : ${result.whois?.domain || "—"}`,
    `  Registrar   : ${result.whois?.registrar || "—"}`,
    `  Created     : ${result.whois?.creation_date || "—"} ${result.whois?.age_days != null ? `(${result.whois.age_days} days ago)` : ""}`,
    `  Registrant C: ${result.whois?.country || "—"}`,
    "—— DNS RECORDS ——",
    `  MX Records  : ${(result.dns?.mx || []).join(", ") || "None"}`,
    `  A Records   : ${(result.dns?.a || []).join(", ") || "None"}`,
    `  Suspicious  : ${result.dns?.suspicious ? "YES — no MX records (domain cannot receive mail, classic spoof)" : "No"}`,
    "—— VIRUSTOTAL DOMAIN ——",
    `  Engine flags: ${result.vt_domain?.malicious || 0} malicious, ${result.vt_domain?.suspicious || 0} suspicious / ${result.vt_domain?.total || 0} engines`,
    ...(result.vt_urls || []).map(v => `  URL (${v.url?.slice(0, 45) || ""}…): ${v.malicious} malicious, ${v.suspicious} suspicious`),
    "",
    "── CAMPAIGN CORRELATION ───────────────────────────────────────",
    camp.matched ? "⚠ MATCHED KNOWN CAMPAIGN" : "New / standalone cluster",
    `  Campaign ID  : ${camp.campaign_id || "—"}`,
    `  Campaign Name: ${camp.campaign_name || "—"}`,
    `  Similar emails in cluster: ${camp.similar_emails_in_campaign || 1}`,
    `  Campaign window            : ${camp.campaign_window || "first seen today"}`,
    "",
    "── ATTACHMENTS ────────────────────────────────────────────────",
    ...(result.attachments || []).length > 0
      ? (result.attachments || []).map(a => `${a.filename} (${a.content_type})${a.dangerous ? " ⚠⚠ DANGEROUS EXTENSION" : ""}`)
      : ["None"],
    "",
    "── CHAIN OF CUSTODY / EVIDENCE INTEGRITY ──────────────────────",
    `Hash Algorithm : ${ev.algo || "SHA-256"}`,
    `SHA-256        : ${ev.sha256 || "(computed at ingestion)"}`,
    `SHA-1          : ${ev.sha1 || ""}`,
    `MD5            : ${ev.md5 || ""}`,
    `Evidence Size  : ${ev.size_bytes || 0} bytes`,
    `Preserved At   : ${ev.preserved_at || result.analyzed_at || new Date().toISOString()}`,
    `Retention Days : ${result.retention_days || 90} (per organizational policy)`,
    `PII Masking    : ${result.mask_pii_applied ? "APPLIED (GDPR/DPDP)" : "Not applied"}`,
    "",
    "── CORRELATION GRAPH SUMMARY ──────────────────────────────────",
    ...(result.correlation_graph?.summary
      ? [
          `Nodes: ${result.correlation_graph.summary.total_nodes || 0}  |  Edges: ${result.correlation_graph.summary.total_edges || 0}`,
          `Node Types: ${JSON.stringify(result.correlation_graph.summary.node_types || {})}`,
        ]
      : ["(not available)"]),
    "",
    "── BODY PREVIEW (PII-masked if enabled) ───────────────────────",
    result.body_preview || "(empty)",
    "",
    "── ANALYST ACTION RECOMMENDATIONS ─────────────────────────────",
    (result.score >= 75) ? "  ⚠ QUARANTINE immediately. Block sender IOCs. Escalate to SOC on-call." : "",
    (result.score >= 55 && result.score < 75) ? "  HOLD in suspicious queue. Await analyst review before user delivery." : "",
    (origin.origin_type === "spoofed_domain") ? "  · Report spoofed domain to registrar + hosting provider. Block at perimeter." : "",
    (origin.origin_type === "anonymized_infrastructure") ? "  · Block VPN/TOR/proxy ASN at mail gateway. Alert network team." : "",
    (origin.origin_type === "compromised_account") ? "  · FORCE password reset + MFA re-enrollment. Audit sender account logins." : "",
    "  · Preserve raw .eml file + SHA-256 for chain-of-custody and law enforcement.",
    "================================================================",
  ].filter(l => l !== "");

  const blob = new Blob([lines.join("\n")], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `forensic-report-${result.case_id || "new"}-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

function CorrelationGraphView({ graph }) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  if (nodes.length === 0) return null;

  const typeColors = {
    EMAIL: "#56a987", DOMAIN: "#648fa5", RELAY: "#e1a142",
    IP: "#c085d1", URL: "#e96856",
  };
  const cx = 260, cy = 160, rSpread = 110;
  const positions = {};
  nodes.forEach((n, i) => {
    if (i === 0) { positions[n.id] = [cx, cy]; return; }
    const a = ((i - 1) / Math.max(1, nodes.length - 1)) * Math.PI * 2;
    positions[n.id] = [cx + Math.cos(a) * rSpread, cy + Math.sin(a) * rSpread * 0.75];
  });

  return (
    <div style={{ marginTop: 6 }}>
      <svg viewBox="0 0 520 320" style={{ width: "100%", height: 220, borderRadius: 6, border: "1px solid var(--line)", background: "var(--bg-card)" }}>
        <defs>
          <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--muted)" />
          </marker>
        </defs>
        {edges.map((e, i) => {
          const s = positions[e.source] || [0, 0], t = positions[e.target] || [0, 0];
          const midX = (s[0] + t[0]) / 2, midY = (s[1] + t[1]) / 2;
          return (
            <g key={i}>
              <line x1={s[0]} y1={s[1]} x2={t[0]} y2={t[1]} stroke="var(--muted)" strokeWidth="1" markerEnd="url(#arr)" opacity="0.6" />
              <text x={midX} y={midY} fontSize="7" fill="var(--muted)" textAnchor="middle" style={{ pointerEvents: "none" }}>
                {e.type?.replace(/_/g, " ") || ""}
              </text>
            </g>
          );
        })}
        {nodes.map(n => {
          const [x, y] = positions[n.id] || [0, 0];
          const col = typeColors[n.type] || "#888";
          return (
            <g key={n.id}>
              <circle cx={x} cy={y} r="14" fill={col} stroke="#fff" strokeWidth="2" />
              <text x={x} y={y + 3} fontSize="7" textAnchor="middle" fill="#fff" fontWeight="700">
                {(n.type || "?").slice(0, 2)}
              </text>
              <text x={x} y={y + 26} fontSize="7" textAnchor="middle" fill="var(--ink)" style={{ wordBreak: "break-all" }}>
                {(n.label || "").slice(0, 24)}
              </text>
            </g>
          );
        })}
      </svg>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 6 }}>
        {Object.entries(typeColors).map(([t, c]) => (
          <span key={t} style={{ fontSize: 9, display: "flex", alignItems: "center", gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: c, display: "inline-block" }} />{t}
          </span>
        ))}
      </div>
    </div>
  );
}

function ScanResultModal({ result, onClose, onAddCase }) {
  const geoPoints = (result.geo || []).filter(g => g.lat !== 0);
  const becKeys = Object.keys(result.bec || {});
  const dangerousAttachments = (result.attachments || []).filter(a => a.dangerous);
  const origin = result.origin_attribution || {};
  const originIp = result.originating_ip || {};
  const ev = result.evidence_hash || {};
  const spoof = result.display_name_spoofing || {};
  const camp = result.campaign || {};
  const urlAnalysis = result.url_analysis || [];
  const obfuscatedUrls = urlAnalysis.filter(u => u.obfuscated);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="scan-result-modal" onClick={e => e.stopPropagation()}>
        <button type="button" className="modal-close" onClick={onClose}>✕</button>
        <div className="sr-header">
          <div>
            <p className="eyebrow">ANALYSIS COMPLETE{result.case_id ? ` · ${result.case_id}` : ""}</p>
            <h2>{result.subject || "(No subject)"}</h2>
            <p className="from">From <b>{result.from}</b>{result.from_display_name && result.from_display_name !== result.from ? <span style={{ color: "var(--muted)" }}> · display name: "{result.from_display_name}"</span> : null}</p>
          </div>
          <ScoreRing score={result.score} />
        </div>
        <div className="risk-summary">
          <span className="status-pill"><i /> {result.label} RISK</span>
          <span>Score <b>{result.score}/100</b></span>
          <span className={`severity ${result.accent}`}>{result.label}</span>
        </div>

        {(origin.origin_type || ev.sha256) && (
          <div className="sr-grid">
            <div className="sr-card">
              <p className="hi-card-label"><Icon name="target" size={12} /> ORIGIN ATTRIBUTION</p>
              <div style={{ fontSize: 11, fontWeight: 700, color: origin.origin_type === "spoofed_domain" ? "var(--coral)" : "var(--ink)" }}>
                {origin.origin_label || "Determining…"}
              </div>
              <div style={{ fontSize: 9, color: "var(--muted)", marginTop: 2 }}>
                Confidence {origin.confidence || 0}% · {originIp.source || ""}{originIp.ip ? ` · ${originIp.ip}` : ""}
              </div>
              {origin.scores && (
                <div style={{ display: "flex", gap: 4, marginTop: 6, flexWrap: "wrap" }}>
                  {Object.entries(origin.scores).map(([k, v]) => (
                    <span key={k} style={{
                      fontSize: 8, padding: "2px 4px", background: "var(--line)",
                      borderRadius: 3, fontWeight: 600, color: v > 0 ? "var(--ink)" : "var(--muted)"
                    }}>
                      {k.split("_")[0]}:{v}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div className="sr-card">
              <p className="hi-card-label"><Icon name="shield" size={12} /> EVIDENCE INTEGRITY · CHAIN OF CUSTODY</p>
              {ev.sha256 ? (
                <>
                  <div style={{ fontFamily: "'Space Mono',monospace", fontSize: 8, wordBreak: "break-all", color: "var(--ink)", lineHeight: 1.4 }}>
                    <b>SHA-256</b>: {ev.sha256.slice(0, 32)}…<br />
                    <b>size</b>: {ev.size_bytes || 0} bytes · <b>retention</b>: {result.retention_days || 90}d
                  </div>
                  {result.mask_pii_applied && (
                    <div style={{ marginTop: 4, fontSize: 9, color: "var(--mint)", fontWeight: 700 }}>✓ PII masking applied (GDPR/DPDP)</div>
                  )}
                </>
              ) : (
                <span style={{ fontSize: 9, color: "var(--muted)" }}>Hash computed server-side in audit log</span>
              )}
            </div>
          </div>
        )}

        {camp.campaign_id && (
          <div className="sr-section">
            <p className="hi-section-label"><Icon name="zap" size={12} /> CAMPAIGN CORRELATION</p>
            <div style={{ padding: 10, borderRadius: 6, background: camp.matched ? "rgba(233,104,86,0.06)" : "var(--bg-card)", border: `1px solid var(--line)`, borderLeft: `4px solid var(--${camp.campaign_accent || "yellow"})` }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: "var(--ink)" }}>
                <span className="ioc-type-badge" style={{ marginRight: 6 }}>{(camp.campaign_id || "").split("-")[1] || "CAMP"}</span>
                {camp.campaign_name}
                {camp.matched && <span style={{ color: "var(--coral)", marginLeft: 8 }}>⚠ KNOWN CAMPAIGN</span>}
              </div>
              <div style={{ fontSize: 9, color: "var(--muted)", marginTop: 4 }}>
                ~{camp.similar_emails_in_campaign || 1} related emails · {camp.campaign_window || "first seen today"}
              </div>
            </div>
          </div>
        )}

        <div className="sr-grid">
          <div className="sr-card"><p className="hi-card-label"><Icon name="shield" size={12} /> AUTH RESULTS</p>
            {["spf","dkim","dmarc"].map(k => <div key={k} className="sr-auth-row"><span className="ioc-type-badge">{k.toUpperCase()}</span><span className={`auth-val ${result.auth?.[k] === "pass" ? "pass" : "fail"}`}>{result.auth?.[k] || "unknown"}</span></div>)}
          </div>
          <div className="sr-card"><p className="hi-card-label"><Icon name="alert" size={12} /> FLAGS TRIGGERED</p>
            {(result.flags || []).length === 0 ? <span style={{ fontSize: 10, color: "var(--muted)" }}>No flags</span> : (result.flags || []).slice(0, 8).map(f => <div key={f} className="sr-flag">{f}</div>)}
            {(result.flags || []).length > 8 && <div style={{ fontSize: 9, color: "var(--muted)" }}>+{(result.flags || []).length - 8} more</div>}
          </div>
        </div>

        {spoof.is_spoofed && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="eye" size={12} /> ⚠ DISPLAY-NAME SPOOFING DETECTED</p>
            {spoof.techniques?.map((t, i) => <div key={i} className="sr-hop"><span className="ioc-type-badge danger">SPOOF</span><span style={{ fontSize: 9, color: "var(--coral)" }}>{t}</span></div>)}
          </div>
        )}

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

        <div className="sr-grid">
          {(result.hops || []).length > 0 && (
            <div className="sr-card">
              <p className="hi-card-label"><Icon name="server" size={12} /> RELAY HOPS ({result.hops.length})</p>
              {result.hops.slice(0, 4).map((h, i) => <div key={i} className="sr-hop" style={{ margin: "3px 0" }}><span className="ioc-type-badge" style={{ fontSize: 8 }}>HOP {i + 1}</span><span style={{ fontFamily: "'Space Mono',monospace", fontSize: 8 }}>{(h.host || "").slice(0, 28)} {h.ip ? `[${h.ip}]` : ""}</span></div>)}
              {result.hops.length > 4 && <div style={{ fontSize: 8, color: "var(--muted)" }}>+{result.hops.length - 4} more</div>}
            </div>
          )}
          {geoPoints.length > 0 && (
            <div className="sr-card">
              <p className="hi-card-label"><Icon name="map" size={12} /> GEOLOCATION ({geoPoints.length})</p>
              {geoPoints.slice(0, 3).map(g => (
                <div key={g.ip} className="sr-hop" style={{ margin: "3px 0" }}>
                  <span className={`ioc-type-badge ${g.tor ? "danger" : g.vpn ? "" : ""}`} style={{ fontSize: 8 }}>{g.tor ? "TOR" : g.vpn ? "VPN" : "IP"}</span>
                  <span style={{ fontSize: 8 }}>{g.ip?.slice(0, 15)} · {g.city}, {g.country}{g.tor && " ⚠"}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {obfuscatedUrls.length > 0 && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="link" size={12} /> ⚠ URL OBFUSCATION ({obfuscatedUrls.length})</p>
            {obfuscatedUrls.map((u, i) => (
              <div key={i} className="sr-hop">
                <span className="ioc-type-badge danger">OBFUSCATED</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: "'Space Mono',monospace", fontSize: 8, wordBreak: "break-all" }}>{u.url}</div>
                  <div style={{ fontSize: 8, color: "var(--coral)" }}>{(u.techniques || []).join(" · ")}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {(result.urls || []).length > 0 && urlAnalysis.length > 0 && obfuscatedUrls.length === 0 && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="link" size={12} /> URLS FOUND</p>
            {result.urls.slice(0, 4).map((u, i) => <div key={i} className="sr-hop"><span className="ioc-type-badge">URL</span><span style={{ fontFamily: "'Space Mono',monospace", fontSize: 8, wordBreak: "break-all" }}>{u.slice(0, 70)}{u.length > 70 ? "…" : ""}</span></div>)}
          </div>
        )}

        {result.dns && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="globe" size={12} /> DNS + WHOIS</p>
            <div className="sr-hop"><span className="ioc-type-badge">MX</span><span style={{ fontSize: 9 }}>{(result.dns.mx || []).slice(0, 2).join(", ") || "None"}{result.dns.suspicious && <span style={{ color: "var(--coral)", marginLeft: 6 }}>⚠ No MX (spoofed)</span>}</span></div>
            {result.whois?.domain && <div className="sr-hop"><span className="ioc-type-badge">REG</span><span style={{ fontSize: 9 }}>{result.whois.registrar?.slice(0, 30) || "—"} · {result.whois.creation_date}{result.whois.age_days != null ? ` (${result.whois.age_days}d old)` : ""}</span></div>}
          </div>
        )}
        {result.vt_domain?.domain && (
          <div className="sr-section"><p className="hi-section-label"><Icon name="radar" size={12} /> VIRUSTOTAL</p>
            <div className="sr-hop"><span className={`ioc-type-badge ${result.vt_domain.malicious > 0 ? "danger" : ""}`}>VT</span><span style={{ fontSize: 9 }}>{result.vt_domain.malicious} malicious · {result.vt_domain.suspicious} suspicious · {result.vt_domain.total} engines</span></div>
          </div>
        )}

        {result.correlation_graph?.nodes?.length > 0 && (
          <div className="sr-section">
            <p className="hi-section-label"><Icon name="target" size={12} /> IDENTITY CORRELATION GRAPH</p>
            <div style={{ fontSize: 9, color: "var(--muted)", marginBottom: 4 }}>
              {result.correlation_graph.summary?.total_nodes || 0} nodes · {result.correlation_graph.summary?.total_edges || 0} edges
            </div>
            <CorrelationGraphView graph={result.correlation_graph} />
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

function ConnectAccountModal({ onClose, onCasesFetched, setNotice }) {
  const [provider, setProvider] = useState("gmail");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [maxEmails, setMaxEmails] = useState(5);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [step, setStep] = useState("");

  // Microsoft Device Code OAuth State
  const [msDevice, setMsDevice] = useState(null);
  const [msPolling, setMsPolling] = useState(false);
  const [codeCopied, setCodeCopied] = useState(false);

  useEffect(() => {
    let intervalId = null;
    if (msDevice && msPolling) {
      intervalId = setInterval(async () => {
        try {
          const res = await fetch(`${API}/auth/outlook/poll-token`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ device_code: msDevice.device_code, max_emails: parseInt(maxEmails) || 5 }),
          });
          const data = await res.json();
          if (data.status === "complete") {
            clearInterval(intervalId);
            setMsPolling(false);
            setStep(`Analyzed ${data.count} live Outlook emails!`);
            if (data.cases && data.cases.length > 0) {
              onCasesFetched(data.count, "outlook", data.account_email || email || "Outlook Account");
            } else {
              setNotice("Connected to Outlook via Microsoft OAuth2. No unread emails found.");
            }
            onClose();
          } else if (data.status === "pending") {
            setStep("Waiting for you to complete sign-in on Microsoft's page...");
          }
        } catch (err) {
          clearInterval(intervalId);
          setMsPolling(false);
          setError(err.message || "Microsoft Auth failed");
        }
      }, 4000);
    }
    return () => { if (intervalId) clearInterval(intervalId); };
  }, [msDevice, msPolling, maxEmails]);

  async function handleStartMsOAuth() {
    setError("");
    setLoading(true);
    setStep("Generating Microsoft OAuth Authorization Link...");
    try {
      const res = await fetch(`${API}/auth/outlook/device-code`, { method: "POST" });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to start Microsoft Auth");
      }
      const data = await res.json();
      setMsDevice(data);
      setMsPolling(true);
      setStep(`Code generated: ${data.user_code}. Please approve in your browser.`);
    } catch (err) {
      setError(err.message || "Could not connect to Microsoft OAuth.");
    }
    setLoading(false);
  }

  async function handleSync(e) {
    if (e && e.preventDefault) e.preventDefault();
    const targetEmail = email.trim();
    const targetPassword = password.trim();

    if (!targetEmail || !targetPassword) {
      setError("Please enter your email and password (or App Password).");
      return;
    }
    setError("");
    setLoading(true);
    setStep(`Connecting via IMAP to ${provider.toUpperCase()} (${targetEmail})...`);

    try {
      const res = await fetch(`${API}/fetch-live`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider,
        email: targetEmail,
        password: targetPassword,
        max_emails: parseInt(maxEmails) || 5
      }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to fetch emails");
      }

      const data = await res.json();
      setStep(`Analyzed ${data.count} incoming emails!`);
      if (data.cases && data.cases.length > 0) {
        onCasesFetched(data.count, provider, targetEmail);
      } else {
        setNotice(`Connected to ${provider.toUpperCase()} (${targetEmail}). No unread emails found.`);
      }
      onClose();
    } catch (err) {
      setError(err.message || "Failed to connect. Check credentials.");
    }
    setLoading(false);
    setStep("");
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <form className="scan-modal" onSubmit={handleSync} onClick={e => e.stopPropagation()} style={{ maxWidth: 540 }}>
        <button type="button" className="modal-close" onClick={onClose}>✕</button>
        <p className="eyebrow">LIVE EMAIL INTEGRATION</p>
        <h2>Connect Gmail or Outlook</h2>
        <p style={{ fontSize: 12, color: "var(--muted)", marginBottom: 12 }}>Sync unread incoming emails directly from your inbox for automated forensic threat analysis.</p>

        <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
          <button
            type="button"
            className={`account-provider-btn ${provider === "gmail" ? "active" : ""}`}
            onClick={() => { setProvider("gmail"); setError(""); setMsDevice(null); setMsPolling(false); }}
            style={{ flex: 1, padding: "8px 12px", display: "flex", alignItems: "center", justifyContent: "center", gap: 6, borderRadius: 6, border: "1px solid var(--line)", background: provider === "gmail" ? "var(--line)" : "transparent", cursor: "pointer", color: "var(--ink)", fontWeight: 600 }}
          >
            <Icon name="inbox" size={16} /> Gmail
          </button>
          <button
            type="button"
            className={`account-provider-btn ${provider === "outlook" ? "active" : ""}`}
            onClick={() => { setProvider("outlook"); setError(""); setMsDevice(null); setMsPolling(false); }}
            style={{ flex: 1, padding: "8px 12px", display: "flex", alignItems: "center", justifyContent: "center", gap: 6, borderRadius: 6, border: "1px solid var(--line)", background: provider === "outlook" ? "var(--line)" : "transparent", cursor: "pointer", color: "var(--ink)", fontWeight: 600 }}
          >
            <Icon name="inbox" size={16} /> Outlook
          </button>
        </div>

        {provider === "outlook" ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ background: "rgba(0, 120, 212, 0.08)", border: "1px solid rgba(0, 120, 212, 0.3)", borderRadius: 8, padding: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <Icon name="shield" size={18} />
                <b style={{ color: "#0078D4", fontSize: 13 }}>Microsoft Official OAuth2 Sign-In</b>
              </div>
              <p style={{ fontSize: 11, color: "var(--ink)", lineHeight: 1.5, margin: 0 }}>
                Microsoft requires OAuth2 authentication for live Outlook inboxes. Click below to sign in safely via Microsoft's official login page.
              </p>
              
              {!msDevice ? (
                <button
                  type="button"
                  onClick={handleStartMsOAuth}
                  disabled={loading}
                  style={{ width: "100%", marginTop: 12, padding: "10px 14px", background: "#0078D4", color: "#fff", border: "none", borderRadius: 6, fontWeight: 700, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, fontSize: 13 }}
                >
                  <Icon name="radar" size={16} /> Sign in &amp; Sync Live Outlook Emails
                </button>
              ) : (
                <div style={{ marginTop: 12, padding: 14, background: "var(--bg-card)", border: "1px solid var(--line)", borderRadius: 8 }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <div>
                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--amber)", textTransform: "uppercase", letterSpacing: 0.5 }}>Step 1: Copy Authentication Code</span>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                        <div style={{ fontSize: 20, fontWeight: 800, letterSpacing: 3, color: "var(--amber)", padding: "8px 12px", background: "rgba(255,180,0,0.12)", border: "1px dashed var(--amber)", borderRadius: 6, flex: 1, textAlign: "center" }}>
                          {msDevice.user_code}
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard?.writeText(msDevice.user_code);
                            setCodeCopied(true);
                            setTimeout(() => setCodeCopied(false), 2500);
                          }}
                          style={{ padding: "8px 14px", background: codeCopied ? "var(--mint)" : "var(--accent)", color: "#fff", border: "none", borderRadius: 6, fontWeight: 700, cursor: "pointer", fontSize: 12, display: "flex", alignItems: "center", gap: 6, transition: "all 0.2s ease" }}
                        >
                          <Icon name={codeCopied ? "check" : "copy"} size={15} />
                          {codeCopied ? "Copied!" : "Copy Code"}
                        </button>
                      </div>
                    </div>

                    <div>
                      <span style={{ fontSize: 11, fontWeight: 700, color: "var(--accent)", textTransform: "uppercase", letterSpacing: 0.5 }}>Step 2: Navigate to Microsoft Login</span>
                      <p style={{ fontSize: 11, color: "var(--muted)", margin: "4px 0 8px 0" }}>
                        Click the button below to open Microsoft's official login page in a new tab:
                      </p>
                      <a
                        href={msDevice.verification_uri}
                        target="_blank"
                        rel="noreferrer"
                        style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, background: "#0078D4", color: "#fff", padding: "10px 16px", borderRadius: 6, textDecoration: "none", fontSize: 13, fontWeight: 700 }}
                      >
                        <Icon name="link" size={15} /> Open {msDevice.verification_uri} ↗
                      </a>
                    </div>

                    <div style={{ padding: "10px 12px", background: "rgba(255,255,255,0.03)", borderRadius: 6, border: "1px solid var(--line)" }}>
                      <p style={{ fontSize: 11, color: "var(--ink)", margin: 0, fontWeight: 600, display: "flex", alignItems: "center", gap: 6 }}>
                        <span className="scan-spinner" style={{ width: 14, height: 14 }} />
                        Step 3 &amp; 4: Enter Code &amp; Approve
                      </p>
                      <p style={{ fontSize: 10, color: "var(--muted)", margin: "4px 0 0 0", lineHeight: 1.4 }}>
                        Paste code <b>{msDevice.user_code}</b> on Microsoft's page and click <b>Approve</b>. MailShield is listening in real-time and will automatically import your live unread Outlook emails as soon as approved!
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <details style={{ fontSize: 11, color: "var(--muted)" }}>
              <summary style={{ cursor: "pointer", color: "var(--ink)", fontWeight: 600 }}>Or connect via custom IMAP password</summary>
              <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 10 }}>
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="your-email@outlook.com"
                  disabled={loading}
                  style={{ width: "100%", padding: "10px 12px", background: "var(--bg-card)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--ink)" }}
                />
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Outlook Password / App Password"
                  disabled={loading}
                  style={{ width: "100%", padding: "10px 12px", background: "var(--bg-card)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--ink)" }}
                />
              </div>
            </details>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="your-email@gmail.com"
              disabled={loading}
              style={{ width: "100%", padding: "10px 12px", background: "var(--bg-card)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--ink)" }}
            />
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Google App Password (16 characters)"
              disabled={loading}
              style={{ width: "100%", padding: "10px 12px", background: "var(--bg-card)", border: "1px solid var(--line)", borderRadius: 6, color: "var(--ink)" }}
            />
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
              <span style={{ fontSize: 11, color: "var(--muted)" }}>Max emails to fetch:</span>
              <select
                value={maxEmails}
                onChange={e => setMaxEmails(e.target.value)}
                disabled={loading}
                style={{ padding: "4px 8px", background: "var(--bg-card)", border: "1px solid var(--line)", borderRadius: 4, color: "var(--ink)" }}
              >
                <option value={3}>3 emails</option>
                <option value={5}>5 emails</option>
                <option value={10}>10 emails</option>
              </select>
            </div>

            <div style={{ background: "rgba(255,255,255,0.03)", padding: 12, borderRadius: 6, border: "1px solid var(--line)", marginTop: 8, fontSize: 11, color: "var(--muted)" }}>
              <b style={{ color: "var(--amber)" }}>🔑 Gmail Authentication Requirement:</b>
              <ol style={{ paddingLeft: 16, margin: "6px 0 0 0", lineHeight: 1.5 }}>
                <li>Enable 2-Step Verification on your Google Account.</li>
                <li>Go to <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noreferrer" style={{ color: "var(--coral)", textDecoration: "underline" }}>myaccount.google.com/apppasswords</a></li>
                <li>Generate a 16-character <b>App Password</b> and paste it above.</li>
              </ol>
            </div>
          </div>
        )}

        {step && <div className="scan-step"><span className="scan-spinner" />{step}</div>}
        {error && (
          <div className="scan-error" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <div><Icon name="alert" size={13} /> {error}</div>
          </div>
        )}

        <div className="modal-actions" style={{ marginTop: 16, display: "flex", justifyContent: "flex-end", gap: 10 }}>
          <button type="button" className="cancel" onClick={onClose} disabled={loading}>Cancel</button>
          <button className="scan-button" type="submit" disabled={loading}>
            <Icon name="radar" size={16} /> {loading ? "Syncing..." : "Sync Live Emails"}
          </button>
        </div>
      </form>
    </div>
  );
}

export default function App() {
  const [active, setActive] = useState("Overview");
  const [dark, setDark] = useState(() => localStorage.getItem("mailshield_theme") === "dark");

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("mailshield_theme", dark ? "dark" : "light");
  }, [dark]);

  function toggleTheme() {
    setDark(d => !d);
  }
  const [cases, setCases] = useState([]);
  const [workspaceMenuOpen, setWorkspaceMenuOpen] = useState(false);
  const [workspaces, setWorkspaces] = useState([]);
  const [activeWs, setActiveWs] = useState(() => localStorage.getItem("mailshield_ws") || null);
  const [selected, setSelected] = useState(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [stats, setStats] = useState(null);
  const [threatIntel, setThreatIntel] = useState(null);
  const [infraNodes, setInfraNodes] = useState(null);
  const [caseHistory, setCaseHistory] = useState(null);
  const [query, setQuery] = useState("");
  const [scanOpen, setScanOpen] = useState(false);
  const [connectOpen, setConnectOpen] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [notice, setNotice] = useState("");
  const [location, setLocation] = useState(null);
  const [locationStatus, setLocationStatus] = useState("idle");
  const [hackerOpen, setHackerOpen] = useState(false);
  const [lastSyncedAt, setLastSyncedAt] = useState(null);

  async function refreshData({ keepSelection = true } = {}) {
    try {
      const wsQ = activeWs ? `?ws=${encodeURIComponent(activeWs)}` : "";
      const [casesData, statsData, tiData, infraData, histData] = await Promise.all([
        apiGet(`/cases${wsQ}`), apiGet(`/stats${wsQ}`), apiGet("/threat-intel"),
        apiGet("/infrastructure"), apiGet(`/case-history${wsQ}`),
      ]);
      setCases(casesData);
      setStats(statsData);
      setThreatIntel(tiData);
      setInfraNodes(infraData);
      setCaseHistory(histData);
      setLastSyncedAt(new Date().toISOString());
      setSelected(prev => {
        if (!keepSelection || !prev) return casesData[0] || null;
        return casesData.find(c => c.id === prev.id) || casesData[0] || null;
      });
    } catch {
      setNotice("Backend unreachable. Is the API running on port 8000?");
    }
  }

  useEffect(() => {
    refreshData({ keepSelection: false });
    loadWorkspaces();
  }, []);

  async function loadWorkspaces() {
    try {
      setWorkspaces(await apiGet("/workspaces"));
    } catch { /* dropdown simply stays empty if backend is down */ }
  }

  function switchWorkspace(slugOrWs) {
    const slug = typeof slugOrWs === "string" ? slugOrWs : slugOrWs?.slug;
    setActiveWs(slug);
    localStorage.setItem("mailshield_ws", slug);
    setWorkspaceMenuOpen(false);
    refreshData({ keepSelection: false });
    setActive("Overview");
    const ws = workspaces.find(w => w.slug === slug);
    setNotice(ws ? `Workspace opened: ${ws.name}` : "Global view restored");
  }

  function resetWorkspace() {
    setActiveWs(null);
    localStorage.removeItem("mailshield_ws");
    setWorkspaceMenuOpen(false);
    refreshData({ keepSelection: false });
    setActive("Overview");
    setNotice("Showing all threat domains (global view)");
  }

  const activeWorkspace = workspaces.find(w => w.slug === activeWs);

  async function removeWorkspaceById(id) {
    try {
      const res = await fetch(`${API}/workspaces/${id}`, { method: "DELETE" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || "Could not remove domain");
      await loadWorkspaces();
      setNotice("Community threat domain removed");
    } catch (err) {
      setNotice(err.message);
    }
  }

  useEffect(() => {
    if (!selected?.id) { setSelectedAnalysis(null); return; }
    let cancelled = false;
    apiGet(`/analysis/${selected.id}`)
      .then(a => { if (!cancelled) setSelectedAnalysis(a); })
      .catch(() => { if (!cancelled) setSelectedAnalysis(null); });
    return () => { cancelled = true; };
  }, [selected?.id]);

  const visibleCases = cases.filter(item => `${item.sender} ${item.subject}`.toLowerCase().includes(query.toLowerCase()));

  function handleScanResult(data) {
    setScanResult(data);
    refreshData();
  }

  async function handleResolveCase(caseId, action = "Blocked · Resolved in SOC") {
    try {
      const res = await fetch(`${API}/cases/${caseId}/resolve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, analyst: "AS" }),
      });
      if (res.ok) {
        const data = await res.json();
        setNotice(`Case ${caseId} resolved: ${action}`);
        if (data.case) {
          setCaseHistory(prev => (prev ? [data.case, ...prev] : [data.case]));
        }
      }
    } catch {
      setNotice(`Failed to resolve case ${caseId}`);
    }
    refreshData();
  }

  function handleLiveCasesFetched(fetchedCount, provider, accountEmail) {
    setNotice(`Synced ${fetchedCount} live emails from ${provider.toUpperCase()} (${accountEmail})`);
    setActive("Overview");
    refreshData();
  }


  function addCaseFromScan(data) {
    setNotice(`New case added${data.case_id ? `: ${data.case_id}` : ""} · Score ${dash(data.score)}`);
    setActive("Overview");
    refreshData();
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
    { label: "Workspaces", icon: "server" },
    { label: "Email Queue", icon: "inbox", count: cases.length },
    { label: "Threat Intel", icon: "radar" },
    { label: "Infrastructure", icon: "map" },
    { label: "Case History", icon: "clock" },
  ];

  // Real indicators extracted from the selected case's stored analysis
  const analysis = selectedAnalysis;
  const indicators = (() => {
    if (!analysis) return [];
    const out = [];
    const whoisDomain = analysis.whois?.domain;
    if (whoisDomain && whoisDomain !== "Unknown") {
      out.push({ type: "DOMAIN", value: whoisDomain, note: dash(analysis.whois.registrar), icon: "link", tone: analysis.score >= 55 ? "red" : "green" });
    }
    for (const g of (analysis.geo || [])) {
      if (!g.ip) continue;
      out.push({
        type: "IP ADDRESS",
        value: g.ip,
        note: `${g.city || "—"}, ${g.country || "—"}`,
        icon: "map",
        tone: g.tor ? "red" : g.vpn ? "orange" : "yellow",
      });
    }
    for (const u of (analysis.urls || []).slice(0, 2)) {
      out.push({ type: "URL", value: u.slice(0, 44) + (u.length > 44 ? "…" : ""), note: "Extracted from body", icon: "link", tone: "orange" });
    }
    for (const a of (analysis.attachments || []).filter(x => x.dangerous)) {
      out.push({ type: "ATTACHMENT", value: a.filename, note: `${a.extension} · dangerous extension`, icon: "file", tone: "red" });
    }
    return out.slice(0, 4);
  })();

  // Relay path reconstructed from real Received headers of the selected email
  const relayPath = (() => {
    if (!analysis) return null;
    const hops = (analysis.hops || []).slice(0, 3).reverse();
    if (hops.length === 0) return null;
    const originIp = analysis.originating_ip || {};
    return hops.map((h, i) => ({
      label: i === hops.length - 1 && originIp.ip === h.ip ? "ORIGIN LIKELY" : `RELAY ${String(i + 1).padStart(2, "0")}`,
      host: h.host || "—",
      ip: h.ip || "—",
      safe: i === 0,
      danger: i === hops.length - 1,
    }));

  })();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand" role="button" tabIndex={0} style={{ cursor: "pointer" }} onClick={() => setActive("Overview")} onKeyDown={e => { if (e.key === "Enter") setActive("Overview"); }}><span className="brand-mark"><Icon name="shield" size={22} /></span><span>Mail<span className="brand-dot">Shield</span><small>FORENSIC INTELLIGENCE</small></span></div>
        <div className="workspace ws-wrap" role="button" tabIndex={0} style={{ cursor: "pointer" }} onClick={() => setWorkspaceMenuOpen(o => !o)} onKeyDown={e => { if (e.key === "Enter") setWorkspaceMenuOpen(o => !o); }}>
          <span className="workspace-avatar">{activeWorkspace ? (activeWorkspace.name || "?").replace(/[^a-zA-Z0-9]/g, "").slice(0, 2).toUpperCase() : "ALL"}</span>
          <span><b>{activeWorkspace?.name || "All Domains"}</b><small>{activeWorkspace ? "Threat domain workspace" : "Global threat view"}</small></span>
          <span style={{ marginLeft: "auto", color: "#789095", display: "inline-flex", transform: workspaceMenuOpen ? "rotate(180deg)" : "rotate(90deg)", transition: "transform .15s" }}><Icon name="chevron" size={14} /></span>
        </div>
        {workspaceMenuOpen && (
          <>
            <button className="ws-backdrop" aria-label="Close menu" onClick={() => setWorkspaceMenuOpen(false)} />
            <div className="ws-menu">
              <p>THREAT DOMAIN HUB</p>
              {!activeWs && (
                <div className="ws-item active">
                  <span className="ws-open"><Icon name="check" size={14} /> <span>All domains · global</span></span>
                </div>
              )}
              {workspaces.filter(w => w.slug !== activeWs).map(w => (
                <div key={w.id} className="ws-item">
                  <button className="ws-open" title={`Open “${w.name}”`} onClick={() => switchWorkspace(w.slug)}>
                    <Icon name={w.icon} size={14} /> <span>{w.name}</span>
                  </button>
                  {w.is_custom && !w.total_cases && (
                    <button className="ws-remove" title={`Remove “${w.name}”`} onClick={() => removeWorkspaceById(w.id)}>
                      <Icon name="x" size={13} />
                    </button>
                  )}
                </div>
              ))}
              {!workspaces.length && <p style={{ margin: "2px 9px 8px", color: "#9fb1b1", fontFamily: "'DM Sans',sans-serif", fontSize: 11 }}>Loading domains…</p>}
              <p style={{ borderTop: "1px solid #30434b", marginTop: 6, paddingTop: 8 }}>QUICK LINKS</p>
              <button className="ws-link" onClick={() => { setActive("Workspaces"); setWorkspaceMenuOpen(false); }}><Icon name="server" size={15} /> Manage domains</button>
              <button className="ws-link" onClick={() => { setActive("Overview"); setWorkspaceMenuOpen(false); }}><Icon name="radar" size={15} /> Dashboard</button>
              <button className="ws-link" onClick={() => { setActive("Settings"); setWorkspaceMenuOpen(false); }}><Icon name="settings" size={15} /> Settings</button>
              <button className="ws-link" onClick={() => { refreshData(); loadWorkspaces(); setWorkspaceMenuOpen(false); }}><Icon name="zap" size={15} /> Refresh data</button>
            </div>
          </>
        )}
        <p className="nav-label">WORKSPACE</p>
        <nav>{nav.map(item => <button key={item.label} className={active === item.label ? "nav-item active" : "nav-item"} onClick={() => setActive(item.label)}><Icon name={item.icon} size={17} /><span>{item.label}</span>{item.count && <em>{item.count}</em>}</button>)}</nav>
        <p className="nav-label lower">SYSTEM</p>
        <button className="nav-item" onClick={toggleTheme}><Icon name={dark ? "sun" : "moon"} size={17} /><span>{dark ? "Light Mode" : "Dark Mode"}</span></button>
        <button className={active === "Settings" ? "nav-item active" : "nav-item"} onClick={() => setActive("Settings")}><Icon name="settings" size={17} /><span>Settings</span></button>
        <div className="sidebar-footer"><span className="online-dot" /><div><b>All systems operational</b><small>Last synced {timeAgo(lastSyncedAt)}</small></div></div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div><span className="crumb">SECURITY OPERATIONS</span><span className="slash">/</span><b>{active}</b></div>
          <div className="top-actions"><span className="live"><i /> Live monitoring</span><button className="avatar">AS</button></div>
        </header>
        <div className="content">
          {active !== "Overview" && (
            <div>
              {active === "Email Queue" && <EmailQueue cases={cases} onSelectCase={c => { setSelected(c); setActive("Overview"); }} onAnalyze={() => setScanOpen(true)} />}
              {active === "Threat Intel" && <ThreatIntel data={threatIntel} />}
              {active === "Infrastructure" && <Infrastructure nodes={infraNodes} />}
              {active === "Case History" && <CaseHistory history={caseHistory} />}
              {active === "Workspaces" && <Workspaces workspaces={workspaces} activeWs={activeWs} onOpen={switchWorkspace} onReset={resetWorkspace} onChanged={loadWorkspaces} />}
              {active === "Settings" && <Settings setNotice={setNotice} />}
            </div>
          )}
          {active === "Overview" && (
            <div>
              <section className="welcome">
                <div>
                  <p className="eyebrow">{new Date().toLocaleDateString("en-US", { weekday: "long", day: "numeric", month: "long", year: "numeric" }).toUpperCase()} <span className="pulse" /></p>
                  <h1>{`Good ${new Date().getHours() < 12 ? "morning" : new Date().getHours() < 17 ? "afternoon" : "evening"}, Analyst.`}</h1>
                  <p className="lede">Here is what your intelligence workspace has surfaced today.</p>
                </div>
                <div style={{ display: "flex", gap: 10 }}>
                  <button className="scan-button" onClick={() => setConnectOpen(true)} style={{ background: "var(--amber)", color: "#111", border: "none" }}><Icon name="radar" size={17} /> Sync Live Mail</button>
                  <button className="scan-button" onClick={() => setScanOpen(true)}><Icon name="upload" size={17} /> Analyze email</button>
                </div>
              </section>
              {notice && <div className="notice" onClick={() => setNotice("")}><Icon name="shield" size={16} />{notice}{location && <small className="location-coordinates">{location.latitude.toFixed(5)}, {location.longitude.toFixed(5)} · ±{location.accuracy}m</small>}<span>Dismiss</span></div>}
              <section className="metric-grid">
                <div className="metric"><span className="metric-icon coral"><Icon name="inbox" size={17} /></span><div><small>EMAILS ANALYZED</small><strong>{stats ? (stats.emails_analyzed ?? "—") : "—"}</strong><p><b>{dash(stats?.new_threats_24h)}</b> analyzed in last 24h</p></div><span className="spark coral-spark" /></div>
                <div className="metric"><span className="metric-icon amber"><Icon name="radar" size={17} /></span><div><small>THREATS DETECTED</small><strong>{stats ? (stats.threats_detected ?? "—") : "—"}</strong><p><b>+{dash(stats?.new_threats_24h)}</b> new in 24 hours</p></div><span className="spark amber-spark" /></div>
                <div className="metric"><span className="metric-icon mint"><Icon name="shield" size={17} /></span><div><small>CASES RESOLVED</small><strong>{stats ? (stats.resolution_rate != null ? `${stats.resolution_rate}%` : "—") : "—"}</strong><p>resolution rate · all time</p></div><span className="spark mint-spark" /></div>
                <div className="metric"><span className="metric-icon blue"><Icon name="map" size={17} /></span><div><small>IOC MATCHES</small><strong>{stats ? (stats.ioc_matches ?? "—") : "—"}</strong><p><b>{dash(stats?.high_confidence_hits)}</b> malicious indicators</p></div><span className="spark blue-spark" /></div>
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
                    <button key={item.id} className={`case-row ${selected?.id === item.id ? "selected" : ""}`} onClick={() => setSelected(item)}>
                      <span className={`case-avatar ${item.accent}`}>{item.initials || "EM"}</span>
                      <span className="case-info"><b>{item.sender || "—"}</b><span>{item.subject || "(No subject)"}</span><small>{item.id} · {timeAgo(item.received_at)}</small></span>
                      <span className={`severity ${item.accent}`}>{item.label}</span>
                      <span className="row-score">{item.score ?? "—"}</span>
                      <Icon name="more" size={17} />
                    </button>
                  ))}
                  {visibleCases.length === 0 && (
                    <p style={{ padding: "20px", color: "var(--muted)", fontSize: 12 }}>No active cases in priority queue. Analyze an email or sync live mail to populate the queue.</p>
                  )}
                </div>
                {selected && (
                  <article className="detail-panel">
                    <div className="detail-top">
                      <div><p className="eyebrow">SELECTED INVESTIGATION · {selected.id}</p><h2>{selected.subject || "(No subject)"}</h2><p className="from">From <b>{selected.sender || "—"}</b> <span>·</span> {timeAgo(selected.received_at)}</p></div>
                      <ScoreRing score={selected.score} />
                    </div>
                    <div className="risk-summary">
                      <span className="status-pill"><i /> {selected.label} RISK</span>
                      <span>Confidence <b>{analysis?.origin_attribution?.confidence != null ? `${analysis.origin_attribution.confidence}%` : "—"}</b></span>
                      <button className="hacker-insights-btn" style={{ background: "var(--mint)", color: "#111" }} onClick={() => handleResolveCase(selected.id)}>
                        <Icon name="check" size={14} /> Resolve Case
                      </button>
                      <button className="hacker-insights-btn" onClick={() => setHackerOpen(true)}><Icon name="skull" size={14} /> Hacker Insights</button>
                    </div>
                  <div className="detail-section">
                    <div className="subhead"><b>Relay path reconstruction</b><span>{relayPath ? `${relayPath.length} hops` : analysis?.hops?.length === 0 ? "no Received headers stored" : "loading…"}</span></div>
                    {relayPath ? (
                      <div className="relay">
                        {relayPath.map((hop, i) => (
                          <Fragment key={i}>
                            {i > 0 && <div className={`connector ${hop.danger ? "danger" : ""}`}><i /><span>{hop.danger ? "final hop" : "relayed via"}</span></div>}
                            <div className="node">
                              <span className={`node-icon ${hop.safe ? "safe" : hop.danger ? "danger" : "warn"}`}><Icon name={hop.safe ? "inbox" : hop.danger ? "radar" : "server"} size={16} /></span>
                              <small>{i === 0 ? "ORIGIN" : hop.label}</small>
                              <b>{hop.host}</b>
                              <em>{hop.ip}</em>
                            </div>
                          </Fragment>
                        ))}
                      </div>
                    ) : (
                      <p style={{ padding: "10px 0", color: "var(--muted)", fontSize: 11 }}>Relay path unavailable — no header data stored for this case.</p>
                    )}
                  </div>
                  <div className="detail-section">
                    <div className="subhead"><b>Extracted indicators</b><span>{indicators.length > 0 ? `${indicators.length} found` : ""}</span></div>
                    <div className="indicator-grid">
                      {indicators.map(item => (
                        <div className="indicator" key={item.type + item.value}>
                          <span className={`indicator-icon ${item.tone}`}><Icon name={item.icon} size={15} /></span>
                          <div><small>{item.type}</small><b>{item.value}</b><span>{item.note}</span></div>
                          <button title="Copy" onClick={() => { navigator.clipboard?.writeText(item.value); setNotice(`${item.value} copied`); }}><Icon name="copy" size={14} /></button>
                        </div>
                      ))}
                    </div>
                    {indicators.length === 0 && (
                      <p style={{ color: "var(--muted)", fontSize: 11 }}>No indicators extracted for this case yet.</p>
                    )}
                  </div>
                </article>
              )}
              </section>
            </div>
          )}
        </div>
      </main>

      {connectOpen && <ConnectAccountModal onClose={() => setConnectOpen(false)} onCasesFetched={handleLiveCasesFetched} setNotice={setNotice} />}
      {scanOpen && <ScanModal onClose={() => setScanOpen(false)} onResult={handleScanResult} />}
      {scanResult && <ScanResultModal result={scanResult} onClose={() => setScanResult(null)} onAddCase={addCaseFromScan} />}
      {hackerOpen && <HackerInsightsModal case_={selected} onClose={() => setHackerOpen(false)} />}
    </div>
  );
}
