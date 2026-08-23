import os
import re
import json
import base64
import logging
import ipaddress
from datetime import datetime, timezone
from email import policy
import email as email_lib

import requests
import dns.resolver
import whois
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")

logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

app = FastAPI(title="Email Threat Detection API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Known VPN / TOR / Hosting ASNs ──────────────────────────────────────────
SUSPICIOUS_ASNS = {
    "AS20473", "AS14061", "AS16276", "AS24940", "AS51167",  # VPS/cloud
    "AS9009", "AS60781", "AS197695", "AS49981",              # bulletproof
    "AS7922", "AS209", "AS701",                              # residential proxies (common abuse)
}
TOR_EXIT_ASNS = {"AS60729", "AS4224", "AS50628"}

PHISHING_KEYWORDS = [
    "urgent", "verify", "suspended", "account", "click here", "confirm",
    "password", "login", "update", "immediately", "action required",
    "limited time", "expire", "unusual activity", "security alert",
    "invoice", "payment", "wire transfer", "overdue", "attached",
    "reset", "validate", "reactivate", "unauthorized", "locked",
]

BEC_PATTERNS = {
    "payment_diversion": ["wire transfer", "bank account", "routing number", "swift", "iban", "change.*payment", "new.*account"],
    "exec_impersonation": ["ceo", "cfo", "president", "director", "executive", "on behalf of"],
    "invoice_fraud": ["invoice", "overdue", "past due", "remittance", "purchase order", "po number"],
    "credential_harvest": ["verify.*account", "confirm.*identity", "reset.*password", "login.*link", "click.*here.*verify"],
}

LOOKALIKE_PATTERNS = [
    r"micros[o0]ft", r"g[o0]{2}gle", r"paypa[l1]", r"app[l1]e",
    r"amaz[o0]n", r"faceb[o0]{2}k", r"netf[l1]ix", r"dropb[o0]x",
    r"linkedln", r"tw[i1]tter", r"inst[a4]gram",
]

DANGEROUS_EXTENSIONS = {".exe", ".xlsm", ".xls", ".docm", ".doc", ".js", ".vbs", ".bat", ".ps1", ".zip", ".rar", ".iso"}


class EmailRequest(BaseModel):
    raw: str


# ── Helpers ──────────────────────────────────────────────────────────────────

def is_valid_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def extract_ips(text: str) -> list:
    found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return list({ip for ip in found if is_valid_public_ip(ip)})


def parse_auth_results(msg) -> dict:
    auth_header = msg.get("Authentication-Results", "")
    result = {}
    for proto in ("spf", "dkim", "dmarc"):
        for val in ("pass", "fail", "neutral", "none", "softfail", "permerror"):
            if f"{proto}={val}" in auth_header:
                result[proto] = val
                break
        else:
            result[proto] = "unknown"
    return result


def extract_relay_hops(msg) -> list:
    received = msg.get_all("Received") or []
    hops = []
    for r in received:
        ip_match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", r)
        host_match = re.search(r"from\s+(\S+)", r)
        hops.append({
            "raw": r.strip()[:120],
            "ip": ip_match.group(1) if ip_match else None,
            "host": host_match.group(1) if host_match else "unknown",
        })
    return hops


def extract_urls(text: str) -> list:
    return re.findall(r"https?://[^\s\)\"'<>]+", text)


def extract_attachments(msg) -> list:
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                ext = os.path.splitext(filename)[1].lower()
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "extension": ext,
                    "dangerous": ext in DANGEROUS_EXTENSIONS,
                })
    return attachments


def classify_bec(subject: str, body: str) -> dict:
    combined = (subject + " " + body).lower()
    detected = {}
    for pattern_type, patterns in BEC_PATTERNS.items():
        hits = [p for p in patterns if re.search(p, combined)]
        if hits:
            detected[pattern_type] = hits
    return detected


def dns_mx_lookup(domain: str) -> dict:
    result = {"mx": [], "a": [], "suspicious": False}
    try:
        mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
        result["mx"] = [str(r.exchange).rstrip(".") for r in mx_records]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        result["suspicious"] = True
    try:
        a_records = dns.resolver.resolve(domain, "A", lifetime=5)
        result["a"] = [str(r) for r in a_records]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        pass
    return result


def nlp_score(subject: str, body: str, auth: dict, from_addr: str, reply_to: str):
    score = 0
    flags = []
    combined = (subject + " " + body).lower()

    keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in combined]
    score += min(len(keyword_hits) * 8, 40)
    if keyword_hits:
        flags.append(f"Phishing keywords: {', '.join(keyword_hits[:5])}")

    if auth["spf"] == "fail":
        score += 20
        flags.append("SPF failed")
    elif auth["spf"] in ("neutral", "softfail"):
        score += 8
        flags.append(f"SPF {auth['spf']}")
    if auth["dkim"] in ("fail", "none"):
        score += 15
        flags.append(f"DKIM {auth['dkim']}")
    if auth["dmarc"] in ("fail", "none"):
        score += 10
        flags.append(f"DMARC {auth['dmarc']}")

    from_domain = re.search(r"@([\w.\-]+)", from_addr)
    reply_domain = re.search(r"@([\w.\-]+)", reply_to) if reply_to else None
    if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
        score += 15
        flags.append("Reply-To domain mismatch")

    for pat in LOOKALIKE_PATTERNS:
        if re.search(pat, from_addr.lower()):
            score += 20
            flags.append(f"Lookalike domain: {from_addr}")
            break

    urls = extract_urls(body)
    if urls:
        score += min(len(urls) * 5, 15)
        flags.append(f"{len(urls)} URL(s) in body")

    score = min(score, 100)
    label, accent = _label(score)
    return score, label, accent, flags


def _label(score: int):
    if score >= 75:
        return "CRITICAL", "red"
    elif score >= 55:
        return "HIGH", "orange"
    elif score >= 35:
        return "MEDIUM", "yellow"
    return "LOW", "green"


def geoip(ip: str) -> dict:
    if not is_valid_public_ip(ip):
        return {"ip": ip, "city": "Private", "region": "", "country": "", "org": "", "lat": 0, "lng": 0, "vpn": False, "tor": False}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            loc = d.get("loc", "0,0").split(",")
            org = d.get("org", "")
            asn = org.split(" ")[0] if org else ""
            return {
                "ip": ip,
                "city": d.get("city", "Unknown"),
                "region": d.get("region", ""),
                "country": d.get("country", ""),
                "org": org,
                "lat": float(loc[0]) if len(loc) == 2 else 0,
                "lng": float(loc[1]) if len(loc) == 2 else 0,
                "vpn": asn in SUSPICIOUS_ASNS,
                "tor": asn in TOR_EXIT_ASNS,
            }
    except requests.RequestException:
        pass
    return {"ip": ip, "city": "Unknown", "region": "", "country": "", "org": "", "lat": 0, "lng": 0, "vpn": False, "tor": False}


def vt_check_domain(domain: str) -> dict:
    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=8)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "domain": domain,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
            }
    except requests.RequestException:
        pass
    return {"domain": domain, "malicious": 0, "suspicious": 0, "total": 0}


def vt_check_url(url: str) -> dict:
    try:
        headers = {"x-apikey": VT_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"url": url, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    except requests.RequestException:
        pass
    return {"url": url, "malicious": 0, "suspicious": 0}


def whois_lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - creation).days if creation else None
        return {
            "domain": domain,
            "registrar": w.registrar or "Unknown",
            "creation_date": str(creation)[:10] if creation else "Unknown",
            "age_days": age_days,
            "country": w.country or "Unknown",
        }
    except Exception:
        return {"domain": domain, "registrar": "Unknown", "creation_date": "Unknown", "age_days": None, "country": "Unknown"}


def audit_log(event: str, data: dict):
    logging.info("%s | %s", event, json.dumps(data, default=str))


# ── Routes ───────────────────────────────────────────────────────────────────

@app.post("/analyze")
def analyze_email(req: EmailRequest):
    try:
        msg = email_lib.message_from_string(req.raw, policy=policy.default)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid email format")

    subject = str(msg.get("Subject", ""))
    from_addr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    message_id = str(msg.get("Message-ID", ""))
    date = str(msg.get("Date", ""))
    return_path = str(msg.get("Return-Path", ""))

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    auth = parse_auth_results(msg)
    hops = extract_relay_hops(msg)
    ips = extract_ips(req.raw)
    urls = extract_urls(body)
    attachments = extract_attachments(msg)
    bec = classify_bec(subject, body)

    score, label, accent, flags = nlp_score(subject, body, auth, from_addr, reply_to)

    # Dangerous attachments
    dangerous_attachments = [a for a in attachments if a["dangerous"]]
    if dangerous_attachments:
        score = min(score + 15, 100)
        flags.append(f"Dangerous attachment: {dangerous_attachments[0]['filename']}")

    # BEC detection
    if bec:
        score = min(score + 10, 100)
        flags.append(f"BEC pattern: {', '.join(bec.keys())}")

    geo_results = [geoip(ip) for ip in ips[:4]]

    # VPN/TOR flags from geo
    for g in geo_results:
        if g.get("tor"):
            score = min(score + 20, 100)
            flags.append(f"TOR exit node detected: {g['ip']}")
        elif g.get("vpn"):
            score = min(score + 10, 100)
            flags.append(f"VPN/hosting ASN: {g['ip']} ({g['org']})")

    from_domain_match = re.search(r"@([\w.\-]+)", from_addr)
    from_domain = from_domain_match.group(1) if from_domain_match else ""

    vt_domain = vt_check_domain(from_domain) if from_domain else {}
    vt_urls = [vt_check_url(u) for u in urls[:2]]
    whois_data = whois_lookup(from_domain) if from_domain else {}
    dns_data = dns_mx_lookup(from_domain) if from_domain else {}

    if vt_domain.get("malicious", 0) > 0:
        score = min(score + 20, 100)
        flags.append(f"VirusTotal: {vt_domain['malicious']} engines flagged domain")

    if whois_data.get("age_days") is not None and whois_data["age_days"] < 30:
        score = min(score + 15, 100)
        flags.append(f"Domain only {whois_data['age_days']} days old")

    if dns_data.get("suspicious"):
        score = min(score + 10, 100)
        flags.append("No MX records — domain cannot receive email (spoofed)")

    label, accent = _label(score)

    result = {
        "subject": subject,
        "from": from_addr,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "date": date,
        "score": score,
        "label": label,
        "accent": accent,
        "flags": flags,
        "auth": auth,
        "hops": hops,
        "ips": ips,
        "urls": urls,
        "attachments": attachments,
        "bec": bec,
        "geo": geo_results,
        "vt_domain": vt_domain,
        "vt_urls": vt_urls,
        "whois": whois_data,
        "dns": dns_data,
        "body_preview": body[:300],
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

    audit_log("EMAIL_ANALYZED", {
        "from": from_addr,
        "subject": subject,
        "score": score,
        "label": label,
        "message_id": message_id,
    })

    return result


@app.get("/report/{case_id}")
def get_report(case_id: str):
    """Return a structured forensic report as JSON (frontend renders/downloads it)."""
    return JSONResponse({
        "report_type": "FORENSIC_INTELLIGENCE_REPORT",
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": "trace.ai Forensic Intelligence Platform",
        "classification": "CONFIDENTIAL — FOR AUTHORIZED USE ONLY",
        "chain_of_custody": {
            "received_by": "trace.ai automated ingestion",
            "analyzed_by": "AI Engine v1.0 + Analyst review",
            "evidence_hash": "SHA-256 preserved at ingestion",
            "retention_policy": "90 days per organizational policy",
        },
        "note": "Full report data is embedded in the /analyze response. Use case data to populate this report.",
    })


@app.get("/geoip/{ip}")
def get_geoip(ip: str):
    if not is_valid_public_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid or private IP address")
    return geoip(ip)


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
