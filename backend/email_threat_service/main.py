import os
import re
import json
import base64
import hashlib
import secrets
import logging
import ipaddress
import asyncio
from datetime import datetime, timezone
from email import policy
import email as email_lib
from collections import Counter, defaultdict
from difflib import SequenceMatcher

import requests
import dns.resolver
import whois
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv
import db
from mail_fetcher import (
    test_connection,
    fetch_unread_emails,
    start_outlook_device_code,
    poll_outlook_token,
    fetch_outlook_live_emails_via_graph
)

load_dotenv()

try:
    db.init_db()
    logging.info("Database schema ready")
except Exception as exc:
    logging.error(
        "DATABASE NOT REACHABLE — set the DATABASE_URL environment variable "
        "to your cloud Postgres connection string. Details: %s", exc,
    )

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")

logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

async def _catch_all_errors(request, call_next):
    """Convert any unhandled exception into JSON *inside* the CORS layer so
    the browser can always read the error instead of blocking it."""
    try:
        return await call_next(request)
    except Exception as exc:
        logging.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": f"Internal server error: {exc}"},
        )


app = FastAPI(
    title="Email Threat Detection API",
    middleware=[Middleware(BaseHTTPMiddleware, dispatch=_catch_all_errors)],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        *[
            o.strip()
            for o in os.getenv("ALLOWED_ORIGINS", "").split(",")
            if o.strip()
        ],
    ],
    allow_origin_regex=r"https://[a-z0-9-]+\.onrender\.com",
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Account Connection & Ingestion Models ────────────────────────────────────

class EmailRequest(BaseModel):
    raw: str

class AccountConnectRequest(BaseModel):
    provider: str  # "gmail" or "outlook"
    email: str
    password: str
    custom_host: Optional[str] = None
    custom_port: Optional[int] = 993

class FetchLiveRequest(BaseModel):
    provider: str
    email: str
    password: str
    max_emails: Optional[int] = 5
    custom_host: Optional[str] = None
    custom_port: Optional[int] = 993

class ResolveCaseRequest(BaseModel):
    action: str
    analyst: Optional[str] = "AS"

CONNECTED_ACCOUNTS = []


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

# ── Privacy & Compliance Configuration (SIH Requirement) ─────────────────────

PRIVACY_CONFIG = {
    "retention_days": int(os.getenv("RETENTION_DAYS", 90)),
    "mask_pii": os.getenv("MASK_PII", "true").lower() == "true",
    "pii_patterns": {
        "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "aadhaar": r"\b\d{4}\s\d{4}\s\d{4}\b",
        "pan": r"\b[A-Z]{5}\d{4}[A-Z]\b",
        "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    },
    "evidence_hash_algo": "SHA-256",
}

# ── SSE Real-Time Alert Queue (SIH Requirement: Real-time alerts) ────────────

ALERT_SUBSCRIBERS: list[asyncio.Queue] = []


# ── Evidence & Privacy Helpers ───────────────────────────────────────────────

def compute_evidence_hash(raw_email: str) -> dict:
    raw_bytes = raw_email.encode("utf-8", errors="replace")
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    sha1 = hashlib.sha1(raw_bytes).hexdigest()
    md5 = hashlib.md5(raw_bytes).hexdigest()
    return {
        "algo": "SHA-256",
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "size_bytes": len(raw_bytes),
        "preserved_at": datetime.now(timezone.utc).isoformat(),
    }


def mask_pii(text: str) -> str:
    if not PRIVACY_CONFIG["mask_pii"] or not text:
        return text
    masked = text
    masked = re.sub(PRIVACY_CONFIG["pii_patterns"]["email"], "[EMAIL_MASKED]", masked)
    masked = re.sub(PRIVACY_CONFIG["pii_patterns"]["phone"], "[PHONE_MASKED]", masked)
    masked = re.sub(PRIVACY_CONFIG["pii_patterns"]["credit_card"], "[CARD_MASKED]", masked)
    masked = re.sub(PRIVACY_CONFIG["pii_patterns"]["ssn"], "[SSN_MASKED]", masked)
    masked = re.sub(PRIVACY_CONFIG["pii_patterns"]["aadhaar"], "[AADHAAR_MASKED]", masked)
    masked = re.sub(PRIVACY_CONFIG["pii_patterns"]["pan"], "[PAN_MASKED]", masked)
    return masked


# ── Display-Name Spoofing Detection (SIH Requirement) ────────────────────────

LEGIT_BRAND_NAMES = [
    "microsoft", "google", "apple", "amazon", "paypal", "netflix", "dropbox",
    "facebook", "linkedin", "twitter", "instagram", "whatsapp", "meta",
    "icici", "hdfc", "sbi", "axis", "kotak", "citibank", "hsbc",
    "irs", "it department", "income tax", "gst", "uidai",
    "ceo", "cfo", "director", "hr department", "it support",
]


def detect_display_name_spoofing(from_addr: str, display_name: str = "") -> dict:
    findings = {"is_spoofed": False, "techniques": [], "matched_brand": None, "score_delta": 0}
    full_from = (display_name + " " + from_addr).lower()

    email_match = re.search(r"<([^>]+)>", from_addr) or re.search(r"([\w.\-+]+@[\w.\-]+)", from_addr)
    email_only = email_match.group(1) if email_match else from_addr
    email_domain = re.search(r"@([\w.\-]+)", email_only)
    email_domain = email_domain.group(1).lower() if email_domain else ""

    disp_clean = re.sub(r"[<>\[\]\"]+", "", display_name).strip().lower()

    for brand in LEGIT_BRAND_NAMES:
        if brand in disp_clean and brand not in email_domain:
            sim = SequenceMatcher(None, disp_clean.replace(" ", ""), brand).ratio()
            if sim >= 0.6:
                findings["is_spoofed"] = True
                findings["techniques"].append(f"Display name '{display_name}' impersonates brand '{brand}' (domain: {email_domain or 'unknown'})")
                findings["matched_brand"] = brand
                findings["score_delta"] += 12
                break

    if disp_clean and email_domain:
        disp_tokens = re.findall(r"[a-z0-9]+", disp_clean)
        domain_tokens = re.findall(r"[a-z0-9]+", email_domain)
        if disp_tokens and not any(tok in domain_tokens for tok in disp_tokens if len(tok) >= 4):
            common_biz = ["accounts", "payable", "receivable", "support", "helpdesk", "hr", "payroll", "admin", "billing", "ceo", "cfo", "office", "noreply", "newsletter", "info"]
            if not any(tok in common_biz for tok in disp_tokens if len(tok) >= 4):
                pass

    for pat in LOOKALIKE_PATTERNS:
        if re.search(pat, disp_clean):
            findings["is_spoofed"] = True
            findings["techniques"].append(f"Lookalike pattern in display name: {display_name}")
            findings["score_delta"] += 8
            break

    if "<>" in from_addr or "undisclosed" in full_from:
        findings["techniques"].append("Empty or 'undisclosed' sender")
        findings["score_delta"] += 5

    return findings


# ── URL Obfuscation Detection (SIH Requirement) ──────────────────────────────

def analyze_urls(urls: List[str]) -> List[dict]:
    analyzed = []
    for u in urls:
        info = {
            "url": u,
            "obfuscated": False,
            "techniques": [],
            "redirect_chain": False,
            "has_ip": False,
            "shortened": False,
            "suspicious_tld": False,
        }
        try:
            from urllib.parse import urlparse
            parsed = urlparse(u)
            host = parsed.hostname or ""
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                info["has_ip"] = True
                info["obfuscated"] = True
                info["techniques"].append("Raw IP URL (no domain)")
            shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "adf.ly", "shorte.st", "cutt.ly", "rb.gy"]
            if any(s in host for s in shorteners):
                info["shortened"] = True
                info["obfuscated"] = True
                info["techniques"].append("URL shortener used (hides destination)")
            if re.search(r"(@|%40|#)", parsed.path or "") and not parsed.username:
                info["redirect_chain"] = True
                info["obfuscated"] = True
                info["techniques"].append("@-redirect trick in URL path")
            if "%2f" in u.lower() or "%3a" in u.lower() or re.search(r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}", u):
                info["obfuscated"] = True
                info["techniques"].append("Percent-encoding / character obfuscation")
            if re.search(r"\.zip$|\.xyz$|\.top$|\.work$|\.click$|\.country$|\.stream$|\.gq$|\.cf$|\.ml$|\.ga$", host):
                info["suspicious_tld"] = True
                info["techniques"].append("Suspicious TLD")
            if re.search(r"\d{5,}", host) and not info["has_ip"]:
                info["obfuscated"] = True
                info["techniques"].append("Numbers in domain (typical for DGA/phishing)")
        except Exception:
            pass
        analyzed.append(info)
    return analyzed


# ── Earliest Reliable Originating IP (SIH Requirement) ───────────────────────

def find_originating_ip(hops: List[dict], all_ips: List[str]) -> dict:
    for hop in reversed(hops):
        ip = hop.get("ip")
        if ip and is_valid_public_ip(ip):
            return {"ip": ip, "source": f"Received header (hop)", "hop_raw": hop.get("raw", "")[:80]}
    for ip in all_ips:
        if is_valid_public_ip(ip):
            return {"ip": ip, "source": "Body/header IP extraction", "hop_raw": None}
    return {"ip": None, "source": "No public IP found", "hop_raw": None}


# ── Origin Attribution Type (SIH Requirement) ─────────────────────────────────

def attribute_origin_type(
    auth: dict,
    geo: List[dict],
    whois_data: dict,
    dns_data: dict,
    vt_domain: dict,
    reply_to_mismatch: bool,
    display_spoof: dict,
    relay_hops: List[dict],
) -> dict:
    flags_compromised = 0
    flags_spoofed = 0
    flags_anonymized = 0
    flags_direct = 0
    reasons = []

    if auth["spf"] in ("pass", "softfail") and dns_data.get("mx"):
        flags_compromised += 2
        reasons.append("Sender passed SPF and domain has valid MX — possible compromised account on legitimate infrastructure")
    if auth["dkim"] == "pass":
        flags_compromised += 1
    if whois_data.get("age_days") and whois_data["age_days"] > 365:
        flags_compromised += 1
        reasons.append("Domain is well-established (>1 year) — likely legitimate but compromised")

    if auth["spf"] in ("fail", "none", "permerror", "neutral"):
        flags_spoofed += 2
        reasons.append("SPF failed/none — domain is being spoofed")
    if auth["dkim"] in ("fail", "none"):
        flags_spoofed += 1
    if auth["dmarc"] in ("fail", "none"):
        flags_spoofed += 1
    if dns_data.get("suspicious") or not dns_data.get("mx"):
        flags_spoofed += 2
        reasons.append("Domain has no MX records — cannot receive email (classic spoofed sender)")
    if reply_to_mismatch:
        flags_spoofed += 1
        reasons.append("Reply-To domain differs from From domain")
    if display_spoof.get("is_spoofed"):
        flags_spoofed += 2
        reasons.append("Display-name spoofing detected")
    if whois_data.get("age_days") is not None and whois_data["age_days"] < 30:
        flags_spoofed += 1
        reasons.append(f"Newly registered domain ({whois_data['age_days']} days old)")

    for g in geo:
        if g.get("tor"):
            flags_anonymized += 3
            reasons.append(f"TOR exit node used: {g['ip']}")
        if g.get("vpn"):
            flags_anonymized += 2
            reasons.append(f"VPN/hosting/bulletproof ASN: {g.get('org','')}")
        if g.get("org") and ("bulletproof" in g["org"].lower() or "proxy" in g["org"].lower()):
            flags_anonymized += 1

    if len(relay_hops) <= 1 and vt_domain.get("malicious", 0) == 0 and not display_spoof.get("is_spoofed"):
        flags_direct += 1

    scores = {
        "compromised_account": flags_compromised,
        "spoofed_domain": flags_spoofed,
        "anonymized_infrastructure": flags_anonymized,
        "direct_malicious_actor": flags_direct,
    }
    origin_type = max(scores, key=scores.get)
    total = sum(scores.values()) or 1
    confidence = int(round((scores[origin_type] / total) * 100))

    label_map = {
        "compromised_account": "Likely Compromised Legitimate Account",
        "spoofed_domain": "Spoofed Domain / Forged Sender",
        "anonymized_infrastructure": "Anonymized Infrastructure (VPN/TOR/Proxy)",
        "direct_malicious_actor": "Direct Malicious Actor Environment",
    }

    return {
        "origin_type": origin_type,
        "origin_label": label_map[origin_type],
        "confidence": max(confidence, 40) if total > 0 else 0,
        "scores": scores,
        "reasons": reasons,
    }


# ── Graph-Based Correlation (SIH Requirement) ─────────────────────────────────

def build_correlation_graph(
    from_addr: str,
    from_domain: str,
    reply_to: str,
    return_path: str,
    ips: List[str],
    urls: List[str],
    hops: List[dict],
) -> dict:
    nodes = []
    edges = []

    def add_node(nid, ntype, label, risk="low"):
        if not any(n["id"] == nid for n in nodes):
            nodes.append({"id": nid, "type": ntype, "label": label, "risk": risk})

    def add_edge(src, dst, etype, detail=""):
        edges.append({"source": src, "target": dst, "type": etype, "detail": detail})

    add_node(f"sender:{from_addr}", "EMAIL", from_addr or "unknown-sender")
    if from_domain:
        add_node(f"domain:{from_domain}", "DOMAIN", from_domain, "medium")
        add_edge(f"sender:{from_addr}", f"domain:{from_domain}", "belongs_to", "From domain")

    reply_addr = re.search(r"[\w.\-+]+@[\w.\-]+", reply_to or "")
    if reply_addr:
        ra = reply_addr.group(0)
        add_node(f"reply:{ra}", "EMAIL", ra, "medium")
        add_edge(f"sender:{from_addr}", f"reply:{ra}", "reply_to", "Reply-To address")
        rd = re.search(r"@([\w.\-]+)", ra)
        if rd:
            add_node(f"rdomain:{rd.group(1)}", "DOMAIN", rd.group(1), "medium")
            add_edge(f"reply:{ra}", f"rdomain:{rd.group(1)}", "belongs_to", "Reply-To domain")

    rp = re.search(r"[\w.\-+]+@[\w.\-]+", return_path or "")
    if rp:
        rp_addr = rp.group(0)
        add_node(f"rp:{rp_addr}", "EMAIL", rp_addr, "medium")
        add_edge(f"sender:{from_addr}", f"rp:{rp_addr}", "return_path", "Bounce address")

    for i, hop in enumerate(hops):
        hop_id = f"hop:{i}:{hop.get('ip') or hop.get('host')}"
        add_node(hop_id, "RELAY", hop.get("host") or f"Relay {i+1}", "low")
        if i == 0:
            add_edge(f"sender:{from_addr}", hop_id, "relayed_via", f"Hop {i+1} (closest)")
        else:
            prev = f"hop:{i-1}:{hops[i-1].get('ip') or hops[i-1].get('host')}"
            add_edge(prev, hop_id, "relayed_to", f"Hop {i+1}")
        if hop.get("ip") and is_valid_public_ip(hop["ip"]):
            ip_id = f"ip:{hop['ip']}"
            add_node(ip_id, "IP", hop["ip"], "medium")
            add_edge(hop_id, ip_id, "has_ip", hop.get("host", ""))

    for ip in set(ips[:6]):
        if is_valid_public_ip(ip):
            ip_id = f"ip:{ip}"
            add_node(ip_id, "IP", ip, "medium")
            add_edge(f"sender:{from_addr}", ip_id, "seen_ip", "Observed in transmission")

    for u in urls[:4]:
        url_id = f"url:{hashlib.md5(u.encode()).hexdigest()[:8]}"
        from urllib.parse import urlparse
        host = urlparse(u).hostname or u
        add_node(url_id, "URL", u[:60], "medium")
        add_edge(f"sender:{from_addr}", url_id, "links_to", host)

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_types": Counter(n["type"] for n in nodes),
        }
    }


# ── Campaign Clustering (SIH Requirement) ─────────────────────────────────────

def cluster_into_campaign(
    from_domain: str,
    ips: List[str],
    urls: List[str],
    bec_patterns: dict,
    subject: str,
    score_label: str = "MEDIUM",
    score_accent: str = "yellow",
    ttp_ids: Optional[List[str]] = None,
) -> dict:
    from urllib.parse import urlparse
    url_hosts = [(urlparse(u).hostname or "").lower() for u in urls if urlparse(u).hostname]
    ioc_values = [v for v in [from_domain.lower()] + ips + url_hosts if v]

    matched = db.match_campaign(ioc_values)
    ttp_ids = ttp_ids or []

    if matched:
        db.update_campaign_hit(matched["id"], ioc_values, ttp_ids)
        count = matched["count"] + 1
        window = f"{matched['first_seen'].strftime('%d %b %Y')} – {datetime.now(timezone.utc).strftime('%d %b %Y')}"
        return {
            "matched": True,
            "campaign_id": matched["id"],
            "campaign_name": matched["name"],
            "campaign_risk": matched["risk"],
            "campaign_accent": matched["accent"],
            "similar_emails_in_campaign": count,
            "campaign_window": window,
        }

    new_id = f"CAMP-{hashlib.md5(((subject or '') + (from_domain or '')).encode()).hexdigest()[:6].upper()}"
    name = f"New campaign cluster · {from_domain or 'unknown sender'}"
    db.create_campaign(new_id, name, score_label, score_accent, ioc_values, list(set(ttp_ids)))
    return {
        "matched": False,
        "campaign_id": new_id,
        "campaign_name": name,
        "campaign_risk": score_label,
        "campaign_accent": score_accent,
        "similar_emails_in_campaign": 1,
        "campaign_window": f"First seen {datetime.now(timezone.utc).strftime('%d %b %Y')}",
    }


# ── MITRE ATT&CK Technique Derivation (from real detection flags) ────────────

# ── Threat-domain classification (global hub taxonomy) ───────────────────────

CREDENTIAL_KEYWORDS = (
    "login", "log in", "password", "credentials", "verify your account",
    "confirm your account", "sign in", "reset your password", "unlock",
    "validate your identity", "security check",
)


def classify_workspace(result: dict) -> str:
    """Map an analyzed email to one global threat-domain workspace slug."""
    bec = result.get("bec") or {}
    flags = " ".join((f or "").lower() for f in result.get("flags", []))
    attachments = result.get("attachments") or []

    if bec:
        return "bec"
    if any(a.get("dangerous") for a in attachments) or "dangerous attachment" in flags:
        return "malware"

    spoofed = result.get("display_name_spoofing")
    if spoofed or "lookalike domain" in flags or "exec_impersonation" in (bec or {}) \
            or "reply-to domain mismatch" in flags:
        return "impersonation"

    origin = (result.get("origin_attribution") or {}).get("origin_type")
    if origin == "compromised_account":
        return "account"

    urls = result.get("urls") or []
    if any(k in flags for k in CREDENTIAL_KEYWORDS) and urls:
        return "phishing"
    if "phishing keywords" in flags:
        return "phishing"

    if (result.get("score") or 0) < 25 and not urls:
        return "spam"
    return "general"


def derive_ttps(flags: List[str], bec: dict, origin_attribution: dict) -> List[dict]:
    found: Dict[str, dict] = {}

    def add(tid, name, detail):
        if tid not in found:
            found[tid] = {"id": tid, "name": name, "detail": detail}

    joined = " ".join(f.lower() for f in flags)

    if any("url" in f and ("body" in f or "obfuscation" in f) for f in (x.lower() for x in flags)):
        add("T1566.002", "Spearphishing Link", "Email body contains links to potential lure pages")

    if "dangerous attachment" in joined:
        add("T1566.001", "Spearphishing Attachment", "Malicious file attachment used as initial access vector")
        add("T1204.002", "User Execution: Malicious File", "Recipient may open the malicious attachment")

    if "lookalike domain" in joined or "display-name spoof" in joined or "no mx records" in joined:
        add("T1036.005", "Match Legitimate Name or Location", "Sender masquerades as a legitimate brand or domain")

    if "payment_diversion" in bec or "invoice_fraud" in bec:
        add("T1657", "Financial Theft and Impact", "BEC pattern aimed at diverting payments")
    if "exec_impersonation" in bec:
        add("T1534", "Internal Spearphishing", "Executive impersonation to trigger fraudulent actions")
    if "credential_harvest" in bec:
        add("T1598.003", "Phishing for Information: Credential Harvesting", "Lure designed to capture user credentials")

    for f in flags:
        fl = f.lower()
        if "tor exit node" in fl or "vpn/hosting asn" in fl:
            add("T1090", "Proxy", "Traffic routed through anonymizing infrastructure")
            break

    if origin_attribution.get("origin_type") == "compromised_account":
        add("T1078", "Valid Accounts", "Legitimate account likely compromised and abused")

    return list(found.values())


# ── SSE Alert Dispatcher ─────────────────────────────────────────────────────

async def dispatch_alert(alert_type: str, case_id: str, score: int, label: str, detail: str):
    alert = json.dumps({
        "event": "NEW_ALERT",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": alert_type,
        "case_id": case_id,
        "score": score,
        "label": label,
        "detail": detail,
    })
    dead = []
    for q in ALERT_SUBSCRIBERS:
        try:
            await q.put(alert)
        except Exception:
            dead.append(q)
    for q in dead:
        ALERT_SUBSCRIBERS.remove(q)


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
async def analyze_email(req: EmailRequest):
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

    display_name = ""
    from_match = re.match(r"\"?([^\"<]+?)\"?\s*<", from_addr)
    if from_match:
        display_name = from_match.group(1).strip()
    elif "<" not in from_addr:
        display_name = from_addr.split("@")[0] if "@" in from_addr else ""

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

    evidence_hash = compute_evidence_hash(req.raw)

    auth = parse_auth_results(msg)
    hops = extract_relay_hops(msg)
    ips = extract_ips(req.raw)
    urls = extract_urls(body)
    attachments = extract_attachments(msg)
    bec = classify_bec(subject, body)

    score, label, accent, flags = nlp_score(subject, body, auth, from_addr, reply_to)

    dangerous_attachments = [a for a in attachments if a["dangerous"]]
    if dangerous_attachments:
        score = min(score + 15, 100)
        flags.append(f"Dangerous attachment: {dangerous_attachments[0]['filename']}")

    if bec:
        score = min(score + 10, 100)
        flags.append(f"BEC pattern: {', '.join(bec.keys())}")

    geo_results = [geoip(ip) for ip in ips[:4]]

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

    display_spoof = detect_display_name_spoofing(from_addr, display_name)
    if display_spoof.get("is_spoofed"):
        score = min(score + display_spoof.get("score_delta", 10), 100)
        for tech in display_spoof.get("techniques", []):
            flags.append(f"Display-name spoof: {tech}")

    url_analysis = analyze_urls(urls)
    for ua in url_analysis:
        if ua.get("obfuscated"):
            score = min(score + 6, 100)
            for tech in ua.get("techniques", []):
                flags.append(f"URL obfuscation ({ua['url'][:50]}…): {tech}")

    reply_domain = re.search(r"@([\w.\-]+)", reply_to) if reply_to else None
    from_d_match = re.search(r"@([\w.\-]+)", from_addr)
    reply_to_mismatch = bool(reply_domain and from_d_match and reply_domain.group(1) != from_d_match.group(1))

    originating_ip = find_originating_ip(hops, ips)
    origin_attribution = attribute_origin_type(
        auth, geo_results, whois_data, dns_data, vt_domain,
        reply_to_mismatch, display_spoof, hops
    )

    if origin_attribution.get("scores", {}).get("anonymized_infrastructure", 0) >= 2:
        score = min(score + 5, 100)
    if origin_attribution.get("origin_type") == "spoofed_domain" and origin_attribution["confidence"] > 60:
        score = min(score + 5, 100)

    correlation_graph = build_correlation_graph(
        from_addr, from_domain, reply_to, return_path, ips, urls, hops
    )

    derived_ttps = derive_ttps(flags, bec, origin_attribution)
    campaign = cluster_into_campaign(
        from_domain, ips, urls, bec, subject,
        score_label=_label(score)[0], score_accent=_label(score)[1],
        ttp_ids=[t["id"] for t in derived_ttps],
    )

    if campaign.get("matched"):
        flags.append(f"Matched campaign: {campaign['campaign_name']} ({campaign['similar_emails_in_campaign']} emails)")

    masked_body = mask_pii(body)

    label, accent = _label(score)

    recommendations = _build_recommendations(score, origin_attribution, campaign, flags)

    case_id = db.next_case_id()
    addr_match = re.search(r"([\w.\-+]+)@", from_addr)
    local_part = addr_match.group(1) if addr_match else "em"
    initials = (re.sub(r"[^a-z0-9]", "", local_part.lower())[:2] or "em").upper()

    result = {
        "case_id": case_id,
        "subject": subject,
        "from": from_addr,
        "from_display_name": display_name,
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
        "url_analysis": url_analysis,
        "attachments": attachments,
        "bec": bec,
        "geo": geo_results,
        "originating_ip": originating_ip,
        "origin_attribution": origin_attribution,
        "display_name_spoofing": display_spoof,
        "vt_domain": vt_domain,
        "vt_urls": vt_urls,
        "whois": whois_data,
        "dns": dns_data,
        "correlation_graph": correlation_graph,
        "campaign": campaign,
        "ttps": derived_ttps,
        "recommendations": recommendations,
        "evidence_hash": evidence_hash,
        "retention_days": PRIVACY_CONFIG["retention_days"],
        "mask_pii_applied": PRIVACY_CONFIG["mask_pii"],
        "body_preview": masked_body[:300],
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

    # ── Persist to PostgreSQL ────────────────────────────────────────────────
    try:
        ws_slug = classify_workspace(result)
        result["ws_slug"] = ws_slug
        db.insert_case(case_id, from_addr, subject, score, label, accent, initials,
                       campaign.get("campaign_id"), result, ws_slug=ws_slug)
        db.insert_case_ttps(case_id, derived_ttps)

        # IOCs observed in this email
        if from_domain:
            vt_flags = vt_domain.get("malicious", 0) if isinstance(vt_domain, dict) else 0
            ioc_status = "MALICIOUS" if vt_flags > 0 else ("SUSPICIOUS" if dns_data.get("suspicious") else "WATCHLIST")
            ioc_accent = "red" if vt_flags > 0 else ("orange" if dns_data.get("suspicious") else "yellow")
            threat_desc = "Sender domain · lookalike/spoof risk" if any("lookalike" in f.lower() for f in flags) else "Sender domain"
            db.upsert_ioc("DOMAIN", from_domain, threat_desc, vt_flags, ioc_status, ioc_accent)

        for g in geo_results:
            if not is_valid_public_ip(g.get("ip")):
                continue
            if g.get("tor"):
                st, ac, desc = "MALICIOUS", "red", f"TOR exit node · {g.get('city') or 'Unknown'}"
            elif vt_domain.get("malicious", 0) > 0:
                st, ac, desc = "SUSPICIOUS", "orange", f"Flagged infrastructure · {g.get('city') or 'Unknown'}"
            elif g.get("vpn"):
                st, ac, desc = "SUSPICIOUS", "orange", f"Hosting/VPN ASN · {g.get('org') or ''}"
            else:
                st, ac, desc = "WATCHLIST", "yellow", f"{g.get('city') or 'Unknown'}, {g.get('country') or ''}"
            db.upsert_ioc("IP", g["ip"], desc, vt_domain.get("malicious", 0) if st != "WATCHLIST" else 0, st, ac)

        for ua in url_analysis:
            u = ua.get("url")
            if not u:
                continue
            mal = next((v.get("malicious", 0) for v in vt_urls if v.get("url") == u), 0)
            obf = bool(ua.get("obfuscated"))
            st = "MALICIOUS" if mal > 0 else ("SUSPICIOUS" if obf or ua.get("suspicious_tld") else "WATCHLIST")
            ac = "red" if st == "MALICIOUS" else ("orange" if st == "SUSPICIOUS" else "yellow")
            db.upsert_ioc("URL", u, "; ".join(ua.get("techniques", [])) or "URL found in body", mal, st, ac)

        # Infrastructure nodes from geolocation results
        for g in geo_results:
            if not g.get("ip") or not is_valid_public_ip(g.get("ip")):
                continue
            if g.get("tor"):
                ntype, nrisk = "PROXY", "red"
            elif g.get("vpn"):
                ntype, nrisk = "VPS", "orange"
            else:
                ntype, nrisk = "LEGIT", "green"
            db.upsert_infra(
                ip=g["ip"], host=None, city=g.get("city") or None,
                country=g.get("country") or None, org=g.get("org") or None,
                lat=g.get("lat") or 0, lng=g.get("lng") or 0,
                node_type=ntype, risk=nrisk,
                vpn=bool(g.get("vpn")), tor=bool(g.get("tor")),
            )
    except Exception as e:
        logging.error("Database persistence failed for %s: %s", case_id, e)

    audit_log("EMAIL_ANALYZED", {
        "case_id": case_id,
        "from": from_addr,
        "subject": subject,
        "score": score,
        "label": label,
        "message_id": message_id,
        "evidence_sha256": evidence_hash["sha256"],
        "origin_attribution": origin_attribution["origin_type"],
        "campaign_id": campaign["campaign_id"],
    })

    if score >= 75:
        await dispatch_alert(
            alert_type="CRITICAL_THREAT",
            case_id=case_id,
            score=score,
            label=label,
            detail=f"{subject} from {from_addr} — origin: {origin_attribution['origin_label']}"
        )
    elif score >= 55:
        await dispatch_alert(
            alert_type="HIGH_SUSPICIOUS",
            case_id=case_id,
            score=score,
            label=label,
            detail=f"{subject} — score {score}/100"
        )

    return result


@app.get("/report/{case_id}")
def get_report(case_id: str, full: bool = False):
    """Return a structured forensic intelligence report built from the stored
    analysis record. When full=true, includes inline evidence, graph, and IOCs."""

    row = db.get_case_row(case_id)
    if not row or not row.get("analysis"):
        raise HTTPException(status_code=404, detail="Case/analysis not found")

    analysis = row["analysis"]
    if isinstance(analysis, str):
        analysis = json.loads(analysis)

    subject = analysis.get("subject") or row.get("subject") or "Unknown"
    sender = analysis.get("from") or row.get("sender") or "Unknown"
    score = analysis.get("score") or row.get("score") or 0
    label = analysis.get("label") or row.get("label") or "LOW"
    accent = analysis.get("accent") or row.get("accent") or "green"

    auth = analysis.get("auth") or {}
    hops = analysis.get("hops") or []
    geo = analysis.get("geo") or []
    bec = analysis.get("bec") or {}
    flags = analysis.get("flags") or []
    attachments = analysis.get("attachments") or []
    urls = analysis.get("urls") or []
    vt_domain = analysis.get("vt_domain") or {}
    whois_data = analysis.get("whois") or {}
    dns_data = analysis.get("dns") or {}
    evidence_hash = analysis.get("evidence_hash") or {}
    origin_attribution = analysis.get("origin_attribution") or {}
    originating_ip = analysis.get("originating_ip") or {}
    display_spoof = analysis.get("display_name_spoofing") or {}
    correlation_graph = analysis.get("correlation_graph") or {}
    campaign = analysis.get("campaign") or {}
    url_analysis = analysis.get("url_analysis") or []

    report = {
        "report_type": "FORENSIC_INTELLIGENCE_REPORT",
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": "MailShield — AI-Powered Email Threat & Forensic Intelligence Platform",
        "classification": "CONFIDENTIAL — FOR AUTHORIZED INVESTIGATIVE USE ONLY",
        "case_summary": {
            "subject": subject,
            "sender": sender,
            "from_display_name": analysis.get("from_display_name") or "",
            "reply_to": analysis.get("reply_to") or "",
            "return_path": analysis.get("return_path") or "",
            "message_id": analysis.get("message_id") or "",
            "date": analysis.get("date") or "",
            "risk_score": score,
            "risk_label": label,
            "risk_accent": accent,
            "analyzed_at": analysis.get("analyzed_at") or datetime.now(timezone.utc).isoformat(),
        },
        "chain_of_custody": {
            "received_by": "MailShield automated ingestion engine",
            "analyzed_by": "AI Forensic Engine v2.0 (NLP + Header + Geo + Intel Correlation)",
            "evidence_hash_algo": evidence_hash.get("algo", "SHA-256"),
            "sha256": evidence_hash.get("sha256", "COMPUTED_AT_INGESTION"),
            "sha1": evidence_hash.get("sha1", ""),
            "md5": evidence_hash.get("md5", ""),
            "evidence_size_bytes": evidence_hash.get("size_bytes", 0),
            "evidence_preserved_at": evidence_hash.get("preserved_at", datetime.now(timezone.utc).isoformat()),
            "retention_days": PRIVACY_CONFIG["retention_days"],
            "retention_policy": f"{PRIVACY_CONFIG['retention_days']} days per organizational data retention policy",
            "pii_masking_applied": PRIVACY_CONFIG["mask_pii"],
        },
        "threat_assessment": {
            "score": score,
            "label": label,
            "detection_flags": flags,
        },
        "sender_authentication": {
            "spf": auth.get("spf", "unknown"),
            "dkim": auth.get("dkim", "unknown"),
            "dmarc": auth.get("dmarc", "unknown"),
            "anomalies": [],
        },
        "display_name_spoofing": display_spoof,
        "bec_patterns_detected": bec,
        "url_threat_analysis": url_analysis,
        "attachments": attachments,
        "urls_found": urls,
        "origin_traceability": {
            "originating_ip": originating_ip,
            "origin_attribution": origin_attribution,
            "geolocation": geo,
            "relay_hops": hops,
        },
        "domain_infrastructure_intel": {
            "whois": whois_data,
            "dns_records": dns_data,
            "virustotal_domain": vt_domain,
        },
        "identity_and_campaign": {
            "campaign": campaign,
            "correlation_graph_summary": correlation_graph.get("summary", {}) if isinstance(correlation_graph, dict) else {},
        },
        "investigator_assessment": {
            "origin_reasons": origin_attribution.get("reasons", []),
            "recommended_actions": _build_recommendations(score, origin_attribution, campaign, flags),
        },
        "legal_and_evidentiary_standards": {
            "integrity_statement": "All analysis artifacts generated with non-repudiable SHA-256 evidence hash.",
            "privacy_compliance": "GDPR / DPDP compliant. PII masking enabled. Retention window configurable.",
            "chain_of_custody_note": "For law enforcement subpoenas, case_id + SHA-256 uniquely identify evidence record.",
        },
    }

    if auth.get("spf") in ("fail", "softfail", "neutral", "none", "permerror"):
        report["sender_authentication"]["anomalies"].append(f"SPF {auth['spf']} — sender may be spoofed")
    if auth.get("dkim") in ("fail", "none"):
        report["sender_authentication"]["anomalies"].append(f"DKIM {auth['dkim']} — message body/tampering risk")
    if dns_data.get("suspicious"):
        report["sender_authentication"]["anomalies"].append("From-domain has no MX records — cannot receive mail")
    if origin_attribution.get("origin_label"):
        report["investigator_assessment"]["summary"] = (
            f"{origin_attribution['origin_label']} (confidence {origin_attribution.get('confidence', 0)}%)"
        )

    if full:
        report["correlation_graph"] = correlation_graph

    return JSONResponse(report)


def _build_recommendations(score: int, origin: dict, campaign: dict, flags: list) -> list:
    recs = []
    if score >= 75:
        recs.append("QUARANTINE email immediately. Prevent user interaction.")
        recs.append("Notify SOC on-call analyst.")
    elif score >= 55:
        recs.append("HOLD in suspicious queue. Await analyst review.")

    otype = origin.get("origin_type", "")
    if otype == "spoofed_domain":
        recs.append("Report spoofed domain to registrar and hosting provider.")
        recs.append("Block domain + MX-less sender IPs at perimeter.")
    elif otype == "anonymized_infrastructure":
        recs.append("Block VPN/TOR/proxy ASN source at mail gateway.")
        recs.append("Alert network team about anonymity-service source.")
    elif otype == "compromised_account":
        recs.append("FORCE password reset + MFA re-enrollment for sender account.")
        recs.append("Review sender account audit log for recent unauthorized access.")
    elif otype == "direct_malicious_actor":
        recs.append("Submit sender IOC (IP + domain) to national CERT feed.")

    if campaign.get("matched"):
        recs.append(f"Cross-reference campaign {campaign['campaign_id']} — check all users for similar deliveries.")

    if any("xlsm" in f.lower() or "docm" in f.lower() or "attachment" in f.lower() for f in flags):
        recs.append("Submit suspicious attachment to sandbox / AV detonation queue.")
    if any("credential" in f.lower() or "verify.*account" in f.lower() or "login" in f.lower() for f in flags):
        recs.append("WARNING: Likely credential harvest attempt. Inform users NOT to click links.")

    recs.append("Preserve full headers + raw .eml file with SHA-256 evidence hash for chain-of-custody.")
    return recs


# ── Privacy Config Endpoint ──────────────────────────────────────────────────

class PrivacyConfigUpdate(BaseModel):
    retention_days: Optional[int] = None
    mask_pii: Optional[bool] = None


@app.get("/privacy-config")
def get_privacy_config():
    return {
        "retention_days": PRIVACY_CONFIG["retention_days"],
        "mask_pii": PRIVACY_CONFIG["mask_pii"],
        "pii_patterns_keys": list(PRIVACY_CONFIG["pii_patterns"].keys()),
        "evidence_hash_algo": PRIVACY_CONFIG["evidence_hash_algo"],
    }


@app.post("/privacy-config")
def update_privacy_config(req: PrivacyConfigUpdate):
    if req.retention_days is not None:
        PRIVACY_CONFIG["retention_days"] = max(1, min(req.retention_days, 3650))
    if req.mask_pii is not None:
        PRIVACY_CONFIG["mask_pii"] = req.mask_pii
    return {"status": "updated", "config": get_privacy_config()}


# ── Campaigns Endpoint ───────────────────────────────────────────────────────

@app.get("/campaigns")
def get_campaigns():
    return db.list_campaigns()


# ── SSE Real-Time Alert Stream ───────────────────────────────────────────────

@app.get("/alerts/stream")
async def alerts_stream(request: Request):
    queue: asyncio.Queue = asyncio.Queue()
    ALERT_SUBSCRIBERS.append(queue)

    async def event_generator():
        try:
            yield f"data: {json.dumps({'event': 'CONNECTED', 'subscribers': len(ALERT_SUBSCRIBERS)})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    yield f": keep-alive {datetime.now(timezone.utc).isoformat()}\n\n"
        finally:
            if queue in ALERT_SUBSCRIBERS:
                ALERT_SUBSCRIBERS.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Analysis Cache Lookup ────────────────────────────────────────────────────

@app.get("/analysis/{case_id}")
def get_cached_analysis(case_id: str):
    row = db.get_case_row(case_id)
    if not row:
        raise HTTPException(status_code=404, detail="Case/analysis not found")
    analysis = row.get("analysis") or {}
    if isinstance(analysis, str):
        analysis = json.loads(analysis)
    return {
        "case_id": case_id,
        "subject": row.get("subject") or analysis.get("subject"),
        "from": row.get("sender") or analysis.get("from"),
        "score": analysis.get("score", row.get("score")),
        "label": analysis.get("label", row.get("label")),
        "accent": analysis.get("accent", row.get("accent")),
        "flags": analysis.get("flags", []),
        "ips": analysis.get("ips", []),
        "urls": analysis.get("urls", []),
        "url_analysis": analysis.get("url_analysis", []),
        "attachments": analysis.get("attachments", []),
        "geo": analysis.get("geo", []),
        "hops": analysis.get("hops", []),
        "auth": analysis.get("auth", {}),
        "originating_ip": analysis.get("originating_ip", {}),
        "origin_attribution": analysis.get("origin_attribution", {}),
        "display_name_spoofing": analysis.get("display_name_spoofing", {}),
        "correlation_graph": analysis.get("correlation_graph", {}),
        "campaign": analysis.get("campaign", {}),
        "ttps": analysis.get("ttps", []),
        "recommendations": analysis.get("recommendations", []),
        "evidence_hash": analysis.get("evidence_hash", {}),
        "analyzed_at": analysis.get("analyzed_at"),
    }


@app.get("/geoip/{ip}")
def get_geoip(ip: str):
    if not is_valid_public_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid or private IP address")
    return geoip(ip)


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# ── Workspaces (global threat-domain hub) ────────────────────────────────────

class WorkspaceRequest(BaseModel):
    name: str
    description: Optional[str] = None


@app.get("/workspaces")
def get_workspaces():
    return db.list_workspaces()


@app.post("/workspaces")
def add_workspace(req: WorkspaceRequest):
    name = (req.name or "").strip()
    if not name or len(name) > 60:
        raise HTTPException(status_code=400, detail="Workspace name must be 1–60 characters")
    ws = db.create_workspace(name, req.description)
    if not ws:
        raise HTTPException(status_code=409, detail="A workspace like this already exists")
    audit_log("WORKSPACE_CREATED", {"id": ws["id"], "name": ws["name"]})
    return {"status": "created", "workspace": ws}


@app.delete("/workspaces/{ws_id}")
def remove_workspace(ws_id: int):
    status, row = db.delete_workspace(ws_id)
    if status == "not_found":
        raise HTTPException(status_code=404, detail="Workspace not found")
    if status == "builtin":
        raise HTTPException(status_code=400, detail="Core threat domains are shared by the whole community and cannot be removed")
    if status == "has_cases":
        raise HTTPException(status_code=400, detail="This domain still has analyzed cases — resolve or export them first")
    audit_log("WORKSPACE_DELETED", {"id": row["id"], "name": row["name"]})
    return {"status": "deleted", "workspace": row}


@app.post("/connect-account")
def connect_account(req: AccountConnectRequest):
    try:
        res = test_connection(req.provider, req.email, req.password, req.custom_host, req.custom_port or 993)
        acct_meta = {
            "id": f"{req.provider}-{req.email}",
            "provider": req.provider,
            "email": req.email,
            "status": "connected",
            "connected_at": datetime.now(timezone.utc).isoformat()
        }
        if not any(a["id"] == acct_meta["id"] for a in CONNECTED_ACCOUNTS):
            CONNECTED_ACCOUNTS.append(acct_meta)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/connected-accounts")
def get_connected_accounts():
    return CONNECTED_ACCOUNTS


class PollTokenRequest(BaseModel):
    device_code: str
    max_emails: Optional[int] = 5


@app.post("/auth/outlook/device-code")
def outlook_device_code():
    try:
        return start_outlook_device_code()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/auth/outlook/poll-token")
async def outlook_poll_token(req: PollTokenRequest):
    try:
        poll_res = await asyncio.to_thread(poll_outlook_token, req.device_code)
        if poll_res.get("status") == "pending":
            return poll_res

        access_token = poll_res.get("access_token")
        raw_list = await asyncio.to_thread(
            fetch_outlook_live_emails_via_graph, access_token, max_emails=req.max_emails or 5
        )

        analyzed_results = []
        for raw in raw_list:
            try:
                analyzed = await analyze_email(EmailRequest(raw=raw))
                analyzed_results.append(analyzed)
            except Exception:
                logging.exception("Failed to analyze live Outlook email")

        return {
            "status": "complete",
            "count": len(analyzed_results),
            "provider": "outlook",
            "cases": analyzed_results
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/fetch-live")
async def fetch_live_emails(req: FetchLiveRequest):
    try:
        raw_list = await asyncio.to_thread(
            fetch_unread_emails,
            provider=req.provider,
            email_address=req.email,
            password=req.password,
            max_emails=req.max_emails or 5,
            custom_host=req.custom_host,
            custom_port=req.custom_port or 993,
        )
        analyzed_results = []
        for raw in raw_list:
            try:
                analyzed = await analyze_email(EmailRequest(raw=raw))
                analyzed_results.append(analyzed)
            except Exception:
                logging.exception("Failed to analyze fetched email")

        return {
            "count": len(analyzed_results),
            "provider": req.provider,
            "email": req.email,
            "cases": analyzed_results
        }
    except Exception as e:
        logging.exception("Live fetch failed for %s (%s)", req.email, req.provider)
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/cases")
def get_cases(ws: Optional[str] = None):
    cases = []
    for c in db.get_open_cases(ws):
        cases.append({
            "id": c["id"],
            "sender": c["sender"] or "",
            "subject": c["subject"] or "",
            "received_at": c["received_at"].isoformat() if c["received_at"] else None,
            "score": c["score"],
            "label": c["label"],
            "accent": c["accent"],
            "initials": c["initials"],
        })
    return cases


@app.post("/cases")
def add_case(case_data: dict):
    case_id = case_data.get("id") or db.next_case_id()
    analysis = case_data.get("raw_data") or {}
    db.insert_case(
        case_id,
        case_data.get("sender"),
        case_data.get("subject"),
        case_data.get("score", 0),
        case_data.get("label", "LOW"),
        case_data.get("accent", "green"),
        (case_data.get("sender") or "EM")[:2].upper(),
        None,
        {"case_id": case_id, **analysis},
    )
    return {"status": "added", "case_id": case_id}


@app.post("/cases/{case_id}/resolve")
def resolve_case(case_id: str, req: ResolveCaseRequest):
    row = db.resolve_case(case_id, req.action or "Resolved by analyst", req.analyst or "AS")
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")
    resolved_entry = {
        "id": row["id"],
        "sender": row["sender"] or "",
        "subject": row["subject"] or "",
        "closed": row["resolved_at"].strftime("%d %b %Y") if row["resolved_at"] else "—",
        "score": row["score"],
        "label": row["label"],
        "accent": row["accent"],
        "resolution": row["resolution"] or "—",
        "analyst": row["analyst"] or "—",
    }
    return {"status": "resolved", "case": resolved_entry}


@app.get("/threat-intel")
def get_threat_intel():
    iocs = [
        {
            "type": r["type"],
            "value": r["value"],
            "threat": r["threat"] or "—",
            "detections": r["detections"],
            "vt": r["vt"],
            "status": r["status"] or "WATCHLIST",
            "accent": r["accent"] or "yellow",
        }
        for r in db.list_iocs()
    ]
    ttps = [
        {"id": t["id"], "name": t["name"] or t["id"], "count": t["count"]}
        for t in db.aggregate_ttps()
    ]
    return {"iocs": iocs, "ttps": ttps}


@app.get("/infrastructure")
def get_infrastructure():
    nodes = []
    for n in db.list_infrastructure():
        nodes.append({
            "ip": n["ip"],
            "host": n["host"] or "—",
            "city": n["city"] or "Unknown",
            "country": n["country"] or "",
            "org": n["org"] or "—",
            "lat": n["lat"],
            "lng": n["lng"],
            "type": n["type"] or "NODE",
            "risk": n["risk"] or "green",
        })
    return nodes


@app.get("/stats")
def get_stats(ws: Optional[str] = None):
    return db.get_stats(ws)


@app.get("/case-history")
def get_case_history(ws: Optional[str] = None):
    return db.get_resolved_cases(ws)


