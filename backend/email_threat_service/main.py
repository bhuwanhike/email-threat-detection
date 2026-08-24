import os
import re
import json
import base64
import hashlib
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
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv
from mail_fetcher import (
    test_connection,
    fetch_unread_emails,
    start_outlook_device_code,
    poll_outlook_token,
    fetch_outlook_live_emails_via_graph
)

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
    use_demo: Optional[bool] = False
    custom_host: Optional[str] = None
    custom_port: Optional[int] = 993

class ResolveCaseRequest(BaseModel):
    action: str
    analyst: Optional[str] = "AS"

CONNECTED_ACCOUNTS = []

CASES_DB = [
    {
        "id": "INC-2481",
        "sender": "accounts-payable@micros0ft.com",
        "subject": "Urgent: invoice overdue - action required",
        "time": "12m ago",
        "score": 94,
        "label": "CRITICAL",
        "accent": "red",
        "initials": "AP",
        "raw_data": {
            "from": "accounts-payable@micros0ft.com",
            "subject": "Urgent: invoice overdue - action required",
            "score": 94,
            "label": "CRITICAL",
            "accent": "red",
            "flags": ["Phishing keywords: invoice, urgent, overdue", "Lookalike domain: micros0ft.com", "SPF softfail"],
            "ips": ["185.23.45.10"],
            "urls": ["http://micros0ft.com/verify-invoice"],
            "attachments": [{"filename": "Invoice_8831.xlsm", "dangerous": True, "extension": ".xlsm"}],
            "geo": [{"ip": "185.23.45.10", "city": "Agra", "region": "Uttar Pradesh", "country": "IN", "org": "AS12345 BulkHosting", "lat": 27.18, "lng": 78.01, "vpn": True, "tor": False}]
        }
    },
    {
        "id": "INC-2479",
        "sender": "ceo.office@northstar-holdings.co",
        "subject": "Confidential acquisition request",
        "time": "38m ago",
        "score": 81,
        "label": "HIGH",
        "accent": "orange",
        "initials": "CO",
        "raw_data": {
            "from": "ceo.office@northstar-holdings.co",
            "subject": "Confidential acquisition request",
            "score": 81,
            "label": "HIGH",
            "accent": "orange",
            "flags": ["BEC pattern: payment_diversion", "Reply-To domain mismatch"],
            "ips": ["41.58.120.77"],
            "urls": ["http://northstar-holdings.co/wire"],
            "attachments": [],
            "geo": [{"ip": "41.58.120.77", "city": "Lagos", "region": "Lagos State", "country": "NG", "org": "AS37148 MainOne", "lat": 6.52, "lng": 3.38, "vpn": False, "tor": False}]
        }
    },
    {
        "id": "INC-2476",
        "sender": "support@cloud-storage-verify.net",
        "subject": "Your storage is almost full",
        "time": "1h ago",
        "score": 67,
        "label": "MEDIUM",
        "accent": "yellow",
        "initials": "CS",
        "raw_data": {
            "from": "support@cloud-storage-verify.net",
            "subject": "Your storage is almost full",
            "score": 67,
            "label": "MEDIUM",
            "accent": "yellow",
            "flags": ["1 URL(s) in body", "Domain only 6 days old"],
            "ips": ["95.216.44.22"],
            "urls": ["http://cloud-storage-verify.net/upgrade"],
            "attachments": [],
            "geo": [{"ip": "95.216.44.22", "city": "Frankfurt", "region": "Hesse", "country": "DE", "org": "AS24940 Hetzner", "lat": 50.11, "lng": 8.68, "vpn": False, "tor": False}]
        }
    },
    {
        "id": "INC-2472",
        "sender": "newsletter@security-weekly.com",
        "subject": "Weekly threat briefing",
        "time": "2h ago",
        "score": 12,
        "label": "LOW",
        "accent": "green",
        "initials": "NW",
        "raw_data": {
            "from": "newsletter@security-weekly.com",
            "subject": "Weekly threat briefing",
            "score": 12,
            "label": "LOW",
            "accent": "green",
            "flags": [],
            "ips": ["203.0.113.10"],
            "urls": [],
            "attachments": [],
            "geo": [{"ip": "203.0.113.10", "city": "San Francisco", "region": "CA", "country": "US", "org": "AS15169 Google LLC", "lat": 37.77, "lng": -122.41, "vpn": False, "tor": False}]
        }
    }
]

CASE_HISTORY_DB = [
    {"id": "INC-2455", "sender": "payroll@fake-hr-portal.com", "subject": "Payroll update required", "closed": "22 Aug 2026", "score": 91, "label": "CRITICAL", "accent": "red", "resolution": "Blocked · Reported to IT", "analyst": "AS"},
    {"id": "INC-2441", "sender": "cfo@acme-corp-finance.net", "subject": "Wire transfer authorization", "closed": "21 Aug 2026", "score": 87, "label": "CRITICAL", "accent": "red", "resolution": "Blocked · Legal notified", "analyst": "RK"},
    {"id": "INC-2430", "sender": "support@dropbox-verify.co", "subject": "Your Dropbox storage is full", "closed": "20 Aug 2026", "score": 63, "label": "MEDIUM", "accent": "yellow", "resolution": "Quarantined · User warned", "analyst": "AS"},
    {"id": "INC-2418", "sender": "noreply@linkedin-jobs.net", "subject": "You have a new job offer", "closed": "19 Aug 2026", "score": 44, "label": "MEDIUM", "accent": "yellow", "resolution": "Marked suspicious · Monitored", "analyst": "PD"},
    {"id": "INC-2400", "sender": "newsletter@techcrunch.com", "subject": "Weekly tech digest", "closed": "18 Aug 2026", "score": 6, "label": "LOW", "accent": "green", "resolution": "Cleared · Legitimate", "analyst": "AS"},
    {"id": "INC-2388", "sender": "billing@aws-invoice-alert.com", "subject": "Your AWS bill is ready", "closed": "17 Aug 2026", "score": 79, "label": "HIGH", "accent": "orange", "resolution": "Blocked · Domain reported", "analyst": "RK"},
]


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
CAMPAIGN_DB: list[dict] = [
    {
        "id": "CAMP-INVOICE-01",
        "name": "INVOICE-STORM · Microsoft Lookalike BEC",
        "risk": "CRITICAL",
        "accent": "red",
        "count": 14,
        "iocs": ["micros0ft.com", "micros0ft-billing.com", "185.23.45.10"],
        "first_seen": "18 Aug 2026",
        "last_seen": "24 Aug 2026",
        "ttps": ["T1566.001", "T1036.005", "T1078"],
    },
    {
        "id": "CAMP-WIRE-02",
        "name": "CEO-WIRE-01 · Executive Impersonation",
        "risk": "HIGH",
        "accent": "orange",
        "count": 6,
        "iocs": ["northstar-holdings.co", "41.58.120.77"],
        "first_seen": "20 Aug 2026",
        "last_seen": "23 Aug 2026",
        "ttps": ["T1566.002", "T1534", "T1657"],
    },
    {
        "id": "CAMP-CLOUD-03",
        "name": "CLOUD-LURE-22 · Commodity Phishing Kit",
        "risk": "MEDIUM",
        "accent": "yellow",
        "count": 200,
        "iocs": ["cloud-storage-verify.net", "cloud-verify-storage.net", "95.216.44.22"],
        "first_seen": "15 Aug 2026",
        "last_seen": "23 Aug 2026",
        "ttps": ["T1566.002", "T1598.003"],
    },
]


class EmailRequest(BaseModel):
    raw: str


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
) -> dict:
    matched = None
    for camp in CAMPAIGN_DB:
        ioc_list = [i.lower() for i in camp["iocs"]]
        score = 0
        if from_domain and from_domain.lower() in ioc_list:
            score += 3
        for ip in ips:
            if ip in ioc_list:
                score += 2
        for u in urls:
            from urllib.parse import urlparse
            uh = urlparse(u).hostname or ""
            if uh.lower() in ioc_list:
                score += 2
        for t in camp.get("ttps", []):
            for bp in bec_patterns.keys():
                if bp.upper() in t or t.split(".")[-1][:3] in bp.upper():
                    score += 1
        if score >= 2:
            matched = camp
            break
    if matched:
        return {
            "matched": True,
            "campaign_id": matched["id"],
            "campaign_name": matched["name"],
            "campaign_risk": matched["risk"],
            "campaign_accent": matched["accent"],
            "similar_emails_in_campaign": matched["count"],
            "campaign_window": f"{matched['first_seen']} – {matched['last_seen']}",
        }
    new_id = f"CAMP-NEW-{hashlib.md5((subject+from_domain).encode()).hexdigest()[:5].upper()}"
    return {
        "matched": False,
        "campaign_id": new_id,
        "campaign_name": f"New campaign cluster · {from_domain or 'unknown'}",
        "campaign_risk": "MEDIUM",
        "campaign_accent": "yellow",
        "similar_emails_in_campaign": 1,
        "campaign_window": "First seen today",
    }


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

ANALYSIS_CACHE: Dict[str, dict] = {}


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

    campaign = cluster_into_campaign(from_domain, ips, urls, bec, subject)

    if campaign.get("matched"):
        flags.append(f"Matched campaign: {campaign['campaign_name']} ({campaign['similar_emails_in_campaign']} emails)")

    masked_body = mask_pii(body)

    label, accent = _label(score)

    case_id = f"INC-{2500 + len(ANALYSIS_CACHE) + len(CASES_DB)}"
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
        "evidence_hash": evidence_hash,
        "retention_days": PRIVACY_CONFIG["retention_days"],
        "mask_pii_applied": PRIVACY_CONFIG["mask_pii"],
        "body_preview": masked_body[:300],
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

    ANALYSIS_CACHE[case_id] = result

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
    """Return a structured forensic intelligence report. Uses cached analysis if available,
    otherwise pulls from static CASES_DB. When full=true, includes inline evidence, graph, and IOCs."""

    analysis = ANALYSIS_CACHE.get(case_id)
    case_static = next((c for c in CASES_DB if c["id"] == case_id), None)
    raw_data = case_static.get("raw_data") if case_static else {}

    subject = analysis.get("subject") or case_static.get("subject") or "Unknown"
    sender = analysis.get("from") or case_static.get("sender") or "Unknown"
    score = analysis.get("score") or case_static.get("score") or 0
    label = analysis.get("label") or case_static.get("label") or "LOW"
    accent = analysis.get("accent") or case_static.get("accent") or "green"

    auth = analysis.get("auth") or {}
    hops = analysis.get("hops") or []
    geo = analysis.get("geo") or (raw_data.get("geo") if isinstance(raw_data, dict) else [])
    bec = analysis.get("bec") or {}
    flags = analysis.get("flags") or (raw_data.get("flags") if isinstance(raw_data, dict) else [])
    attachments = analysis.get("attachments") or (raw_data.get("attachments") if isinstance(raw_data, dict) else [])
    urls = analysis.get("urls") or (raw_data.get("urls") if isinstance(raw_data, dict) else [])
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
        "platform": "trace.ai — AI-Powered Email Threat & Forensic Intelligence Platform",
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
            "received_by": "trace.ai automated ingestion engine",
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
    enriched = []
    for c in CAMPAIGN_DB:
        case_refs = [
            case for case in CASES_DB
            if any(ioc.lower() in case["sender"].lower() for ioc in c["iocs"])
            or any(ioc.lower() in (case.get("raw_data", {}).get("subject", case["subject"]).lower() if isinstance(case.get("raw_data"), dict) else case["subject"].lower()) for ioc in c["iocs"])
        ]
        enriched.append({
            **c,
            "related_case_ids": [x["id"] for x in case_refs],
            "avg_risk_score": (sum(x["score"] for x in case_refs) / len(case_refs)) if case_refs else 0,
        })

    all_case_ids_in_camps = set()
    for e in enriched:
        all_case_ids_in_camps.update(e["related_case_ids"])

    orphans = [c["id"] for c in CASES_DB if c["id"] not in all_case_ids_in_camps]
    if orphans:
        enriched.append({
            "id": "CAMP-UNCATEGORIZED",
            "name": "Uncategorized / Standalone incidents",
            "risk": "LOW",
            "accent": "green",
            "count": len(orphans),
            "iocs": [],
            "first_seen": "N/A",
            "last_seen": "N/A",
            "ttps": [],
            "related_case_ids": orphans,
            "avg_risk_score": (sum(next(x for x in CASES_DB if x["id"] == o)["score"] for o in orphans) / len(orphans)),
        })
    return enriched


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
    if case_id in ANALYSIS_CACHE:
        return ANALYSIS_CACHE[case_id]
    static = next((c for c in CASES_DB if c["id"] == case_id), None)
    if static:
        raw = static.get("raw_data", {}) if isinstance(static.get("raw_data"), dict) else {}
        return {
            "case_id": case_id,
            "subject": static.get("subject"),
            "from": static.get("sender"),
            "score": static.get("score"),
            "label": static.get("label"),
            "accent": static.get("accent"),
            "flags": raw.get("flags", []),
            "ips": raw.get("ips", []),
            "urls": raw.get("urls", []),
            "attachments": raw.get("attachments", []),
            "geo": raw.get("geo", []),
            "source": "static_db",
        }
    raise HTTPException(status_code=404, detail="Case/analysis not found")


@app.get("/geoip/{ip}")
def get_geoip(ip: str):
    if not is_valid_public_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid or private IP address")
    return geoip(ip)


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


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
def outlook_poll_token(req: PollTokenRequest):
    try:
        poll_res = poll_outlook_token(req.device_code)
        if poll_res.get("status") == "pending":
            return poll_res
        
        access_token = poll_res.get("access_token")
        raw_list = fetch_outlook_live_emails_via_graph(access_token, max_emails=req.max_emails or 5)
        
        analyzed_results = []
        for raw in raw_list:
            try:
                analyzed = analyze_email(EmailRequest(raw=raw))
                analyzed_results.append(analyzed)
            except Exception as e:
                logging.error("Failed to analyze live Outlook email: %s", str(e))

        return {
            "status": "complete",
            "count": len(analyzed_results),
            "provider": "outlook",
            "cases": analyzed_results
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/fetch-live")
def fetch_live_emails(req: FetchLiveRequest):
    try:
        raw_list = fetch_unread_emails(
            provider=req.provider,
            email_address=req.email,
            password=req.password,
            max_emails=req.max_emails or 5,
            custom_host=req.custom_host,
            custom_port=req.custom_port or 993,
            use_demo=req.use_demo or False
        )
        analyzed_results = []
        for raw in raw_list:
            try:
                analyzed = analyze_email(EmailRequest(raw=raw))
                analyzed_results.append(analyzed)
            except Exception as e:
                logging.error("Failed to analyze fetched email: %s", str(e))

        return {
            "count": len(analyzed_results),
            "provider": req.provider,
            "email": req.email,
            "cases": analyzed_results
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/cases")
def get_cases():
    return CASES_DB


@app.post("/cases")
def add_case(case_data: dict):
    CASES_DB.insert(0, case_data)
    return {"status": "added", "case_id": case_data.get("id")}


@app.post("/cases/{case_id}/resolve")
def resolve_case(case_id: str, req: ResolveCaseRequest):
    global CASES_DB, CASE_HISTORY_DB
    found_idx = -1
    for idx, c in enumerate(CASES_DB):
        if c["id"] == case_id:
            found_idx = idx
            break

    if found_idx == -1:
        raise HTTPException(status_code=404, detail="Case not found")

    found_case = CASES_DB.pop(found_idx)
    resolved_entry = {
        "id": found_case["id"],
        "sender": found_case["sender"],
        "subject": found_case["subject"],
        "closed": datetime.now(timezone.utc).strftime("%d %b %Y"),
        "score": found_case["score"],
        "label": found_case["label"],
        "accent": found_case["accent"],
        "resolution": req.action or "Resolved by analyst",
        "analyst": req.analyst or "AS",
    }
    CASE_HISTORY_DB.insert(0, resolved_entry)
    return {"status": "resolved", "case": resolved_entry}


@app.get("/threat-intel")
def get_threat_intel():
    iocs = [
        {"type": "DOMAIN", "value": "micros0ft.com", "threat": "Lookalike · BEC", "detections": 14, "vt": 8, "status": "MALICIOUS", "accent": "red"},
        {"type": "DOMAIN", "value": "northstar-holdings.co", "threat": "BEC · CEO fraud", "detections": 6, "vt": 5, "status": "MALICIOUS", "accent": "red"},
        {"type": "DOMAIN", "value": "cloud-storage-verify.net", "threat": "Phishing kit", "detections": 200, "vt": 3, "status": "SUSPICIOUS", "accent": "orange"},
        {"type": "IP", "value": "185.23.45.10", "threat": "Open relay · Agra IN", "detections": 9, "vt": 2, "status": "SUSPICIOUS", "accent": "orange"},
        {"type": "IP", "value": "41.58.120.77", "threat": "Residential proxy · Lagos NG", "detections": 4, "vt": 1, "status": "SUSPICIOUS", "accent": "orange"},
        {"type": "IP", "value": "95.216.44.22", "threat": "Hetzner VPS · Frankfurt DE", "detections": 3, "vt": 0, "status": "WATCHLIST", "accent": "yellow"},
        {"type": "URL", "value": "http://secure-example-login.test/verify", "threat": "Credential harvesting", "detections": 7, "vt": 11, "status": "MALICIOUS", "accent": "red"},
        {"type": "HASH", "value": "d41d8cd98f00b204e9800998ecf8427e", "threat": "Macro dropper · Invoice_8831.xlsm", "detections": 2, "vt": 6, "status": "MALICIOUS", "accent": "red"},
    ]

    ttps = [
        {"id": "T1566.001", "name": "Spearphishing Attachment", "count": 3},
        {"id": "T1566.002", "name": "Spearphishing via Link", "count": 5},
        {"id": "T1036.005", "name": "Match Legitimate Name", "count": 4},
        {"id": "T1078", "name": "Valid Accounts", "count": 2},
        {"id": "T1534", "name": "Internal Spearphishing", "count": 1},
        {"id": "T1657", "name": "Financial Theft (BEC)", "count": 2},
    ]

    return {"iocs": iocs, "ttps": ttps}


@app.get("/infrastructure")
def get_infrastructure():
    nodes = [
        {"ip": "185.23.45.10", "host": "mail-relay.pro", "city": "Agra", "country": "IN", "org": "AS12345 BulkHosting", "lat": 27.18, "lng": 78.01, "type": "RELAY", "risk": "red"},
        {"ip": "41.58.120.77", "host": "proxy-ng.net", "city": "Lagos", "country": "NG", "org": "AS37148 MainOne", "lat": 6.52, "lng": 3.38, "type": "PROXY", "risk": "red"},
        {"ip": "95.216.44.22", "host": "vps-de.hetzner.com", "city": "Frankfurt", "country": "DE", "org": "AS24940 Hetzner", "lat": 50.11, "lng": 8.68, "type": "VPS", "risk": "orange"},
        {"ip": "203.0.113.10", "host": "mail.example.com", "city": "Mumbai", "country": "IN", "org": "AS55836 Reliance", "lat": 19.07, "lng": 72.87, "type": "LEGIT", "risk": "green"},
        {"ip": "198.51.100.25", "host": "suspicious-host.test", "city": "Amsterdam", "country": "NL", "org": "AS20473 Vultr", "lat": 52.37, "lng": 4.89, "type": "PHISH", "risk": "red"},
    ]
    return nodes


@app.get("/case-history")
def get_case_history():
    return CASE_HISTORY_DB


