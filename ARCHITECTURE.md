# MailShield — Open-Source Email Threat Intelligence Hub

> An open-source email threat intelligence ecosystem that transforms individual
> email attacks into reusable security knowledge.

MailShield doesn't just detect malicious emails — it **understands, reconstructs,
correlates, and learns** from email-based attacks.

**Core pipeline:** `Email → Threat Analysis → Attack Reconstruction → Threat Intelligence → Collective Learning`

It answers a deeper question than *"Is this email malicious?"*:

> *What attack is this email attempting, how does it work, what infrastructure is
> associated with it, is it part of a larger campaign, and how can the knowledge
> extracted from this attack help detect the next one?*

---

## Product Flow

```
            ┌──────────────────────────────────────────────────────────┐
            │                      EMAIL INPUT                          │
            │   (.eml / raw RFC-822 upload · IMAP/Gmail · Outlook)      │
            └───────────────┬──────────────────────────────────────────┘
                            ▼
        ┌───────────────────────────────────────────┐
        │ 1. THREAT ANALYSIS ENGINE                 │
        │  header parsing · auth (SPF/DKIM/DMARC)   │
        │  content classifier · URL de-obfuscation  │
        │  attachment hashing · geolocation (IP→geo)│
        │  → explainable score + evidence flags     │
        └───────────────┬───────────────────────────┘
                        ▼
        ┌───────────────────────────────────────────┐
        │ 2. ATTACK RECONSTRUCTION ENGINE           │
        │  rebuilds the probable kill-chain         │
        │  every stage labeled OBSERVED / INFERRED  │
        └───────────────┬───────────────────────────┘
                        ▼
        ┌───────────────────────────────────────────┐      ┌──────────────────────┐
        │ 3. THREAT INTELLIGENCE REPOSITORY         │◄────►│ CORRELATION ENGINE   │
        │  sanitized indicators only (no raw mail)  │      │ campaign clustering  │
        │  domains·IPs·URLs·hashes·TTPs·patterns    │      │ infrastructure reuse │
        └───────────────┬───────────────────────────┘      └──────────────────────┘
                        ▼
        ┌───────────────────────────────────────────┐
        │ 4. COLLECTIVE LEARNING                    │
        │  new mail matched against repository →    │
        │  recurrence flags + campaign linkage      │
        └───────────────┬───────────────────────────┘
                        ▼
        ┌───────────────────────────────────────────┐
        │ 5. ANALYST SURFACES                       │
        │  dashboard · threat graph · scenario      │
        │  simulation · reports · live alerts (SSE) │
        └───────────────────────────────────────────┘
```

## Module Map (loosely coupled, independently deployable where practical)

| Component | Location | Responsibility |
|---|---|---|
| Analysis API | `backend/email_threat_service/main.py` | FastAPI app; `/analyze` orchestrates the pipeline |
| Content classifier | `main.py::nlp_score` | Weighted signal categories → explainable score |
| Sender/domain analysis | `main.py::detect_display_name_spoofing`, `attribute_origin_type`, `dns_mx_lookup`, `whois_lookup`, VT checks | Spoofing, lookalikes, domain reputation |
| URL analysis | `main.py::analyze_urls` | Obfuscation, shorteners, risky TLDs, IP-literal URLs |
| Attachment analysis | `main.py::extract_attachments` | Dangerous/double extensions, SHA-256 hashing |
| Geolocation service | `main.py::geoip` (+ cache & provider fallback) | IP → city/org/ASN/TOR-VPN; per-hop enrichment |
| Attack reconstruction engine | `main.py::reconstruct_attack` | Kill-chain stages with OBSERVED/INFERRED labels |
| Scenario simulation engine | `main.py::simulate_scenarios` | Safe what-if paths (ignore/click/open/reply), SIM-labeled |
| Correlation engine | `main.py::cluster_into_campaign` + `build_correlation_graph` | Campaign clustering on IOC overlap; graph nodes/edges |
| Intelligence repository | `db.py` (`iocs`, `infrastructure`, `campaigns`, `case_ttps`) | Sanitized collective memory; recurrence counting |
| Collective matching | `main.py::collect_intel_matches` + `db.find_known_indicators` | New mail vs. known indicators/campaigns |
| Live ingestion | `main.py` live-sync engine + `mail_fetcher.py` | Poll-based mailbox sync (Gmail IMAP / Outlook Graph OAuth) |
| Frontend dashboard | `frontend/` (React + Vite) | Overview queue, case forensics, threat graph, hub pages |
| Intelligence API v1 | `/api/v1/*` (read-only, sanitized) | Future external consumers |

## Database Schema (PostgreSQL)

- `cases` — one row per analyzed email; full analysis JSONB (incl. `attack_chain`,
  `scenarios`, `intel_matches`), workspace slug, resolution state.
- `iocs` — sanitized indicator repository: `DOMAIN` / `IP` / `URL` / `FILE_HASH`;
  detections counter increments on recurrence (**this is the collective-memory core**).
- `campaigns` — clustered attack campaigns with IOC/TTP snapshots and time bounds.
- `infrastructure` — geolocated relay nodes (city/org/ASN/TOR-VPN).
- `connected_accounts` — live-sync mailbox registrations (secrets encrypted at rest).

Raw email bodies are **never stored globally by default** — PII masking is applied
(`MASK_PII=true`) and only a masked preview plus evidence hashes persist.

## Intelligence API v1 (read-only, sanitized)

```
GET /api/v1/indicators?type=DOMAIN|IP|URL|FILE_HASH&status=MALICIOUS&min_detections=2&limit=100
GET /api/v1/campaigns[/{campaign_id}]
```

Designed for future consumers: email gateways, SIEM platforms, EDR/AV products,
SOC tooling, browser-security extensions. No raw email content is exposed.

## Roadmap

**Phase 1 — MVP (done):** upload, analysis, explainable scoring, indicator
extraction, intelligence repository, attack reconstruction, campaign correlation,
threat graph/dashboard.

**Phase 2:** STIX/TAXII export from the repository; MISP bridge; multi-tenant
workspaces with RBAC; feedback loop (analyst verdicts re-weighting signals);
ML classifier trained on the accumulating repository.

**Phase 3:** public Intelligence API with API keys/rate limits; gateway integrations
(postfix/milter, Microsoft Graph mail-flow rules); browser-extension URL lookup;
federated hub-to-hub indicator sharing between deployments.
