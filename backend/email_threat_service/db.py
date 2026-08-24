"""PostgreSQL persistence layer for MailShield.

All application data (cases, campaigns, IOCs, infrastructure, TTPs) lives here.
No seed/demo data is inserted — every row originates from real email analyses.
"""
import os
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json
from psycopg_pool import ConnectionPool

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://traceai:traceai@localhost:5432/traceai",
)

_pool: ConnectionPool | None = None


def init_pool():
    global _pool
    if _pool is None:
        _pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=8, open=True)
    return _pool


@contextmanager
def get_conn():
    pool = init_pool()
    with pool.connection() as conn:
        yield conn


def init_db():
    """Create schema if it does not exist. Idempotent."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("""
            CREATE SEQUENCE IF NOT EXISTS inc_id_seq START 2501;

            CREATE TABLE IF NOT EXISTS cases (
                id            TEXT PRIMARY KEY,
                sender        TEXT,
                subject       TEXT,
                score         INTEGER,
                label         TEXT,
                accent        TEXT,
                initials      TEXT,
                status        TEXT NOT NULL DEFAULT 'open',
                campaign_id   TEXT,
                analysis      JSONB,
                resolution    TEXT,
                analyst       TEXT,
                received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                resolved_at   TIMESTAMPTZ
            );

            CREATE TABLE IF NOT EXISTS campaigns (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                risk        TEXT,
                accent      TEXT,
                count       INTEGER NOT NULL DEFAULT 1,
                iocs        JSONB NOT NULL DEFAULT '[]'::jsonb,
                ttps        JSONB NOT NULL DEFAULT '[]'::jsonb,
                first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS iocs (
                id          SERIAL PRIMARY KEY,
                type        TEXT NOT NULL,
                value       TEXT NOT NULL UNIQUE,
                threat      TEXT,
                detections  INTEGER NOT NULL DEFAULT 1,
                vt          INTEGER NOT NULL DEFAULT 0,
                status      TEXT,
                accent      TEXT,
                first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS infrastructure (
                ip         TEXT PRIMARY KEY,
                host       TEXT,
                city       TEXT,
                country    TEXT,
                org        TEXT,
                lat        DOUBLE PRECISION DEFAULT 0,
                lng        DOUBLE PRECISION DEFAULT 0,
                type       TEXT,
                risk       TEXT,
                vpn        BOOLEAN DEFAULT FALSE,
                tor        BOOLEAN DEFAULT FALSE,
                last_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS case_ttps (
                case_id   TEXT REFERENCES cases(id) ON DELETE CASCADE,
                ttp_id    TEXT NOT NULL,
                ttp_name  TEXT,
                detail    TEXT,
                PRIMARY KEY (case_id, ttp_id)
            );

            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
            CREATE INDEX IF NOT EXISTS idx_cases_campaign ON cases(campaign_id);
            ALTER TABLE cases ADD COLUMN IF NOT EXISTS ws_slug TEXT NOT NULL DEFAULT 'general';

            CREATE TABLE IF NOT EXISTS connected_accounts (
                id            TEXT PRIMARY KEY,
                provider      TEXT NOT NULL,
                email         TEXT NOT NULL,
                method        TEXT NOT NULL DEFAULT 'imap',
                secret_enc    TEXT,
                enabled       BOOLEAN NOT NULL DEFAULT TRUE,
                last_sync_at  TIMESTAMPTZ,
                last_status   TEXT,
                processed     INTEGER NOT NULL DEFAULT 0,
                connected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            DROP TABLE IF EXISTS workspaces CASCADE;
            CREATE TABLE workspaces (
                id           SERIAL PRIMARY KEY,
                slug         TEXT UNIQUE NOT NULL,
                name         TEXT UNIQUE NOT NULL,
                description  TEXT NOT NULL DEFAULT '',
                icon         TEXT NOT NULL DEFAULT 'shield',
                accent       TEXT NOT NULL DEFAULT 'blue',
                is_custom    BOOLEAN NOT NULL DEFAULT FALSE,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        """)
        for row in WORKSPACE_SEED:
            cur.execute(
                "INSERT INTO workspaces (slug, name, description, icon, accent) "
                "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (slug) DO NOTHING",
                row,
            )
        conn.commit()


# Global threat-domain hub. Every analyzed case is classified into exactly one
# of these shared workspaces, so all users see the same taxonomy.
WORKSPACE_SEED = [
    ("general",       "General Triage",             "Mixed inbox monitoring and first-pass triage of suspicious mail.",        "radar",  "blue"),
    ("phishing",      "Phishing & Credential Theft", "Credential harvesting, fake login pages and social-engineering lures.",  "skull",  "coral"),
    ("bec",           "BEC & Payment Fraud",         "Invoice fraud, executive impersonation and wire-transfer diversion.",    "target", "amber"),
    ("malware",       "Malware & Ransomware",        "Malicious attachments, droppers, ransom notes and payload delivery.",    "file",   "mint"),
    ("impersonation", "Spoofing & Impersonation",    "Look-alike domains, display-name spoofing and brand abuse.",             "eye",    "amber"),
    ("account",       "Account Takeover",            "Abuse of compromised legitimate accounts and anomalous authentication.", "lock",   "coral"),
    ("spam",          "Spam & Unwanted Mail",        "Bulk campaigns, marketing abuse and low-reputation senders.",            "inbox",  "blue"),
]


# ── Workspaces ───────────────────────────────────────────────────────────────

def list_workspaces() -> list:
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT w.id, w.slug, w.name, w.description, w.icon, w.accent,
                   w.is_custom, w.created_at,
                   (SELECT COUNT(*) FROM cases c
                     WHERE c.ws_slug = w.slug AND c.status='open')   AS open_cases,
                   (SELECT COUNT(*) FROM cases c
                     WHERE c.ws_slug = w.slug)                       AS total_cases,
                   (SELECT COUNT(*) FROM cases c
                     WHERE c.ws_slug = w.slug AND c.score >= 55)     AS threats
            FROM workspaces w ORDER BY w.is_custom, w.id
            """
        )
        return cur.fetchall()


def create_workspace(name, description="") -> dict | None:
    import re as _re
    base = _re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")[:40] or None
    if not base:
        return None
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """INSERT INTO workspaces (slug, name, description, icon, accent, is_custom)
               VALUES (%s,%s,%s,'shield','blue',TRUE)
               ON CONFLICT (slug) DO NOTHING
               RETURNING id, slug, name""",
            (base, name.strip(), (description or "").strip()[:300]),
        )
        row = cur.fetchone()
        conn.commit()
        return row


def delete_workspace(ws_id):
    """Returns ('deleted', row), ('has_cases', None) or ('builtin', None)."""
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM workspaces WHERE id=%s", (ws_id,))
        ws = cur.fetchone()
        if not ws:
            return "not_found", None
        if not ws["is_custom"]:
            return "builtin", None
        cur.execute("SELECT COUNT(*) AS n FROM cases WHERE ws_slug=%s", (ws["slug"],))
        if cur.fetchone()["n"] > 0:
            return "has_cases", None
        cur.execute("DELETE FROM workspaces WHERE id=%s RETURNING id, name", (ws_id,))
        row = cur.fetchone()
        conn.commit()
        return "deleted", row


def next_case_id() -> str:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT nextval('inc_id_seq')")
        seq = cur.fetchone()[0]
        conn.commit()
    return f"INC-{seq}"


# ── Cases ────────────────────────────────────────────────────────────────────

def insert_case(case_id, sender, subject, score, label, accent, initials,
                campaign_id, analysis, received_at=None, ws_slug="general"):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cases (id, sender, subject, score, label, accent, initials,
                               status, campaign_id, analysis, received_at, ws_slug)
            VALUES (%s,%s,%s,%s,%s,%s,%s,'open',%s,%s,COALESCE(%s, now()),%s)
            ON CONFLICT (id) DO UPDATE SET analysis = EXCLUDED.analysis,
                                           score = EXCLUDED.score,
                                           label = EXCLUDED.label,
                                           accent = EXCLUDED.accent
            """,
            (case_id, sender, subject, score, label, accent, initials,
             campaign_id, Json(analysis or {}), received_at, ws_slug),
        )
        conn.commit()


def get_open_cases(ws=None) -> list[dict]:
    where, vals = "status='open'", []
    if ws:
        where += " AND ws_slug=%s"
        vals.append(ws)
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT id, sender, subject, score, label, accent, initials, received_at "
            f"FROM cases WHERE {where} ORDER BY received_at DESC",
            vals,
        )
        return cur.fetchall()


def get_resolved_cases(ws=None) -> list[dict]:
    where, vals = "status='resolved'", []
    if ws:
        where += " AND ws_slug=%s"
        vals.append(ws)
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT id, sender, subject, score, label, accent, resolution, analyst, "
            f"resolved_at FROM cases WHERE {where} ORDER BY resolved_at DESC",
            vals,
        )
        rows = cur.fetchall()
    out = []
    for r in rows:
        closed = r.get("resolved_at")
        out.append({
            "id": r["id"],
            "sender": r["sender"] or "",
            "subject": r["subject"] or "",
            "closed": closed.strftime("%d %b %Y") if closed else "—",
            "score": r["score"],
            "label": r["label"],
            "accent": r["accent"],
            "resolution": r["resolution"] or "—",
            "analyst": r["analyst"] or "—",
        })
    return out


def get_case_row(case_id) -> dict | None:
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM cases WHERE id=%s", (case_id,))
        return cur.fetchone()


def resolve_case(case_id, action, analyst):
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "UPDATE cases SET status='resolved', resolution=%s, analyst=%s, "
            "resolved_at=now() WHERE id=%s AND status='open' RETURNING *",
            (action, analyst, case_id),
        )
        row = cur.fetchone()
        conn.commit()
        return row


# ── Campaigns ────────────────────────────────────────────────────────────────

def match_campaign(ioc_values: list[str]) -> dict | None:
    vals = [v.lower() for v in ioc_values if v]
    if not vals:
        return None
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM campaigns WHERE iocs ?| %s::text[] LIMIT 1", (vals,))
        return cur.fetchone()


def create_campaign(camp_id, name, risk, accent, iocs, ttps):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO campaigns (id, name, risk, accent, count, iocs, ttps) "
            "VALUES (%s,%s,%s,%s,1,%s,%s)",
            (camp_id, name, risk, accent, Json(iocs), Json(ttps)),
        )
        conn.commit()


def update_campaign_hit(camp_id, new_iocs, new_ttps):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE campaigns SET count = count + 1, last_seen = now(),
                iocs = (SELECT jsonb_agg(DISTINCT v) FROM (
                            SELECT jsonb_array_elements(iocs) AS v
                            UNION SELECT jsonb_array_elements(%s::jsonb)) s),
                ttps = (SELECT jsonb_agg(DISTINCT v) FROM (
                            SELECT jsonb_array_elements(ttps) AS v
                            UNION SELECT jsonb_array_elements(%s::jsonb)) s)
            WHERE id = %s
            """,
            (Json(new_iocs), Json(new_ttps), camp_id),
        )
        conn.commit()


def list_campaigns() -> list[dict]:
    fmt = "%d %b %Y"
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM campaigns ORDER BY last_seen DESC")
        camps = cur.fetchall()
        cur.execute(
            "SELECT campaign_id, COUNT(*) AS n, AVG(score) AS avg_score, "
            "array_agg(id) AS ids FROM cases WHERE campaign_id IS NOT NULL "
            "GROUP BY campaign_id"
        )
        rel = {r["campaign_id"]: r for r in cur.fetchall()}
    out = []
    for c in camps:
        r = rel.get(c["id"])
        out.append({
            "id": c["id"],
            "name": c["name"],
            "risk": c["risk"],
            "accent": c["accent"],
            "count": c["count"],
            "iocs": c["iocs"],
            "ttps": c["ttps"],
            "first_seen": c["first_seen"].strftime(fmt) if c["first_seen"] else "—",
            "last_seen": c["last_seen"].strftime(fmt) if c["last_seen"] else "—",
            "related_case_ids": (r["ids"] if r else []),
            "avg_risk_score": float(r["avg_score"]) if r and r["avg_score"] is not None else 0,
        })
    return out


# ── IOCs ─────────────────────────────────────────────────────────────────────

def upsert_ioc(ioc_type, value, threat, vt, status, accent):
    if not value:
        return
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO iocs (type, value, threat, vt, status, accent)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (value) DO UPDATE SET
                detections = iocs.detections + 1,
                last_seen = now(),
                vt = GREATEST(iocs.vt, EXCLUDED.vt),
                threat = COALESCE(EXCLUDED.threat, iocs.threat),
                status = EXCLUDED.status,
                accent = EXCLUDED.accent
            """,
            (ioc_type, value.lower(), threat, vt or 0, status, accent),
        )
        conn.commit()


def list_iocs() -> list[dict]:
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM iocs ORDER BY detections DESC, last_seen DESC")
        return cur.fetchall()


# ── Infrastructure ───────────────────────────────────────────────────────────

def upsert_infra(ip, host, city, country, org, lat, lng, node_type, risk, vpn, tor):
    if not ip:
        return
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO infrastructure (ip, host, city, country, org, lat, lng, type,
                                        risk, vpn, tor, last_seen)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
            ON CONFLICT (ip) DO UPDATE SET
                host = COALESCE(NULLIF(infrastructure.host,''), EXCLUDED.host),
                city = COALESCE(EXCLUDED.city, infrastructure.city),
                country = COALESCE(EXCLUDED.country, infrastructure.country),
                org = COALESCE(EXCLUDED.org, infrastructure.org),
                lat = COALESCE(NULLIF(EXCLUDED.lat,0), infrastructure.lat),
                lng = COALESCE(NULLIF(EXCLUDED.lng,0), infrastructure.lng),
                risk = CASE WHEN infrastructure.risk = 'green' THEN EXCLUDED.risk
                            ELSE infrastructure.risk END,
                vpn = infrastructure.vpn OR EXCLUDED.vpn,
                tor = infrastructure.tor OR EXCLUDED.tor,
                last_seen = now()
            """,
            (ip, host, city, country, org, lat, lng, node_type, risk, vpn, tor),
        )
        conn.commit()


def list_infrastructure() -> list[dict]:
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM infrastructure ORDER BY last_seen DESC")
        return cur.fetchall()


# ── TTPs ─────────────────────────────────────────────────────────────────────

def insert_case_ttps(case_id, ttps):
    if not ttps:
        return
    with get_conn() as conn, conn.cursor() as cur:
        for t in ttps:
            cur.execute(
                "INSERT INTO case_ttps (case_id, ttp_id, ttp_name, detail) "
                "VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (case_id, t.get("id"), t.get("name"), t.get("detail")),
            )
        conn.commit()


def aggregate_ttps() -> list[dict]:
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT cttp.ttp_id AS id, MAX(cttp.ttp_name) AS name, COUNT(*) AS count "
            "FROM case_ttps cttp GROUP BY cttp.ttp_id ORDER BY count DESC"
        )
        return cur.fetchall()


# ── Stats (overview dashboard) ───────────────────────────────────────────────

def get_stats(ws=None) -> dict:
    where, vals = "TRUE", []
    if ws:
        where, vals = "ws_slug=%s", [ws]
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT COUNT(*) AS total FROM cases WHERE {where}", vals)
        total = cur.fetchone()["total"]
        cur.execute(f"SELECT COUNT(*) AS n FROM cases WHERE {where} AND score >= 55", vals)
        threats = cur.fetchone()["n"]
        cur.execute(f"SELECT COUNT(*) AS n FROM cases WHERE {where} AND status='resolved'", vals)
        resolved = cur.fetchone()["n"]
        cur.execute(f"SELECT COUNT(*) AS n FROM cases WHERE {where} AND received_at > now() - interval '24 hours'", vals)
        threats_24h = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) AS n, COALESCE(SUM(detections),0) AS hits FROM iocs")
        ioc_row = cur.fetchone()
        cur.execute("SELECT COUNT(*) AS n FROM iocs WHERE status='MALICIOUS'")
        malicious = cur.fetchone()["n"]
    return {
        "emails_analyzed": total if total else None,
        "threats_detected": threats if total else None,
        "new_threats_24h": threats_24h if total else None,
        "resolution_rate": round(resolved * 100.0 / total, 1) if total else None,
        "ioc_matches": int(ioc_row["hits"]) if total else None,
        "high_confidence_hits": malicious if total else None,
    }


# ── Connected accounts (live sync) ───────────────────────────────────────────

def upsert_connected_account(acct_id, provider, email, method, secret_enc):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO connected_accounts (id, provider, email, method, secret_enc)
               VALUES (%s,%s,%s,%s,%s)
               ON CONFLICT (id) DO UPDATE SET
                 provider=EXCLUDED.provider, method=EXCLUDED.method,
                 secret_enc=EXCLUDED.secret_enc, enabled=TRUE""",
            (acct_id, provider, email, method, secret_enc),
        )
        conn.commit()


def list_connected_accounts() -> list:
    with get_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM connected_accounts ORDER BY connected_at")
        return cur.fetchall()


def delete_connected_account(acct_id):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM connected_accounts WHERE id=%s", [acct_id])
        conn.commit()
        return cur.rowcount > 0


def set_account_synced(acct_id, status: str, processed_inc: int = 0):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE connected_accounts
               SET last_sync_at=now(), last_status=%s,
                   processed = processed + %s""",
            [status, processed_inc],
        )
        conn.commit()


def message_id_seen(message_id: str) -> bool:
    if not message_id or message_id in ("(No Subject)", ""):
        return False
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM cases WHERE analysis->>'message_id' = %s LIMIT 1",
            [message_id],
        )
        return cur.fetchone() is not None
