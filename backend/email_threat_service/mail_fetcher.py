import imaplib
import logging
import requests
import json

import os

IMAP_SERVERS = {
    "gmail": [{"host": "imap.gmail.com", "port": 993}],
    "outlook": [
        {"host": "outlook.office365.com", "port": 993},
        {"host": "imap-mail.outlook.com", "port": 993},
        {"host": "imap.live.com", "port": 993}
    ],
}

# Standard Microsoft Multi-Tenant Public Client ID for Graph & OAuth Device Code
MS_CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "14d82eec-204b-4c2f-b7e8-296a70dab67e")


def start_outlook_device_code() -> dict:
    """Initiates Microsoft OAuth2 Device Code Flow for real live Outlook access."""
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
    data = {
        "client_id": MS_CLIENT_ID,
        "scope": "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read offline_access"
    }
    try:
        res = requests.post(url, data=data, timeout=10)
        res.raise_for_status()
        payload = res.json()
        return {
            "user_code": payload.get("user_code"),
            "device_code": payload.get("device_code"),
            "verification_uri": payload.get("verification_uri", "https://login.microsoft.com/device"),
            "expires_in": payload.get("expires_in", 900),
            "interval": payload.get("interval", 5),
            "message": payload.get("message")
        }
    except Exception as e:
        logging.error("Failed to start Microsoft Device Code Flow: %s", str(e))
        raise RuntimeError(f"Failed to connect to Microsoft OAuth server: {str(e)}")


def poll_outlook_token(device_code: str) -> dict:
    """Polls Microsoft token endpoint until user approves authorization."""
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": MS_CLIENT_ID,
        "device_code": device_code
    }
    res = requests.post(url, data=data, timeout=10)
    payload = res.json()

    if res.status_code == 200 and "access_token" in payload:
        return {
            "status": "complete",
            "access_token": payload["access_token"],
            "refresh_token": payload.get("refresh_token")
        }
    
    error_code = payload.get("error")
    if error_code == "authorization_pending":
        return {"status": "pending", "message": "Waiting for user authorization..."}
    elif error_code == "slow_down":
        return {"status": "pending", "message": "Slowing down polling..."}
    elif error_code == "expired_token":
        raise RuntimeError("Authorization code expired. Please restart sign-in.")
    else:
        err_desc = payload.get("error_description", "Authentication failed")
        raise RuntimeError(f"Microsoft Auth Error: {err_desc}")


def fetch_outlook_live_emails_via_graph(access_token: str, max_emails: int = 5) -> list:
    """Fetches real live emails directly from Microsoft Graph API using OAuth2 access token."""
    graph_url = f"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top={max_emails}&$select=id,subject,from,toRecipients,receivedDateTime,body,internetMessageHeaders"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    try:
        res = requests.get(graph_url, headers=headers, timeout=12)
        res.raise_for_status()
        data = res.json()
        messages = data.get("value", [])

        raw_emails = []
        for msg in messages:
            sender_obj = msg.get("from", {}).get("emailAddress", {})
            sender_name = sender_obj.get("name", "")
            sender_addr = sender_obj.get("address", "")
            sender_header = f'"{sender_name}" <{sender_addr}>' if sender_name else sender_addr

            subject = msg.get("subject", "(No Subject)")
            date_str = msg.get("receivedDateTime", "")
            body_content = msg.get("body", {}).get("content", "")

            # Reconstruct clean text payload for forensic email analysis
            raw_str = f"""From: {sender_header}
To: recipient@outlook.com
Subject: {subject}
Date: {date_str}
Message-ID: <{msg.get('id', 'ms-graph-id')}>
Content-Type: text/plain; charset="utf-8"

{body_content}
"""
            raw_emails.append(raw_str)

        return raw_emails
    except Exception as e:
        logging.error("Failed to fetch live Outlook emails via Microsoft Graph: %s", str(e))
        raise RuntimeError(f"Failed to fetch live Outlook messages: {str(e)}")


def get_imap_configs(provider: str, custom_host: str = None, custom_port: int = 993):
    provider_key = provider.lower().strip()
    if custom_host:
        return [{"host": custom_host, "port": custom_port}]
    if provider_key in IMAP_SERVERS:
        return IMAP_SERVERS[provider_key]
    raise ValueError(f"Unsupported provider '{provider}'. Use 'gmail', 'outlook', or specify custom_host.")


def format_imap_error(provider: str, raw_err: str) -> str:
    err_str = str(raw_err)
    if "Basic authentication is disabled" in err_str or "BASICAUTHCONN" in err_str:
        return (
            "Microsoft has disabled Basic Auth for Outlook. Please click 'Sign in with Microsoft' to authorize live email sync via Modern OAuth2."
        )
    if "Application-specific password required" in err_str or "185833" in err_str:
        return (
            "Gmail requires a 16-character App Password instead of your regular password. "
            "Please generate one at: https://myaccount.google.com/apppasswords"
        )
    if "AUTHENTICATIONFAILED" in err_str or "login failed" in err_str.lower() or "invalid credentials" in err_str.lower():
        if provider.lower() == "gmail":
            return (
                "Gmail Authentication Failed. Please ensure 2-Step Verification is enabled and "
                "use an App Password generated at https://myaccount.google.com/apppasswords"
            )
        elif provider.lower() == "outlook":
            return (
                "Outlook Authentication Failed. Microsoft requires OAuth2 sign-in for Outlook. "
                "Use 'Sign in with Microsoft' below."
            )
        return "Authentication failed. Please verify your email and password."

    clean = err_str.replace("b'", "'").replace("b\"", "\"")
    return f"IMAP Connection Error: {clean}"


def test_connection(provider: str, email_address: str, password: str, custom_host: str = None, custom_port: int = 993) -> dict:
    configs = get_imap_configs(provider, custom_host, custom_port)
    last_err = None

    for cfg in configs:
        host, port = cfg["host"], cfg["port"]
        try:
            mail = imaplib.IMAP4_SSL(host, port, timeout=8)
            mail.login(email_address, password)
            mail.select("INBOX", readonly=True)
            mail.logout()
            return {
                "success": True,
                "provider": provider,
                "email": email_address,
                "message": f"Successfully connected to {provider.upper()} ({email_address})"
            }
        except Exception as e:
            last_err = e

    friendly_err = format_imap_error(provider, str(last_err))
    raise RuntimeError(friendly_err)


def get_demo_raw_emails(provider: str, email_address: str, max_emails: int = 3) -> list:
    """Returns realistic raw RFC822 email payloads for instant live testing."""
    domain = email_address.split("@")[-1] if "@" in email_address else "outlook.com"
    demo_emails = [
        f"""From: "Accounts Payable" <accounts-payable@micros0ft-billing.com>
To: <{email_address}>
Subject: URGENT: Overdue Invoice #99412 - Immediate Action Required
Date: Mon, 24 Aug 2026 00:10:00 +0000
Message-ID: <live-demo-1@{domain}>
Content-Type: text/plain; charset="utf-8"

Dear Customer,

Your account statement is past due. Please review the attached invoice Invoice_88412.xlsm immediately to avoid service interruption.

Verify online: http://micros0ft-billing.com/pay-now

Origin Server: 185.23.45.10 (Agra, IN)
""",
        f"""From: "Executive Office" <ceo.office@northstar-holdings-corp.net>
To: <{email_address}>
Subject: CONFIDENTIAL: Wire Transfer Request for Acquisition
Date: Sun, 23 Aug 2026 23:45:00 +0000
Message-ID: <live-demo-2@{domain}>
Content-Type: text/plain; charset="utf-8"

Hi,

Please process a wire transfer of $45,000 for the pending acquisition today. 
Reply directly to this email with confirmation details once sent.

Sender Proxy: 41.58.120.77 (Lagos, NG)
""",
        f"""From: "Cloud Storage Alert" <support@cloud-verify-storage.net>
To: <{email_address}>
Subject: Warning: Your storage allocation is 98% full
Date: Sun, 23 Aug 2026 22:30:00 +0000
Message-ID: <live-demo-3@{domain}>
Content-Type: text/plain; charset="utf-8"

Your storage mailbox is almost full. Upgrade your storage quota now to continue receiving messages:

http://cloud-verify-storage.net/login

Host VPS: 95.216.44.22 (Frankfurt, DE)
"""
    ]
    return demo_emails[:max_emails]


def fetch_unread_emails(provider: str, email_address: str, password: str, max_emails: int = 5, custom_host: str = None, custom_port: int = 993, use_demo: bool = False) -> list:
    if use_demo or password.strip().lower() in ("demo", "test", "demo123"):
        return get_demo_raw_emails(provider, email_address, max_emails)

    configs = get_imap_configs(provider, custom_host, custom_port)
    raw_emails = []
    last_err = None

    for cfg in configs:
        host, port = cfg["host"], cfg["port"]
        try:
            mail = imaplib.IMAP4_SSL(host, port, timeout=10)
            mail.login(email_address, password)
            mail.select("INBOX")

            status, messages = mail.search(None, "UNSEEN")
            email_ids = messages[0].split()

            if not email_ids:
                status, messages = mail.search(None, "ALL")
                email_ids = messages[0].split()[-max_emails:]
            else:
                email_ids = email_ids[-max_emails:]

            for e_id in reversed(email_ids):
                res, data = mail.fetch(e_id, "(RFC822)")
                if res != "OK":
                    continue
                for response_part in data:
                    if isinstance(response_part, tuple):
                        raw_bytes = response_part[1]
                        try:
                            raw_str = raw_bytes.decode("utf-8", errors="replace")
                        except Exception:
                            raw_str = raw_bytes.decode("latin1", errors="replace")
                        raw_emails.append(raw_str)

            mail.logout()
            return raw_emails
        except Exception as e:
            last_err = e

    friendly_err = format_imap_error(provider, str(last_err))
    logging.error("IMAP Fetch Error for %s (%s): %s", provider, email_address, friendly_err)
    raise RuntimeError(friendly_err)
