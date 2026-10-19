"""SMTP delivery and text generation for manually triggered notice emails."""

import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import parseaddr

import streamlit as st


def _smtp_setting(name: str, default: str = "") -> str:
    try:
        secrets = st.secrets
    except (FileNotFoundError, RuntimeError):
        secrets = {}
    value = os.getenv(name) or secrets.get(name) or secrets.get(name.lower()) or default
    return str(value).strip()


def is_valid_email(address: str) -> bool:
    if "\r" in address or "\n" in address:
        return False
    display_name, parsed_address = parseaddr(address)
    return not display_name and parsed_address == address.strip() and "@" in parsed_address


def send_notice_email(to_email: str, subject: str, body: str) -> bool:
    """Send a manually requested notice email using SMTP settings in Streamlit Secrets."""
    smtp_host = _smtp_setting("SMTP_HOST", "smtp.gmail.com")
    smtp_port_value = _smtp_setting("SMTP_PORT", "587")
    smtp_user = _smtp_setting("SMTP_USER")
    smtp_pass = _smtp_setting("SMTP_PASS")

    if not smtp_user or not smtp_pass:
        st.error("SMTP credentials are missing. Configure SMTP_USER and SMTP_PASS in Streamlit Secrets.")
        return False
    if not is_valid_email(to_email):
        st.error("Enter a valid recipient email address.")
        return False

    try:
        smtp_port = int(smtp_port_value)
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = smtp_user
        msg["To"] = to_email.strip()

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(smtp_user, smtp_pass)
            refused_recipients = server.send_message(msg)
        if refused_recipients:
            st.error(f"SMTP server refused the recipient: {', '.join(refused_recipients)}.")
            return False
        return True
    except (OSError, ValueError, smtplib.SMTPException) as exc:
        st.error(f"Failed to dispatch email: {exc}")
        return False


def generate_owner_notice(infringing_url: str, original_url: str) -> str:
    """Render a Stage 1 notice for a website owner."""
    return f"""NOTICE OF COPYRIGHT INFRINGEMENT (DMCA Stage 1)

To Website Administrator / Owner,

Infringing Material URL: {infringing_url}
Authorized Original Asset: {original_url}

It has come to our attention that copyrighted visual assets belonging to our client are hosted/displayed on your website without valid authorization.

Please remove or disable access to the specified material within 96 hours (4 days) from the date of this notice. Failure to respond will result in immediate escalation to your upstream web hosting provider / CDN abuse team.

Regards,
AlphaGuard Automated Enforcement Team
"""


def generate_host_notice(infringing_url: str, original_url: str) -> str:
    """Render a Stage 2 escalation notice for a web host or CDN."""
    return f"""URGENT: STAGE 2 DMCA ESCALATION NOTICE

To Web Host / CDN Abuse Department,

Infringing Site URL: {infringing_url}
Original Protected Asset: {original_url}

This is a formal Stage 2 escalation. The website administrator was served a DMCA notice 4 days ago regarding unauthorized hosting of the asset linked above and has failed to remediate the infringement.

Under applicable copyright laws and hosting Terms of Service, we request that access to the infringing material be disabled promptly.

Regards,
AlphaGuard Automated Enforcement Team
"""
