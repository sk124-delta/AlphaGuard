"""Public takedown email helpers used by the Streamlit app."""

import time

from src.alphaguard.notice_email import (
    generate_host_notice,
    generate_owner_notice,
    is_valid_email,
    send_notice_email,
)


def generate_notice_subject() -> str:
    """Create a timestamped subject line for DMCA notice emails."""
    return f"Notice of Copyright Infringement - Ref: AG-2026-{int(time.time())}"


__all__ = [
    "send_notice_email",
    "generate_owner_notice",
    "generate_host_notice",
    "is_valid_email",
    "generate_notice_subject",
]
