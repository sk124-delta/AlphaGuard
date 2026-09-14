"""DMCA notice generation helpers."""

from datetime import date

from .models import NoticeData


def generate_notice(data: NoticeData, notice_date: date | None = None) -> str:
    """Render a professional DMCA notification from validated notice data."""
    current_date = (notice_date or date.today()).isoformat()
    return f"""DMCA COPYRIGHT INFRINGEMENT NOTIFICATION

Date: {current_date}

To the Designated Copyright Agent:

I, {data.claimant_name}, am the copyright owner or an authorized representative of the copyright owner.

1. Original work
The copyrighted work is: {data.original_work}
Original work URL: {data.original_url}

2. Infringing material
The material that is allegedly infringing is available at:
{data.infringing_url}

3. Contact information
Name: {data.claimant_name}
Email: {data.claimant_email}
Address: {data.claimant_address}

4. Statements
{data.good_faith_statement}

{data.accuracy_statement}

Please remove or disable access to the infringing material and notify the relevant account holder as required by applicable law.

Sincerely,
{data.signature or data.claimant_name}
"""
