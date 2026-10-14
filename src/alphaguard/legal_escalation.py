"""Draft follow-up countermeasures for overdue takedown notices."""

from typing import Any


def build_escalation_drafts(notice: dict[str, Any]) -> dict[str, str]:
    target_url = str(notice.get("target_url") or "")
    image_url = str(notice.get("infringing_image_url") or "")
    owner_email = str(notice.get("owner_email") or "")
    claimant = str(notice.get("owner_name") or "Copyright owner")
    summary = (
        f"Copyright infringement follow-up\n"
        f"Claimant: {claimant}\n"
        f"Contact: {owner_email}\n"
        f"Reported URL: {target_url}\n"
        f"Image URL: {image_url}\n"
        f"Original work: {notice.get('original_url') or ''}\n"
        f"Prior notice dispatched: {notice.get('dispatched_at') or ''}\n"
        "Please review this report and advise on the applicable removal process."
    )
    return {
        "Google Search": (
            "Google Search de-indexing follow-up\n"
            "Submit through Google Search Console's Removals tool or the applicable "
            "Google legal removal process. Google API request not submitted.\n\n"
            + summary
        ),
        "Bing": (
            "Bing content removal claim\n"
            "Submit using Microsoft's Content Removal Request form. No claim was submitted.\n\n"
            + summary
        ),
        "Namecheap": "Namecheap abuse ticket draft\n\n" + summary,
        "GoDaddy": "GoDaddy abuse ticket draft\n\n" + summary,
        "Cloudflare": "Cloudflare abuse ticket draft\n\n" + summary,
        "AWS": "AWS abuse report draft\n\n" + summary,
    }
