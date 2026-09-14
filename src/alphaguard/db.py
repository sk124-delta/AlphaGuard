"""Supabase persistence helpers for AlphaGuard user activity."""

import os
from typing import Any, Iterable

from supabase import Client, create_client

from .models import NoticeData, ScanResult


class DatabaseError(RuntimeError):
    """Raised when AlphaGuard cannot persist data to Supabase."""


def get_client() -> Client:
    """Create a Supabase client from the configured environment variables."""
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    if not url or not key:
        raise DatabaseError("SUPABASE_URL and SUPABASE_KEY are not configured.")
    return create_client(url, key)


def _insert(table: str, record: dict[str, Any]) -> None:
    try:
        response = get_client().table(table).insert(record).execute()
    except Exception as exc:
        raise DatabaseError(f"Could not save data to the {table} table.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not save data to the {table} table: {response.error}")


def _select(table: str, columns: str = "*", **filters: Any) -> list[dict[str, Any]]:
    try:
        query = get_client().table(table).select(columns)
        for column, value in filters.items():
            query = query.eq(column, value)
        response = query.execute()
    except Exception as exc:
        raise DatabaseError(f"Could not read data from the {table} table.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not read data from the {table} table: {response.error}")
    return response.data or []


def get_user_tier(user_id: str) -> str:
    """Return a user's subscription tier, defaulting to the least-privileged tier."""
    rows = _select("user_profiles", "tier", user_id=user_id)
    return str(rows[0].get("tier") or "Free") if rows else "Free"


def get_user_id_by_stripe_customer(customer_id: str) -> str | None:
    """Find the local user associated with a Stripe customer ID."""
    rows = _select("user_profiles", "user_id", stripe_customer_id=customer_id)
    return str(rows[0]["user_id"]) if rows else None


def update_user_subscription(
    user_id: str,
    tier: str,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
) -> None:
    """Persist a user's tier and Stripe identifiers."""
    if tier not in {"Free", "Pro"}:
        raise ValueError("tier must be either 'Free' or 'Pro'.")
    record: dict[str, Any] = {"user_id": user_id, "tier": tier}
    if stripe_customer_id is not None:
        record["stripe_customer_id"] = stripe_customer_id
    if stripe_subscription_id is not None:
        record["stripe_subscription_id"] = stripe_subscription_id
    try:
        response = get_client().table("user_profiles").upsert(record, on_conflict="user_id").execute()
    except Exception as exc:
        raise DatabaseError("Could not update the user's subscription.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not update the user's subscription: {response.error}")


def save_encoded_image_metadata(
    user_id: str,
    filename: str,
    image_size: tuple[int, int],
    message_length: int,
    capacity: int,
    image_url: str = "",
) -> None:
    """Persist metadata for an image that successfully received an encoded message."""
    _insert(
        "encoded_images",
        {
            "user_id": user_id,
            "filename": filename,
            "width": image_size[0],
            "height": image_size[1],
            "message_length": message_length,
            "capacity_bytes": capacity,
            "image_url": image_url,
            "is_active": bool(image_url),
        },
    )


def get_active_protected_assets() -> list[dict[str, Any]]:
    """Return active encoded assets that have a public URL to scan."""
    return _select("encoded_images", "id, user_id, image_url", is_active=True)


def get_detected_match_links(asset_id: int, links: Iterable[str]) -> set[str]:
    """Return links already recorded for one protected asset."""
    links = list(dict.fromkeys(link for link in links if link))
    if not links:
        return set()
    try:
        response = get_client().table("detected_matches").select("match_url").eq("asset_id", asset_id).in_("match_url", links).execute()
    except Exception as exc:
        raise DatabaseError("Could not read existing detected matches.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not read existing detected matches: {response.error}")
    return {row["match_url"] for row in (response.data or [])}


def save_detected_match(user_id: str, asset_id: int, image_url: str, result: ScanResult) -> None:
    """Persist one newly detected infringement match."""
    _insert(
        "detected_matches",
        {
            "user_id": user_id,
            "asset_id": asset_id,
            "image_url": image_url,
            "match_url": result.link,
            "title": result.title,
            "source": result.source,
            "thumbnail": result.thumbnail,
            "position": result.position,
            "raw": result.raw,
        },
    )


def update_user_match_count(user_id: str, match_count: int) -> None:
    """Update the user's aggregate detected-match flag and count."""
    try:
        response = (
            get_client()
            .table("user_match_counts")
            .upsert(
                {
                    "user_id": user_id,
                    "match_count": match_count,
                    "has_detected_matches": match_count > 0,
                },
                on_conflict="user_id",
            )
            .execute()
        )
    except Exception as exc:
        raise DatabaseError("Could not update the user's match count.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not update the user's match count: {response.error}")


def get_user_match_count(user_id: str) -> int:
    """Return the user's current aggregate detected-match count."""
    rows = _select("user_match_counts", "match_count", user_id=user_id)
    return int(rows[0].get("match_count", 0)) if rows else 0


def _scan_record(user_id: str, image_url: str, provider: str, results: Iterable[ScanResult]) -> dict[str, Any]:
    return {
        "user_id": user_id,
        "image_url": image_url,
        "provider": provider,
        "results": [
            {
                "title": result.title,
                "link": result.link,
                "source": result.source,
                "displayed_link": result.displayed_link,
                "thumbnail": result.thumbnail,
                "position": result.position,
                "raw": result.raw,
            }
            for result in results
        ],
    }


def save_scan_results(user_id: str, image_url: str, provider: str, results: Iterable[ScanResult]) -> None:
    """Persist one completed image scan and its normalized results."""
    _insert("scan_results", _scan_record(user_id, image_url, provider, results))


def save_valueserp_scan_results(user_id: str, image_url: str, results: Iterable[ScanResult]) -> None:
    """Persist a completed ValueSERP scan and its normalized results."""
    save_scan_results(user_id, image_url, "ValueSERP", results)


def save_dmca_notice_log(user_id: str, notice_data: NoticeData, notice: str) -> None:
    """Persist a generated DMCA notice and the information used to create it."""
    _insert(
        "dmca_notices",
        {
            "user_id": user_id,
            "claimant_name": notice_data.claimant_name,
            "claimant_email": notice_data.claimant_email,
            "claimant_address": notice_data.claimant_address,
            "original_work": notice_data.original_work,
            "original_url": notice_data.original_url,
            "infringing_url": notice_data.infringing_url,
            "signature": notice_data.signature,
            "notice": notice,
        },
    )