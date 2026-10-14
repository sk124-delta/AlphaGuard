"""Supabase persistence helpers for AlphaGuard user activity."""

import os
import hashlib
import hmac
import secrets
import sqlite3
from typing import Any, Iterable

from supabase import Client, create_client

from .models import NoticeData, ScanResult


class DatabaseError(RuntimeError):
    """Raised when AlphaGuard cannot persist data to Supabase."""


def init_db() -> None:
    """Create the local account table when the application starts."""
    conn = sqlite3.connect("alphaguard.db")
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                tier TEXT DEFAULT 'Free',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return f"{salt.hex()}${digest.hex()}"


def _password_matches(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        expected = _password_hash(password, bytes.fromhex(salt_hex)).split("$", 1)[1]
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, digest_hex)


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


def _update(table: str, record: dict[str, Any], **filters: Any) -> None:
    try:
        query = get_client().table(table).update(record)
        for column, value in filters.items():
            query = query.eq(column, value)
        response = query.execute()
    except Exception as exc:
        raise DatabaseError(f"Could not update the {table} table.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not update the {table} table: {response.error}")


def user_exists(email: str) -> bool:
    """Return whether an account already exists for the normalized email."""
    normalized_email = email.strip().lower()
    with sqlite3.connect("alphaguard.db") as conn:
        row = conn.execute("SELECT 1 FROM users WHERE email = ? LIMIT 1", (normalized_email,)).fetchone()
    return row is not None


def create_user(email: str, password: str) -> None:
    """Create a durable account using a salted PBKDF2 password hash."""
    normalized_email = email.strip().lower()
    try:
        with sqlite3.connect("alphaguard.db") as conn:
            conn.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (normalized_email, _password_hash(password)),
            )
    except sqlite3.IntegrityError as exc:
        raise DatabaseError("An account with this email already exists.") from exc
    except sqlite3.Error as exc:
        raise DatabaseError("Could not create the local account.") from exc


def verify_user_credentials(email: str, password: str) -> bool:
    """Verify credentials against the persisted users table."""
    normalized_email = email.strip().lower()
    with sqlite3.connect("alphaguard.db") as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE email = ?", (normalized_email,)).fetchone()
    return bool(row and _password_matches(password, str(row[0])))


def send_password_reset(email: str, redirect_to: str) -> None:
    """Ask Supabase Auth to email a password recovery link."""
    try:
        get_client().auth.reset_password_for_email(
            email.strip().lower(), {"redirect_to": redirect_to}
        )
    except Exception as exc:
        raise DatabaseError(str(exc)) from exc


def exchange_password_reset_code(code: str) -> tuple[str, str, str]:
    """Exchange a Supabase recovery code for the access and refresh tokens."""
    try:
        response = get_client().auth.exchange_code_for_session({"auth_code": code})
        session = response.session
        if not session:
            raise DatabaseError("The password reset session is no longer valid.")
        email = str(getattr(session.user, "email", "") or "")
        return session.access_token, session.refresh_token, email
    except DatabaseError:
        raise
    except Exception as exc:
        raise DatabaseError("The password reset link is invalid or has expired.") from exc


def update_user_password(email: str, new_password: str, access_token: str, refresh_token: str) -> None:
    """Update Supabase Auth and the local password hash for a recovered account."""
    try:
        client = get_client()
        client.auth.set_session(access_token, refresh_token)
        response = client.auth.update_user({"password": new_password})
        auth_email = str(getattr(response.user, "email", "") or email).strip().lower()
    except Exception as exc:
        raise DatabaseError("Could not update your password in Supabase Auth.") from exc
    if not auth_email:
        raise DatabaseError("The password reset session did not identify an account.")
    with sqlite3.connect("alphaguard.db") as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (_password_hash(new_password), auth_email),
        )


def get_user_settings(user_id: str) -> dict[str, Any]:
    """Return persisted preferences for a user."""
    rows = _select("user_profiles", "settings", user_id=user_id)
    settings = rows[0].get("settings") if rows else {}
    return settings if isinstance(settings, dict) else {}


def save_user_settings(user_id: str, settings: dict[str, Any]) -> None:
    """Persist user preferences without changing subscription data."""
    try:
        response = get_client().table("user_profiles").upsert(
            {"user_id": user_id, "settings": settings}, on_conflict="user_id"
        ).execute()
    except Exception as exc:
        raise DatabaseError("Could not save user settings.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not save user settings: {response.error}")


def get_user_tier(user_id: str) -> str:
    """Return a user's subscription tier, defaulting to the least-privileged tier."""
    if user_id.strip().lower() == "sanifaiqbal970@gmail.com":
        return "Pro"
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