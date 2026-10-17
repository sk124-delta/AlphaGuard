"""Supabase persistence helpers for AlphaGuard user activity."""

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import UUID

from supabase import Client, create_client

from .models import NoticeData, ScanResult
from .legal_escalation import build_escalation_drafts
from .url_utils import primary_domain_from_url


ADMIN_EMAILS = {"saniaiqbal870@gmail.com", "sanifaiqbal970@gmail.com"}
PASSWORD_RESET_REDIRECT_URL = (
    "https://alphaguard-bjj2uybezhkleovau3p47k.streamlit.app"
)


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
    _init_auth_session_db()


def _auth_session_db_path() -> Path:
    configured_path = os.getenv("ALPHAGUARD_SESSION_DB")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path.home() / ".alphaguard" / "auth_sessions.db"


def _init_auth_session_db() -> None:
    """Initialize auth-token storage outside the source-controlled app database."""
    database_path = _auth_session_db_path()
    try:
        database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            os.chmod(database_path.parent, 0o700)
        with sqlite3.connect(database_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    session_hash TEXT PRIMARY KEY,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    email TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    email_verified INTEGER NOT NULL,
                    auth_expires_at INTEGER NOT NULL,
                    cookie_expires_at INTEGER NOT NULL,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        if os.name != "nt":
            os.chmod(database_path, 0o600)
    except (OSError, sqlite3.Error) as exc:
        raise DatabaseError("Could not prepare private authentication-session storage.") from exc


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


def _session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def save_persistent_auth_session(
    session_id: str,
    auth_session: tuple[str, str, str, int, bool, str],
    cookie_expires_at: int,
) -> None:
    """Persist tokens server-side under a hash of an opaque browser session ID."""
    access_token, refresh_token, email, auth_expires_at, email_verified, user_id = auth_session
    if len(session_id) < 32:
        raise ValueError("Persistent session IDs must contain at least 32 characters.")
    try:
        database_path = _auth_session_db_path()
        database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with sqlite3.connect(_auth_session_db_path()) as conn:
            conn.execute(
                """
                INSERT INTO auth_sessions (
                    session_hash, access_token, refresh_token, email, user_id,
                    email_verified, auth_expires_at, cookie_expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(session_hash) DO UPDATE SET
                    access_token = excluded.access_token,
                    refresh_token = excluded.refresh_token,
                    email = excluded.email,
                    user_id = excluded.user_id,
                    email_verified = excluded.email_verified,
                    auth_expires_at = excluded.auth_expires_at,
                    cookie_expires_at = excluded.cookie_expires_at,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    _session_hash(session_id),
                    access_token,
                    refresh_token,
                    email,
                    user_id,
                    int(email_verified),
                    auth_expires_at,
                    cookie_expires_at,
                ),
            )
            conn.execute(
                "DELETE FROM auth_sessions WHERE cookie_expires_at <= ?",
                (int(datetime.now(timezone.utc).timestamp()),),
            )
        if os.name != "nt":
            os.chmod(database_path, 0o600)
    except (OSError, sqlite3.Error) as exc:
        raise DatabaseError("Could not persist the authentication session.") from exc


def get_persistent_auth_session(
    session_id: str,
) -> tuple[str, str, str, int, bool, str] | None:
    """Load a non-expired Supabase session by opaque browser session ID."""
    if len(session_id) < 32:
        return None
    now = int(datetime.now(timezone.utc).timestamp())
    try:
        with sqlite3.connect(_auth_session_db_path()) as conn:
            row = conn.execute(
                """
                SELECT access_token, refresh_token, email, auth_expires_at,
                       email_verified, user_id
                FROM auth_sessions
                WHERE session_hash = ? AND cookie_expires_at > ?
                """,
                (_session_hash(session_id), now),
            ).fetchone()
    except sqlite3.Error as exc:
        raise DatabaseError("Could not restore the persistent authentication session.") from exc
    if row is None:
        return None
    return str(row[0]), str(row[1]), str(row[2]), int(row[3]), bool(row[4]), str(row[5])


def delete_persistent_auth_session(session_id: str) -> None:
    """Delete one server-side persistent session."""
    if len(session_id) < 32:
        return
    try:
        with sqlite3.connect(_auth_session_db_path()) as conn:
            conn.execute(
                "DELETE FROM auth_sessions WHERE session_hash = ?",
                (_session_hash(session_id),),
            )
    except sqlite3.Error as exc:
        raise DatabaseError("Could not remove the persistent authentication session.") from exc


def _get_secret(name: str) -> str | None:
    try:
        import streamlit as st

        secrets = st.secrets
    except (ImportError, FileNotFoundError):
        secrets = {}
    value = os.getenv(name) or secrets.get(name) or secrets.get(name.lower())
    if not value:
        return None
    normalized = str(value).replace("\n", "").replace("\r", "").strip()
    return normalized or None


def get_client() -> Client:
    """Create a Supabase client from the configured environment or Streamlit secrets."""
    url = _get_secret("SUPABASE_URL")
    key = _get_secret("SUPABASE_KEY")
    if not url or not key:
        raise DatabaseError(
            "SUPABASE_URL and SUPABASE_KEY are not configured in Streamlit Secrets or environment variables."
        )
    return create_client(url, key)


def _auth_session(response: Any) -> tuple[str, str, str, int, bool, str]:
    session = getattr(response, "session", None)
    user = getattr(response, "user", None) or getattr(session, "user", None)
    if not session or not user:
        raise DatabaseError("Supabase Auth did not return an active session.")
    email = str(getattr(user, "email", "") or "").strip().lower()
    if not email:
        raise DatabaseError("Supabase Auth returned a session without an email address.")
    user_id = str(getattr(user, "id", "") or "").strip()
    if not user_id:
        raise DatabaseError("Supabase Auth returned a session without a user ID.")
    return (
        str(session.access_token),
        str(session.refresh_token),
        email,
        int(getattr(session, "expires_at", 0) or 0),
        bool(
            getattr(user, "email_confirmed_at", None)
            or getattr(user, "confirmed_at", None)
        ),
        user_id,
    )


def sign_in_with_password(email: str, password: str) -> tuple[str, str, str, int, bool, str]:
    """Authenticate a user with Supabase Auth and return its session tokens."""
    try:
        response = get_client().auth.sign_in_with_password(
            {"email": email.strip().lower(), "password": password}
        )
        return _auth_session(response)
    except DatabaseError:
        raise
    except Exception as exc:
        raise DatabaseError("Could not sign in. Check your email and password.") from exc


def sign_up_with_password(email: str, password: str) -> tuple[str, str, str, int, bool, str] | None:
    """Register a user with Supabase Auth; return None when email confirmation is required."""
    try:
        response = get_client().auth.sign_up(
            {"email": email.strip().lower(), "password": password}
        )
        if not getattr(response, "session", None):
            return None
        return _auth_session(response)
    except DatabaseError:
        raise
    except Exception as exc:
        raise DatabaseError("Could not create your Supabase Auth account.") from exc


def refresh_auth_session(refresh_token: str) -> tuple[str, str, str, int, bool, str]:
    """Refresh an expired or expiring Supabase Auth session."""
    try:
        response = get_client().auth.refresh_session(refresh_token)
        return _auth_session(response)
    except DatabaseError:
        raise
    except Exception as exc:
        raise DatabaseError("Your session expired. Please sign in again.") from exc


def sign_out_auth_session(access_token: str, refresh_token: str) -> None:
    """Revoke the current Supabase Auth session."""
    try:
        client = get_client()
        client.auth.set_session(access_token, refresh_token)
        client.auth.sign_out()
    except Exception as exc:
        raise DatabaseError("Could not sign out of Supabase Auth.") from exc


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
        raise DatabaseError("Could not send the password recovery email.") from exc


def trigger_password_reset(email: str) -> tuple[bool, str]:
    """Send a password-recovery email and return a user-facing status."""
    try:
        send_password_reset(email, PASSWORD_RESET_REDIRECT_URL)
    except DatabaseError as exc:
        cause = exc.__cause__ or exc
        return False, f"Failed to send reset email: {cause}"
    return True, "Password reset link sent! Please check your inbox."


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


def update_user_password(
    email: str, new_password: str, access_token: str, refresh_token: str
) -> tuple[bool, str]:
    """Update Supabase Auth and the local password hash for a recovered account."""
    try:
        client = get_client()
        client.auth.set_session(access_token, refresh_token)
        response = client.auth.update_user({"password": new_password})
        auth_email = str(getattr(response.user, "email", "") or email).strip().lower()
        if not auth_email:
            raise DatabaseError("The password reset session did not identify an account.")
        with sqlite3.connect("alphaguard.db") as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE email = ?",
                (_password_hash(new_password), auth_email),
            )
    except Exception as exc:
        cause = exc.__cause__ or exc
        return False, f"Could not update password: {cause}"
    return True, "Password updated successfully! You can now log in."


def get_user_settings(user_id: str) -> dict[str, Any]:
    """Return persisted preferences for a user."""
    rows = _select("user_profiles", "settings", id=user_id)
    settings = rows[0].get("settings") if rows else {}
    return settings if isinstance(settings, dict) else {}


def get_user_profile(user_id: str) -> dict[str, Any] | None:
    """Return a persisted onboarding and subscription profile."""
    try:
        UUID(user_id)
    except (ValueError, TypeError, AttributeError):
        rows = _select("user_profiles", "*", email=user_id.strip().lower())
    else:
        rows = _select("user_profiles", "*", id=user_id)
    return rows[0] if rows else None


def save_user_onboarding(
    user_id: str,
    email: str,
    business_email: str,
    shop_name: str,
    owner_name: str,
    mailing_address: str,
    website_url: str,
    primary_market: str,
    whitelisted_partners: str,
    selected_plan: str,
    trial_start_date: str,
    trial_end_date: str,
) -> None:
    """Save onboarding fields and the initial trial window without overwriting tier data."""
    if selected_plan not in {"Standard", "Enterprise"}:
        raise ValueError("Select a supported AlphaGuard plan.")
    primary_domain = primary_domain_from_url(website_url)
    existing_domains = _select(
        "user_profiles", "id", primary_domain=primary_domain
    )
    if any(str(row.get("id")) != user_id for row in existing_domains):
        raise DatabaseError(
            "This primary domain is already registered to another AlphaGuard account."
        )
    record = {
        "id": user_id,
        "email": email.strip().lower(),
        "business_email": business_email.strip().lower(),
        "shop_name": shop_name.strip(),
        "owner_name": owner_name.strip(),
        "owner_address": mailing_address.strip(),
        "mailing_address": mailing_address.strip(),
        "website_url": website_url.strip(),
        "primary_domain": primary_domain,
        "primary_market": primary_market.strip(),
        "whitelisted_partners": whitelisted_partners.strip(),
        "selected_plan": selected_plan,
        "trial_start_date": trial_start_date,
        "trial_end_date": trial_end_date,
    }
    try:
        response = get_client().table("user_profiles").upsert(
            record, on_conflict="id"
        ).execute()
    except Exception as exc:
        message = str(exc).lower()
        if "primary_domain" in message:
            raise DatabaseError(
                "This primary domain is already registered to another AlphaGuard account."
            ) from exc
        raise DatabaseError("Could not save your onboarding details.") from exc
    if getattr(response, "error", None):
        error = str(response.error)
        if "primary_domain" in error.lower():
            raise DatabaseError(
                "This primary domain is already registered to another AlphaGuard account."
            )
        raise DatabaseError(f"Could not save your onboarding details: {response.error}")


def save_user_settings(user_id: str, settings: dict[str, Any]) -> None:
    """Persist user preferences without changing subscription data."""
    try:
        response = get_client().table("user_profiles").upsert(
            {"id": user_id, "settings": settings}, on_conflict="id"
        ).execute()
    except Exception as exc:
        raise DatabaseError("Could not save user settings.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not save user settings: {response.error}")


def get_user_tier(user_id: str) -> str:
    """Return a user's subscription tier, defaulting to the least-privileged tier."""
    try:
        UUID(user_id)
    except (ValueError, TypeError, AttributeError):
        email = user_id.strip().lower()
        if email in ADMIN_EMAILS:
            return "Enterprise"
        rows = _select("user_profiles", "tier", email=email)
    else:
        rows = _select("user_profiles", "email,tier", id=user_id)
        if rows and str(rows[0].get("email") or "").strip().lower() in ADMIN_EMAILS:
            return "Enterprise"
    return str(rows[0].get("tier") or "Free") if rows else "Free"


def get_user_id_by_stripe_customer(customer_id: str) -> str | None:
    """Find the Supabase Auth user associated with a Stripe customer ID."""
    rows = _select("user_profiles", "id", stripe_customer_id=customer_id)
    return str(rows[0]["id"]) if rows else None


def update_user_subscription(
    user_id: str,
    tier: str,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
) -> None:
    """Persist a user's tier and Stripe identifiers."""
    if tier not in {"Trial", "Free", "Standard", "Enterprise", "Pro", "Pro (Full Auto)"}:
        raise ValueError("Unsupported subscription tier.")
    try:
        UUID(user_id)
    except (ValueError, TypeError, AttributeError):
        profile_rows = _select("user_profiles", "id", email=user_id.strip().lower())
    else:
        profile_rows = _select("user_profiles", "id", id=user_id)
    if not profile_rows:
        raise DatabaseError("The subscription account has no onboarding profile.")
    record: dict[str, Any] = {"tier": tier}
    if stripe_customer_id is not None:
        record["stripe_customer_id"] = stripe_customer_id
    if stripe_subscription_id is not None:
        record["stripe_subscription_id"] = stripe_subscription_id
    try:
        response = (
            get_client()
            .table("user_profiles")
            .update(record)
            .eq("id", profile_rows[0]["id"])
            .execute()
        )
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
    normalized_results = list(results)
    return {
        "user_id": user_id,
        "image_url": image_url,
        "provider": provider,
        "matches_found": len(normalized_results),
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
            for result in normalized_results
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


def get_user_dmca_notice_count(user_id: str) -> int:
    """Return the number of generated notices recorded for one user."""
    try:
        response = get_client().table("dmca_notices").select(
            "id", count="exact", head=True
        ).eq("user_id", user_id).execute()
    except Exception as exc:
        raise DatabaseError("Could not count generated DMCA notices.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not count generated DMCA notices: {response.error}")
    return int(getattr(response, "count", 0) or 0)


def get_global_match_count() -> int:
    """Return the aggregate number of detected matches across all users."""
    rows = _select("user_match_counts", "match_count")
    return sum(int(row.get("match_count") or 0) for row in rows)


def get_takedown_notices(user_id: str) -> list[dict[str, Any]]:
    """Return a user's takedown queue, newest entries first."""
    return sorted(
        _select("takedown_notices", "*", user_id=user_id),
        key=lambda row: str(row.get("created_at") or ""),
        reverse=True,
    )


def get_admin_takedown_notices() -> list[dict[str, Any]]:
    """Return all accounts' notices for the authenticated admin review center."""
    return sorted(
        _select("takedown_notices"),
        key=lambda row: str(row.get("created_at") or ""),
        reverse=True,
    )


def get_takedown_notice(notice_id: str, user_id: str) -> dict[str, Any] | None:
    """Return a queued notice scoped to its owner."""
    rows = _select("takedown_notices", "*", id=notice_id, user_id=user_id)
    return rows[0] if rows else None


def save_takedown_notice(user_id: str, target_url: str, image_url: str) -> str:
    """Create a pending notice record unless the same target is already queued."""
    existing = _select(
        "takedown_notices",
        "id",
        user_id=user_id,
        target_url=target_url,
        infringing_image_url=image_url,
    )
    if existing:
        return str(existing[0]["id"])
    try:
        response = (
            get_client()
            .table("takedown_notices")
            .insert(
                {
                    "user_id": user_id,
                    "target_url": target_url,
                    "infringing_image_url": image_url,
                }
            )
            .execute()
        )
    except Exception as exc:
        raise DatabaseError("Could not add the takedown notice to the action queue.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not add the takedown notice to the action queue: {response.error}")
    data = response.data or []
    if not data or not data[0].get("id"):
        raise DatabaseError("Supabase did not return the queued takedown notice ID.")
    return str(data[0]["id"])


def update_takedown_notice_status(
    notice_id: str,
    user_id: str,
    status: str,
    generated_notice: str | None = None,
) -> None:
    """Update a queued notice status, scoped to its owning user."""
    if status not in {
        "Pending Authorization",
        "Authorized - Ready to Download",
        "Admin Approved - Ready to Dispatch",
        "Notice Dispatched",
        "False Positive",
        "Enforcement Overridden",
        "Resolved",
        "Escalation Drafts Ready",
    }:
        raise ValueError("Unsupported takedown notice status.")
    record: dict[str, Any] = {"status": status}
    if generated_notice is not None:
        record["generated_notice"] = generated_notice
    try:
        response = (
            get_client()
            .table("takedown_notices")
            .update(record)
            .eq("id", notice_id)
            .eq("user_id", user_id)
            .execute()
        )
    except Exception as exc:
        raise DatabaseError("Could not update the takedown notice status.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not update the takedown notice status: {response.error}")


def admin_update_takedown_notice(
    notice_id: str,
    status: str,
    generated_notice: str | None = None,
) -> None:
    """Update a review-queue notice by ID; only call after verifying admin identity."""
    if status not in {
        "Admin Approved - Ready to Dispatch",
        "False Positive",
        "Enforcement Overridden",
        "Resolved",
    }:
        raise ValueError("Unsupported admin takedown notice status.")
    record: dict[str, Any] = {"status": status}
    if generated_notice is not None:
        record["generated_notice"] = generated_notice
    try:
        response = (
            get_client()
            .table("takedown_notices")
            .update(record)
            .eq("id", notice_id)
            .execute()
        )
    except Exception as exc:
        raise DatabaseError("Could not update the admin review-queue notice.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(
            f"Could not update the admin review-queue notice: {response.error}"
        )


def mark_takedown_notice_dispatched(notice_id: str, user_id: str | None = None) -> None:
    """Record a dispatch date only after a person has actually sent the notice."""
    record = {
        "status": "Notice Dispatched",
        "dispatched_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        query = get_client().table("takedown_notices").update(record).eq("id", notice_id)
        if user_id is not None:
            query = query.eq("user_id", user_id)
        response = query.execute()
    except Exception as exc:
        raise DatabaseError("Could not record the takedown notice dispatch.") from exc
    if getattr(response, "error", None):
        raise DatabaseError(f"Could not record the takedown notice dispatch: {response.error}")


def prepare_due_takedown_escalations(now: datetime | None = None) -> int:
    """Persist escalation drafts for notices dispatched at least seven days ago."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    threshold = now - timedelta(days=7)
    due_notices = []
    for notice in get_admin_takedown_notices():
        if (
            notice.get("status") != "Notice Dispatched"
            or not notice.get("dispatched_at")
            or notice.get("escalation_at")
        ):
            continue
        try:
            dispatched_at = datetime.fromisoformat(
                str(notice["dispatched_at"]).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise DatabaseError(
                f"Invalid dispatch date for takedown notice {notice.get('id')}."
            ) from exc
        if dispatched_at.tzinfo is None:
            dispatched_at = dispatched_at.replace(tzinfo=timezone.utc)
        if dispatched_at.astimezone(timezone.utc) <= threshold:
            due_notices.append(notice)
    prepared = 0
    for notice in due_notices:
        profile = get_user_profile(str(notice.get("user_id") or ""))
        if profile is None:
            raise DatabaseError(
                f"Could not prepare escalation: profile missing for notice {notice.get('id')}."
            )
        escalation_context = {
            **notice,
            "owner_email": profile.get("business_email") or profile.get("email") or "",
            "owner_name": profile.get("owner_name") or "",
            "original_url": profile.get("website_url") or "",
        }
        drafts = build_escalation_drafts(escalation_context)
        try:
            response = (
                get_client()
                .table("takedown_notices")
                .update(
                    {
                        "status": "Escalation Drafts Ready",
                        "escalation_drafts": drafts,
                        "escalation_at": now.isoformat(),
                    }
                )
                .eq("id", notice["id"])
                .eq("status", "Notice Dispatched")
                .execute()
            )
        except Exception as exc:
            raise DatabaseError(
                f"Could not save escalation drafts for notice {notice.get('id')}."
            ) from exc
        if getattr(response, "error", None):
            raise DatabaseError(
                f"Could not save escalation drafts for notice {notice.get('id')}: {response.error}"
            )
        prepared += 1
    return prepared