from datetime import date, datetime, timedelta, timezone
from io import BytesIO
from sqlite3 import connect
from types import SimpleNamespace
from uuid import uuid4

import numpy as np
from PIL import Image

from app import (
    _convert_image_bytes,
    _domain_is_whitelisted,
    _is_admin_email,
    _is_verified_admin,
    _trial_state,
)
from src.alphaguard.dmca import generate_notice
from src.alphaguard.db import (
    delete_persistent_auth_session,
    get_persistent_auth_session,
    init_db,
    save_persistent_auth_session,
    send_password_reset,
)
from src.alphaguard.models import NoticeData
from src.alphaguard.scanner import normalize_results
from src.alphaguard.stego import SteganographyError, capacity_bytes, decode, encode, strip_metadata_lossless
from src.alphaguard.legal_escalation import build_escalation_drafts
from src.alphaguard.url_utils import (
    filter_whitelisted_matches,
    primary_domain_from_url,
)


def test_steganography_round_trip():
    image = Image.fromarray(np.zeros((80, 80, 3), dtype=np.uint8))
    message = "Ownership record: AlphaGuard / 2026"
    assert capacity_bytes(image) >= len(message.encode())
    assert decode(encode(image, message)) == message


def test_steganography_rejects_missing_payload():
    image = Image.fromarray(np.zeros((20, 20, 3), dtype=np.uint8))
    try:
        decode(image)
    except SteganographyError as exc:
        assert "payload" in str(exc).lower()
    else:
        raise AssertionError("decode should reject an unprotected image")


def test_scanner_normalizes_lens_results():
    results = normalize_results({"visual_matches": [{"title": "Copy", "link": "https://www.example.com/a"}]})
    assert results[0].source == "example.com"
    assert results[0].position == 1


def test_dmca_notice_contains_claims():
    data = NoticeData("A. Owner", "owner@example.com", "1 Main St", "My photo", "https://original.test", "https://copy.test")
    notice = generate_notice(data, date(2026, 8, 27))
    assert "2026-08-27" in notice
    assert "https://copy.test" in notice
    assert "good faith" in notice.lower()


def test_admin_override_is_case_insensitive():
    assert _is_admin_email("SaniaIqbal870@gmail.com")
    assert _is_admin_email("sanifaiqbal970@gmail.com")
    assert _is_verified_admin("saniaiqbal870@gmail.com", True)
    assert not _is_verified_admin("saniaiqbal870@gmail.com", False)
    assert not _is_admin_email("user@example.com")


def test_whitelisted_domains_match_subdomains_only():
    allowed = "trusted.example, https://reseller.test/catalog"
    assert _domain_is_whitelisted("https://www.trusted.example/product", allowed)
    assert _domain_is_whitelisted("https://shop.trusted.example/item", allowed)
    assert _domain_is_whitelisted("https://reseller.test/item", allowed)
    assert not _domain_is_whitelisted("https://nottrusted.example/item", allowed)


def test_filter_whitelisted_matches_excludes_partner_results():
    results = normalize_results(
        {
            "visual_matches": [
                {"title": "Authorized", "link": "https://shop.trusted.example/item"},
                {"title": "Unrecognized", "link": "https://copycat.example/item"},
            ]
        }
    )
    filtered = filter_whitelisted_matches(results, "trusted.example")
    assert [result.title for result in filtered] == ["Unrecognized"]


def test_primary_domain_normalizes_url_host():
    assert primary_domain_from_url("https://WWW.Store.Example/catalog/item") == "store.example"


def test_escalation_drafts_cover_search_engines_and_providers():
    drafts = build_escalation_drafts(
        {
            "target_url": "https://copycat.example/item",
            "infringing_image_url": "https://copycat.example/item.jpg",
            "dispatched_at": "2026-10-01T00:00:00+00:00",
            "owner_name": "Store Owner",
            "owner_email": "owner@example.com",
            "original_url": "https://store.example",
        }
    )
    assert set(drafts) == {
        "Google Search",
        "Bing",
        "Namecheap",
        "GoDaddy",
        "Cloudflare",
        "AWS",
    }
    assert all("copycat.example" in draft for draft in drafts.values())
    assert "not submitted" in drafts["Google Search"]


def test_escalation_drafts_are_prepared_at_seven_day_threshold(monkeypatch):
    from src.alphaguard import db

    now = datetime(2026, 10, 14, tzinfo=timezone.utc)
    notice = {
        "id": "notice-1",
        "user_id": "owner-1",
        "target_url": "https://copycat.example/item",
        "infringing_image_url": "https://copycat.example/item.jpg",
        "status": "Notice Dispatched",
        "dispatched_at": (now - timedelta(days=7)).isoformat(),
        "escalation_at": None,
    }
    updates = []

    class FakeQuery:
        def update(self, record):
            self.record = record
            return self

        def eq(self, column, value):
            return self

        def execute(self):
            updates.append(self.record)
            return SimpleNamespace(error=None)

    class FakeClient:
        def table(self, table_name):
            assert table_name == "takedown_notices"
            return FakeQuery()

    monkeypatch.setattr(db, "get_admin_takedown_notices", lambda: [notice])
    monkeypatch.setattr(
        db,
        "get_user_profile",
        lambda user_id: {
            "id": user_id,
            "email": "owner@example.com",
            "owner_name": "Store Owner",
            "website_url": "https://store.example",
        },
    )
    monkeypatch.setattr(db, "get_client", FakeClient)

    assert db.prepare_due_takedown_escalations(now) == 1
    assert updates[0]["status"] == "Escalation Drafts Ready"
    assert set(updates[0]["escalation_drafts"]) == {
        "Google Search",
        "Bing",
        "Namecheap",
        "GoDaddy",
        "Cloudflare",
        "AWS",
    }


def test_onboarding_rejects_a_domain_registered_to_another_account(monkeypatch):
    from src.alphaguard import db

    class FakeQuery:
        def select(self, columns):
            return self

        def eq(self, column, value):
            assert column == "primary_domain"
            assert value == "store.example"
            return self

        def execute(self):
            return SimpleNamespace(data=[{"id": "another-account"}], error=None)

    class FakeClient:
        def table(self, table_name):
            assert table_name == "user_profiles"
            return FakeQuery()

    monkeypatch.setattr(db, "get_client", FakeClient)
    try:
        db.save_user_onboarding(
            user_id="new-account",
            email="account@example.com",
            business_email="owner@example.com",
            shop_name="Store",
            owner_name="Owner",
            mailing_address="1 Main Street",
            website_url="https://www.store.example/catalog",
            primary_market="United States",
            whitelisted_partners="reseller.example",
            selected_plan="Standard",
            trial_start_date="2026-10-01T00:00:00+00:00",
            trial_end_date="2026-10-15T00:00:00+00:00",
        )
    except db.DatabaseError as exc:
        assert "already registered" in str(exc)
    else:
        raise AssertionError("duplicate primary domains must be rejected")


def test_trial_state_calculates_active_window_and_day_thirteen():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    profile = {
        "trial_start_date": start.isoformat(),
        "trial_end_date": (start + timedelta(days=14)).isoformat(),
    }
    active, remaining, trial_day = _trial_state(
        profile, start + timedelta(days=12, hours=1)
    )
    assert active
    assert remaining == 2
    assert trial_day == 13

    active, remaining, _ = _trial_state(
        profile, start + timedelta(days=15)
    )
    assert not active
    assert remaining == 0


def test_persistent_auth_session_is_server_side_and_expires(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(
        "ALPHAGUARD_SESSION_DB", str(tmp_path / "private" / "auth_sessions.db")
    )
    init_db()
    session_id = "opaque-session-id-" + uuid4().hex * 2
    now = int(datetime.now(timezone.utc).timestamp())
    auth_session = (
        "access-token",
        "refresh-token",
        "owner@example.com",
        now + 3600,
        True,
        str(uuid4()),
    )

    save_persistent_auth_session(session_id, auth_session, now + 3600)

    assert get_persistent_auth_session(session_id) == auth_session
    with connect(tmp_path / "private" / "auth_sessions.db") as conn:
        stored_session_id = conn.execute(
            "SELECT session_hash FROM auth_sessions"
        ).fetchone()[0]
    assert stored_session_id != session_id
    assert get_persistent_auth_session("short") is None

    delete_persistent_auth_session(session_id)
    assert get_persistent_auth_session(session_id) is None

    expired_session_id = "expired-session-id-" + uuid4().hex * 2
    save_persistent_auth_session(expired_session_id, auth_session, now - 1)
    assert get_persistent_auth_session(expired_session_id) is None


def test_password_reset_uses_configured_supabase_redirect(monkeypatch):
    from src.alphaguard import db

    class FakeAuth:
        def __init__(self):
            self.call = None

        def reset_password_for_email(self, email, options):
            self.call = (email, options)

    class FakeClient:
        def __init__(self):
            self.auth = FakeAuth()

    client = FakeClient()
    monkeypatch.setattr(db, "get_client", lambda: client)

    send_password_reset(" OWNER@EXAMPLE.COM ", "https://alphaguard.streamlit.app")

    assert client.auth.call == (
        "owner@example.com",
        {"redirect_to": "https://alphaguard.streamlit.app"},
    )


def test_protected_image_conversion_supports_download_formats():
    image = Image.new("RGBA", (8, 8), (255, 0, 0, 128))

    png_data, png_extension, png_mime = _convert_image_bytes(image, "PNG")
    png_image = Image.open(BytesIO(png_data))
    assert png_extension == "png"
    assert png_mime == "image/png"
    assert png_image.mode == "RGBA"

    jpeg_data, jpeg_extension, jpeg_mime = _convert_image_bytes(image, "JPEG")
    jpeg_image = Image.open(BytesIO(jpeg_data))
    assert jpeg_extension == "jpg"
    assert jpeg_mime == "image/jpeg"
    assert jpeg_image.mode == "RGB"

    pdf_data, pdf_extension, pdf_mime = _convert_image_bytes(image, "PDF")
    assert pdf_extension == "pdf"
    assert pdf_mime == "application/pdf"
    assert pdf_data.startswith(b"%PDF")


def test_jpeg_export_strips_metadata_without_reencoding():
    source = BytesIO()
    Image.new("RGB", (8, 8), (255, 0, 0)).save(source, format="JPEG", quality=91, subsampling=0)
    jpeg = source.getvalue()
    sos = jpeg.index(b"\xff\xda")
    metadata = b"\xff\xe1\x00\x08EXIF\x00\x00"
    metadata += b"\xff\xfe\x00\x06note"
    raw_with_metadata = jpeg[:2] + metadata + jpeg[2:]
    raw_with_trailing_data = raw_with_metadata + b"TRAILING TEST BLOCK"

    exported, extension, mime = _convert_image_bytes(
        Image.open(BytesIO(jpeg)), "JPEG", raw_with_trailing_data
    )

    assert extension == "jpg"
    assert mime == "image/jpeg"
    assert b"EXIF" not in exported
    assert b"note" not in exported
    assert exported == strip_metadata_lossless(jpeg)
    assert exported[exported.index(b"\xff\xda"):] == raw_with_metadata[sos + len(metadata):]
    assert exported.endswith(b"\xff\xd9")
    assert b"TRAILING TEST BLOCK" not in exported
    assert b"\xff\xdb" in exported
    assert b"\xff\xc4" in exported
    assert b"\xff\xc0" in exported
