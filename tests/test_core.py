import sys
from contextlib import nullcontext
from datetime import date, datetime, timedelta, timezone
from io import BytesIO
from sqlite3 import connect
from types import SimpleNamespace
from uuid import uuid4

import numpy as np
import app as app_module
from PIL import Image

from app import (
    _convert_image_bytes,
    _domain_is_whitelisted,
    _is_admin_email,
    _is_verified_admin,
    _process_password_recovery_link,
    _trial_state,
)
from src.alphaguard.dmca import generate_notice
from src.alphaguard.db import (
    _scan_record,
    delete_persistent_auth_session,
    get_persistent_auth_session,
    init_db,
    save_persistent_auth_session,
    send_password_reset,
)
from src.alphaguard.models import NoticeData
from src.alphaguard.scanner import (
    ScannerError,
    image_search_provider_name,
    keyless_visual_scan,
    normalize_results,
    scan_product_footprint,
    scan_image,
)
from src.alphaguard.stego import SteganographyError, capacity_bytes, decode, encode, strip_metadata_lossless
from src.alphaguard.legal_escalation import build_escalation_drafts
from src.alphaguard.url_utils import (
    filter_whitelisted_matches,
    is_http_url,
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


def test_scan_record_persists_match_count_with_normalized_results():
    results = normalize_results(
        {
            "visual_matches": [
                {"title": "Copy A", "link": "https://copy.example/a"},
                {"title": "Copy B", "link": "https://copy.example/b"},
            ]
        }
    )

    record = _scan_record("owner@example.com", "https://store.example/image.png", "Google Lens", iter(results))

    assert record["matches_found"] == 2
    assert len(record["results"]) == 2


def test_takedown_queue_requires_authorization_before_preparing_notice(monkeypatch):
    session_state = {
        "user_email": "owner@example.com",
        "auth_user_id": "user-123",
    }
    monkeypatch.setattr(app_module.st, "session_state", session_state)
    monkeypatch.setattr(app_module.st, "markdown", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "caption", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "form", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(app_module.st, "checkbox", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        app_module.st, "form_submit_button", lambda *args, **kwargs: False
    )
    queued = []
    monkeypatch.setattr(
        app_module,
        "save_takedown_notice",
        lambda user_id, target_url, image_url: queued.append(target_url),
    )
    monkeypatch.setattr(
        app_module,
        "get_takedown_notices",
        lambda user_id: [
            {
                "id": "notice-123",
                "target_url": "https://copy.example/image.jpg",
                "status": "Pending Authorization",
            }
        ],
    )
    monkeypatch.setattr(
        app_module,
        "_build_takedown_notice",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("a notice must not be prepared before authorization")
        ),
    )

    result = SimpleNamespace(
        link="https://copy.example/image.jpg",
        title="Possible copy",
        thumbnail="",
    )
    app_module._takedown_action_queue([result], {})

    assert queued == ["https://copy.example/image.jpg"]
    assert "notice-123" not in session_state.get("generated_takedown_notices", {})


def test_keyless_visual_scan_searches_filename_and_extracts_external_results(monkeypatch):
    from src.alphaguard import scanner

    class FakeResponse:
        text = """
            <a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fcopy.example%2Fproduct">
                Possible copy
            </a>
            <a class="result__a" href="https://store.example/products/own-copy">Own site</a>
            <a class="result__a" href="https://shop.google.com/item">Google</a>
            <a href="https://copy.example/product">Duplicate</a>
            <a class="result__a" href="https://other.example/item"><b>Other match</b></a>
            <a class="result__a" href="javascript:alert(1)">Invalid</a>
        """

        def raise_for_status(self):
            pass

    def fake_get(url, *, params, headers, timeout):
        assert url == "https://html.duckduckgo.com/html/"
        assert params == {"q": '"product name"'}
        assert headers["User-Agent"].startswith("Mozilla/5.0")
        assert timeout == 10
        return FakeResponse()

    monkeypatch.setattr(scanner.requests, "get", fake_get)
    results = keyless_visual_scan(
        "https://store.example/product-name_2x2.jpg?version=3"
    )

    assert [result.link for result in results] == [
        "https://copy.example/product",
        "https://other.example/item",
    ]
    assert results[0].title == "Possible copy"
    assert results[0].source == "copy.example"
    assert results[0].position == 1
    assert results[1].title == "Other match"


def test_scan_image_uses_keyless_search_without_serpapi_key(monkeypatch):
    from src.alphaguard import scanner

    expected = [SimpleNamespace(link="https://copy.example/product")]
    monkeypatch.setattr(scanner, "_serpapi_key", lambda: None)
    monkeypatch.setattr(
        scanner,
        "keyless_visual_scan",
        lambda image_url, timeout=10: expected,
    )

    assert scan_image("https://store.example/image.jpg") == expected
    assert image_search_provider_name() == "DuckDuckGo filename keyword search"


def test_keyless_visual_scan_surfaces_provider_failures(monkeypatch):
    from requests import RequestException
    from src.alphaguard import scanner

    def failing_get(*args, **kwargs):
        raise RequestException("provider unavailable")

    monkeypatch.setattr(scanner.requests, "get", failing_get)

    try:
        keyless_visual_scan("https://store.example/image.jpg")
    except ScannerError as exc:
        assert "DuckDuckGo filename search failed" in str(exc)
        assert isinstance(exc.__cause__, RequestException)
    else:
        raise AssertionError("provider failures should not be treated as no matches")


def test_keyless_visual_scan_returns_no_fabricated_match_when_search_has_no_links(monkeypatch):
    from src.alphaguard import scanner

    class FakeResponse:
        text = "<html><body>No matching pages</body></html>"

        def raise_for_status(self):
            pass

    monkeypatch.setattr(scanner.requests, "get", lambda *args, **kwargs: FakeResponse())

    assert keyless_visual_scan("https://store.example/image.jpg") == []


def test_product_footprint_search_excludes_registered_domain(monkeypatch):
    class FakeDDGS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def text(self, *, keywords, max_results):
            assert keywords == '"Handmade mug"'
            assert max_results == 5
            return [
                {
                    "title": "Our product",
                    "href": "https://shop.example/products/mug",
                },
                {
                    "title": "Possible copy",
                    "href": "https://copy.example/products/mug",
                },
            ]

    monkeypatch.setitem(sys.modules, "duckduckgo_search", SimpleNamespace(DDGS=FakeDDGS))

    results = scan_product_footprint(" Handmade mug ", "https://www.shop.example")

    assert len(results) == 1
    assert results[0].title == "Possible copy"
    assert results[0].link == "https://copy.example/products/mug"


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


def test_http_url_validation_requires_supported_scheme_and_valid_host():
    assert is_http_url(" https://store.example/image.jpg ")
    assert is_http_url("http://localhost:8080/image.jpg")
    assert not is_http_url("")
    assert not is_http_url("javascript:alert(1)")
    assert not is_http_url("https:///image.jpg")
    assert not is_http_url("https://store.example:invalid/image.jpg")


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

    redirect_url = "https://alphaguard-fkre8tyjzbkpv2hjt5gvay.streamlit.app"
    send_password_reset(" OWNER@EXAMPLE.COM ", redirect_url)

    assert client.auth.call == (
        "owner@example.com",
        {"redirect_to": redirect_url},
    )


def test_supabase_client_reads_lowercase_streamlit_secrets(monkeypatch):
    import streamlit as st

    from src.alphaguard import db

    secrets = {
        "supabase_url": "https://project.supabase.co",
        "supabase_key": "secret-key",
    }
    monkeypatch.setattr(st, "secrets", secrets, raising=False)
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    monkeypatch.setattr(db, "create_client", lambda url, key: (url, key))

    assert db.get_client() == ("https://project.supabase.co", "secret-key")


def test_password_recovery_accepts_fragment_tokens(monkeypatch):
    query_params = {
        "type": "recovery",
        "token": "access-token",
        "refresh_token": "refresh-token",
    }
    session_state = {"password_reset_mode": False}
    monkeypatch.setattr(app_module.components, "html", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "query_params", query_params, raising=False)
    monkeypatch.setattr(app_module.st, "session_state", session_state, raising=False)

    _process_password_recovery_link()

    assert session_state["password_reset_mode"] is True
    assert session_state["reset_access_token"] == "access-token"
    assert session_state["reset_refresh_token"] == "refresh-token"
    assert query_params == {}


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
