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
from src.alphaguard import cron_scanner
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
from src.alphaguard.notice_email import (
    generate_host_notice,
    generate_owner_notice,
    send_notice_email,
)
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


def test_scan_history_save_falls_back_to_session_without_error_box(monkeypatch):
    from src.alphaguard.db import DatabaseError

    session_state = {"local_scan_history": []}
    captions = []
    monkeypatch.setattr(app_module.st, "session_state", session_state)
    monkeypatch.setattr(app_module.st, "caption", captions.append)
    monkeypatch.setattr(
        app_module.st,
        "error",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Scan-history fallback should not show an error box.")
        ),
    )
    monkeypatch.setattr(
        app_module,
        "save_scan_results",
        lambda *args: (_ for _ in ()).throw(DatabaseError("database unavailable")),
    )
    results = normalize_results(
        {"visual_matches": [{"title": "Copy", "link": "https://copy.example/image"}]}
    )

    saved = app_module._save_scan_history_with_fallback(
        "owner@example.com",
        "https://store.example/image.png",
        "Google Lens",
        results,
    )

    assert saved is False
    assert session_state["local_scan_history"][0]["user_id"] == "owner@example.com"
    assert session_state["local_scan_history"][0]["scan_url"] == "https://store.example/image.png"
    assert session_state["local_scan_history"][0]["matches_found"] == 1
    assert session_state["local_scan_history"][0]["scan_data"][0]["link"] == (
        "https://copy.example/image"
    )
    assert "current session only" in captions[0]


def test_dashboard_metrics_falls_back_and_preserves_user_scope(monkeypatch):
    from src.alphaguard.db import DatabaseError

    monkeypatch.setattr(
        app_module.st,
        "session_state",
        {
            "user_email": "owner@example.com",
            "protected_asset_count": 2,
            "infringements_detected": 5,
        },
    )
    monkeypatch.setattr(
        app_module,
        "get_active_protected_assets",
        lambda: [
            {"user_id": "owner@example.com"},
            {"user_id": "other@example.com"},
            {"user_id": "OWNER@example.com"},
        ],
    )
    monkeypatch.setattr(
        app_module,
        "get_user_match_count",
        lambda user_id: (_ for _ in ()).throw(DatabaseError("database unavailable")),
    )

    assets, matches, incomplete = app_module._dashboard_metrics()

    assert assets == 2
    assert matches == 5
    assert incomplete is True


def test_dashboard_report_download_uses_saved_account_totals(monkeypatch):
    session_state = {
        "user_email": "owner@example.com",
        "auth_user_id": "user-123",
        "user_profile": {"website_url": "https://store.example"},
        "tier": "Standard",
    }
    downloads = []
    column = SimpleNamespace(metric=lambda *args, **kwargs: None)

    monkeypatch.setattr(app_module.st, "session_state", session_state)
    monkeypatch.setattr(app_module.st, "subheader", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "caption", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "markdown", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "columns", lambda *args, **kwargs: (column, column))
    monkeypatch.setattr(app_module.st, "download_button", lambda *args, **kwargs: downloads.append(kwargs))
    monkeypatch.setattr(
        app_module, "_dashboard_metrics", lambda is_admin=False: (2, 5, False)
    )
    monkeypatch.setattr(app_module, "get_user_dmca_notice_count", lambda user_id: 3)
    monkeypatch.setattr(
        app_module, "get_takedown_notices", lambda user_id: [{}, {}]
    )

    app_module._analytics_dashboard()

    report = downloads[0]["data"]
    report_text = report.decode("ascii")
    assert report.startswith(b"%PDF-1.4")
    assert downloads[0]["mime"] == "application/pdf"
    assert "Current saved totals; not date-filtered." in report_text
    assert "Active protected assets: 2" in report_text
    assert "Detected matches: 5" in report_text
    assert "Generated DMCA notices: 3" in report_text
    assert "Takedown queue entries: 2" in report_text
    assert "https://store.example" in report_text


def test_takedown_queue_requires_authorization_before_preparing_notice(monkeypatch):
    session_state = {
        "user_email": "owner@example.com",
        "auth_user_id": "user-123",
    }
    monkeypatch.setattr(app_module.st, "session_state", session_state)
    monkeypatch.setattr(app_module.st, "markdown", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "caption", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "info", lambda *args, **kwargs: None)
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
        "get_existing_queued_urls",
        lambda user_id: [],
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


def test_takedown_action_queue_skips_existing_and_repeated_urls(monkeypatch):
    session_state = {
        "user_email": "owner@example.com",
        "auth_user_id": "user-123",
    }
    monkeypatch.setattr(app_module.st, "session_state", session_state)
    monkeypatch.setattr(app_module.st, "markdown", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "caption", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "info", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "form", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(app_module.st, "checkbox", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        app_module.st, "form_submit_button", lambda *args, **kwargs: False
    )
    queued = []
    monkeypatch.setattr(
        app_module,
        "get_existing_queued_urls",
        lambda user_id: ["https://copy.example/already-queued"],
    )
    monkeypatch.setattr(
        app_module,
        "save_takedown_notice",
        lambda user_id, target_url, image_url: queued.append(target_url),
    )
    monkeypatch.setattr(app_module, "get_takedown_notices", lambda user_id: [])

    app_module._takedown_action_queue(
        [
            SimpleNamespace(link="https://copy.example/already-queued", thumbnail=""),
            SimpleNamespace(link="https://copy.example/new-match", thumbnail=""),
            SimpleNamespace(link="https://copy.example/new-match", thumbnail=""),
        ],
        {},
    )

    assert queued == ["https://copy.example/new-match"]


def test_takedown_action_queue_stops_if_existing_url_read_fails(monkeypatch):
    from src.alphaguard.db import DatabaseError

    errors = []
    session_state = {
        "user_email": "owner@example.com",
        "auth_user_id": "user-123",
    }
    monkeypatch.setattr(app_module.st, "session_state", session_state)
    monkeypatch.setattr(app_module.st, "error", errors.append)
    monkeypatch.setattr(
        app_module,
        "get_existing_queued_urls",
        lambda user_id: (_ for _ in ()).throw(DatabaseError("database unavailable")),
    )
    monkeypatch.setattr(
        app_module,
        "save_takedown_notice",
        lambda *args: (_ for _ in ()).throw(
            AssertionError("Must not queue if duplicate-check read fails.")
        ),
    )

    app_module._takedown_action_queue(
        [SimpleNamespace(link="https://copy.example/match", thumbnail="")],
        {},
    )

    assert errors == [
        "Could not check for existing queued notices: database unavailable"
    ]


def test_queue_dmca_draft_prefills_match_and_requests_dmca_navigation(monkeypatch):
    session_state = {
        "user_email": "owner@example.com",
        "primary_asset_url": "https://store.example/assets/photo.jpg",
    }
    monkeypatch.setattr(app_module.st, "session_state", session_state)
    result = SimpleNamespace(
        link="https://copy.example/photo.jpg",
        raw={},
    )

    app_module._queue_dmca_draft(
        result,
        {
            "owner_name": "Store Owner",
            "business_email": "legal@example.com",
            "mailing_address": "1 Main Street",
            "website_url": "https://store.example",
        },
    )

    assert session_state["auto_fill_infringing_url"] == "https://copy.example/photo.jpg"
    assert session_state["auto_fill_original_url"] == "https://store.example/assets/photo.jpg"
    assert session_state["jump_to_dmca"] is True
    assert session_state["dmca_prefill"]["dmca_infringing_url"] == "https://copy.example/photo.jpg"
    assert session_state["dmca_prefill"]["dmca_claimant_email"] == "legal@example.com"
    assert session_state["dmca_notice_mode"] == "Single notice"


def test_queue_selected_dmca_matches_prefills_bulk_notice(monkeypatch):
    session_state = {
        "user_email": "owner@example.com",
        "primary_asset_url": "https://store.example/assets/photo.jpg",
    }
    monkeypatch.setattr(app_module.st, "session_state", session_state)

    app_module._queue_selected_dmca_matches(
        [
            SimpleNamespace(link="https://copy.example/one.jpg"),
            SimpleNamespace(link="https://copy.example/two.jpg"),
        ],
        {
            "owner_name": "Store Owner",
            "business_email": "legal@example.com",
            "mailing_address": "1 Main Street",
            "website_url": "https://store.example",
            "shop_name": "Example Shop",
        },
    )

    assert session_state["dmca_notice_mode"] == "Bulk notices"
    assert session_state["bulk_claimant_name"] == "Store Owner"
    assert session_state["bulk_claimant_email"] == "legal@example.com"
    assert session_state["bulk_claimant_address"] == "1 Main Street"
    assert session_state["bulk_original_url"] == "https://store.example/assets/photo.jpg"
    assert session_state["bulk_infringing_urls"] == (
        "https://copy.example/one.jpg\nhttps://copy.example/two.jpg"
    )
    assert session_state["bulk_signature"] == "Store Owner"
    assert session_state["jump_to_dmca"] is True


def test_queue_single_selected_match_detects_and_prefills_target_contacts(monkeypatch):
    from src.alphaguard.contact_discovery import TargetContacts

    session_state = {
        "user_email": "owner@example.com",
        "primary_asset_url": "https://store.example/assets/photo.jpg",
    }
    monkeypatch.setattr(app_module.st, "session_state", session_state)
    monkeypatch.setattr(
        app_module,
        "discover_target_contacts",
        lambda url: TargetContacts(
            owner_email="registrant@target.example",
            hosting_provider="Example Hosting",
            host_abuse_email="abuse@hosting.example",
        ),
    )

    app_module._queue_selected_dmca_matches(
        [SimpleNamespace(link="https://copy.example/photo.jpg", raw={})],
        {"owner_name": "Store Owner"},
    )

    assert session_state["dmca_notice_mode"] == "Single notice"
    assert session_state["new_staged_infringing_url"] == "https://copy.example/photo.jpg"
    assert session_state["new_staged_owner_email"] == "registrant@target.example"
    assert session_state["new_staged_host_email"] == "abuse@hosting.example"
    assert session_state["detected_host_provider"] == "Example Hosting"
    assert session_state["target_contact_discovery"]["target_url"] == "https://copy.example/photo.jpg"


def test_contact_discovery_uses_public_domain_and_hosting_rdap(monkeypatch):
    from src.alphaguard import contact_discovery

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self.payload

    def fake_get(url, **kwargs):
        if url.endswith("/domain/copy.example"):
            return FakeResponse(
                {
                    "entities": [
                        {
                            "roles": ["registrant"],
                            "vcardArray": [
                                "vcard",
                                [["email", {}, "text", "owner@copy.example"]],
                            ],
                        }
                    ]
                }
            )
        if "dns-query" in url:
            if kwargs["params"]["type"] == "A":
                return FakeResponse(
                    {"Answer": [{"data": "8.8.8.8"}]}
                )
            return FakeResponse({})
        if url.endswith("/ip/8.8.8.8"):
            return FakeResponse(
                {
                    "name": "Example Hosting Network",
                    "entities": [
                        {
                            "roles": ["abuse"],
                            "vcardArray": [
                                "vcard",
                                [["email", {}, "text", "abuse@hosting.example"]],
                            ],
                        }
                    ],
                }
            )
        raise AssertionError(f"Unexpected lookup URL: {url}")

    monkeypatch.setattr(contact_discovery.requests, "get", fake_get)

    contacts = contact_discovery.discover_target_contacts("https://www.copy.example/item")

    assert contacts.owner_email == "owner@copy.example"
    assert contacts.hosting_provider == "Example Hosting Network"
    assert contacts.host_abuse_email == "abuse@hosting.example"
    assert contacts.errors == ()


def test_contact_discovery_does_not_query_non_public_ip(monkeypatch):
    from src.alphaguard import contact_discovery

    monkeypatch.setattr(
        contact_discovery.requests,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Non-public IP addresses must not be queried.")
        ),
    )

    contacts = contact_discovery.discover_target_contacts("http://127.0.0.1/item")

    assert "not publicly routable" in contacts.errors[0]


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


def test_serpapi_scan_retries_timeouts_with_sixty_second_timeout(monkeypatch):
    from requests import Timeout
    from src.alphaguard import scanner

    attempts = []
    delays = []

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "visual_matches": [
                    {"title": "Copy", "link": "https://copy.example/item"}
                ]
            }

    def fake_get(url, *, params, timeout):
        attempts.append((url, params, timeout))
        if len(attempts) < 3:
            raise Timeout("provider timed out")
        return FakeResponse()

    monkeypatch.setattr(scanner, "_serpapi_key", lambda: "managed-key")
    monkeypatch.setattr(scanner.requests, "get", fake_get)
    monkeypatch.setattr(scanner.time, "sleep", delays.append)

    results = scan_image("https://store.example/image.jpg")

    assert [result.link for result in results] == ["https://copy.example/item"]
    assert len(attempts) == 3
    assert all(attempt[2] == 90 for attempt in attempts)
    assert delays == [1, 2]


def test_serpapi_scan_surfaces_timeout_after_retry_limit(monkeypatch):
    from requests import Timeout
    from src.alphaguard import scanner

    attempts = []

    def failing_get(*args, **kwargs):
        attempts.append(kwargs["timeout"])
        raise Timeout("timed out")

    monkeypatch.setattr(scanner, "_serpapi_key", lambda: "managed-key")
    monkeypatch.setattr(scanner.requests, "get", failing_get)
    monkeypatch.setattr(scanner.time, "sleep", lambda _: None)

    try:
        scan_image("https://store.example/image.jpg")
    except ScannerError as exc:
        assert "SerpApi request failed" in str(exc)
        assert isinstance(exc.__cause__, Timeout)
    else:
        raise AssertionError("SerpApi timeout should remain an explicit scan failure")

    assert attempts == [90, 90, 90]


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


def test_dmca_notice_form_defaults_use_profile_and_recent_scan(monkeypatch):
    session_state = {
        "user_email": "owner@example.com",
        "user_profile": {
            "owner_name": "Example Shop",
            "business_email": "legal@example.com",
            "mailing_address": "1 Main Street",
            "shop_name": "Example Shop",
            "website_url": "https://shop.example",
        },
        "last_original_url": "https://assets.example/original.jpg",
        "last_infringing_url": "https://copy.example/infringing.jpg",
    }
    monkeypatch.setattr(app_module.st, "session_state", session_state)

    defaults = app_module._dmca_notice_form_defaults()

    assert defaults["dmca_claimant_name"] == "Example Shop"
    assert defaults["dmca_claimant_email"] == "owner@example.com"
    assert defaults["dmca_claimant_address"] == "1 Main Street"
    assert defaults["dmca_original_work"] == "Copyrighted product imagery for Example Shop"
    assert defaults["dmca_original_url"] == "https://assets.example/original.jpg"
    assert defaults["dmca_infringing_url"] == "https://copy.example/infringing.jpg"
    assert defaults["dmca_signature"] == "Example Shop"


def test_save_dmca_notice_to_supabase_uses_authenticated_email_and_existing_schema(monkeypatch):
    session_state = {"user_email": " owner@example.com "}
    monkeypatch.setattr(app_module.st, "session_state", session_state)
    saved = []
    monkeypatch.setattr(
        app_module,
        "save_dmca_notice_log",
        lambda user_id, notice_data, notice: saved.append((user_id, notice_data, notice)),
    )

    success = app_module.save_dmca_notice_to_supabase(
        "A. Owner",
        "owner@example.com",
        "1 Main St",
        "My photo",
        "https://original.test/photo",
        "https://copy.test/photo",
        "Generated DMCA notice",
    )

    assert success is True
    assert len(saved) == 1
    user_id, notice_data, notice = saved[0]
    assert user_id == "owner@example.com"
    assert notice_data.claimant_name == "A. Owner"
    assert notice_data.claimant_email == "owner@example.com"
    assert notice_data.claimant_address == "1 Main St"
    assert notice_data.original_work == "My photo"
    assert notice_data.original_url == "https://original.test/photo"
    assert notice_data.infringing_url == "https://copy.test/photo"
    assert notice == "Generated DMCA notice"


def test_save_dmca_notice_to_supabase_warns_when_save_fails(monkeypatch):
    from src.alphaguard.db import DatabaseError

    session_state = {"user_email": "owner@example.com"}
    warnings = []
    monkeypatch.setattr(app_module.st, "session_state", session_state)
    monkeypatch.setattr(app_module.st, "warning", warnings.append)
    monkeypatch.setattr(
        app_module,
        "save_dmca_notice_log",
        lambda *args: (_ for _ in ()).throw(DatabaseError("database unavailable")),
    )

    success = app_module.save_dmca_notice_to_supabase(
        "A. Owner",
        "owner@example.com",
        "1 Main St",
        "My photo",
        "https://original.test/photo",
        "https://copy.test/photo",
        "Generated DMCA notice",
    )

    assert success is False
    assert "database unavailable" in warnings[0]


def test_save_encoded_image_metadata_includes_asset_hash_and_metadata(monkeypatch):
    from src.alphaguard import db

    saved = {}
    monkeypatch.setattr(
        db,
        "_insert",
        lambda table, record: saved.update(table=table, record=record),
    )

    db.save_encoded_image_metadata(
        "owner@example.com",
        "protected-image.png",
        (320, 240),
        24,
        1024,
        "https://store.example/protected-image.png",
        "a" * 64,
    )

    assert saved["table"] == "encoded_images"
    assert saved["record"]["asset_name"] == "protected-image.png"
    assert saved["record"]["asset_url"] == "https://store.example/protected-image.png"
    assert saved["record"]["image_hash"] == "a" * 64
    assert saved["record"]["metadata"] == {
        "width": 320,
        "height": 240,
        "message_length": 24,
        "capacity_bytes": 1024,
    }


def test_staged_notice_templates_include_both_asset_urls():
    owner_notice = generate_owner_notice("https://copy.example/item", "https://original.example/photo")
    host_notice = generate_host_notice("https://copy.example/item", "https://original.example/photo")

    assert "Stage 1" in owner_notice
    assert "96 hours (4 days)" in owner_notice
    assert "https://copy.example/item" in owner_notice
    assert "https://original.example/photo" in owner_notice
    assert "Stage 2" in host_notice
    assert "4 days ago" in host_notice
    assert "https://copy.example/item" in host_notice
    assert "https://original.example/photo" in host_notice


def test_owner_notice_includes_claimant_identity_and_signature():
    notice = generate_owner_notice(
        "https://copy.example/item",
        "https://original.example/photo",
        claimant_name="Store Owner",
        claimant_email="owner@example.com",
        claimant_address="1 Main Street",
        signature="Store Owner",
    )

    assert "Claimant: Store Owner" in notice
    assert "Contact email: owner@example.com" in notice
    assert "Mailing address: 1 Main Street" in notice
    assert notice.rstrip().endswith("Store Owner")
    assert "belonging to our client" not in notice


def test_generate_notice_subject_includes_timestamp(monkeypatch):
    import takedown

    monkeypatch.setattr(takedown.time, "time", lambda: 1_797_000_123)

    assert takedown.generate_notice_subject() == (
        "Notice of Copyright Infringement - Ref: AG-2026-1797000123"
    )


def test_send_notice_email_uses_configured_smtp(monkeypatch):
    import streamlit as st
    from src.alphaguard import notice_email

    monkeypatch.setattr(
        st,
        "secrets",
        {"SMTP_USER": "sender@example.com", "SMTP_PASS": "secret", "SMTP_HOST": "mail.example.com"},
        raising=False,
    )
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self, context):
            sent["tls"] = context

        def login(self, username, password):
            sent["login"] = (username, password)

        def send_message(self, message):
            sent["message"] = message

    monkeypatch.setattr(notice_email.smtplib, "SMTP", FakeSMTP)
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASS", raising=False)
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_PORT", raising=False)

    assert send_notice_email("owner@example.com", "Subject", "Body")
    assert sent["host"] == "mail.example.com"
    assert sent["port"] == 587
    assert sent["message"]["To"] == "owner@example.com"
    assert sent["message"]["Subject"] == "Subject"
    assert sent["message"]["From"] == "AlphaGuard Security <sender@example.com>"
    assert sent["message"]["Date"]
    assert sent["message"]["Message-ID"].endswith("@example.com>")
    assert sent["message"].get_content_type() == "text/plain"
    assert sent["message"].get_content_charset() == "utf-8"
    assert sent["message"].get_content().strip() == "Body"


def test_send_notice_email_rejects_missing_credentials_and_bad_recipient(monkeypatch):
    import streamlit as st

    errors = []
    monkeypatch.setattr(st, "secrets", {}, raising=False)
    monkeypatch.setattr(st, "error", errors.append)
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASS", raising=False)

    assert not send_notice_email("owner@example.com", "Subject", "Body")
    assert "SMTP_USER" in errors[-1]

    monkeypatch.setattr(st, "secrets", {"SMTP_USER": "sender@example.com", "SMTP_PASS": "secret"}, raising=False)
    assert not send_notice_email("bad@example.com\r\nBcc: victim@example.com", "Subject", "Body")
    assert "valid recipient" in errors[-1]


def test_send_notice_email_reports_recipient_refusal(monkeypatch):
    import streamlit as st
    from src.alphaguard import notice_email

    monkeypatch.setattr(
        st,
        "secrets",
        {"SMTP_USER": "sender@example.com", "SMTP_PASS": "secret"},
        raising=False,
    )
    errors = []
    monkeypatch.setattr(st, "error", errors.append)

    class RefusingSMTP:
        def __init__(self, host, port):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self, context):
            pass

        def login(self, username, password):
            pass

        def send_message(self, message):
            return {"owner@example.com": (550, b"mailbox unavailable")}

    monkeypatch.setattr(notice_email.smtplib, "SMTP", RefusingSMTP)
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASS", raising=False)
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_PORT", raising=False)

    assert not send_notice_email("owner@example.com", "Subject", "Body")
    assert "refused the recipient" in errors[-1]


def test_staged_notice_elapsed_days_uses_utc_and_four_day_threshold():
    now = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)

    assert app_module._staged_notice_elapsed_days(
        (now - timedelta(days=4)).isoformat(), now
    ) == 4
    assert app_module._staged_notice_elapsed_days(
        (now - timedelta(days=4) + timedelta(seconds=1)).isoformat(), now
    ) == 3
    assert app_module._staged_notice_elapsed_days(
        (now - timedelta(days=4)).replace(tzinfo=None).isoformat(), now
    ) == 4


def test_staged_notice_database_helpers_scope_and_record_escalation(monkeypatch):
    from src.alphaguard import db

    records = []
    filters = []

    class FakeQuery:
        def __init__(self):
            self.record = None
            self.mode = ""

        def insert(self, record):
            self.record = record
            self.mode = "insert"
            return self

        def update(self, record):
            self.record = record
            self.mode = "update"
            return self

        def select(self, columns):
            return self

        def eq(self, column, value):
            filters.append((column, value))
            return self

        def execute(self):
            if self.mode == "insert":
                records.append(self.record)
                return SimpleNamespace(error=None, data=[{"id": "notice-1"}])
            records.append(self.record)
            return SimpleNamespace(error=None, data=[{"id": "notice-1"}])

    class FakeClient:
        def table(self, table_name):
            assert table_name == "takedown_notices"
            return FakeQuery()

    monkeypatch.setattr(db, "get_client", FakeClient)
    notice_id = db.save_staged_takedown_notice(
        "user-1",
        "https://copy.example/item",
        "owner@example.com",
        "abuse@host.example",
        "https://original.example/photo",
    )
    assert notice_id == "notice-1"
    assert records[0]["status"] == "Owner Notified"
    assert records[0]["user_id"] == "user-1"
    assert records[0]["host_email"] == "abuse@host.example"
    assert records[0]["notice_sent_at"]

    assert db.claim_staged_takedown_escalation("notice-1", "user-1")
    assert records[1] == {"status": "Stage 2 Sending"}
    assert ("status", "Owner Notified") in filters

    db.update_staged_takedown_escalation("notice-1", "user-1", sent=True)
    assert records[2]["status"] == "Host Escalated"
    assert records[2]["host_escalated_at"]
    assert ("status", "Stage 2 Sending") in filters


def test_admin_override_is_case_insensitive():
    assert _is_admin_email("SaniaIqbal870@gmail.com")
    assert _is_admin_email("sanifaiqbal970@gmail.com")
    assert _is_verified_admin("saniaiqbal870@gmail.com", True)
    assert not _is_verified_admin("saniaiqbal870@gmail.com", False)
    assert not _is_admin_email("user@example.com")


def test_admin_plan_preview_specs_are_display_only_and_use_finite_labels():
    assert set(app_module.ADMIN_PLAN_PREVIEWS) == {"Starter", "Pro", "Enterprise"}
    assert app_module.ADMIN_PLAN_PREVIEWS["Starter"]["takedown_limit"] == "15 per month"
    assert app_module.ADMIN_PLAN_PREVIEWS["Starter"]["scan_interval_hours"] == 24
    assert app_module.ADMIN_PLAN_PREVIEWS["Starter"]["fallback_days"] == 7
    assert app_module.ADMIN_PLAN_PREVIEWS["Pro"]["takedown_limit"] == "Unlimited"
    assert app_module.ADMIN_PLAN_PREVIEWS["Pro"]["scan_interval_hours"] == 6
    assert app_module.ADMIN_PLAN_PREVIEWS["Pro"]["fallback_days"] == 7
    assert app_module.ADMIN_PLAN_PREVIEWS["Enterprise"]["domains"] == "Unlimited"
    assert app_module.ADMIN_PLAN_PREVIEWS["Enterprise"]["max_domains"] is None
    assert app_module.ADMIN_PLAN_PREVIEWS["Enterprise"]["takedown_limit_count"] is None
    assert app_module.ADMIN_PLAN_PREVIEWS["Enterprise"]["scan_interval_hours"] == 1
    assert app_module.ADMIN_PLAN_PREVIEWS["Enterprise"]["fallback_days"] == 4


def test_scheduled_scan_cycle_only_scans_requested_persisted_tier(monkeypatch):
    assets = [
        {"id": 1, "user_id": "user-pro", "image_url": "https://pro.example/image.png"},
        {
            "id": 2,
            "user_id": "user-standard",
            "image_url": "https://standard.example/image.png",
        },
    ]
    tiers = {"user-pro": "Pro", "user-standard": "Standard"}
    scanned_urls = []

    monkeypatch.setattr(cron_scanner, "get_active_protected_assets", lambda: assets)
    monkeypatch.setattr(cron_scanner, "get_user_tier", lambda user_id: tiers[user_id])
    monkeypatch.setattr(cron_scanner, "get_user_profile", lambda user_id: {})
    monkeypatch.setattr(
        cron_scanner,
        "scan_image_valueserp",
        lambda image_url: scanned_urls.append(image_url) or [],
    )
    monkeypatch.setattr(
        cron_scanner, "filter_whitelisted_matches", lambda results, partners: results
    )
    monkeypatch.setattr(cron_scanner, "get_detected_match_links", lambda asset_id, links: set())

    assert cron_scanner.run_scan_cycle({"Pro"}) == 0
    assert scanned_urls == ["https://pro.example/image.png"]


def test_tiered_scan_scheduler_uses_plan_intervals():
    scheduler = cron_scanner.create_scheduler()
    jobs = {job.id: job for job in scheduler.get_jobs()}

    assert jobs["alphaguard-daily-value-serp-scan"].trigger.interval.total_seconds() == 24 * 3600
    assert jobs["alphaguard-pro-value-serp-scan"].trigger.interval.total_seconds() == 6 * 3600
    assert jobs["alphaguard-enterprise-value-serp-scan"].trigger.interval.total_seconds() == 3600
    assert "alphaguard-takedown-escalation-check" in jobs


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
    redirect_url = "https://alphaguard-bjj2uybezhkleovau3p47k.streamlit.app"
    send_password_reset(" OWNER@EXAMPLE.COM ", redirect_url)

    assert client.auth.call == (
        "owner@example.com",
        {"redirect_to": redirect_url},
    )


def test_password_reset_surfaces_supabase_failure(monkeypatch):
    from src.alphaguard import db

    class FakeAuth:
        def reset_password_for_email(self, email, options):
            raise RuntimeError("provider unavailable")

    class FakeClient:
        auth = FakeAuth()

    monkeypatch.setattr(db, "get_client", lambda: FakeClient())

    try:
        send_password_reset("owner@example.com", "https://example.com/reset")
    except db.DatabaseError as exc:
        assert "Could not send the password recovery email" in str(exc)
        assert isinstance(exc.__cause__, RuntimeError)
    else:
        raise AssertionError("Supabase reset failures should not be hidden")


def test_trigger_password_reset_returns_status_and_uses_deployed_redirect(monkeypatch):
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

    success, message = db.trigger_password_reset(" OWNER@EXAMPLE.COM ")

    assert success is True
    assert message == "Password reset link sent! Please check your inbox."
    assert client.auth.call == (
        "owner@example.com",
        {"redirect_to": db.PASSWORD_RESET_REDIRECT_URL},
    )


def test_trigger_password_reset_returns_failure_status(monkeypatch):
    from src.alphaguard import db

    class FakeAuth:
        def reset_password_for_email(self, email, options):
            raise RuntimeError("provider unavailable")

    class FakeClient:
        auth = FakeAuth()

    monkeypatch.setattr(db, "get_client", lambda: FakeClient())

    success, message = db.trigger_password_reset("owner@example.com")

    assert success is False
    assert message == "Failed to send reset email: provider unavailable"


def test_update_user_password_returns_success_and_syncs_local_password(
    monkeypatch, tmp_path
):
    from src.alphaguard import db

    class FakeUser:
        email = "owner@example.com"

    class FakeResponse:
        user = FakeUser()

    class FakeAuth:
        def __init__(self):
            self.session = None

        def set_session(self, access_token, refresh_token):
            self.session = (access_token, refresh_token)

        def update_user(self, attributes):
            assert attributes == {"password": "new-password"}
            return FakeResponse()

    class FakeClient:
        def __init__(self):
            self.auth = FakeAuth()

    monkeypatch.chdir(tmp_path)
    db.init_db()
    db.create_user("owner@example.com", "old-password")
    client = FakeClient()
    monkeypatch.setattr(db, "get_client", lambda: client)

    success, message = db.update_user_password(
        "access-token", "new-password", "refresh-token"
    )

    assert success is True
    assert message == (
        "Password updated successfully! You can now log in with your new password."
    )
    assert client.auth.session == ("access-token", "refresh-token")
    assert db.verify_user_credentials("owner@example.com", "new-password")


def test_update_user_password_returns_failure_status(monkeypatch):
    from src.alphaguard import db

    class FakeAuth:
        def set_session(self, access_token, refresh_token):
            pass

        def update_user(self, attributes):
            raise RuntimeError("provider unavailable")

    class FakeClient:
        auth = FakeAuth()

    monkeypatch.setattr(db, "get_client", lambda: FakeClient())

    success, message = db.update_user_password(
        "access-token", "new-password", "refresh-token"
    )

    assert success is False
    assert message == "Error updating password: provider unavailable"


def test_update_user_password_rejects_missing_access_token(monkeypatch):
    from src.alphaguard import db

    def unexpected_client():
        raise AssertionError("A missing recovery token must not use any auth session.")

    monkeypatch.setattr(db, "get_client", unexpected_client)

    success, message = db.update_user_password("", "new-password")
    assert success is False
    assert message == "Error updating password: the recovery access token is missing."


def test_update_user_password_does_not_continue_after_session_failure(monkeypatch):
    from src.alphaguard import db

    class FakeAuth:
        def set_session(self, access_token, refresh_token):
            raise RuntimeError("invalid recovery token")

        def update_user(self, attributes):
            raise AssertionError("Must not update another active auth session.")

    class FakeClient:
        auth = FakeAuth()

    monkeypatch.setattr(db, "get_client", lambda: FakeClient())

    success, message = db.update_user_password("invalid-token", "new-password")

    assert success is False
    assert message == "Error updating password: invalid recovery token"


def test_supabase_client_reads_lowercase_streamlit_secrets(monkeypatch):
    import streamlit as st

    from src.alphaguard import db

    secrets = {
        "supabase_url": " \nhttps://project.supabase.co\r\n",
        "supabase_key": "\n secret-key \r\n",
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


def test_password_recovery_accepts_access_token_query_parameter(monkeypatch):
    query_params = {
        "access_token": "access-token",
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


def test_password_recovery_accepts_access_token_without_refresh_token(monkeypatch):
    query_params = {"access_token": "access-token"}
    session_state = {"password_reset_mode": False}
    monkeypatch.setattr(app_module.components, "html", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.st, "query_params", query_params, raising=False)
    monkeypatch.setattr(app_module.st, "session_state", session_state, raising=False)

    _process_password_recovery_link()

    assert session_state["password_reset_mode"] is True
    assert session_state["reset_access_token"] == "access-token"
    assert session_state["reset_refresh_token"] == ""
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
