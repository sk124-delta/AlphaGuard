import os
import hashlib
import math
import re
import secrets
import textwrap
from io import BytesIO
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlparse
from zipfile import BadZipFile, ZipFile

import streamlit as st
import streamlit.components.v1 as components
import extra_streamlit_components as stx
from dotenv import load_dotenv
from PIL import Image

try:
    import openai
except ImportError:
    openai = None

from src.alphaguard.db import (
    DatabaseError,
    delete_persistent_auth_session,
    get_persistent_auth_session,
    get_global_match_count,
    get_active_protected_assets,
    get_takedown_notices,
    get_admin_takedown_notices,
    get_user_dmca_notice_count,
    get_user_match_count,
    get_user_profile,
    get_takedown_notice,
    get_user_tier,
    admin_update_takedown_notice,
    exchange_password_reset_code,
    mark_takedown_notice_dispatched,
    prepare_due_takedown_escalations,
    save_takedown_notice,
    save_user_onboarding,
    save_persistent_auth_session,
    sign_in_with_password,
    sign_out_auth_session,
    sign_up_with_password,
    refresh_auth_session,
    send_password_reset,
    update_user_password,
    update_takedown_notice_status,
    save_dmca_notice_log,
    save_encoded_image_metadata,
    save_scan_results,
    save_valueserp_scan_results,
    init_db,
)
from src.alphaguard.dmca import generate_notice
from src.alphaguard.models import NoticeData
from src.alphaguard.scanner import ScannerError, scan_image, scan_image_valueserp
from src.alphaguard.url_utils import (
    domain_is_whitelisted as _domain_is_whitelisted,
    filter_whitelisted_matches,
)
from src.alphaguard.stego import (
    SteganographyError,
    capacity_bytes,
    decode,
    encode,
    from_bytes,
    strip_metadata_lossless,
    to_png_bytes,
)

load_dotenv()
init_db()
st.set_page_config(page_title="AlphaGuard", page_icon="AG", layout="wide")
st.markdown(
    """
    <style>
    /* Hide the top header bar, GitHub cat icon, and Fork button */
    header[data-testid="stHeader"] {
        visibility: hidden;
        height: 0%;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    [data-testid="stToolbar"] {visibility: hidden !important;}
    </style>
    """,
    unsafe_allow_html=True,
)

MAX_CATALOG_IMAGES = 1_000
ADMIN_EMAILS = {"sanifaiqbal970@gmail.com", "saniaiqbal870@gmail.com"}
SUPPORT_EMAIL = "alphaguard.securitysuite@gmail.com"
AUTH_COOKIE_NAME = "alphaguard_session"
AUTH_SESSION_MAX_AGE = 30 * 24 * 60 * 60
PAYONEER_GROWTH_URL = "https://link.payoneer.com/Token?t=46755D76D4364792BD370CECD76A60E7&src=pl"
PAYONEER_PRO_URL = "https://link.payoneer.com/Token?t=17262895A26A4AAE90841E7268F0D4CB&src=pl"
PAYONEER_ENTERPRISE_URL = "https://link.payoneer.com/Token?t=A685ABEC12A642EC94690CC83597DAB1&src=pl"
DOWNLOAD_FORMATS = ["PNG", "JPEG", "PDF"]
DOWNLOAD_FORMAT_DETAILS = {
    "PNG": ("png", "image/png"),
    "JPEG": ("jpg", "image/jpeg"),
    "PDF": ("pdf", "application/pdf"),
}


def _is_admin_email(email: str) -> bool:
    return email.strip().lower() in ADMIN_EMAILS


def _is_verified_admin(email: str, email_verified: bool) -> bool:
    return email_verified and _is_admin_email(email)


def _set_auth_session(
    session: tuple[str, str, str, int, bool, str],
    session_id: str | None = None,
) -> None:
    access_token, refresh_token, email, expires_at, email_verified, user_id = session
    st.session_state["auth_access_token"] = access_token
    st.session_state["auth_refresh_token"] = refresh_token
    st.session_state["auth_expires_at"] = expires_at
    st.session_state["user_email"] = email
    st.session_state["auth_user_id"] = user_id
    st.session_state["authenticated"] = True
    st.session_state["is_admin"] = _is_verified_admin(email, email_verified)
    if session_id:
        st.session_state["persistent_session_id"] = session_id


def _clear_auth_session() -> None:
    for key in (
        "auth_access_token",
        "auth_refresh_token",
        "auth_expires_at",
        "auth_user_id",
        "persistent_session_id",
    ):
        st.session_state.pop(key, None)
    st.session_state["authenticated"] = False
    st.session_state["user_email"] = ""
    st.session_state["is_admin"] = False
    st.session_state.pop("user_profile", None)


def _persist_auth_session(
    session: tuple[str, str, str, int, bool, str],
    cookie_manager,
) -> None:
    session_id = secrets.token_urlsafe(32)
    cookie_expires_at = int(_now().timestamp()) + AUTH_SESSION_MAX_AGE
    save_persistent_auth_session(session_id, session, cookie_expires_at)
    _set_auth_session(session, session_id)
    cookie_manager.set(
        AUTH_COOKIE_NAME,
        session_id,
        key="save_alphaguard_session",
        expires_at=datetime.fromtimestamp(cookie_expires_at, timezone.utc),
        secure=True,
        same_site="strict",
    )


def _refresh_auth_cookie(cookie_manager, session_id: str) -> None:
    cookie_expires_at = int(_now().timestamp()) + AUTH_SESSION_MAX_AGE
    cookie_manager.set(
        AUTH_COOKIE_NAME,
        session_id,
        key="refresh_alphaguard_session",
        expires_at=datetime.fromtimestamp(cookie_expires_at, timezone.utc),
        secure=True,
        same_site="strict",
    )


def _restore_auth_session(cookie_manager) -> bool:
    session_id = st.session_state.get("persistent_session_id")
    if not session_id:
        session_id = cookie_manager.get(cookie=AUTH_COOKIE_NAME)
    if not session_id:
        if not st.session_state.get("authenticated"):
            return False
        session_id = st.session_state.get("persistent_session_id")
        if not session_id:
            _clear_auth_session()
            return False
    session_id = str(session_id)
    if not st.session_state.get("authenticated"):
        try:
            session = get_persistent_auth_session(session_id)
        except DatabaseError as exc:
            st.error(f"Could not restore your saved sign-in: {exc}")
            return False
        if session is None:
            cookie_manager.delete(AUTH_COOKIE_NAME, key="delete_expired_session")
            return False
        _set_auth_session(session, session_id)

    access_token = st.session_state.get("auth_access_token", "")
    refresh_token = st.session_state.get("auth_refresh_token", "")
    expires_at = int(st.session_state.get("auth_expires_at", 0) or 0)
    if (
        not access_token
        or not refresh_token
        or not st.session_state.get("auth_user_id")
    ):
        _clear_auth_session()
        return False
    if expires_at and expires_at > int(_now().timestamp()) + 60:
        return True
    try:
        session = refresh_auth_session(refresh_token)
        save_persistent_auth_session(
            session_id,
            session,
            int(_now().timestamp()) + AUTH_SESSION_MAX_AGE,
        )
        _set_auth_session(session, session_id)
        _refresh_auth_cookie(cookie_manager, session_id)
    except DatabaseError as exc:
        delete_persistent_auth_session(session_id)
        cookie_manager.delete(AUTH_COOKIE_NAME, key="delete_invalid_session")
        _clear_auth_session()
        st.warning(f"Your saved sign-in session could not be restored: {exc}")
        return False
    return True


def _process_password_recovery_link() -> None:
    components.html(
        """
        <script>
        const appWindow = window.parent;
        const url = new URL(appWindow.location.href);
        if (url.hash.includes('access_token')) {
            const params = new URLSearchParams(url.hash.substring(1));
            const accessToken = params.get('access_token');
            const refreshToken = params.get('refresh_token');
            if (params.get('type') === 'recovery' && accessToken) {
                url.hash = '';
                url.searchParams.set('type', 'recovery');
                url.searchParams.set('token', accessToken);
                if (refreshToken) {
                    url.searchParams.set('refresh_token', refreshToken);
                }
                appWindow.history.replaceState(null, '', url.toString());
                appWindow.location.reload();
            }
        }
        </script>
        """,
        height=0,
    )

    code = st.query_params.get("code")
    recovery_type = st.query_params.get("type")
    if st.session_state.get("password_reset_mode"):
        return

    if code:
        try:
            access_token, refresh_token, email = exchange_password_reset_code(str(code))
        except DatabaseError as exc:
            st.session_state["reset_notice"] = str(exc)
        else:
            st.session_state["reset_access_token"] = access_token
            st.session_state["reset_refresh_token"] = refresh_token
            st.session_state["reset_email"] = email
            st.session_state["password_reset_mode"] = True
        st.query_params.clear()
    elif recovery_type == "recovery":
        access_token = st.query_params.get("token")
        refresh_token = st.query_params.get("refresh_token")
        if not access_token or not refresh_token:
            st.session_state["reset_notice"] = (
                "The password reset link is invalid or incomplete. Request a new link."
            )
        else:
            st.session_state["reset_access_token"] = str(access_token)
            st.session_state["reset_refresh_token"] = str(refresh_token)
            st.session_state["reset_email"] = ""
            st.session_state["password_reset_mode"] = True
        st.query_params.clear()


def _download_text(label: str, text: str, filename: str, key: str | None = None) -> None:
    st.download_button(
        label,
        text,
        file_name=filename,
        mime="text/plain",
        use_container_width=True,
        key=key,
    )


def _save_activity(save_action) -> None:
    try:
        save_action()
    except DatabaseError as exc:
        st.warning(f"Activity was not saved to Supabase: {exc}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pdf_bytes(title: str, lines: list[str]) -> bytes:
    """Build a small, standards-compatible PDF without an external runtime dependency."""
    wrapped_lines = [line for raw_line in lines for line in textwrap.wrap(str(raw_line), width=88) or [""]]
    content_lines = ["BT", "/F1 11 Tf", "50 760 Td"]
    for index, line in enumerate(wrapped_lines):
        if index:
            content_lines.append("0 -15 Td")
        escaped = line.encode("ascii", "replace").decode("ascii").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content_lines.append(f"({escaped}) Tj")
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream",
    ]
    output = BytesIO()
    output.write(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(output.tell())
        output.write(f"{number} 0 obj\n".encode("ascii"))
        output.write(obj)
        output.write(b"\nendobj\n")
    xref_offset = output.tell()
    output.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("ascii")
    )
    return output.getvalue()


def _provenance_text(filename: str, file_hash: str, timestamp: datetime) -> str:
    return "\n".join(
        [
            "ALPHAGUARD CERTIFICATE OF PROVENANCE",
            f"File: {filename}",
            f"SHA-256: {file_hash}",
            f"Owner email: {st.session_state['user_email']}",
            f"Timestamp (UTC): {timestamp.isoformat()}",
            "Verification: The SHA-256 hash identifies the exact protected file produced by AlphaGuard.",
        ]
    )


def _provenance_pdf(filename: str, file_hash: str, timestamp: datetime) -> bytes:
    return _pdf_bytes(
        "Certificate of Provenance",
        _provenance_text(filename, file_hash, timestamp).splitlines(),
    )


def _convert_image_bytes(
    image: Image.Image, selected_format: str, raw_bytes: bytes | None = None
) -> tuple[bytes, str, str]:
    extension, mime = DOWNLOAD_FORMAT_DETAILS[selected_format]
    if selected_format == "JPEG" and raw_bytes is not None and raw_bytes.startswith(b"\xff\xd8"):
        return strip_metadata_lossless(raw_bytes), extension, mime
    output = BytesIO()
    export_image = image.convert("RGB") if selected_format in ("JPEG", "PDF") else image
    save_options = {"quality": 95} if selected_format == "JPEG" else {}
    export_image.save(output, format=selected_format, **save_options)
    return output.getvalue(), extension, mime


def _zip_images(uploaded_files, zip_upload) -> list[tuple[str, bytes]]:
    files = [(upload.name, upload.getvalue()) for upload in uploaded_files]
    if zip_upload:
        try:
            with ZipFile(BytesIO(zip_upload.getvalue())) as archive:
                for entry in archive.infolist():
                    if entry.is_dir() or not entry.filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                        continue
                    files.append((os.path.basename(entry.filename), archive.read(entry)))
        except BadZipFile:
            raise ValueError("The uploaded file is not a valid ZIP archive.")
    if len(files) > MAX_CATALOG_IMAGES:
        raise ValueError(f"Catalog uploads are limited to {MAX_CATALOG_IMAGES:,} images.")
    return files


def _package_protected_images(
    files: list[tuple[str, bytes]], message: str, selected_format: str
) -> tuple[bytes, list[tuple[str, str, datetime]]]:
    timestamp = _now()
    output = BytesIO()
    certificates = []
    with ZipFile(output, "w") as archive:
        for index, (filename, raw_data) in enumerate(files, start=1):
            try:
                image = from_bytes(raw_data)
                protected = encode(image, message)
            except (OSError, SteganographyError) as exc:
                raise ValueError(f"Could not protect {filename}: {exc}") from exc
            protected_data, extension, _ = _convert_image_bytes(protected, selected_format, raw_data)
            output_name = f"protected-{index:02d}-{os.path.splitext(filename)[0]}.{extension}"
            archive.writestr(output_name, protected_data)
            file_hash = _sha256(protected_data)
            certificates.append((output_name, file_hash, timestamp))
            archive.writestr(f"{output_name}.provenance.txt", _provenance_text(output_name, file_hash, timestamp))
            _save_activity(
                lambda filename=filename, image=image, message=message: save_encoded_image_metadata(
                    st.session_state["user_email"],
                    filename,
                    image.size,
                    len(message.encode("utf-8")),
                    capacity_bytes(image),
                )
            )
    return output.getvalue(), certificates


def _apply_theme() -> None:
    themes = {
        "Light": {
            "background": "#FFFFFF",
            "sidebar": "#F1F5F9",
            "text": "#0F172A",
            "subtext": "#334155",
            "input": "#0F172A",
            "border": "#94A3B8",
            "button_background": "#E2E8F0",
            "button_text": "#0F172A",
            "button_border": "#CBD5E1",
            "button_hover": "#CBD5E1",
            "input_background": "#FFFFFF",
            "placeholder": "#64748B",
            "select_arrow": "#0F172A",
        },
        "Dark": {
            "background": "#121212",
            "sidebar": "#1E1E1E",
            "text": "#FFFFFF",
            "subtext": "#E2E8F0",
            "input": "#FFFFFF",
            "border": "#64748B",
            "button_background": "#2D3748",
            "button_text": "#FFFFFF",
            "button_border": "#4A5568",
            "button_hover": "#4A5568",
            "input_background": "#1A202C",
            "placeholder": "#A0AEC0",
            "select_arrow": "#FFFFFF",
        },
        "Grey": {
            "background": "#27272A",
            "sidebar": "#18181B",
            "text": "#FAFAFA",
            "subtext": "#D4D4D8",
            "input": "#FAFAFA",
            "border": "#71717A",
            "button_background": "#3F3F46",
            "button_text": "#FFFFFF",
            "button_border": "#52525B",
            "button_hover": "#52525B",
            "input_background": "#27272A",
            "placeholder": "#A1A1AA",
            "select_arrow": "#FFFFFF",
        },
    }
    selected_theme = st.session_state.get("selected_theme", "Dark")
    palette = themes[selected_theme]
    st.markdown(
        f"""
        <style>
            :root {{
                --ag-background: {palette['background']};
                --ag-sidebar: {palette['sidebar']};
                --ag-text: {palette['text']};
                --ag-subtext: {palette['subtext']};
                --ag-input: {palette['input']};
                --ag-border: {palette['border']};
                --ag-button-background: {palette['button_background']};
                --ag-button-text: {palette['button_text']};
                --ag-button-border: {palette['button_border']};
                --ag-button-hover: {palette['button_hover']};
                --ag-input-background: {palette['input_background']};
                --ag-placeholder: {palette['placeholder']};
                --ag-select-arrow: {palette['select_arrow']};
            }}
            .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {{
                background-color: var(--ag-background);
            }}
            [data-testid="stSidebar"] {{
                background-color: var(--ag-sidebar);
            }}
            [data-testid="stAppViewContainer"] .main,
            [data-testid="stVerticalBlockBorderWrapper"],
            [data-testid="stExpander"] {{
                background-color: var(--ag-background);
            }}

            .stApp h1, .stApp h2, .stApp h3,
            [data-testid="stAppViewContainer"] h1,
            [data-testid="stAppViewContainer"] h2,
            [data-testid="stAppViewContainer"] h3,
            .stApp p, .stApp span, .stApp label,
            [data-testid="stAppViewContainer"] p,
            [data-testid="stAppViewContainer"] span,
            [data-testid="stAppViewContainer"] label,
            .stMarkdown, .stMarkdown p, .stMarkdown span,
            [data-testid="stSidebar"] h1,
            [data-testid="stSidebar"] h2,
            [data-testid="stSidebar"] h3,
            [data-testid="stSidebar"] p,
            [data-testid="stSidebar"] span,
            [data-testid="stSidebar"] label,
            [data-testid="stSidebar"] .stMarkdown {{
                color: var(--ag-text) !important;
            }}
            .stApp p, .stApp span, .stMarkdown p,
            [data-testid="stAppViewContainer"] p,
            [data-testid="stSidebar"] p,
            [data-testid="stSidebar"] .stCaption {{
                color: var(--ag-subtext) !important;
            }}

            .stButton button, [data-testid="stButton"] button,
            [data-testid="stDownloadButton"] button {{
                background-color: var(--ag-button-background) !important;
                color: var(--ag-button-text) !important;
                border: 1px solid var(--ag-button-border) !important;
            }}
            .stButton button:hover, [data-testid="stButton"] button:hover,
            [data-testid="stDownloadButton"] button:hover {{
                background-color: var(--ag-button-hover) !important;
                color: var(--ag-button-text) !important;
            }}
            div[data-baseweb="input"], div[data-baseweb="input"] input,
            input, textarea, [role="textbox"] {{
                background-color: var(--ag-input-background) !important;
                color: var(--ag-input) !important;
                border-color: var(--ag-border) !important;
            }}
            div[data-baseweb="input"] input::placeholder,
            input::placeholder, textarea::placeholder {{
                color: var(--ag-placeholder) !important;
                opacity: 1 !important;
            }}
            div[data-baseweb="select"], div[data-baseweb="select"] *,
            [data-testid="stSelectbox"], [data-testid="stSelectbox"] * {{
                color: var(--ag-input) !important;
                border-color: var(--ag-border) !important;
            }}
            div[data-baseweb="select"] {{
                background-color: var(--ag-input-background) !important;
            }}
            div[data-baseweb="select"] svg {{
                color: var(--ag-select-arrow) !important;
                fill: var(--ag-select-arrow) !important;
                stroke: var(--ag-select-arrow) !important;
            }}
            [role="option"] {{
                background-color: var(--ag-input-background) !important;
                color: var(--ag-input) !important;
            }}
            [data-baseweb="tab"], [data-baseweb="tab-list"] {{
                color: var(--ag-input) !important;
                border-color: var(--ag-border) !important;
            }}
            [data-baseweb="tab-highlight"] {{
                background-color: var(--ag-input) !important;
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _keyword_ai_guidance(user_query: str) -> str:
    lowered_query = user_query.lower()
    if "upload" in lowered_query or "watermark" in lowered_query:
        return "Go to the Protect tab, drag and drop your PNG/JPG/ZIP files into the Upload box, and click Encode to inject your ownership payload."
    if "scan" in lowered_query:
        return "Navigate to the Scan tab or check your Match Review Center to run automated queries against ValueSERP."
    if "dmca" in lowered_query:
        return "Open the DMCA Notice tab, enter the infringing URL, and click Generate PDF to create an official takedown notice."
    return f'I can help with "{user_query.strip()}". Try asking about uploads, watermarking, scans, or DMCA notices for step-by-step guidance.'


def _ai_response(user_query: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or openai is None:
        return _keyword_ai_guidance(user_query)

    try:
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are AlphaGuard AI, an expert assistant for e-commerce sellers dealing with stolen images, DMCA takedowns, and digital watermarking. Keep answers concise (2-3 sentences max) and helpful.",
                },
                {"role": "user", "content": user_query.strip()},
            ],
            max_tokens=180,
        )
        answer = response.choices[0].message.content
        return answer.strip() if answer else _keyword_ai_guidance(user_query)
    except Exception:
        return _keyword_ai_guidance(user_query)


def _ai_helper() -> None:
    if not st.session_state.get("show_ai_helper", True):
        return

    with st.sidebar.container():
        close_col, title_col = st.columns([1, 5])
        with close_col:
            if st.button("✕", key="close_ai_helper", help="Dismiss AI helper"):
                st.session_state["show_ai_helper"] = False
                st.rerun()
        with title_col:
            st.markdown("**AlphaGuard AI helper**")
        st.markdown(
            "<div style='font-size:2.3rem; text-align:center; padding-top:1rem;'>🤖</div>",
            unsafe_allow_html=True,
        )
        user_query = st.text_input(
            "Ask a quick question",
            placeholder="How do I embed a watermark?",
            key="ai_helper_question",
            label_visibility="collapsed",
        )
        if user_query.strip():
            with st.spinner("AlphaGuard AI is thinking..."):
                st.caption(_ai_response(user_query))
        else:
            st.caption("Try asking about uploads, watermarking, scans, or DMCA notices.")


def steganography_tab() -> None:
    st.subheader("Protect a message inside an image")
    st.session_state.setdefault("protect_download_format", "PNG")
    st.markdown("#### Bulk protection")
    bulk_files = st.file_uploader(
        "Drop your Product Catalog (.ZIP up to 1,000 images) or Bulk Media Files",
        type=["png", "jpg", "jpeg", "webp"],
        accept_multiple_files=True,
        help="Upload up to 1,000 PNG, JPG, JPEG, or WebP product images. You can also provide a ZIP catalog below.",
        key="bulk_images",
    )
    bulk_zip = st.file_uploader(
        "Drop your Product Catalog (.ZIP up to 1,000 images) or Bulk Media Files",
        type=["zip"],
        help="ZIP archives are extracted in memory and processed as a single catalog batch of up to 1,000 images.",
        key="bulk_zip",
    )
    bulk_message = st.text_area(
        "Bulk ownership message",
        placeholder="Owner email, copyright record, or provenance note",
        key="bulk_message",
    )
    bulk_format = st.selectbox("Bulk download format", DOWNLOAD_FORMATS, key="bulk_download_format")
    if st.button("Protect image set and download ZIP", type="primary", disabled=not (bulk_files or bulk_zip), use_container_width=True):
        try:
            files = _zip_images(bulk_files or [], bulk_zip)
            if not files:
                st.warning("No supported images were found in the upload.")
            else:
                message = bulk_message.strip() or "AlphaGuard protected ownership record"
                message = f"{message}\nOwner: {st.session_state['user_email']}\nTimestamp: {_now().isoformat()}"
                protected_zip, certificates = _package_protected_images(files, message, bulk_format)
                st.session_state["bulk_protected_zip"] = protected_zip
                st.session_state["bulk_certificates"] = certificates
                st.session_state["bulk_protected_format"] = bulk_format
                st.session_state["protected_asset_count"] = st.session_state.get("protected_asset_count", 0) + len(certificates)
                st.success(f"Protected {len(certificates)} image(s).")
        except ValueError as exc:
            st.error(str(exc))
    if st.session_state.get("bulk_protected_zip"):
        bulk_protected_format = st.session_state.get("bulk_protected_format", "PNG")
        st.download_button(
            f"Download protected image set ({bulk_protected_format}) (ZIP)",
            st.session_state["bulk_protected_zip"],
            file_name="alphaguard-protected-images.zip",
            mime="application/zip",
            use_container_width=True,
        )
        certificates = st.session_state.get("bulk_certificates", [])
        if certificates:
            certificate_text = "\n\n".join(_provenance_text(name, file_hash, timestamp) for name, file_hash, timestamp in certificates)
            st.download_button(
                "Download provenance certificates (TXT)",
                certificate_text,
                file_name="alphaguard-provenance-certificates.txt",
                mime="text/plain",
                use_container_width=True,
            )

    encode_col, decode_col = st.columns(2, gap="large")
    with encode_col:
        st.markdown("#### Encode")
        upload = st.file_uploader("Choose an image carrier (PNG, JPG, WebP)", type=["png", "jpg", "jpeg", "webp"], key="encode")
        message = st.text_area("Private message", height=140, placeholder="Copyright ownership record, case ID, or provenance note")
        image_url = st.text_input("Public image URL to monitor (optional)", placeholder="https://example.com/your-image.jpg")
        if upload:
            image = from_bytes(upload.getvalue())
            st.caption(f"Capacity: {capacity_bytes(image):,} UTF-8 bytes")
            if st.button("Encode and download", type="primary", use_container_width=True):
                try:
                    protected = encode(image, message)
                    _save_activity(
                        lambda: save_encoded_image_metadata(
                            st.session_state["user_email"],
                            upload.name,
                            image.size,
                            len(message.encode("utf-8")),
                            capacity_bytes(image),
                            image_url.strip(),
                        )
                    )
                    if image_url.strip():
                        st.session_state["protected_asset_count"] = st.session_state.get("protected_asset_count", 0) + 1
                    st.session_state["protected_image_data"] = to_png_bytes(protected)
                    st.session_state["protected_raw_bytes"] = upload.getvalue()
                    st.session_state["protected_upload_name"] = upload.name
                except SteganographyError as exc:
                    st.error(str(exc))

            if st.session_state.get("protected_image_data"):
                protected_image = from_bytes(st.session_state["protected_image_data"])
                st.image(protected_image, caption="Protected image preview", use_container_width=True)
                selected_format = st.radio(
                    "Download format",
                    DOWNLOAD_FORMATS,
                    horizontal=True,
                    key="protect_download_format",
                )
                protected_data, extension, mime = _convert_image_bytes(
                    protected_image,
                    selected_format,
                    st.session_state.get("protected_raw_bytes"),
                )
                timestamp = _now()
                file_hash = _sha256(protected_data)
                protected_filename = f"alphaguard-protected.{extension}"
                st.download_button(
                    f"Download Protected File ({selected_format})",
                    protected_data,
                    protected_filename,
                    mime,
                    use_container_width=True,
                )
                st.download_button(
                    "Download certificate (PDF)",
                    _provenance_pdf(protected_filename, file_hash, timestamp),
                    "alphaguard-certificate-of-provenance.pdf",
                    "application/pdf",
                    use_container_width=True,
                )
                st.download_button(
                    "Download certificate (TXT)",
                    _provenance_text(protected_filename, file_hash, timestamp),
                    "alphaguard-certificate-of-provenance.txt",
                    "text/plain",
                    use_container_width=True,
                )
    with decode_col:
        st.markdown("#### Decode")
        protected_upload = st.file_uploader("Choose a protected image (PNG, WebP)", type=["png", "webp"], key="decode")
        if protected_upload and st.button("Reveal embedded message", use_container_width=True):
            try:
                st.text_area("Recovered message", decode(from_bytes(protected_upload.getvalue())), height=140)
            except SteganographyError as exc:
                st.error(str(exc))


def _match_review_center(results) -> None:
    dismissed = st.session_state.setdefault("dismissed_matches", set())
    active_results = [result for result in results if result.link not in dismissed]
    with st.container(border=True):
        st.markdown("### Match Review Center")
        st.caption("Review detected matches and move promising results into a takedown notice.")
        if not active_results:
            st.info("No active matches require review.")
            return
        for index, result in enumerate(active_results):
            action_col, detail_col = st.columns([1, 4])
            with detail_col:
                st.markdown(f"**{result.title}**  \n{result.link}")
                if result.source:
                    st.caption(result.source)
            with action_col:
                if st.button("Dismiss", key=f"dismiss_match_{index}", use_container_width=True):
                    dismissed.add(result.link)
                    st.rerun()
                if st.button("Draft Takedown Notice", key=f"draft_match_{index}", use_container_width=True):
                    st.session_state["dmca_prefill"] = {
                        "dmca_claimant_email": st.session_state["user_email"],
                        "dmca_original_work": "Protected AlphaGuard artwork",
                        "dmca_infringing_url": result.link,
                    }
                    st.rerun()


def _build_takedown_notice(result, profile: dict[str, object], user_email: str) -> tuple[NoticeData, str]:
    notice_data = NoticeData(
        claimant_name=str(profile.get("owner_name") or ""),
        claimant_email=str(profile.get("business_email") or user_email),
        claimant_address=str(profile.get("mailing_address") or profile.get("owner_address") or ""),
        original_work=f"Copyrighted product imagery for {profile.get('shop_name') or 'the claimant'}",
        original_url=str(profile.get("website_url") or ""),
        infringing_url=result.link,
        signature=str(profile.get("owner_name") or ""),
    )
    return notice_data, generate_notice(notice_data)


def _takedown_action_queue(results, profile: dict[str, object], tier: str) -> None:
    user_email = st.session_state["user_email"]
    auth_user_id = st.session_state["auth_user_id"]
    for result in results:
        if not result.link:
            continue
        try:
            notice_id = save_takedown_notice(auth_user_id, result.link, result.thumbnail or "")
        except DatabaseError as exc:
            st.error(f"Could not queue {result.link}: {exc}")
            continue
        if tier != "Pro (Full Auto)":
            continue
        try:
            queued_notice = get_takedown_notice(notice_id, auth_user_id)
        except DatabaseError as exc:
            st.error(f"Could not check the automatic notice status: {exc}")
            continue
        if not queued_notice or queued_notice.get("status") != "Pending Authorization":
            continue
        notices = st.session_state.setdefault("generated_takedown_notices", {})
        if notice_id in notices:
            continue
        try:
            notice_data, notice = _build_takedown_notice(result, profile, user_email)
            save_dmca_notice_log(user_email, notice_data, notice)
            update_takedown_notice_status(
                notice_id,
                auth_user_id,
                "Authorized - Ready to Download",
                generated_notice=notice,
            )
        except DatabaseError as exc:
            st.error(f"Could not automatically prepare the notice for {result.link}: {exc}")
            continue
        notices[notice_id] = notice

    try:
        queue = get_takedown_notices(auth_user_id)
    except DatabaseError as exc:
        st.error(f"Could not load the pending-action queue: {exc}")
        return

    st.markdown("### Pending Action")
    st.caption(
        "Authorize notice generation, then download and send it yourself. AlphaGuard does not "
        "submit legal notices to third parties."
    )
    notices = st.session_state.setdefault("generated_takedown_notices", {})
    if not queue:
        st.info("No non-whitelisted matches are waiting for action.")
        return
    current_results = {result.link: result for result in results}
    for item in queue:
        notice_id = str(item["id"])
        target_url = str(item.get("target_url") or "")
        status = str(item.get("status") or "Pending Authorization")
        st.markdown(f"**{status}** · [{target_url}]({target_url})")
        notice_text = item.get("generated_notice") or notices.get(notice_id)
        if notice_text:
            _download_text(
                "Download generated DMCA notice",
                notice_text,
                f"alphaguard-dmca-notice-{notice_id[:8]}.txt",
                key=f"download_takedown_notice_{notice_id}",
            )
            continue
        if status != "Pending Authorization":
            continue
        result = current_results.get(target_url)
        if result is None:
            result = SimpleNamespace(link=target_url, title="Previously detected match")
        form_key = f"authorize_takedown_{notice_id}"
        with st.form(form_key):
            st.caption("Review the target carefully. Submitting authorizes generation, not external delivery.")
            confirmed = st.checkbox(
                "I confirm I am authorized to request this takedown.",
                key=f"{form_key}_confirm",
            )
            submitted = st.form_submit_button(
                "Authorize & Prepare DMCA Notice",
                type="primary",
                disabled=not confirmed,
            )
        if submitted:
            try:
                notice_data, notice = _build_takedown_notice(result, profile, user_email)
                save_dmca_notice_log(user_email, notice_data, notice)
                update_takedown_notice_status(
                    notice_id,
                    auth_user_id,
                    "Authorized - Ready to Download",
                    generated_notice=notice,
                )
            except DatabaseError as exc:
                st.error(f"Could not generate the authorized notice: {exc}")
            else:
                notices[notice_id] = notice
                st.rerun()


def _admin_review_queue() -> None:
    if not st.session_state.get("is_admin") or not _is_admin_email(
        str(st.session_state.get("user_email") or "")
    ):
        st.error("Administrator access is required to open the global review queue.")
        return

    st.subheader("Admin Control Center / Review Queue")
    st.caption(
        "All non-whitelisted detections require human review. Notice delivery and provider "
        "claims are not automated; record a dispatch only after sending it."
    )
    try:
        escalated_count = prepare_due_takedown_escalations(_now())
        queue = get_admin_takedown_notices()
    except DatabaseError as exc:
        st.error(f"Could not load the global review queue: {exc}")
        return
    if escalated_count:
        st.warning(
            f"Prepared secondary countermeasure drafts for {escalated_count} overdue notice(s)."
        )
    if not queue:
        st.info("No non-whitelisted matches are waiting for review.")
        return

    entries = []
    for item in queue:
        user_id = str(item.get("user_id") or "")
        try:
            profile = get_user_profile(user_id)
        except DatabaseError as exc:
            st.error(f"Could not load the claimant profile for a queued notice: {exc}")
            continue
        entries.append((item, profile or {}))
    entries.sort(
        key=lambda entry: (
            entry[1].get("tier") == "Enterprise"
            or entry[1].get("selected_plan") == "Enterprise"
        ),
        reverse=True,
    )

    for item, profile in entries:
        notice_id = str(item.get("id") or "")
        user_id = str(item.get("user_id") or "")
        target_url = str(item.get("target_url") or "")
        status = str(item.get("status") or "Pending Authorization")
        with st.container(border=True):
            st.markdown(f"**{status}** · [{target_url}]({target_url})")
            st.caption(
                f"Account: {profile.get('email') or user_id} · "
                f"Business: {profile.get('shop_name') or 'Not provided'}"
            )
            if item.get("dispatched_at"):
                st.caption(f"Notice dispatched: {item['dispatched_at']}")

            if status == "Pending Authorization":
                approve_col, false_positive_col, override_col = st.columns(3)
                if approve_col.button(
                    "Approve & Dispatch DMCA Notice",
                    key=f"admin_approve_{notice_id}",
                    type="primary",
                ):
                    try:
                        result = SimpleNamespace(
                            link=target_url,
                            title=str(item.get("title") or "Detected match"),
                        )
                        _, notice = _build_takedown_notice(
                            result, profile, str(profile.get("email") or "")
                        )
                        admin_update_takedown_notice(
                            notice_id,
                            "Admin Approved - Ready to Dispatch",
                            generated_notice=notice,
                        )
                    except (DatabaseError, ValueError) as exc:
                        st.error(f"Could not approve the notice: {exc}")
                    else:
                        st.info(
                            "Approved notice prepared. Download and deliver it through the "
                            "appropriate channel; AlphaGuard has not sent it."
                        )
                        st.rerun()
                if false_positive_col.button(
                    "Flag False Positive", key=f"admin_false_positive_{notice_id}"
                ):
                    try:
                        admin_update_takedown_notice(notice_id, "False Positive")
                    except DatabaseError as exc:
                        st.error(f"Could not flag this match: {exc}")
                    else:
                        st.rerun()
                if override_col.button(
                    "Override Enforcement", key=f"admin_override_{notice_id}"
                ):
                    try:
                        admin_update_takedown_notice(notice_id, "Enforcement Overridden")
                    except DatabaseError as exc:
                        st.error(f"Could not override enforcement: {exc}")
                    else:
                        st.rerun()

            generated_notice = str(item.get("generated_notice") or "")
            if generated_notice and status in {
                "Admin Approved - Ready to Dispatch",
                "Notice Dispatched",
                "Escalation Drafts Ready",
            }:
                _download_text(
                    "Download approved DMCA notice",
                    generated_notice,
                    f"alphaguard-approved-notice-{notice_id[:8]}.txt",
                    key=f"admin_download_notice_{notice_id}",
                )
            if status == "Admin Approved - Ready to Dispatch" and generated_notice:
                if st.button(
                    "Mark as dispatched (after sending)",
                    key=f"admin_mark_dispatched_{notice_id}",
                ):
                    try:
                        mark_takedown_notice_dispatched(notice_id, user_id)
                    except DatabaseError as exc:
                        st.error(f"Could not record the notice dispatch: {exc}")
                    else:
                        st.rerun()

            drafts = item.get("escalation_drafts") or {}
            if isinstance(drafts, dict) and drafts:
                with st.expander("7-day secondary legal countermeasure drafts"):
                    st.warning(
                        "These are drafts only. Submit through the provider's official "
                        "reporting channel; AlphaGuard has not contacted these providers."
                    )
                    for provider_name, draft in drafts.items():
                        st.markdown(f"**{provider_name}**")
                        st.text_area(
                            f"{provider_name} draft",
                            str(draft),
                            key=f"admin_escalation_{notice_id}_{provider_name}",
                            height=180,
                        )
            if status in {"Notice Dispatched", "Escalation Drafts Ready"}:
                if st.button("Mark resolved", key=f"admin_resolve_{notice_id}"):
                    try:
                        admin_update_takedown_notice(notice_id, "Resolved")
                    except DatabaseError as exc:
                        st.error(f"Could not resolve this notice: {exc}")
                    else:
                        st.rerun()


def scanner_tab(tier: str, profile: dict[str, object], can_scan: bool) -> None:
    st.subheader("OSINT Visual Radar")
    st.caption(
        "Search for unauthorized copies of protected logos, product imagery, and other visual "
        "media across indexed e-commerce listings and third-party sites."
    )
    if can_scan:
        if st.session_state.get("is_admin"):
            st.success("⚡ Admin access active: global monitoring enabled.")
        elif tier == "Enterprise":
            st.success("⚡ Enterprise priority radar: daily scheduled scans.")
        elif tier == "Pro (Full Auto)":
            st.success("⚡ Pro Full Auto: authorized notice drafts are generated automatically.")
        elif tier == "Pro":
            st.success("⚡ Pro Access Active: Unlimited Image Scanning Enabled")
        else:
            st.success(
                f"🛡️ Trial scanning active · "
                f"{st.session_state.get('trial_days_remaining', 0)} day(s) remaining."
            )
    else:
        st.warning(
            "🔒 Radar scanning is available during the 14-day trial and on Standard "
            "($29–$99/mo) or Enterprise ($299–$599+/mo) plans."
        )
        render_subscription_tiers()
        return
    
    # Provider selection
    provider = st.radio(
        "Search provider",
        options=["SerpApi (Google Lens)", "ValueSERP (Reverse Image Search)"],
        horizontal=True,
    )
    
    if provider == "SerpApi (Google Lens)":
        st.write("Provide a publicly accessible image URL. SerpApi Google Lens returns visually similar pages and images.")
        image_url = st.text_input("Image URL", placeholder="https://example.com/image.jpg")
        provider_name = "Google Lens"
        scan_func = scan_image
    else:
        st.write("Provide a publicly accessible image URL. ValueSERP performs reverse image search to find similar images across the web.")
        image_url = st.text_input("Image URL", placeholder="https://example.com/image.jpg", key="valueserp_url")
        provider_name = "ValueSERP"
        scan_func = scan_image_valueserp
    
    if st.button("Run Infringement Scan", type="primary", disabled=not image_url, use_container_width=True):
        with st.spinner(f"Searching for visual matches using {provider_name}..."):
            try:
                raw_results = scan_func(image_url)
                whitelist = str(profile.get("whitelisted_partners") or "")
                results = filter_whitelisted_matches(raw_results, whitelist)
                excluded_count = len(raw_results) - len(results)
                if excluded_count:
                    st.info(
                        f"Excluded {excluded_count} match(es) on whitelisted partner domains."
                    )
                st.session_state["scan_results"] = results
                links = {result.link for result in results if result.link}
                known_links = st.session_state.setdefault("detected_links", set())
                new_links = links - known_links
                known_links.update(links)
                st.session_state["infringements_detected"] = st.session_state.get("infringements_detected", 0) + len(new_links)
                month = _now().strftime("%Y-%m")
                trends = st.session_state.setdefault("infringement_trends", {})
                trends[month] = trends.get(month, 0) + len(new_links)
                if provider_name == "ValueSERP":
                    _save_activity(lambda: save_valueserp_scan_results(st.session_state["user_email"], image_url, results))
                else:
                    _save_activity(lambda: save_scan_results(st.session_state["user_email"], image_url, provider_name, results))
            except ScannerError as exc:
                st.error(str(exc))
            except DatabaseError as exc:
                st.error(f"Could not prepare takedown actions: {exc}")
    
    results = st.session_state.get("scan_results", [])
    if results:
        st.metric("Matches found", len(results))
        for result in results:
            st.markdown(f"**{result.position}. [{result.title}]({result.link})**  \\n{result.source or result.displayed_link}")
            if result.thumbnail:
                st.image(result.thumbnail, width=140)
        _match_review_center(results)
    elif image_url and "scan_results" in st.session_state:
        st.info("No visual matches were returned.")
    queue_results = [
        result
        for result in results
        if not _domain_is_whitelisted(
            result.link, str(profile.get("whitelisted_partners") or "")
        )
    ]
    _takedown_action_queue(queue_results, profile, tier)


def _dmca_pdf(notice_data: NoticeData, notice: str) -> bytes:
    return _pdf_bytes(
        "DMCA Notice",
        [
            "ALPHAGUARD DMCA TAKEDOWN NOTICE",
            f"Claimant: {notice_data.claimant_name}",
            f"Contact email: {notice_data.claimant_email}",
            f"Mailing address: {notice_data.claimant_address}",
            f"Original artwork: {notice_data.original_work}",
            f"Original artwork link: {notice_data.original_url}",
            f"Infringing URL: {notice_data.infringing_url}",
            "",
            *notice.splitlines(),
        ],
    )


def render_subscription_tiers() -> None:
    st.markdown("### 💳 Choose Your Digital Rights Defense Plan")
    st.write(
        "Select the tier that best fits your brand's operational scale and protection needs:"
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.subheader("🌱 Starter / Growth")
        st.markdown("### **$49** / month")
        st.caption("Ideal for D2C brands, small online stores & creators")
        st.markdown(
            """
            * Domains: **1**
            * Whitelisted Partners: **3**
            * Scan Frequency: **Every 24 hours**
            * Takedown Limit: **15 per month**
            * 7-Day Fallback Escalation ✅
            * Standard Email Support
            """
        )
        st.link_button(
            "👉 Subscribe to Growth ($49)",
            PAYONEER_GROWTH_URL,
            use_container_width=True,
        )

    with col2:
        st.subheader("⭐ Pro / Business")
        st.markdown("### **$149** / month")
        st.caption("Ideal for established brands & mid-sized e-commerce")
        st.markdown(
            """
            * Domains: **3**
            * Whitelisted Partners: **15**
            * Scan Frequency: **Every 6 Hours**
            * Takedown Limit: **Unlimited**
            * 7-Day Fallback Escalation ✅
            * Admin Permission Gating ✅
            * Priority Support
            """
        )
        st.link_button(
            "🔥 Subscribe to Pro ($149)",
            PAYONEER_PRO_URL,
            use_container_width=True,
        )

    with col3:
        st.subheader("🚀 Enterprise / Agency")
        st.markdown("### **$499+** / month")
        st.caption("Ideal for global enterprises & agencies")
        st.markdown(
            """
            * Domains: **Unlimited**
            * Whitelisted Partners: **Unlimited**
            * Scan Frequency: **Continuous / Priority**
            * Takedown Limit: **Unlimited**
            * Expedited Fallback Escalation ✅
            * API & Webhook Access ✅
            * Dedicated Concierge Support
            """
        )
        st.link_button(
            "👉 Subscribe to Enterprise ($499)",
            PAYONEER_ENTERPRISE_URL,
            use_container_width=True,
        )

    st.markdown("---")
    st.image(
        os.path.join(os.path.dirname(__file__), "AlphaGuard Pro Subscription.png"),
        caption="Scan QR to pay via Payoneer Mobile",
        width=220,
    )
    st.info(
        "Need custom enterprise invoicing or legal inquiries? "
        f"Contact: **{SUPPORT_EMAIL}**"
    )


def dmca_tab(tier: str, trial_active: bool = False) -> None:
    st.subheader("Draft a DMCA takedown notice")
    prefill = st.session_state.pop("dmca_prefill", {})
    for key, value in prefill.items():
        st.session_state[key] = value
    mode = st.radio("Notice mode", ["Single notice", "Bulk notices"], horizontal=True)
    if mode == "Bulk notices":
        if tier not in {"Pro", "Pro (Full Auto)", "Enterprise"} and not trial_active:
            st.info("Bulk DMCA generation is available during your full-access trial or on an eligible paid plan.")
            return
        with st.form("bulk_dmca_form"):
            claimant_name = st.text_input("Your name or organization", key="bulk_claimant_name")
            claimant_email = st.text_input("Contact email", key="bulk_claimant_email")
            claimant_address = st.text_area("Mailing address", height=80, key="bulk_claimant_address")
            original_work = st.text_input("Description of original work", key="bulk_original_work")
            original_url = st.text_input("Original work URL", key="bulk_original_url")
            infringing_urls = st.text_area("Infringing URLs (one per line)", key="bulk_infringing_urls")
            signature = st.text_input("Signature", placeholder="Type your full legal name", key="bulk_signature")
            submitted = st.form_submit_button("Generate notices", type="primary", use_container_width=True)
        if submitted:
            urls = [url.strip() for url in infringing_urls.splitlines() if url.strip()]
            required = [claimant_name, claimant_email, claimant_address, original_work, original_url]
            if not all(value.strip() for value in required) or not urls:
                st.warning("Complete every required field and add at least one infringing URL.")
            else:
                notices = []
                for infringing_url in urls:
                    notice_data = NoticeData(claimant_name, claimant_email, claimant_address, original_work, original_url, infringing_url, signature=signature)
                    notice = generate_notice(notice_data)
                    notices.append(notice)
                    _save_activity(lambda data=notice_data, text=notice: save_dmca_notice_log(st.session_state["user_email"], data, text))
                combined_notice = "\n\n".join(notices)
                st.text_area("Generated notices", combined_notice, height=360)
                _download_text("Download DMCA notices", combined_notice, "alphaguard-dmca-notices.txt")
                st.download_button(
                    "Download DMCA notices (PDF)",
                    _pdf_bytes("DMCA Notices", combined_notice.splitlines()),
                    "alphaguard-dmca-notices.pdf",
                    "application/pdf",
                    use_container_width=True,
                )
        return

    with st.form("dmca_form"):
        claimant_name = st.text_input("Your name or organization", key="dmca_claimant_name")
        claimant_email = st.text_input("Contact email", key="dmca_claimant_email")
        claimant_address = st.text_area("Mailing address", height=80, key="dmca_claimant_address")
        original_work = st.text_input("Description of original work", key="dmca_original_work")
        original_url = st.text_input("Original work URL", key="dmca_original_url")
        infringing_url = st.text_input("Infringing URL", key="dmca_infringing_url")
        signature = st.text_input("Signature", placeholder="Type your full legal name", key="dmca_signature")
        submitted = st.form_submit_button("Generate notice", type="primary", use_container_width=True)
    if submitted:
        required = [claimant_name, claimant_email, claimant_address, original_work, original_url, infringing_url]
        if not all(value.strip() for value in required):
            st.warning("Complete every required field before generating the notice.")
        else:
            notice_data = NoticeData(claimant_name, claimant_email, claimant_address, original_work, original_url, infringing_url, signature=signature)
            notice = generate_notice(notice_data)
            _save_activity(lambda: save_dmca_notice_log(st.session_state["user_email"], notice_data, notice))
            st.text_area("Generated notice", notice, height=360)
            _download_text("Download DMCA notice", notice, "alphaguard-dmca-notice.txt")
            st.download_button(
                "Download DMCA notice (PDF)",
                _dmca_pdf(notice_data, notice),
                "alphaguard-dmca-notice.pdf",
                "application/pdf",
                use_container_width=True,
            )
            st.caption("Review the notice and confirm the legal requirements for your jurisdiction before sending it.")


def _initialize_session_state() -> None:
    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("user_email", "")
    st.session_state.setdefault("is_admin", False)
    st.session_state.setdefault("selected_theme", "Dark")
    st.session_state.setdefault("show_ai_helper", True)
    st.session_state.setdefault("show_upgrade", False)
    st.session_state.setdefault("password_reset_mode", False)
    st.session_state.setdefault("reset_access_token", "")
    st.session_state.setdefault("reset_refresh_token", "")
    st.session_state.setdefault("reset_email", "")
    st.session_state.setdefault("reset_notice", "")
    st.session_state.setdefault("protected_asset_count", 0)
    st.session_state.setdefault("infringements_detected", 0)
    st.session_state.setdefault("detected_links", set())
    st.session_state.setdefault("infringement_trends", {})
    st.session_state.setdefault("completed_takedowns", 89)
    st.session_state.setdefault("total_takedowns", 100)
    st.session_state.setdefault("estimated_revenue_protected", 12400)
    st.session_state.setdefault("generated_takedown_notices", {})


def _login_screen(cookie_manager) -> None:
    st.title("AlphaGuard")
    st.caption("Sign in or create an account to protect your online content.")
    st.markdown(f"[Technical support](mailto:{SUPPORT_EMAIL})")
    login_tab, signup_tab, reset_tab = st.tabs(
        ["Log in", "Create account", "Forgot Password?"]
    )
    with login_tab:
        with st.form("login_form"):
            email = st.text_input("Email address", key="login_email")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Log in", type="primary", use_container_width=True)
        if submitted:
            try:
                _persist_auth_session(
                    sign_in_with_password(email, password), cookie_manager
                )
            except DatabaseError as exc:
                st.error(str(exc))
            else:
                st.rerun()
    with signup_tab:
        with st.form("signup_form"):
            email = st.text_input("Email address", key="signup_email")
            password = st.text_input("Password", type="password", key="signup_password")
            confirm_password = st.text_input(
                "Confirm password", type="password", key="signup_confirm_password"
            )
            submitted = st.form_submit_button(
                "Create account", type="primary", use_container_width=True
            )
        if submitted:
            if not email.strip() or not password:
                st.warning("Enter an email address and password.")
            elif password != confirm_password:
                st.warning("The passwords do not match.")
            else:
                try:
                    session = sign_up_with_password(email, password)
                except DatabaseError as exc:
                    st.error(str(exc))
                else:
                    if session is None:
                        st.success("Account created. Confirm your email, then log in.")
                    else:
                        _persist_auth_session(session, cookie_manager)
                        st.rerun()
    with reset_tab:
        st.caption("Supabase Auth will email you a password-recovery link.")
        with st.form("forgot_password_form"):
            email = st.text_input("Account email", key="forgot_password_email")
            submitted = st.form_submit_button(
                "Send recovery link", type="primary", use_container_width=True
            )
        if submitted:
            if not email.strip():
                st.warning("Enter your account email address.")
            else:
                try:
                    send_password_reset(
                        email,
                        redirect_to="https://alphaguard-fkre8tyjzbkpv2hjt5gvay.streamlit.app",
                    )
                except DatabaseError as exc:
                    st.error(f"Could not send the password reset email: {exc}")
                else:
                    st.success("If the account exists, a password-recovery link has been sent.")
    notice = st.session_state.pop("reset_notice", "")
    if notice:
        st.error(notice)


def _password_recovery_screen() -> None:
    st.title("Set a new password")
    email = st.session_state.get("reset_email", "")
    if email:
        st.caption(f"Resetting password for {email}")
    with st.form("new_password_form"):
        password = st.text_input("New password", type="password")
        confirmation = st.text_input("Confirm new password", type="password")
        submitted = st.form_submit_button("Update password", type="primary")
    if submitted:
        if len(password) < 8:
            st.warning("Use a password with at least 8 characters.")
        elif password != confirmation:
            st.warning("The passwords do not match.")
        else:
            try:
                update_user_password(
                    email,
                    password,
                    st.session_state["reset_access_token"],
                    st.session_state["reset_refresh_token"],
                )
            except DatabaseError as exc:
                st.error(str(exc))
            else:
                for key in (
                    "password_reset_mode",
                    "reset_access_token",
                    "reset_refresh_token",
                    "reset_email",
                ):
                    st.session_state.pop(key, None)
                st.success("Password updated. You can now log in.")
                st.rerun()


def _profile_needs_onboarding(profile: dict[str, object] | None) -> bool:
    if profile is None:
        return True
    required = (
        "shop_name",
        "owner_name",
        "mailing_address",
        "business_email",
        "website_url",
        "primary_market",
    )
    return any(not str(profile.get(field) or "").strip() for field in required)


def _onboarding_form(profile: dict[str, object] | None) -> None:
    st.title("Welcome to AlphaGuard")
    st.write("Complete your business profile to start your 14-day full-access trial.")
    st.markdown(f"[Technical support](mailto:{SUPPORT_EMAIL})")
    with st.form("onboarding_form"):
        shop_name = st.text_input("Shop/Website Name", value=str((profile or {}).get("shop_name") or ""))
        owner_name = st.text_input("Business/Owner Name", value=str((profile or {}).get("owner_name") or ""))
        business_email = st.text_input(
            "Business Email",
            value=str((profile or {}).get("business_email") or ""),
        )
        mailing_address = st.text_area(
            "Physical Mailing Address",
            value=str((profile or {}).get("mailing_address") or (profile or {}).get("owner_address") or ""),
            help="Required for a complete DMCA notice.",
        )
        website_url = st.text_input(
            "Primary Domain URL",
            value=str((profile or {}).get("website_url") or ""),
        )
        primary_market = st.text_input(
            "Primary Geographic Market",
            value=str((profile or {}).get("primary_market") or ""),
        )
        whitelisted_partners = st.text_area(
            "Whitelisted Partners / Authorized Resellers",
            value=str((profile or {}).get("whitelisted_partners") or ""),
            help="Comma-separated domains. Matches on these domains are excluded from the action queue.",
        )
        selected_plan = st.radio(
            "Plan preference after trial",
            ["Standard", "Enterprise"],
            format_func=lambda plan: (
                "Standard · $29–$99/mo · routine scheduled scans · one store and primary partners"
                if plan == "Standard"
                else "Enterprise · $299–$599+/mo · daily priority scans · unlimited partners"
            ),
            index=1 if (profile or {}).get("selected_plan") == "Enterprise" else 0,
        )
        submitted = st.form_submit_button("Save and start trial", type="primary")
    if not submitted:
        return
    parsed_website = urlparse(website_url.strip())
    if not all(
        value.strip()
        for value in (
            shop_name,
            owner_name,
            business_email,
            mailing_address,
            website_url,
            primary_market,
        )
    ):
        st.warning("Complete all required business profile fields.")
        return
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", business_email.strip()):
        st.warning("Enter a valid business email address.")
        return
    if parsed_website.scheme not in {"http", "https"} or not parsed_website.hostname:
        st.warning("Enter a valid website URL beginning with https:// or http://.")
        return
    now = _now()
    prior_onboarding = profile and all(
        str(profile.get(field) or "").strip()
        for field in ("shop_name", "owner_name", "website_url")
    )
    start_value = (profile or {}).get("trial_start_date") if prior_onboarding else None
    end_value = (profile or {}).get("trial_end_date") if prior_onboarding else None
    trial_start = str(start_value) if start_value else now.isoformat()
    trial_end = str(end_value) if end_value else (now + timedelta(days=14)).isoformat()
    try:
        save_user_onboarding(
            user_id=st.session_state["auth_user_id"],
            email=st.session_state["user_email"],
            business_email=business_email,
            shop_name=shop_name,
            owner_name=owner_name,
            mailing_address=mailing_address,
            website_url=website_url,
            primary_market=primary_market,
            whitelisted_partners=whitelisted_partners,
            selected_plan=selected_plan,
            trial_start_date=trial_start,
            trial_end_date=trial_end,
        )
    except DatabaseError as exc:
        st.error(str(exc))
    else:
        st.success("Your onboarding details are saved.")
        st.rerun()


def _trial_state(profile: dict[str, object], now: datetime) -> tuple[bool, int, int]:
    start_raw = profile.get("trial_start_date")
    end_raw = profile.get("trial_end_date")
    if not start_raw or not end_raw:
        raise ValueError("Your profile is missing its trial dates. Contact AlphaGuard support.")
    start = datetime.fromisoformat(str(start_raw).replace("Z", "+00:00"))
    end = datetime.fromisoformat(str(end_raw).replace("Z", "+00:00"))
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    remaining_seconds = (end - now).total_seconds()
    remaining_days = max(0, math.ceil(remaining_seconds / 86400))
    trial_day = max(1, int((now - start).total_seconds() // 86400) + 1)
    return now <= end, remaining_days, trial_day


def _analytics_dashboard(is_admin: bool = False) -> None:
    st.subheader("Analytics Dashboard")
    active_assets = st.session_state.get("protected_asset_count", 0)
    detected_matches = st.session_state.get("infringements_detected", 0)
    try:
        assets = get_active_protected_assets()
        if is_admin:
            active_assets = max(active_assets, len(assets))
            detected_matches = max(detected_matches, get_global_match_count())
        else:
            user_email = st.session_state["user_email"]
            active_assets = max(
                active_assets,
                len([asset for asset in assets if asset.get("user_id") == user_email]),
            )
            detected_matches = max(detected_matches, get_user_match_count(user_email))
    except DatabaseError as exc:
        st.warning(f"Could not load complete persistent analytics: {exc}")

    asset_col, match_col = st.columns(2)
    asset_col.metric("Protected assets", active_assets)
    match_col.metric(
        "Detected matches" if not is_admin else "Global detected matches",
        detected_matches,
    )
    if is_admin:
        try:
            assets = get_active_protected_assets()
        except DatabaseError as exc:
            st.error(f"Could not load global monitoring assets: {exc}")
        else:
            with st.expander("Global monitoring · active protected assets"):
                if not assets:
                    st.info("No active protected assets are registered.")
                for asset in assets:
                    st.write(f"{asset.get('user_id')}: {asset.get('image_url')}")


def _main() -> None:
    _initialize_session_state()
    cookie_manager = stx.CookieManager(key="alphaguard_auth_cookies")
    _process_password_recovery_link()
    if st.session_state.get("password_reset_mode"):
        _password_recovery_screen()
        return
    if not _restore_auth_session(cookie_manager):
        _login_screen(cookie_manager)
        return

    email = st.session_state["user_email"]
    try:
        profile = get_user_profile(st.session_state["auth_user_id"])
    except DatabaseError as exc:
        st.error(f"Could not load your user profile: {exc}")
        st.stop()
        return
    is_admin = bool(st.session_state.get("is_admin")) and _is_admin_email(email)
    if _profile_needs_onboarding(profile) and not is_admin:
        _onboarding_form(profile)
        return
    if profile is None:
        profile = {"email": email, "tier": "Enterprise"}
    st.session_state["is_admin"] = is_admin
    try:
        tier = "Enterprise" if is_admin else get_user_tier(st.session_state["auth_user_id"])
        if is_admin:
            trial_active, days_remaining, trial_day = False, 0, 0
        else:
            trial_active, days_remaining, trial_day = _trial_state(profile, _now())
    except (DatabaseError, ValueError) as exc:
        st.error(f"Could not determine your subscription access: {exc}")
        st.stop()
        return
    st.session_state["tier"] = tier
    st.session_state["trial_days_remaining"] = days_remaining
    paid_tiers = {"Standard", "Enterprise", "Pro", "Pro (Full Auto)"}
    can_scan = is_admin or tier in paid_tiers or trial_active

    if not is_admin and tier not in paid_tiers:
        if trial_day == 13 and trial_active:
            try:
                matches = get_user_match_count(email)
                dmca_count = get_user_dmca_notice_count(email)
            except DatabaseError as exc:
                st.warning(f"Could not load your trial summary: {exc}")
            else:
                st.info(
                    "📊 Your 14-Day AlphaGuard Trial Summary is ready! "
                    "View total detected matches and generated DMCA notices."
                )
                st.caption(
                    f"Trial totals: {matches} detected matches · {dmca_count} generated DMCA notices."
                )
                st.markdown(
                    f"[Contact technical support](mailto:{SUPPORT_EMAIL})"
                )
        if not trial_active:
            st.warning("Your 14-day trial has ended. Choose a paid plan to continue scanning.")
            render_subscription_tiers()
        else:
            st.caption(f"Trial day {trial_day} of 14 · {days_remaining} day(s) remaining.")

    with st.sidebar:
        st.markdown(f"**Signed in:** {email}")
        st.caption(f"Plan: {tier}{' · Admin' if is_admin else ''}")
        st.markdown(f"[Technical support](mailto:{SUPPORT_EMAIL})")
        st.selectbox("Theme", ["Dark", "Light", "Grey"], key="selected_theme")
        workspace_pages = [
            "Dashboard",
            "Protect",
            "Scan/Radar",
            "DMCA Notice",
            "Plans & Billing",
        ]
        if is_admin:
            workspace_pages.append("Admin Control Center")
        page = st.radio(
            "Workspace",
            workspace_pages,
            label_visibility="collapsed",
        )
        if st.button("Log out", use_container_width=True):
            try:
                sign_out_auth_session(
                    st.session_state.get("auth_access_token", ""),
                    st.session_state.get("auth_refresh_token", ""),
                )
                delete_persistent_auth_session(
                    st.session_state.get("persistent_session_id", "")
                )
            except DatabaseError as exc:
                st.error(str(exc))
            else:
                cookie_manager.delete(
                    AUTH_COOKIE_NAME, key="delete_alphaguard_session"
                )
                _clear_auth_session()
                st.rerun()
        _ai_helper()

    _apply_theme()
    if page == "Dashboard":
        _analytics_dashboard(is_admin)
    elif page == "Protect":
        steganography_tab()
    elif page == "Scan/Radar":
        scanner_tab(tier, profile, can_scan)
    elif page == "DMCA Notice":
        dmca_tab(tier, trial_active)
    elif page == "Plans & Billing":
        render_subscription_tiers()
    elif page == "Admin Control Center" and is_admin:
        _admin_review_queue()


if __name__ == "__main__":
    _main()