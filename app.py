import os
import hashlib
import textwrap
from io import BytesIO
from datetime import datetime, timezone
from zipfile import BadZipFile, ZipFile

import streamlit as st
from dotenv import load_dotenv
from PIL import Image

try:
    import openai
except ImportError:
    openai = None

from src.alphaguard.db import (
    DatabaseError,
    get_active_protected_assets,
    get_user_match_count,
    get_user_tier,
    create_user,
    exchange_password_reset_code,
    get_user_settings,
    save_user_settings,
    send_password_reset,
    user_exists,
    update_user_password,
    verify_user_credentials,
    save_dmca_notice_log,
    save_encoded_image_metadata,
    save_scan_results,
    save_valueserp_scan_results,
    init_db,
)
from src.alphaguard.dmca import generate_notice
from src.alphaguard.models import NoticeData
from src.alphaguard.scanner import ScannerError, scan_image, scan_image_valueserp
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
DOWNLOAD_FORMATS = ["PNG", "JPEG", "PDF"]
DOWNLOAD_FORMAT_DETAILS = {
    "PNG": ("png", "image/png"),
    "JPEG": ("jpg", "image/jpeg"),
    "PDF": ("pdf", "application/pdf"),
}


def _download_text(label: str, text: str, filename: str) -> None:
    st.download_button(label, text, file_name=filename, mime="text/plain", use_container_width=True)


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


def scanner_tab(tier: str) -> None:
    st.subheader("Find where an image appears online")
    is_admin = st.session_state.get("user_email", "").strip().lower() == "sanifaiqbal970@gmail.com"
    if tier == "Pro" or is_admin:
        st.success("⚡ Pro Access Active: Unlimited Image Scanning Enabled")
    else:
        st.warning("🔒 Image scanning is exclusive to Pro users. Upgrade your account to unlock full radar scanning.")
        st.link_button(
            "⚡ Upgrade to Pro ($29/mo) via Payoneer",
            "https://link.payoneer.com/Token?t=B00BC444DE9B4D74B55F3814A423B1D1&src=pl",
            type="primary",
        )
        with st.expander("📱 Or scan QR code to pay on mobile"):
            st.image(
                os.path.join(os.path.dirname(__file__), "AlphaGuard Pro Subscription.png"),
                caption="Scan with mobile camera or Payoneer app to complete $29 payment",
                width=250,
            )
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
                results = scan_func(image_url)
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


def dmca_tab(tier: str) -> None:
    st.subheader("Draft a DMCA takedown notice")
    prefill = st.session_state.pop("dmca_prefill", {})
    for key, value in prefill.items():
        st.session_state[key] = value
    mode = st.radio("Notice mode", ["Single notice", "Bulk notices"], horizontal=True)
    if mode == "Bulk notices":
        if tier != "Pro":
            st.info("Bulk DMCA generation is available to Pro users. Upgrade your account to continue.")
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
    if st.session_state.get("user_email") == "sanifaiqbal970@gmail.com":
        st.session_state["tier"] = "Pro"
        st.session_state["is_admin"] = True


def _analytics_dashboard() -> None:
    st.subheader("Analytics Dashboard")
    active_assets = st.session_state.get("protected_asset_count", 0)
    detected_matches = st.session_state.get("infringements_detected", 0)
    try:
        active_assets = max(
            active_assets,
            len([asset for asset in get_active_protected_assets() if asset.get("user_id") == st.session_state["user_email"]]),
        )
        detected_matches = max(detected_matches, get_user_match_count(st.session_state["user_email"]))
    except DatabaseError:
        pass

   c