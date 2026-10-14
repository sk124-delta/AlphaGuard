from datetime import date
from io import BytesIO

import numpy as np
from PIL import Image

from app import _convert_image_bytes
from src.alphaguard.dmca import generate_notice
from src.alphaguard.models import NoticeData
from src.alphaguard.scanner import normalize_results
from src.alphaguard.stego import SteganographyError, capacity_bytes, decode, encode, strip_metadata_lossless


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
