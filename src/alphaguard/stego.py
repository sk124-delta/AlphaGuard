"""Least-significant-bit image steganography for PNG, JPG, and WebP carriers."""

from io import BytesIO
import struct

import numpy as np
from PIL import Image

MAGIC = b"ALPHAGUARD\x01\x00"
_HEADER = struct.Struct(">12sI")


class SteganographyError(ValueError):
    """Raised when a carrier cannot hold or reveal an AlphaGuard payload."""


def _as_rgb_array(image: Image.Image) -> np.ndarray:
    return np.array(image.convert("RGB"), dtype=np.uint8)


def capacity_bytes(image: Image.Image) -> int:
    """Return usable payload bytes for one LSB per RGB channel."""
    return max(0, (_as_rgb_array(image).size // 8) - _HEADER.size)


def encode(image: Image.Image, message: str) -> Image.Image:
    """Embed UTF-8 text in an image and return a PNG-safe RGB image."""
    payload = message.encode("utf-8")
    array = _as_rgb_array(image)
    packed = _HEADER.pack(MAGIC, len(payload)) + payload
    bits = np.unpackbits(np.frombuffer(packed, dtype=np.uint8))
    if bits.size > array.size:
        raise SteganographyError(
            f"Message needs {(bits.size + 7) // 8} bytes, but the image holds {capacity_bytes(image)} bytes."
        )
    flat = array.reshape(-1).copy()
    flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits
    return Image.fromarray(flat.reshape(array.shape), mode="RGB")


def decode(image: Image.Image) -> str:
    """Extract and validate an AlphaGuard UTF-8 payload from an image."""
    flat = _as_rgb_array(image).reshape(-1)
    byte_count = flat.size // 8
    bits = (flat[: byte_count * 8] & 1).astype(np.uint8)
    packed = np.packbits(bits).tobytes()
    if len(packed) < _HEADER.size:
        raise SteganographyError("Image is too small to contain an AlphaGuard payload.")
    magic, payload_length = _HEADER.unpack(packed[: _HEADER.size])
    if magic != MAGIC:
        raise SteganographyError("No AlphaGuard payload was found in this image.")
    payload_start = _HEADER.size
    payload_end = payload_start + payload_length
    if payload_end > len(packed):
        raise SteganographyError("The embedded payload is incomplete or corrupted.")
    try:
        return packed[payload_start:payload_end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SteganographyError("The embedded payload is not valid UTF-8 text.") from exc


def to_png_bytes(image: Image.Image) -> bytes:
    """Serialize a carrier as PNG, preserving lossless embedded bits."""
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def from_bytes(data: bytes) -> Image.Image:
    """Load image bytes and detach them from the upload stream."""
    return Image.open(BytesIO(data)).convert("RGB")


def strip_metadata_lossless(raw_bytes: bytes) -> bytes:
    """Remove JPEG APP and COM segments without decoding or re-encoding."""
    if not raw_bytes.startswith(b"\xff\xd8"):
        return raw_bytes

    output = bytearray(raw_bytes[:2])
    index = 2
    length = len(raw_bytes)
    standalone_markers = {0x01, *range(0xD0, 0xD9)}

    while index < length:
        if raw_bytes[index] != 0xFF:
            return raw_bytes
        marker_start = index
        while index < length and raw_bytes[index] == 0xFF:
            index += 1
        if index >= length:
            return raw_bytes
        marker = raw_bytes[index]
        index += 1

        if marker == 0xDA:
            jpeg_bytes = raw_bytes[marker_start:]
            eoi_index = jpeg_bytes.find(b"\xff\xd9")
            if eoi_index != -1:
                jpeg_bytes = jpeg_bytes[: eoi_index + 2]
            output.extend(jpeg_bytes)
            return bytes(output)
        if marker == 0xD9:
            output.extend(raw_bytes[marker_start:index])
            return bytes(output)
        if marker in standalone_markers:
            output.extend(raw_bytes[marker_start:index])
            continue
        if index + 2 > length:
            return raw_bytes
        segment_length = int.from_bytes(raw_bytes[index:index + 2], "big")
        segment_end = index + segment_length
        if segment_length < 2 or segment_end > length:
            return raw_bytes
        if not (0xE0 <= marker <= 0xEF or marker == 0xFE):
            output.extend(raw_bytes[marker_start:segment_end])
        index = segment_end

    return bytes(output)
