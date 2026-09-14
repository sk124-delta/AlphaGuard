"""SerpApi Google Lens and ValueSERP integration with provider-independent results."""

import os
from typing import Any
from urllib.parse import urlparse

import requests

from .models import ScanResult

SERPAPI_ENDPOINT = "https://serpapi.com/search.json"
VALUESERP_ENDPOINT = "https://api.valueserp.com/search"


class ScannerError(RuntimeError):
    """Raised when SerpApi cannot complete a search."""


def _domain(url: str) -> str:
    return urlparse(url).netloc.removeprefix("www.")


def normalize_results(payload: dict[str, Any]) -> list[ScanResult]:
    """Convert SerpApi's visual match records into stable application data."""
    records = payload.get("visual_matches") or payload.get("inline_images") or []
    results = []
    for index, record in enumerate(records, start=1):
        link = str(record.get("link") or record.get("source") or "")
        results.append(
            ScanResult(
                title=str(record.get("title") or "Untitled match"),
                link=link,
                source=str(record.get("source") or _domain(link)),
                displayed_link=str(record.get("displayed_link") or link),
                thumbnail=str(record.get("thumbnail") or record.get("original") or ""),
                position=int(record.get("position") or index),
                raw=record,
            )
        )
    return results


def normalize_valueserp_results(payload: dict[str, Any]) -> list[ScanResult]:
    """Convert ValueSERP's image search results into stable application data."""
    records = payload.get("image_results") or []
    results = []
    for index, record in enumerate(records, start=1):
        link = str(record.get("link") or "")
        results.append(
            ScanResult(
                title=str(record.get("title") or "Untitled match"),
                link=link,
                source=str(record.get("source") or _domain(link)),
                displayed_link=str(record.get("source") or link),
                thumbnail=str(record.get("image") or record.get("thumbnail") or ""),
                position=int(record.get("position") or index),
                raw=record,
            )
        )
    return results


def _serpapi_key() -> str | None:
    """Resolve the managed search key without accepting user-supplied credentials."""
    try:
        import streamlit as st

        key = st.secrets.get("SERPAPI_KEY")
    except (ImportError, FileNotFoundError, KeyError):
        key = None
    return key or os.getenv("SERPAPI_KEY")


def scan_image(image_url: str, timeout: int = 30) -> list[ScanResult]:
    """Search for visually similar images through SerpApi Google Lens."""
    key = _serpapi_key()
    if not key:
        raise ScannerError("SERPAPI_KEY is not configured.")
    if not image_url.strip():
        raise ScannerError("An image URL is required for a remote scan.")
    params = {"engine": "google_lens", "url": image_url, "api_key": key}
    try:
        response = requests.get(SERPAPI_ENDPOINT, params=params, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise ScannerError(f"SerpApi request failed: {exc}") from exc
    except ValueError as exc:
        raise ScannerError("SerpApi returned invalid JSON.") from exc
    if payload.get("error"):
        raise ScannerError(str(payload["error"]))
    return normalize_results(payload)


def scan_image_valueserp(image_url: str, timeout: int = 30) -> list[ScanResult]:
    """Search for visually similar images through ValueSERP reverse image search."""
    key = _serpapi_key()
    if not key:
        raise ScannerError("SERPAPI_KEY is not configured.")
    if not image_url.strip():
        raise ScannerError("An image URL is required for a remote scan.")
    params = {
        "q": image_url,
        "search_type": "images",
        "api_key": key,
    }
    try:
        response = requests.get(VALUESERP_ENDPOINT, params=params, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise ScannerError(f"ValueSERP request failed: {exc}") from exc
    except ValueError as exc:
        raise ScannerError("ValueSERP returned invalid JSON.") from exc
    if payload.get("error"):
        raise ScannerError(f"ValueSERP error: {payload['error']}")
    return normalize_valueserp_results(payload)
