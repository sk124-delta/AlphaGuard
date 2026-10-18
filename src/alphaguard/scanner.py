"""SerpApi Google Lens and ValueSERP integration with provider-independent results."""

import os
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import requests
from bs4 import BeautifulSoup

from .models import ScanResult
from .url_utils import domain_is_whitelisted

SERPAPI_ENDPOINT = "https://serpapi.com/search.json"
VALUESERP_ENDPOINT = "https://api.valueserp.com/search"
DUCKDUCKGO_HTML_ENDPOINT = "https://html.duckduckgo.com/html/"


class ScannerError(RuntimeError):
    """Raised when an image search provider cannot complete a search."""


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
    return _read_secret("SERPAPI_KEY")


def _read_secret(name: str) -> str | None:
    """Read a key from Streamlit Secrets, then the environment; ignore blanks and stray quotes."""
    value = None
    try:
        import streamlit as st

        value = st.secrets.get(name)
    except Exception:  # no secrets.toml locally, or Streamlit not installed
        value = None
    value = value or os.getenv(name)
    if not value:
        return None
    cleaned = str(value).strip().strip('"').strip("'").strip()
    return cleaned or None


def image_search_provider_name() -> str:
    """Return the provider selected for interactive image searches."""
    if _serpapi_key():
        return "Google Lens"
    return "DuckDuckGo filename keyword search"


def keyless_visual_scan(image_url: str, timeout: int = 10) -> list[ScanResult]:
    """Search the web for the asset filename and return external listing candidates."""
    if not image_url.strip():
        raise ScannerError("An image URL is required for an image search.")
    parsed_image = urlparse(image_url.strip())
    filename = unquote(parsed_image.path.rsplit("/", 1)[-1])
    filename = re.sub(r"\.(?:jpe?g|png|webp|gif|avif)$", "", filename, flags=re.IGNORECASE)
    filename = re.sub(r"(?:[_-]\d+x\d+|[_-]\d+-kw)+$", "", filename, flags=re.IGNORECASE)
    keywords = re.sub(r"[-_]+", " ", filename).strip()
    if not keywords:
        raise ScannerError("The image URL must include a searchable filename.")

    params = {"q": f'"{keywords}"'}
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        )
    }
    try:
        response = requests.get(
            DUCKDUCKGO_HTML_ENDPOINT,
            params=params,
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise ScannerError(f"DuckDuckGo filename search failed: {exc}") from exc

    soup = BeautifulSoup(response.text, "html.parser")
    results = []
    seen_links = set()
    original_host = (urlparse(image_url.strip()).hostname or "").lower().removeprefix("www.")
    excluded_domains = ("duckduckgo.com", "google.com", "bing.com")
    anchors = soup.select("a.result__a[href]") or soup.select("a.result__url[href]")
    for anchor in anchors:
        link = str(anchor["href"]).strip()
        try:
            parsed = urlparse(link)
            if parsed.hostname and parsed.hostname.lower().endswith("duckduckgo.com"):
                link = parse_qs(parsed.query).get("uddg", [""])[0]
                parsed = urlparse(link)
            hostname = (parsed.hostname or "").lower().removeprefix("www.").rstrip(".")
        except ValueError:
            continue
        if (
            parsed.scheme not in {"http", "https"}
            or not hostname
            or any(
                hostname == domain or hostname.endswith(f".{domain}")
                for domain in excluded_domains
            )
            or (
                original_host
                and (
                    hostname == original_host
                    or hostname.endswith(f".{original_host}")
                )
            )
            or link in seen_links
        ):
            continue
        seen_links.add(link)
        results.append(
            ScanResult(
                title=anchor.get_text(" ", strip=True) or "Filename search result",
                link=link,
                source=hostname,
                displayed_link=link,
                position=len(results) + 1,
                raw={"href": link},
            )
        )
        if len(results) == 5:
            break
    return results


def scan_product_footprint(
    product_title: str, excluded_domain: str = ""
) -> list[ScanResult]:
    """Search the web for product-title mentions outside the claimant's domain."""
    title = product_title.strip()
    if not title:
        raise ScannerError("A product title is required for a footprint search.")
    try:
        from duckduckgo_search import DDGS
    except ImportError as exc:
        raise ScannerError(
            "The keyless web-search provider is not installed."
        ) from exc

    try:
        with DDGS() as ddgs:
            query_results = ddgs.text(
                keywords=f'"{title}"',
                max_results=5,
            )
            results = []
            for item in query_results:
                if not isinstance(item, dict):
                    continue
                link = str(item.get("href") or item.get("url") or "")
                if not link or domain_is_whitelisted(link, excluded_domain):
                    continue
                results.append(
                    ScanResult(
                        title=str(item.get("title") or "Product search result"),
                        link=link,
                        source=str(item.get("domain") or _domain(link)),
                        displayed_link=link,
                        thumbnail=str(item.get("image") or ""),
                        position=len(results) + 1,
                        raw=item,
                    )
                )
            return results
    except Exception as exc:
        raise ScannerError("DuckDuckGo product-title search failed.") from exc


def scan_image(image_url: str, timeout: int = 30) -> list[ScanResult]:
    """Search with Google Lens, falling back to filename-based web search."""
    key = _serpapi_key()
    if not key:
        return keyless_visual_scan(image_url, timeout=timeout)
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
    """Search for visually similar images through ValueSERP reverse image search.

    ValueSERP needs its own VALUESERP_KEY. Without one, use the SerpApi Google Lens
    scan so scheduled scans work with the same SERPAPI_KEY as the app.
    """
    key = _read_secret("VALUESERP_KEY")
    if not key:
        if _serpapi_key():
            return scan_image(image_url, timeout=timeout)
        raise ScannerError("Neither VALUESERP_KEY nor SERPAPI_KEY is configured.")
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
