"""URL helpers shared by interactive and scheduled scans."""

from urllib.parse import urlparse


def is_http_url(url: str) -> bool:
    """Return whether a URL has an HTTP(S) scheme and a valid hostname/port."""
    try:
        parsed = urlparse(url.strip())
        _ = parsed.port
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def domain_is_whitelisted(url: str, whitelisted_partners: str) -> bool:
    hostname = (urlparse(url).hostname or "").lower().removeprefix("www.")
    if not hostname:
        return False
    for partner in whitelisted_partners.split(","):
        candidate = partner.strip().lower()
        if not candidate:
            continue
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        domain = (parsed.hostname or "").removeprefix("www.")
        if domain and (hostname == domain or hostname.endswith(f".{domain}")):
            return True
    return False


def filter_whitelisted_matches(results, whitelisted_partners: str):
    """Return scan matches outside authorized partner domains."""
    return [
        result
        for result in results
        if not domain_is_whitelisted(result.link, whitelisted_partners)
    ]


def primary_domain_from_url(url: str) -> str:
    """Normalize a validated website URL to its registrable hostname."""
    hostname = (urlparse(url).hostname or "").lower().removeprefix("www.").rstrip(".")
    if not hostname:
        raise ValueError("Enter a valid website URL with a hostname.")
    return hostname
