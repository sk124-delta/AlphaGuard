"""Public contact discovery using domain and IP RDAP records."""

from dataclasses import dataclass
from email.utils import parseaddr
import ipaddress
from urllib.parse import quote, urlparse

import requests

from .url_utils import is_http_url


RDAP_ENDPOINT = "https://rdap.org"
DNS_OVER_HTTPS_ENDPOINT = "https://cloudflare-dns.com/dns-query"
REQUEST_TIMEOUT_SECONDS = 8


@dataclass(frozen=True)
class TargetContacts:
    owner_email: str = ""
    hosting_provider: str = ""
    host_abuse_email: str = ""
    errors: tuple[str, ...] = ()


def _entity_contacts(entities: list[dict]) -> list[tuple[set[str], list[str]]]:
    contacts = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = {str(role).lower() for role in entity.get("roles", [])}
        emails = []
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for field in vcard[1]:
                if (
                    isinstance(field, list)
                    and len(field) >= 4
                    and str(field[0]).lower() == "email"
                    and isinstance(field[3], str)
                ):
                    candidate = field[3].strip()
                    _, parsed = parseaddr(candidate)
                    if (
                        "\r" not in candidate
                        and "\n" not in candidate
                        and parsed == candidate
                        and "@" in parsed
                    ):
                        emails.append(parsed)
        contacts.append((roles, emails))
        contacts.extend(_entity_contacts(entity.get("entities") or []))
    return contacts


def _rdap_owner_email(record: dict) -> str:
    contacts = _entity_contacts(record.get("entities") or [])
    for preferred_role in ("registrant", "administrative", "technical"):
        for roles, emails in contacts:
            if preferred_role in roles and emails:
                return emails[0]
    return ""


def _rdap_abuse_email(record: dict) -> str:
    for roles, emails in _entity_contacts(record.get("entities") or []):
        if "abuse" in roles and emails:
            return emails[0]
    return ""


def _domain_from_rdap(record: dict) -> str:
    return next(
        (
            name
            for name in _entity_names(record.get("entities") or [])
            if name
        ),
        "",
    )


def _entity_names(entities: list[dict]) -> list[str]:
    names = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        if "registrar" not in {str(role).lower() for role in entity.get("roles", [])}:
            name = _entity_name(entity)
            if name:
                names.append(name)
        names.extend(_entity_names(entity.get("entities") or []))
    return names


def _entity_name(entity: dict) -> str:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
        for field in vcard[1]:
            if (
                isinstance(field, list)
                and len(field) >= 4
                and str(field[0]).lower() in {"fn", "org"}
            ):
                value = field[3]
                if isinstance(value, list):
                    return " ".join(str(part) for part in value)
                if isinstance(value, str):
                    return value
    return ""


def _resolve_public_addresses(domain: str) -> list[str]:
    addresses = []
    for record_type in ("A", "AAAA"):
        response = requests.get(
            DNS_OVER_HTTPS_ENDPOINT,
            params={"name": domain, "type": record_type},
            headers={"accept": "application/dns-json"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("DNS-over-HTTPS returned an invalid response.")
        for answer in payload.get("Answer", []):
            try:
                address = ipaddress.ip_address(answer.get("data", ""))
            except ValueError:
                continue
            if address.is_global and str(address) not in addresses:
                addresses.append(str(address))
        if len(addresses) >= 3:
            break
    return addresses


def discover_target_contacts(url: str) -> TargetContacts:
    """Find public domain registrant and hosting-network abuse contacts."""
    if not is_http_url(url):
        raise ValueError("Contact discovery requires a valid HTTP(S) target URL.")
    domain = (
        (urlparse(url).hostname or "")
        .encode("idna")
        .decode("ascii")
        .lower()
        .removeprefix("www.")
        .rstrip(".")
    )
    errors = []
    owner_email = ""
    hosting_provider = ""
    host_abuse_email = ""
    try:
        target_ip = ipaddress.ip_address(domain)
    except ValueError:
        target_ip = None

    if target_ip and not target_ip.is_global:
        return TargetContacts(errors=("The target IP is not publicly routable.",))

    if target_ip is None:
        try:
            response = requests.get(
                f"{RDAP_ENDPOINT}/domain/{quote(domain, safe='')}",
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            domain_record = response.json()
            if not isinstance(domain_record, dict):
                raise ValueError("Domain RDAP returned an invalid response.")
            owner_email = _rdap_owner_email(domain_record)
        except (requests.RequestException, ValueError) as exc:
            errors.append(f"Domain registration contacts could not be retrieved: {exc}")

    try:
        addresses = (
            [str(target_ip)]
            if target_ip
            else _resolve_public_addresses(domain)
        )
        if not addresses:
            errors.append("No public A or AAAA records were found for the target domain.")
        for address in addresses:
            response = requests.get(
                f"{RDAP_ENDPOINT}/ip/{quote(address, safe='')}",
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            ip_record = response.json()
            if not isinstance(ip_record, dict):
                raise ValueError("IP RDAP returned an invalid response.")
            host_abuse_email = _rdap_abuse_email(ip_record)
            hosting_provider = str(
                ip_record.get("name") or ip_record.get("handle") or ""
            )
            if not hosting_provider:
                hosting_provider = _domain_from_rdap(ip_record)
            if host_abuse_email or hosting_provider:
                break
    except (requests.RequestException, ValueError) as exc:
        errors.append(f"Hosting-network contacts could not be retrieved: {exc}")

    return TargetContacts(
        owner_email=owner_email,
        hosting_provider=hosting_provider,
        host_abuse_email=host_abuse_email,
        errors=tuple(errors),
    )
