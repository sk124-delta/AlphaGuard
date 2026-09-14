from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanResult:
    """Normalized result returned by an image search provider."""

    title: str
    link: str
    source: str = ""
    displayed_link: str = ""
    thumbnail: str = ""
    position: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class NoticeData:
    """Information needed to create a DMCA takedown notice."""

    claimant_name: str
    claimant_email: str
    claimant_address: str
    original_work: str
    original_url: str
    infringing_url: str
    good_faith_statement: str = (
        "I have a good faith belief that the disputed use is not authorized by the copyright owner, its agent, or the law."
    )
    accuracy_statement: str = (
        "Under penalty of perjury, I state that the information in this notification is accurate and that I am the copyright owner or authorized to act on the owner's behalf."
    )
    signature: str = ""
