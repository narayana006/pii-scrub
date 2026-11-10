"""Built-in detectors and helpers for writing custom ones.

A detector is a label plus a function that returns the ``(start, end)`` spans
of every sensitive value it finds in a piece of text. The label becomes the
placeholder prefix, so a detector labelled ``EMAIL`` produces ``<EMAIL_1>``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Union

Span = tuple[int, int]
LABEL_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z")


@dataclass(frozen=True)
class Detector:
    """A named span finder. ``label`` must be UPPER_SNAKE_CASE."""

    label: str
    find: Callable[[str], Iterable[Span]]

    def __post_init__(self) -> None:
        if not LABEL_RE.match(self.label):
            raise ValueError(
                f"detector label must be UPPER_SNAKE_CASE, got {self.label!r}"
            )


def regex_detector(
    label: str,
    pattern: Union[str, "re.Pattern[str]"],
    *,
    validator: Callable[[str], bool] | None = None,
    group: Union[int, str] = 0,
    flags: int = 0,
) -> Detector:
    """Build a detector from a regular expression.

    ``group`` selects which capture group holds the sensitive value (the whole
    match by default). ``validator`` can reject a candidate after the regex
    matched, for example with a checksum.
    """
    compiled = re.compile(pattern, flags) if isinstance(pattern, str) else pattern

    def find(text: str) -> Iterator[Span]:
        for match in compiled.finditer(text):
            start, end = match.span(group)
            if start == -1 or start == end:
                continue
            if validator is None or validator(text[start:end]):
                yield start, end

    return Detector(label, find)


def callable_detector(
    label: str, func: Callable[[str], Iterable[Union[Span, str]]]
) -> Detector:
    """Build a detector from any callable.

    The callable receives the text and returns an iterable whose items are
    either ``(start, end)`` spans or plain strings. Every occurrence of a
    returned string is treated as a finding.
    """

    def find(text: str) -> Iterator[Span]:
        for item in func(text):
            if isinstance(item, str):
                if not item:
                    continue
                pos = text.find(item)
                while pos != -1:
                    yield pos, pos + len(item)
                    pos = text.find(item, pos + len(item))
            else:
                start, end = item
                if not 0 <= start < end <= len(text):
                    raise ValueError(
                        f"detector {label!r} returned an invalid span {item!r}"
                    )
                yield start, end

    return Detector(label, find)


def luhn_valid(number: str) -> bool:
    """Return True if the digits in ``number`` pass the Luhn checksum."""
    digits = [int(ch) for ch in number if ch.isdigit()]
    if not digits:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _card_valid(candidate: str) -> bool:
    digits = [ch for ch in candidate if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:  # 0000 0000 0000 0000 passes Luhn but is no card
        return False
    return luhn_valid(candidate)


def _phone_valid(candidate: str) -> bool:
    return 9 <= sum(ch.isdigit() for ch in candidate) <= 15


def _ipv6_valid(candidate: str) -> bool:
    if candidate.count(":") < 2 or not any(ch.isalnum() for ch in candidate):
        return False
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return True


_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

EMAIL = regex_detector(
    "EMAIL",
    r"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._%+-]*@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w-])",
)

# International numbers written as +<digits> (with or without two groups
# after the country code), or national numbers written in three groups,
# optionally with a country code and an area code in parentheses. A match
# may not continue a longer run of digit groups (a card-like number).
PHONE = regex_detector(
    "PHONE",
    r"(?<![\w.+-])(?<!\d{4}[ -])"
    r"(?:\+\d{9,15}"
    r"|\+\d{1,3}[ .-]\d{4,5}[ .-]\d{4,6}"
    r"|(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]\d{3,4})"
    r"(?![ .-]?\d)(?!\w)",
    validator=_phone_valid,
)

CREDIT_CARD = regex_detector(
    "CREDIT_CARD",
    r"(?<![\w.+-])\d(?:[ -]?\d){12,18}(?![ -]?\d)(?!\w)",
    validator=_card_valid,
)

SSN = regex_detector(
    "SSN",
    r"(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])",
)

IPV4 = regex_detector(
    "IP",
    rf"(?<![\w.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\.?\w)",
)

IPV6 = regex_detector(
    "IP",
    r"(?<![\w:.])[0-9A-Fa-f:]{3,39}(?![\w:])",
    validator=_ipv6_valid,
)

PRIVATE_KEY = regex_detector(
    "PRIVATE_KEY",
    r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z]+ )*PRIVATE KEY-----",
    flags=re.DOTALL,
)

# Token formats with a recognisable prefix.
API_KEY = regex_detector(
    "API_KEY",
    r"(?<![A-Za-z0-9_-])(?:"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}"  # AWS access key id
    r"|gh[pousr]_[A-Za-z0-9]{36,}"  # GitHub tokens
    r"|github_pat_[A-Za-z0-9_]{22,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"  # GitLab personal access token
    r"|sk-[A-Za-z0-9_-]{20,}"  # sk- style provider keys
    r"|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"  # Stripe
    r"|xox[abeprs]-[A-Za-z0-9-]{10,}"  # Slack
    r"|AIza[0-9A-Za-z_-]{35}"  # Google API key
    r")(?![A-Za-z0-9_-])",
)

JWT = regex_detector(
    "TOKEN",
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"
    r"(?![A-Za-z0-9_-])",
)

BEARER = regex_detector(
    "TOKEN",
    r"(?i:\bbearer)\s+(?P<value>[A-Za-z0-9._~+/-]{16,}=*)",
    group="value",
)

# key = value assignments such as  password: hunter2hunter2  or API_KEY="..."
SECRET = regex_detector(
    "SECRET",
    r"(?i:\b[\w-]*(?:api[_-]?key|secret|token|passwd|password)[\w-]*)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"'<>,;]{8,})",
    group="value",
)

# Order matters only as a tie-break: when two detectors claim the same span,
# the one listed first wins.
DEFAULT_DETECTORS: tuple[Detector, ...] = (
    PRIVATE_KEY,
    API_KEY,
    JWT,
    BEARER,
    EMAIL,
    CREDIT_CARD,
    SSN,
    IPV4,
    IPV6,
    PHONE,
    SECRET,
)
