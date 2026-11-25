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


# --- Optional detectors -----------------------------------------------------
# Names and street addresses have no fixed shape, so these two rely on context
# and layout and are NOT part of DEFAULT_DETECTORS: they miss things and can
# match ordinary text. Opt in with ``Scrubber(extra=[NAME, ADDRESS])`` or
# ``pii-scrub scrub --with NAME,ADDRESS``.

_NAME_WORD = r"(?:[A-Z]['\u2019][A-Z][a-z]+|[A-Z][a-z]+(?:['\u2019-][A-Z]?[a-z]+)*)"
_NAME_1_3 = rf"{_NAME_WORD}(?:[ \t]+{_NAME_WORD}){{0,2}}"
_NAME_2_3 = rf"{_NAME_WORD}(?:[ \t]+{_NAME_WORD}){{1,2}}"
_NOT_NAMES = frozenset(
    "team all everyone everybody support sir madam there folks guys friends "
    "colleagues customer service desk sales billing hello hi dear thanks thank "
    "regards best sincerely cheers the a an you".split()
)


def _name_valid(candidate: str) -> bool:
    return not any(word.lower() in _NOT_NAMES for word in candidate.split())


_NAME_CONTEXTS = tuple(
    regex_detector("NAME", pattern, group="value", validator=_name_valid)
    for pattern in (
        # Dr. Jane Smith, Mrs Okafor
        rf"\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof)\.?[ \t]+(?P<value>{_NAME_1_3})",
        # my name is Jane / Name: Jane Smith / customer: Jane Smith
        rf"(?i:\b(?:my name is|name|customer|contact)\s*(?:is\b|:)?)[ \t]+(?P<value>{_NAME_1_3})\b",
        # I'm Jane Smith / I am Jane Smith / this is Jane Smith (two or more words)
        rf"(?i:\b(?:i'm|i am|this is))[ \t]+(?P<value>{_NAME_2_3})\b",
        # Dear Jane,  Hi Jane Smith!
        rf"(?i:\b(?:dear|hi|hello))[ \t]+(?P<value>{_NAME_1_3})[ \t]*[,!]",
        # a name alone on the line after a sign-off
        rf"(?i:\b(?:thanks|thank you|regards|best regards|kind regards|best|sincerely|cheers)),?[ \t]*\r?\n[ \t]*(?P<value>{_NAME_1_3})[ \t]*$",
    )
)


def _find_names(text: str) -> Iterator[Span]:
    seen: set[str] = set()
    for detector in _NAME_CONTEXTS:
        for start, end in detector.find(text):
            name = text[start:end]
            if name not in seen:
                seen.add(name)
    # once a name is known, redact every occurrence of it, not just the one
    # that had a telltale context
    for name in sorted(seen, key=len, reverse=True):
        for match in re.finditer(rf"(?<!\w){re.escape(name)}(?!\w)", text):
            yield match.span()


NAME = Detector("NAME", _find_names)

_STREET_SUFFIX = (
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|"
    r"Way|Place|Pl|Terrace|Ter|Highway|Hwy|Parkway|Pkwy|Circle|Cir|Square|Sq)"
)
_STREET_NAME_WORD = r"(?:[A-Z][A-Za-z'.\u2019-]*|\d+(?:st|nd|rd|th))"

# "221B Baker Street", "1600 Pennsylvania Ave NW, Apt 4B, Springfield, IL 62704",
# "P.O. Box 1234". US-style layout only.
ADDRESS = regex_detector(
    "ADDRESS",
    r"(?<![\w#])(?:"
    rf"\d{{1,6}}[A-Za-z]?[ \t]+(?:{_STREET_NAME_WORD}[ \t]+){{1,4}}?{_STREET_SUFFIX}\b"
    r"(?:[ \t]+(?:N|S|E|W|NE|NW|SE|SW)\b)?"
    r"(?:,?[ \t]+(?:Apt|Apartment|Suite|Ste|Unit|Floor|Fl|#)\.?[ \t]*[\w-]+)?"
    r"(?:,[ \t]*[A-Z][A-Za-z.' -]*?,[ \t]*[A-Z]{2}[ \t]+\d{5}(?:-\d{4})?)?"
    r"|P\.?[ \t]?O\.?[ \t]+Box[ \t]+\d+"
    r")",
)


# --- National IDs outside the US -------------------------------------------
# Each of these is opt-in and only reports candidates whose checksum (or, for
# the UK, whose prefix rules) is valid, which keeps false positives low.

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(number: str) -> bool:
    """Return True if the digits in ``number`` pass the Verhoeff checksum."""
    digits = [int(ch) for ch in number if ch.isdigit()]
    if not digits:
        return False
    check = 0
    for index, digit in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][digit]]
    return check == 0


def _aadhaar_valid(candidate: str) -> bool:
    digits = "".join(ch for ch in candidate if ch.isdigit())
    return len(digits) == 12 and digits[0] in "23456789" and verhoeff_valid(digits)


def _cpf_valid(candidate: str) -> bool:
    digits = [int(ch) for ch in candidate if ch.isdigit()]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for length in (9, 10):
        total = sum(d * w for d, w in zip(digits[:length], range(length + 1, 1, -1)))
        if (total * 10 % 11) % 10 != digits[length]:
            return False
    return True


def _sin_valid(candidate: str) -> bool:
    digits = "".join(ch for ch in candidate if ch.isdigit())
    return len(digits) == 9 and digits[0] not in "08" and luhn_valid(digits)


def _dni_valid(candidate: str) -> bool:
    return "TRWAGMYFPDXBNJZSQVHLCKE"[int(candidate[:8]) % 23] == candidate[8].upper()


# India: 12 digits starting 2-9, written 1234 5678 9012 or without spaces,
# Verhoeff-checked.
AADHAAR = regex_detector(
    "AADHAAR",
    r"(?<![\w.+-])(?:[2-9]\d{3}([ -]?)\d{4}\1\d{4})(?![ -]?\d)(?!\w)",
    validator=_aadhaar_valid,
)

# Brazil CPF: 123.456.789-09 or 12345678909, check digits verified.
CPF = regex_detector(
    "CPF",
    r"(?<![\w.-])(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?![\w-]|\.\d)",
    validator=_cpf_valid,
)

# Canada SIN: 123-456-782 or 123 456 782 (Luhn-checked, first digit not 0 or 8).
SIN = regex_detector(
    "SIN",
    r"(?<![\w.+-])\d{3}([ -])\d{3}\1\d{3}(?![ -]?\d)(?!\w)",
    validator=_sin_valid,
)

# UK National Insurance number: AB 12 34 56 C, with the prefixes HMRC never issues excluded.
NINO = regex_detector(
    "NINO",
    r"(?<![\w-])(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]"
    r"(?:[ ]?\d{2}){3}[ ]?[A-D](?![\w-])",
)

# Spain DNI: 8 digits and a control letter derived from the number.
DNI = regex_detector(
    "DNI",
    r"(?<![\w-])\d{8}-?[A-HJ-NP-TV-Z](?![\w-])",
    validator=lambda c: _dni_valid(c.replace("-", "")),
)

OPTIONAL_DETECTORS: dict[str, Detector] = {
    "NAME": NAME,
    "ADDRESS": ADDRESS,
    "AADHAAR": AADHAAR,
    "CPF": CPF,
    "SIN": SIN,
    "NINO": NINO,
    "DNI": DNI,
}
