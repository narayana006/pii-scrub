"""The vault maps placeholders back to the original values."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterator, Union

PLACEHOLDER_RE = re.compile(r"<([A-Z][A-Z0-9_]*?)_(\d+)>")
FORMAT_VERSION = 1


class Vault:
    """Holds the placeholder-to-original mapping for one or more scrub calls.

    The same original value always gets the same placeholder, so a model can
    still tell that two mentions refer to the same thing. The vault contains
    the real sensitive values: keep it on your side and never send it along.
    """

    def __init__(self) -> None:
        self._originals: dict[str, str] = {}
        self._placeholders: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}

    def placeholder_for(self, label: str, value: str) -> str:
        """Return the placeholder for ``value``, creating one if needed."""
        key = (label, value)
        existing = self._placeholders.get(key)
        if existing is not None:
            return existing
        number = self._counters.get(label, 0) + 1
        self._counters[label] = number
        placeholder = f"<{label}_{number}>"
        self._originals[placeholder] = value
        self._placeholders[key] = placeholder
        return placeholder

    def restore(self, text: str) -> str:
        """Swap every known placeholder in ``text`` for its original value.

        Placeholders that are not in this vault are left untouched.
        """
        return PLACEHOLDER_RE.sub(
            lambda match: self._originals.get(match.group(0), match.group(0)), text
        )

    def __len__(self) -> int:
        return len(self._originals)

    def __contains__(self, placeholder: object) -> bool:
        return placeholder in self._originals

    def __getitem__(self, placeholder: str) -> str:
        return self._originals[placeholder]

    def __iter__(self) -> Iterator[str]:
        return iter(self._originals)

    def items(self) -> list[tuple[str, str]]:
        """``(placeholder, original)`` pairs in the order they were created."""
        return list(self._originals.items())

    def counts(self) -> dict[str, int]:
        """Number of distinct values stored per label."""
        return dict(self._counters)

    def to_dict(self) -> dict:
        return {"version": FORMAT_VERSION, "entries": dict(self._originals)}

    @classmethod
    def from_dict(cls, data: dict) -> "Vault":
        if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
            raise ValueError("not a pii-scrub vault: missing 'entries' mapping")
        vault = cls()
        for placeholder, original in data["entries"].items():
            match = PLACEHOLDER_RE.fullmatch(placeholder)
            if match is None or not isinstance(original, str):
                raise ValueError(f"invalid vault entry {placeholder!r}")
            label, number = match.group(1), int(match.group(2))
            vault._originals[placeholder] = original
            vault._placeholders[(label, original)] = placeholder
            vault._counters[label] = max(vault._counters.get(label, 0), number)
        return vault

    def save(self, path: Union[str, Path]) -> None:
        """Write the vault as JSON, readable only by the current user."""
        path = Path(path)
        payload = json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "Vault":
        with open(path, encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))
