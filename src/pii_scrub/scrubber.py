"""Find sensitive values and replace them with placeholders."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .detectors import DEFAULT_DETECTORS, Detector
from .vault import Vault


@dataclass(frozen=True)
class Finding:
    """One sensitive value located in the text."""

    label: str
    start: int
    end: int
    value: str


class Scrubber:
    """Runs a set of detectors over text.

    ``detectors`` replaces the built-in set; ``extra`` adds to it. Custom
    detectors passed as ``extra`` take precedence over built-ins when both
    claim exactly the same span.
    """

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        extra: Iterable[Detector] = (),
    ) -> None:
        base = DEFAULT_DETECTORS if detectors is None else tuple(detectors)
        self.detectors: tuple[Detector, ...] = tuple(extra) + tuple(base)

    def detect(self, text: str) -> list[Finding]:
        """Return non-overlapping findings in the order they appear.

        When candidates overlap, the one that starts first wins; among those
        starting at the same position the longest wins, then detector order.
        """
        candidates: list[tuple[int, int, int, str]] = []
        for rank, detector in enumerate(self.detectors):
            for start, end in detector.find(text):
                candidates.append((start, -(end - start), rank, detector.label))
        candidates.sort()

        findings: list[Finding] = []
        cursor = 0
        for start, neg_length, _rank, label in candidates:
            if start < cursor:
                continue
            end = start - neg_length
            findings.append(Finding(label, start, end, text[start:end]))
            cursor = end
        return findings

    def scrub(self, text: str, vault: Vault | None = None) -> tuple[str, Vault]:
        """Replace every finding with a placeholder.

        Pass an existing ``vault`` to keep placeholders consistent across
        several texts (for example every message of one conversation).
        """
        if vault is None:
            vault = Vault()
        parts: list[str] = []
        cursor = 0
        for finding in self.detect(text):
            parts.append(text[cursor : finding.start])
            parts.append(vault.placeholder_for(finding.label, finding.value))
            cursor = finding.end
        parts.append(text[cursor:])
        return "".join(parts), vault


def scrub(
    text: str,
    vault: Vault | None = None,
    *,
    detectors: Sequence[Detector] | None = None,
    extra: Iterable[Detector] = (),
) -> tuple[str, Vault]:
    """Scrub ``text`` and return ``(safe_text, vault)``.

    Call ``vault.restore(model_output)`` to put the originals back.
    """
    return Scrubber(detectors, extra).scrub(text, vault)
