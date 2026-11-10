"""Command-line interface: pii-scrub scrub | restore | detect."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Sequence

from . import __version__
from .detectors import DEFAULT_DETECTORS, Detector, regex_detector
from .scrubber import Scrubber
from .vault import Vault


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _write(path: str | None, text: str) -> None:
    if path is None or path == "-":
        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _build_scrubber(args: argparse.Namespace) -> Scrubber:
    detectors: Sequence[Detector] = DEFAULT_DETECTORS
    if args.only:
        wanted = {name.strip().upper() for name in args.only.split(",") if name.strip()}
        known = {detector.label for detector in DEFAULT_DETECTORS}
        unknown = sorted(wanted - known)
        if unknown:
            raise SystemExit(
                f"pii-scrub: unknown detector(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(known))}"
            )
        detectors = [d for d in DEFAULT_DETECTORS if d.label in wanted]
    extra = []
    for spec in args.pattern or []:
        label, sep, pattern = spec.partition("=")
        if not sep or not pattern:
            raise SystemExit(f"pii-scrub: --pattern expects LABEL=REGEX, got {spec!r}")
        try:
            extra.append(regex_detector(label.strip().upper(), pattern))
        except (ValueError, re.error) as exc:
            raise SystemExit(f"pii-scrub: bad --pattern {spec!r}: {exc}")
    return Scrubber(detectors, extra)


def _summary(counts: dict[str, int]) -> str:
    if not counts:
        return "nothing found"
    return ", ".join(f"{label} {count}" for label, count in sorted(counts.items()))


def _cmd_scrub(args: argparse.Namespace) -> int:
    scrubber = _build_scrubber(args)
    vault = None
    if args.vault and os.path.exists(args.vault):
        vault = Vault.load(args.vault)
    text = _read(args.file)
    findings = scrubber.detect(text)
    safe, vault = scrubber.scrub(text, vault)
    _write(args.output, safe)
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.label] = counts.get(finding.label, 0) + 1
    message = f"pii-scrub: replaced {len(findings)} value(s): {_summary(counts)}"
    if args.vault:
        vault.save(args.vault)
        message += f"; vault saved to {args.vault}"
    elif findings:
        message += "; no --vault given, so this cannot be restored"
    print(message, file=sys.stderr)
    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    vault = Vault.load(args.vault)
    _write(args.output, vault.restore(_read(args.file)))
    return 0


def _mask(value: str) -> str:
    first_line = value.splitlines()[0] if value else value
    if len(first_line) <= 4:
        return "*" * len(first_line)
    return first_line[:2] + "*" * min(len(first_line) - 4, 12) + first_line[-2:]


def _cmd_detect(args: argparse.Namespace) -> int:
    text = _read(args.file)
    findings = _build_scrubber(args).detect(text)
    rows = []
    for finding in findings:
        line = text.count("\n", 0, finding.start) + 1
        column = finding.start - (text.rfind("\n", 0, finding.start) + 1) + 1
        rows.append(
            {
                "label": finding.label,
                "line": line,
                "column": column,
                "value": finding.value if args.show else _mask(finding.value),
            }
        )
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    else:
        for row in rows:
            print(f"{row['line']}:{row['column']}\t{row['label']}\t{row['value']}")
    if args.fail_on_find and rows:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-scrub",
        description="Replace PII and secrets with reversible placeholders.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_detector_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("file", nargs="?", default="-", help="input file (default: stdin)")
        p.add_argument(
            "--only",
            metavar="LABELS",
            help="comma-separated built-in detectors to run, e.g. EMAIL,PHONE",
        )
        p.add_argument(
            "--pattern",
            action="append",
            metavar="LABEL=REGEX",
            help="add a custom regex detector (repeatable)",
        )

    p_scrub = sub.add_parser("scrub", help="replace sensitive values with placeholders")
    add_detector_options(p_scrub)
    p_scrub.add_argument("--vault", metavar="PATH", help="vault file to create or extend")
    p_scrub.add_argument("-o", "--output", metavar="PATH", help="write here instead of stdout")
    p_scrub.set_defaults(func=_cmd_scrub)

    p_restore = sub.add_parser("restore", help="put original values back")
    p_restore.add_argument("file", nargs="?", default="-", help="input file (default: stdin)")
    p_restore.add_argument("--vault", metavar="PATH", required=True, help="vault file from scrub")
    p_restore.add_argument("-o", "--output", metavar="PATH", help="write here instead of stdout")
    p_restore.set_defaults(func=_cmd_restore)

    p_detect = sub.add_parser("detect", help="list what would be replaced")
    add_detector_options(p_detect)
    p_detect.add_argument("--json", action="store_true", help="print findings as JSON")
    p_detect.add_argument("--show", action="store_true", help="print full values instead of masked")
    p_detect.add_argument(
        "--fail-on-find", action="store_true", help="exit with status 1 if anything is found"
    )
    p_detect.set_defaults(func=_cmd_detect)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"pii-scrub: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
