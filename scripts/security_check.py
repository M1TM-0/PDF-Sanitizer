#!/usr/bin/env python3
"""Standalone, CI-friendly security check for a single PDF file.

Fails (non-zero exit code) if the given PDF contains any prohibited
active/interactive object (JavaScript, OpenAction, /AA, embedded files,
forms, RichMedia/Movie/Sound/3D, ...), is unreadable, or does not match
its own reported page count on independent re-parsing.

This is intentionally a thin, dependency-light wrapper around
``pdf_sanitizer.validator.validate`` (the same function that gates
release of sanitizer output) so it can be dropped into a CI pipeline as a
release gate independent of the richer ``pdf-sanitizer validate`` CLI
command's human-oriented output.

Usage::

    python scripts/security_check.py output.pdf
    python scripts/security_check.py output.pdf --max-output-bytes 52428800

Exit codes: 0 = clean, 1 = dangerous objects found or validation failed,
2 = the file could not even be opened/parsed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running this script directly from a source checkout without
# installing the package first (`python scripts/security_check.py ...`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import pikepdf  # noqa: E402

from pdf_sanitizer.config import get_settings  # noqa: E402
from pdf_sanitizer.sizes import parse_size  # noqa: E402
from pdf_sanitizer.validator import validate  # noqa: E402

#: Same default the sanitizer pipeline itself uses (persisted config /
#: PDF_SANITIZER_MAX_OUTPUT_BYTES / Settings.max_output_bytes) -- not a
#: second, independently-maintained literal, so this CI check and the
#: pipeline can never silently drift apart on what "too large" means.
_DEFAULT_MAX_OUTPUT_BYTES = get_settings().max_output_bytes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pdf_path", type=Path, help="Path to the PDF file to check.")
    parser.add_argument(
        "--max-output-bytes",
        type=parse_size,
        default=_DEFAULT_MAX_OUTPUT_BYTES,
        help="Maximum allowed file size, in bytes or human-readable form "
        "('500M', '3G'). Defaults to the project's configured max_output_bytes.",
    )
    args = parser.parse_args(argv)

    if not args.pdf_path.is_file():
        print(f"FAIL: not a file: {args.pdf_path}", file=sys.stderr)
        return 2

    data = args.pdf_path.read_bytes()

    try:
        with pikepdf.open(args.pdf_path) as pdf:
            expected_pages = len(pdf.pages)
    except Exception as error:
        print(f"FAIL: could not open {args.pdf_path} as a PDF: {error}", file=sys.stderr)
        return 2

    report = validate(data, expected_page_count=expected_pages, max_output_bytes=args.max_output_bytes)

    for check in report.checks:
        mark = "OK  " if check.passed else "FAIL"
        print(f"[{mark}] {check.name}: {check.detail}")

    if report.passed:
        print(f"PASS: {args.pdf_path} contains no prohibited active objects.")
        return 0

    print(f"FAIL: {args.pdf_path} was rejected: {report.rejection_reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
