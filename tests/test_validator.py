"""Unit tests for :func:`pdf_sanitizer.validator.validate`.

Unlike ``test_sanitizer.py``, these call the validator directly against
both a clean, sanitizer-produced PDF and a still-dangerous PDF that was
*not* produced by the sanitizer -- confirming the gate itself rejects
dangerous input regardless of where it came from, not just as a side
effect of the render-and-reconstruct pipeline never producing dangerous
output in the first place.
"""

from __future__ import annotations

from pdf_sanitizer.validator import validate
from tests import pdf_factory as pf


def test_clean_pdf_passes_validation() -> None:
    data = pf.pdf_normal(2)
    report = validate(data, expected_page_count=2, max_output_bytes=50 * 1024 * 1024)
    assert report.passed
    assert report.structural_scan.is_clean
    assert report.rejection_reason is None
    assert report.rejection_code is None
    assert report.output_page_count == 2


def test_pdf_with_javascript_fails_validation() -> None:
    data = pf.pdf_with_javascript()
    report = validate(data, expected_page_count=1, max_output_bytes=50 * 1024 * 1024)
    assert not report.passed
    assert not report.structural_scan.is_clean
    assert report.rejection_reason is not None
    assert report.rejection_code == "sanitized_output_invalid"
    assert any("dangerous" in c.detail.lower() for c in report.checks if c.name == "no_dangerous_objects")


def test_pdf_with_attachment_fails_the_no_attachments_check() -> None:
    data = pf.pdf_with_attachment()
    report = validate(data, expected_page_count=1, max_output_bytes=50 * 1024 * 1024)
    assert not report.passed
    attachment_check = next(c for c in report.checks if c.name == "no_attachments")
    assert not attachment_check.passed


def test_page_count_mismatch_fails_validation() -> None:
    data = pf.pdf_normal(2)
    report = validate(data, expected_page_count=99, max_output_bytes=50 * 1024 * 1024)
    assert not report.passed
    page_count_check = next(c for c in report.checks if c.name == "page_count_matches_expected")
    assert not page_count_check.passed


def test_oversized_output_fails_validation() -> None:
    data = pf.pdf_normal(1)
    report = validate(data, expected_page_count=1, max_output_bytes=10)
    assert not report.passed
    size_check = next(c for c in report.checks if c.name == "output_size_within_limit")
    assert not size_check.passed


def test_unparseable_bytes_fail_validation_without_raising() -> None:
    report = validate(pf.not_a_pdf_bytes(), expected_page_count=1, max_output_bytes=50 * 1024 * 1024)
    assert not report.passed
    reopen_check = next(c for c in report.checks if c.name == "pikepdf_reopen")
    assert not reopen_check.passed


def test_richmedia_annotation_fails_validation() -> None:
    data = pf.pdf_with_richmedia_annotation()
    report = validate(data, expected_page_count=1, max_output_bytes=50 * 1024 * 1024)
    assert not report.passed
    assert not report.structural_scan.is_clean
    matched = {f.matched_token for f in report.structural_scan.findings}
    assert "/RichMedia" in matched
