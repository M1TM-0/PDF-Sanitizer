"""Unit tests for :func:`pdf_sanitizer.inspector.inspect` (the read-only
report on the ORIGINAL, untrusted PDF) and its isolated wrapper.
"""

from __future__ import annotations

import pytest

from pdf_sanitizer import exceptions as exc
from pdf_sanitizer.inspector import inspect, inspect_isolated
from pdf_sanitizer.models import DomainSourceType
from tests import pdf_factory as pf


def _inspect(data: bytes, **kwargs):
    return inspect(
        data,
        filename=kwargs.pop("filename", "test.pdf"),
        password=kwargs.pop("password", None),
        domain_report_max_entries=kwargs.pop("max_entries", 500),
        domain_report_max_raw_value_len=kwargs.pop("max_raw_len", 300),
    )


def test_normal_pdf_has_no_findings() -> None:
    report = _inspect(pf.pdf_normal(1))
    assert report.page_count == 1
    assert not report.is_encrypted
    assert report.structural_scan.is_clean
    assert report.domain_report.total_findings == 0
    assert not report.javascript_present
    assert not report.open_action_present


def test_javascript_pdf_is_flagged() -> None:
    report = _inspect(pf.pdf_with_javascript('x = "http://js.malicious.example/y";'))
    assert report.javascript_present
    assert any(f.source_type == DomainSourceType.JAVASCRIPT for f in report.domain_report.findings)
    assert "js.malicious.example" in report.domain_report.unique_domains


def test_open_action_uri_is_flagged() -> None:
    report = _inspect(pf.pdf_with_uri_action("https://malicious.example/beacon"))
    assert report.open_action_present
    assert "malicious.example" in report.domain_report.unique_domains
    assert any(f.source_type == DomainSourceType.ACTION_URI for f in report.domain_report.findings)


def test_link_annotation_uri_is_flagged() -> None:
    report = _inspect(pf.pdf_with_links("https://example.org/normal-link"))
    assert any(f.source_type == DomainSourceType.ANNOTATION_URI for f in report.domain_report.findings)
    assert "example.org" in report.domain_report.unique_domains


def test_additional_actions_are_flagged() -> None:
    report = _inspect(pf.pdf_with_additional_actions())
    assert report.additional_actions_present


def test_attachment_is_counted() -> None:
    report = _inspect(pf.pdf_with_attachment("secret.txt"))
    assert report.embedded_files_count == 1
    assert any(f.source_type == DomainSourceType.EMBEDDED_FILE for f in report.domain_report.findings)


def test_acroform_and_xfa_flags() -> None:
    report = _inspect(pf.pdf_with_form_field())
    assert report.acroform_present


def test_richmedia_flag() -> None:
    report = _inspect(pf.pdf_with_richmedia_annotation())
    assert report.richmedia_or_multimedia_present


def test_launch_and_gotor_actions_are_reported() -> None:
    launch_report = _inspect(pf.pdf_with_launch_action("calc.exe"))
    assert any(f.source_type == DomainSourceType.LAUNCH_ACTION for f in launch_report.domain_report.findings)

    gotor_report = _inspect(pf.pdf_with_gotor_action("other.pdf"))
    assert any(f.source_type == DomainSourceType.GOTOR_ACTION for f in gotor_report.domain_report.findings)


def test_submit_form_action_is_reported() -> None:
    report = _inspect(pf.pdf_with_submit_form_action("https://evil.example/submit"))
    assert any(f.source_type == DomainSourceType.SUBMIT_FORM for f in report.domain_report.findings)


def test_encrypted_without_password_raises() -> None:
    with pytest.raises(exc.EncryptedPdfError):
        _inspect(pf.pdf_password_protected("secret"))


def test_encrypted_with_password_succeeds() -> None:
    report = _inspect(pf.pdf_password_protected("secret"), password="secret")
    assert report.is_encrypted
    assert report.page_count == 1


def test_domain_report_cap_truncates() -> None:
    report = _inspect(pf.pdf_with_javascript(), max_entries=0)
    assert report.domain_report.truncated
    assert report.domain_report.total_findings == 0


def test_not_a_pdf_raises() -> None:
    """``inspect()`` (unlike ``sanitize()`` / ``inspect_isolated()``) does
    not run the cheap magic-byte sniff first -- it hands bytes straight
    to pikepdf, so non-PDF input is classified as ``CorruptedPdfError``
    (pikepdf's own parse failure), not ``NotAPdfError``. The sniff-level
    ``NotAPdfError`` path is covered by ``test_sanitizer.py`` and
    ``test_security.py`` instead, against the functions that actually
    call ``security.assert_looks_like_pdf()``.
    """
    with pytest.raises(exc.CorruptedPdfError):
        _inspect(pf.not_a_pdf_bytes())


def test_inspect_isolated_matches_inline_inspect() -> None:
    from pdf_sanitizer.config import Settings

    data = pf.pdf_with_javascript()
    inline_report = _inspect(data)
    isolated_report = inspect_isolated(data, filename="test.pdf", settings=Settings())
    assert inline_report.javascript_present == isolated_report.javascript_present
    assert inline_report.page_count == isolated_report.page_count
