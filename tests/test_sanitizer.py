"""Integration tests for :func:`pdf_sanitizer.sanitizer.sanitize`.

These exercise the full pipeline end to end (isolated worker process
included) against the fixtures in ``tests/pdf_factory.py``. They are
necessarily slower than the unit tests in the other ``test_*.py`` files
because each one spawns a real subprocess.
"""

from __future__ import annotations

import pytest

from pdf_sanitizer import exceptions as exc
from pdf_sanitizer.config import Settings
from pdf_sanitizer.sanitizer import sanitize
from tests import pdf_factory as pf


def test_normal_pdf_is_accepted(fast_settings: Settings) -> None:
    result = sanitize(pf.pdf_normal(1), filename="normal.pdf", settings=fast_settings)
    assert result.accepted
    assert result.sanitized_pdf_bytes
    assert result.report.sanitized_page_count == 1
    assert result.report.validation_report.passed
    assert result.report.validation_report.structural_scan.is_clean


def test_multi_page_pdf_preserves_page_count(fast_settings: Settings) -> None:
    result = sanitize(pf.pdf_multi_page(7), filename="multi.pdf", settings=fast_settings)
    assert result.accepted
    assert result.report.original_page_count == 7
    assert result.report.sanitized_page_count == 7


@pytest.mark.parametrize(
    "factory_name",
    [
        "pdf_with_links",
        "pdf_with_uri_action",
        "pdf_with_javascript",
        "pdf_with_open_action_javascript",
        "pdf_with_additional_actions",
        "pdf_with_launch_action",
        "pdf_with_gotor_action",
        "pdf_with_submit_form_action",
        "pdf_with_attachment",
        "pdf_with_form_field",
        "pdf_with_richmedia_annotation",
    ],
)
def test_dangerous_features_are_removed(fast_settings: Settings, factory_name: str) -> None:
    factory = getattr(pf, factory_name)
    result = sanitize(factory(), filename="dangerous.pdf", settings=fast_settings)

    assert result.accepted, result.report.validation_report.rejection_reason
    assert result.report.validation_report.structural_scan.is_clean
    assert result.report.validation_report.passed

    # Re-validate independently to double-check the scanner agrees with itself.
    from pdf_sanitizer.validator import validate

    revalidation = validate(
        result.sanitized_pdf_bytes,
        expected_page_count=result.report.sanitized_page_count,
        max_output_bytes=fast_settings.max_output_bytes,
    )
    assert revalidation.passed
    assert revalidation.structural_scan.is_clean


def test_javascript_is_reported_before_removal(fast_settings: Settings) -> None:
    result = sanitize(
        pf.pdf_with_javascript('var u = "http://js.malicious.example/x";'),
        filename="js.pdf",
        settings=fast_settings,
    )
    assert result.accepted
    domains = result.report.domain_report
    assert any(f.domain == "js.malicious.example" for f in domains.findings)


def test_attachment_is_counted_and_then_removed(fast_settings: Settings) -> None:
    result = sanitize(pf.pdf_with_attachment("evil.txt"), filename="att.pdf", settings=fast_settings)
    assert result.accepted
    check_names = {c.name for c in result.report.validation_report.checks}
    assert "no_attachments" in check_names
    assert all(c.passed for c in result.report.validation_report.checks if c.name == "no_attachments")


def test_empty_pdf_is_rejected(fast_settings: Settings) -> None:
    with pytest.raises(exc.EmptyPdfError):
        sanitize(pf.pdf_empty_pages(), filename="empty.pdf", settings=fast_settings)


def test_corrupted_pdf_is_rejected(fast_settings: Settings) -> None:
    with pytest.raises(exc.CorruptedPdfError):
        sanitize(pf.pdf_corrupted(), filename="corrupt.pdf", settings=fast_settings)


def test_non_pdf_file_is_rejected(fast_settings: Settings) -> None:
    with pytest.raises(exc.NotAPdfError):
        sanitize(pf.not_a_pdf_bytes(), filename="notapdf.txt", settings=fast_settings)


def test_encrypted_pdf_without_password_is_rejected(fast_settings: Settings) -> None:
    with pytest.raises(exc.EncryptedPdfError):
        sanitize(pf.pdf_password_protected("secret"), filename="enc.pdf", settings=fast_settings)


def test_encrypted_pdf_with_correct_password_succeeds(fast_settings: Settings) -> None:
    result = sanitize(
        pf.pdf_password_protected("secret"), filename="enc.pdf", password="secret", settings=fast_settings
    )
    assert result.accepted


def test_encrypted_pdf_with_wrong_password_is_rejected(fast_settings: Settings) -> None:
    with pytest.raises((exc.IncorrectPasswordError, exc.EncryptedPdfError)):
        sanitize(
            pf.pdf_password_protected("secret"),
            filename="enc.pdf",
            password="wrong-password",
            settings=fast_settings,
        )


def test_file_too_large_is_rejected(fast_settings: Settings) -> None:
    tiny_limit_settings = fast_settings.model_copy(update={"max_input_bytes": 100})
    with pytest.raises(exc.FileTooLargeError):
        sanitize(pf.pdf_multi_page(3), filename="big.pdf", settings=tiny_limit_settings)


def test_too_many_pages_is_rejected(fast_settings: Settings) -> None:
    tiny_page_limit = fast_settings.model_copy(update={"max_pages": 2})
    with pytest.raises(exc.TooManyPagesError):
        sanitize(pf.pdf_multi_page(5), filename="manypages.pdf", settings=tiny_page_limit)


def test_extremely_large_page_is_rejected(fast_settings: Settings) -> None:
    with pytest.raises(exc.PageTooLargeError):
        sanitize(pf.pdf_with_huge_page(), filename="hugepage.pdf", settings=fast_settings)


def test_unusual_but_valid_content_is_handled(fast_settings: Settings) -> None:
    result = sanitize(pf.pdf_with_unusual_content(), filename="unusual.pdf", settings=fast_settings)
    assert result.accepted
    assert result.report.sanitized_page_count == 1


def test_malformed_object_never_crashes_uncaught(fast_settings: Settings) -> None:
    """A mildly-corrupted stream length must be handled gracefully: either
    qpdf's repair logic recovers it (accepted, or a normal rejection) or we
    raise one of our own documented exceptions -- never an unhandled one.
    """
    try:
        result = sanitize(pf.pdf_with_malformed_object(), filename="malformed.pdf", settings=fast_settings)
        assert result.report is not None
    except exc.PdfSanitizerError:
        pass  # also an acceptable, documented outcome


def test_dpi_override_is_clamped_to_configured_maximum(fast_settings: Settings) -> None:
    result = sanitize(
        pf.pdf_normal(1),
        filename="dpi.pdf",
        settings=fast_settings,
        dpi_override=fast_settings.max_render_dpi + 500,
    )
    assert result.accepted
    assert result.report.render_dpi == fast_settings.max_render_dpi
    assert any("clamped" in warning for warning in result.report.warnings)


def test_removed_features_list_is_always_present(fast_settings: Settings) -> None:
    result = sanitize(pf.pdf_normal(1), filename="normal.pdf", settings=fast_settings)
    assert result.accepted
    assert len(result.report.removed_features) > 0


# --------------------------------------------------------------------------- #
# Output image format (PNG / JPEG) wiring -- item 1 of the project brief
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("image_format", ["png", "jpeg"])
def test_output_image_format_produces_valid_pdf(fast_settings: Settings, image_format: str) -> None:
    settings = fast_settings.model_copy(update={"output_image_format": image_format})
    result = sanitize(pf.pdf_normal(2), filename="normal.pdf", settings=settings)
    assert result.accepted, result.report.validation_report.rejection_reason
    assert result.report.validation_report.passed
    assert result.report.sanitized_page_count == 2


@pytest.mark.parametrize("quality", [1, 50, 90, 100])
def test_jpeg_quality_across_the_full_range_is_accepted(fast_settings: Settings, quality: int) -> None:
    settings = fast_settings.model_copy(update={"output_image_format": "jpeg", "jpeg_quality": quality})
    result = sanitize(pf.pdf_normal(1), filename="normal.pdf", settings=settings)
    assert result.accepted, result.report.validation_report.rejection_reason


def test_png_default_dpi_metadata_is_preserved_in_output(fast_settings: Settings) -> None:
    """Sanity check that page geometry survives reconstruction regardless
    of format -- a corrupted/rescaled page would fail this by producing
    an unexpected page size, not just an unreadable file.
    """
    import pikepdf

    result = sanitize(pf.pdf_normal(1), filename="normal.pdf", settings=fast_settings)
    assert result.accepted
    with pikepdf.open(__import__("io").BytesIO(result.sanitized_pdf_bytes)) as pdf:
        width, height = pdf.pages[0].mediabox[2], pdf.pages[0].mediabox[3]
        # The original fixture page is 200x200pt (see pdf_factory._new_pdf_with_pages);
        # allow a small rounding tolerance from the DPI round-trip.
        assert abs(float(width) - 200.0) < 1.0
        assert abs(float(height) - 200.0) < 1.0


# --------------------------------------------------------------------------- #
# Output-too-large: rejected, discarded, never partially written -- item 9
# --------------------------------------------------------------------------- #


def test_output_too_large_is_rejected_with_no_partial_bytes(fast_settings: Settings) -> None:
    tiny_output_limit = fast_settings.model_copy(update={"max_output_bytes": 10})
    result = sanitize(pf.pdf_normal(1), filename="normal.pdf", settings=tiny_output_limit)
    assert not result.accepted
    assert result.sanitized_pdf_bytes is None
    assert result.report.validation_report.rejection_code == "output_too_large"
    assert "exceeding the configured limit" in result.report.validation_report.rejection_reason
