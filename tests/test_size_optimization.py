"""Real, end-to-end size comparisons across output image format, JPEG
quality, and DPI -- project brief item 17.1.

Uses :func:`tests.pdf_factory.pdf_with_photo_like_page` (dense per-pixel
noise, not flat vector art) so the comparison is meaningful: a plain
vector rectangle compresses so well under *both* PNG and JPEG that it
would not demonstrate anything about JPEG's actual advantage for
photographic/scanned content. These are size-ordering assertions
(A should be smaller than B), not exact byte-count pins, since exact
encoder output can legitimately shift a few bytes across Pillow/libjpeg
versions -- what must hold is the *shape* of the size relationship.
"""

from __future__ import annotations

from pdf_sanitizer.config import Settings
from pdf_sanitizer.sanitizer import sanitize
from tests import pdf_factory as pf


def _sanitized_size(settings: Settings) -> int:
    result = sanitize(pf.pdf_with_photo_like_page(), filename="photo.pdf", settings=settings)
    assert result.accepted, result.report.validation_report.rejection_reason
    assert result.sanitized_pdf_bytes is not None
    return len(result.sanitized_pdf_bytes)


def test_jpeg_is_smaller_than_png_for_photographic_content(fast_settings: Settings) -> None:
    png_settings = fast_settings.model_copy(update={"output_image_format": "png", "render_dpi": 150})
    jpeg_settings = fast_settings.model_copy(
        update={"output_image_format": "jpeg", "jpeg_quality": 90, "render_dpi": 150}
    )
    png_size = _sanitized_size(png_settings)
    jpeg_size = _sanitized_size(jpeg_settings)
    assert jpeg_size < png_size, f"expected JPEG ({jpeg_size}B) < PNG ({png_size}B) for photo-like content"


def test_lower_jpeg_quality_is_smaller(fast_settings: Settings) -> None:
    settings_q90 = fast_settings.model_copy(update={"output_image_format": "jpeg", "jpeg_quality": 90, "render_dpi": 150})
    settings_q80 = fast_settings.model_copy(update={"output_image_format": "jpeg", "jpeg_quality": 80, "render_dpi": 150})
    size_q90 = _sanitized_size(settings_q90)
    size_q80 = _sanitized_size(settings_q80)
    assert size_q80 < size_q90, f"expected quality=80 ({size_q80}B) < quality=90 ({size_q90}B)"


def test_lower_dpi_is_smaller_at_fixed_jpeg_quality(fast_settings: Settings) -> None:
    settings_150 = fast_settings.model_copy(update={"output_image_format": "jpeg", "jpeg_quality": 90, "render_dpi": 150})
    settings_120 = fast_settings.model_copy(update={"output_image_format": "jpeg", "jpeg_quality": 90, "render_dpi": 120})
    size_150 = _sanitized_size(settings_150)
    size_120 = _sanitized_size(settings_120)
    assert size_120 < size_150, f"expected dpi=120 ({size_120}B) < dpi=150 ({size_150}B)"


def test_full_recommended_matrix_orders_correctly(fast_settings: Settings) -> None:
    """PNG@150 vs JPEG90@150 vs JPEG80@150 vs JPEG90@120, all in one test,
    matching the four configurations item 17.1 explicitly asks to compare.
    """
    sizes = {
        "png_150": _sanitized_size(fast_settings.model_copy(update={"output_image_format": "png", "render_dpi": 150})),
        "jpeg90_150": _sanitized_size(
            fast_settings.model_copy(update={"output_image_format": "jpeg", "jpeg_quality": 90, "render_dpi": 150})
        ),
        "jpeg80_150": _sanitized_size(
            fast_settings.model_copy(update={"output_image_format": "jpeg", "jpeg_quality": 80, "render_dpi": 150})
        ),
        "jpeg90_120": _sanitized_size(
            fast_settings.model_copy(update={"output_image_format": "jpeg", "jpeg_quality": 90, "render_dpi": 120})
        ),
    }
    assert sizes["jpeg90_150"] < sizes["png_150"]
    assert sizes["jpeg80_150"] < sizes["jpeg90_150"]
    assert sizes["jpeg90_120"] < sizes["jpeg90_150"]
