"""Orchestrates the full sanitization pipeline.

::

    original bytes
        -> cheap pre-checks (magic bytes, upload size) [parent process]
        -> pikepdf open + classification (corrupted / encrypted / page count)
        -> inspection of the ORIGINAL file (best-effort report only)
        -> render every page with PDFium                    (renderer.py)
        -> reconstruct a brand-new PDF from the images       (img2pdf)
        -> validate the new PDF -- the actual security gate  (validator.py)
        -> accept (return sanitized bytes + report) or reject (report only)

Everything from "pikepdf open" onward runs inside an isolated,
time-and-memory-bounded subprocess via :func:`pdf_sanitizer.security.run_isolated`.
See that module's docstring for exactly what this isolation does and does
not guarantee, and the README's "Limitations" section for the full
picture (container-level isolation is the primary boundary; this is a
secondary, defense-in-depth layer that also protects non-containerized
use of the Python API).

``sanitize()`` raises a :class:`~pdf_sanitizer.exceptions.PdfSanitizerError`
subclass for input-level problems (not a PDF, too large, too many pages,
encrypted without a password, corrupted, timeout, out of memory, worker
crash). It does **not** raise when processing completes but the
reconstructed PDF fails validation -- that is a normal, reportable
outcome: the returned :class:`SanitizeResult` has ``accepted=False`` and
``sanitized_pdf_bytes=None``, with the full reason in
``report.validation_report.rejection_reason``. The caller (the CLI) decides
how to surface that.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import img2pdf

from pdf_sanitizer import exceptions as exc
from pdf_sanitizer import inspector, security, validator
from pdf_sanitizer.config import Settings
from pdf_sanitizer.logging_utils import get_logger, log_event, new_job_id
from pdf_sanitizer.models import SanitizationReport, StructuralScanResult, ValidationReport
from pdf_sanitizer.renderer import PdfRenderer
from pdf_sanitizer.sizes import format_size

logger = get_logger("sanitizer")

#: Human-readable summary of what reconstruction removes, regardless of
#: whether any given feature was actually present in a specific input.
#: Reported to the caller so the report is honest even when the structural
#: scan of the *original* file did not happen to flag every category.
REMOVED_FEATURES: list[str] = [
    "JavaScript (document-level and per-action)",
    "OpenAction (document-open action)",
    "Additional Actions (/AA) on the catalog, pages, form fields and annotations",
    "Hyperlinks / URI actions",
    "Launch actions",
    "Remote go-to (/GoToR) and embedded go-to (/GoToE) actions",
    "Form submission (/SubmitForm) actions",
    "Interactive form fields (AcroForm) and XFA forms",
    "Embedded files / attachments",
    "RichMedia, 3D, Movie and Sound annotations",
    "All other original object structure not needed to display the page "
    "(outlines, metadata, names dictionaries, non-visual objects)",
]

_MIN_DPI = 36


def _image_extension(settings: Settings) -> str:
    return "jpg" if settings.output_image_format == "jpeg" else "png"


def _save_rendered_page(image, image_path, settings: Settings) -> None:  # noqa: ANN001 - PIL.Image, Path
    """Save one rendered page to disk in the configured format.

    JPEG has no alpha channel and rejects palette ("P") images -- convert
    defensively even though :class:`~pdf_sanitizer.renderer.PdfRenderer`
    already hands back an RGB image today, so a future renderer change
    can never silently corrupt JPEG output (see project brief "O JPEG
    deve ser convertido corretamente para RGB/RGBA quando necessário").
    PNG has no such restriction and is saved as-is.
    """
    dpi = (settings.render_dpi, settings.render_dpi)
    if settings.output_image_format == "jpeg":
        to_save = image if image.mode in ("RGB", "L") else image.convert("RGB")
        to_save.save(image_path, format="JPEG", quality=settings.jpeg_quality, dpi=dpi, optimize=True)
    else:
        image.save(image_path, format="PNG", dpi=dpi)


@dataclass(frozen=True)
class SanitizeResult:
    accepted: bool
    sanitized_pdf_bytes: bytes | None
    report: SanitizationReport


def _run_pipeline_in_worker(
    pdf_bytes: bytes,
    filename: str | None,
    password: str | None,
    options: dict,
) -> dict:
    """Executed **inside** the isolated subprocess (see security.run_isolated).

    Must return a plain, picklable dict. Any :class:`PdfSanitizerError`
    raised here is caught by ``security._child_entrypoint`` and re-raised,
    with the same type, in the parent process.
    """
    started = time.monotonic()
    settings = Settings(**options)

    security.assert_looks_like_pdf(pdf_bytes)
    if len(pdf_bytes) > settings.max_input_bytes:
        raise exc.FileTooLargeError(
            f"{len(pdf_bytes)} bytes exceeds limit of {settings.max_input_bytes}.",
            user_message=(
                f"Input PDF is {format_size(len(pdf_bytes))}, exceeding the configured "
                f"limit of {format_size(settings.max_input_bytes)}."
            ),
        )

    with security.isolated_temp_dir(settings.temp_dir) as work_dir:
        inspection = inspector.inspect(
            pdf_bytes,
            filename=filename,
            password=password,
            domain_report_max_entries=settings.domain_report_max_entries,
            domain_report_max_raw_value_len=settings.domain_report_max_raw_value_len,
        )

        if not inspection.page_count:
            raise exc.EmptyPdfError("Document has zero pages.")
        if inspection.page_count > settings.max_pages:
            raise exc.TooManyPagesError(
                f"Document has {inspection.page_count} pages; configured limit is {settings.max_pages}."
            )
        if inspection.is_encrypted and not password:
            raise exc.EncryptedPdfError(
                "Document is encrypted. Refusing to process without an explicitly supplied password."
            )

        renderer = PdfRenderer(dpi=settings.render_dpi, max_page_dimension_pt=settings.max_page_dimension_pt)

        image_paths: list[str] = []
        for rendered_page in renderer.render_pages(pdf_bytes, password=password, max_pages=settings.max_pages):
            image_path = work_dir / f"page-{rendered_page.index:06d}.{_image_extension(settings)}"
            try:
                _save_rendered_page(rendered_page.image, image_path, settings)
            except Exception as error:
                raise exc.RenderError(f"Failed to save rendered page {rendered_page.index}: {error}") from error
            image_paths.append(str(image_path))

        rendered_count = len(image_paths)
        if rendered_count == 0:
            raise exc.EmptyPdfError("No pages were rendered.")

        try:
            # nodate/producer/creator: no reason to leak the local wall-clock
            # time or exact library versions into every sanitized output --
            # a small, deliberate metadata-minimization step (see README
            # "Otimização de tamanho"), never touching the security model.
            sanitized_bytes: bytes = img2pdf.convert(
                image_paths, nodate=True, producer="pdf-sanitizer", creator="pdf-sanitizer"
            )
        except Exception as error:
            raise exc.ReconstructionError(f"img2pdf failed to assemble the sanitized PDF: {error}") from error
        if not sanitized_bytes:
            raise exc.ReconstructionError("img2pdf produced empty output.")

        if len(sanitized_bytes) > settings.max_output_bytes:
            validation_report = ValidationReport(
                passed=False,
                checks=[],
                structural_scan=StructuralScanResult(findings=[], objects_visited=0, truncated=False),
                rejection_reason=(
                    f"Sanitized output is {format_size(len(sanitized_bytes))}, exceeding the "
                    f"configured limit of {format_size(settings.max_output_bytes)}."
                ),
                rejection_code="output_too_large",
                output_size_bytes=len(sanitized_bytes),
                output_page_count=rendered_count,
            )
        else:
            validation_report = validator.validate(
                sanitized_bytes,
                expected_page_count=rendered_count,
                max_output_bytes=settings.max_output_bytes,
            )

        elapsed = time.monotonic() - started
        report = SanitizationReport(
            original_filename=filename,
            original_size_bytes=len(pdf_bytes),
            original_page_count=inspection.page_count,
            sanitized_size_bytes=len(sanitized_bytes) if validation_report.passed else None,
            sanitized_page_count=validation_report.output_page_count,
            render_dpi=settings.render_dpi,
            processing_time_seconds=elapsed,
            removed_features=list(REMOVED_FEATURES),
            warnings=[],
            domain_report=inspection.domain_report,
            validation_report=validation_report,
            accepted=validation_report.passed,
        )

        return {
            "accepted": validation_report.passed,
            "sanitized_pdf_bytes": sanitized_bytes if validation_report.passed else None,
            "report": report,
        }


def sanitize(
    pdf_bytes: bytes,
    *,
    filename: str | None = None,
    password: str | None = None,
    settings: Settings | None = None,
    dpi_override: int | None = None,
) -> SanitizeResult:
    """Public entrypoint used by the CLI.

    Runs cheap pre-checks synchronously in the calling process, then hands
    off to an isolated worker for everything that actually touches PDF
    structure. See the module docstring for what raises vs. what comes
    back as ``accepted=False``.
    """
    settings = settings or Settings()
    job_id = new_job_id()
    safe_name = security.sanitize_display_filename(filename)

    log_event(
        logger, logging.INFO, "upload_received",
        job_id=job_id, filename=safe_name, size_bytes=len(pdf_bytes),
    )

    security.assert_looks_like_pdf(pdf_bytes)
    if len(pdf_bytes) > settings.max_input_bytes:
        log_event(
            logger, logging.WARNING, "rejected_file_too_large",
            job_id=job_id, size_bytes=len(pdf_bytes), limit=settings.max_input_bytes,
        )
        raise exc.FileTooLargeError(
            f"{len(pdf_bytes)} bytes exceeds limit of {settings.max_input_bytes}.",
            user_message=(
                f"Input PDF is {format_size(len(pdf_bytes))}, exceeding the configured "
                f"limit of {format_size(settings.max_input_bytes)}."
            ),
        )

    effective_settings = settings
    warning_notes: list[str] = []
    if dpi_override is not None:
        clamped = max(_MIN_DPI, min(dpi_override, settings.max_render_dpi))
        if clamped != dpi_override:
            warning_notes.append(
                f"Requested render DPI {dpi_override} was clamped to {clamped} "
                f"(allowed range {_MIN_DPI}-{settings.max_render_dpi})."
            )
        effective_settings = settings.model_copy(update={"render_dpi": clamped})

    log_event(logger, logging.INFO, "processing_started", job_id=job_id, render_dpi=effective_settings.render_dpi)

    options = effective_settings.model_dump(mode="json")
    try:
        result = security.run_isolated(
            _run_pipeline_in_worker,
            args=(pdf_bytes, safe_name, password, options),
            timeout_seconds=effective_settings.processing_timeout_seconds,
            max_memory_bytes=security.worker_rlimit_bytes(effective_settings.max_memory_bytes),
        )
    except exc.PdfSanitizerError as error:
        log_event(
            logger, logging.WARNING, "processing_failed",
            job_id=job_id, code=error.code, reason=error.message,
        )
        raise

    report: SanitizationReport = result["report"]
    if warning_notes:
        report = report.model_copy(update={"warnings": [*report.warnings, *warning_notes]})

    log_event(
        logger, logging.INFO, "processing_completed",
        job_id=job_id,
        accepted=report.accepted,
        original_pages=report.original_page_count,
        sanitized_pages=report.sanitized_page_count,
        processing_time_seconds=report.processing_time_seconds,
        domain_findings=report.domain_report.total_findings,
    )
    if not report.accepted:
        log_event(
            logger, logging.WARNING, "validation_rejected",
            job_id=job_id, reason=report.validation_report.rejection_reason,
        )

    return SanitizeResult(
        accepted=report.accepted,
        sanitized_pdf_bytes=result["sanitized_pdf_bytes"],
        report=report,
    )
