"""Read-only inspection of the ORIGINAL, untrusted PDF.

Produces an :class:`~pdf_sanitizer.models.InspectionReport`: encryption
status, page count, a structure-aware scan for dangerous objects, and a
best-effort domain/URL report combining structural findings (actions,
annotations, JavaScript, embedded files -- via ``scanning.py``/pikepdf)
with text-layer URLs (via pypdfium2's text extraction).

This module is purely diagnostic. It never decides whether the
*sanitized* output is safe to release -- that is ``validator.py``'s job,
applied to the reconstructed PDF, independent of anything computed here.
Per the project brief: finding every domain in the original file is not,
and is not treated as, a safety guarantee. Removal happens unconditionally
during reconstruction regardless of what this report contains.
"""

from __future__ import annotations

import io

import pikepdf
import pypdfium2 as pdfium

from pdf_sanitizer import exceptions as exc
from pdf_sanitizer import security
from pdf_sanitizer.config import Settings
from pdf_sanitizer.models import (
    DomainFinding,
    DomainReport,
    DomainSourceType,
    InspectionReport,
)
from pdf_sanitizer.scanning import (
    extract_hostname,
    find_domain_findings,
    find_urls_in_text,
    scan_object_graph,
    truncate_text,
)
from pdf_sanitizer.sizes import format_size


def _classify_pikepdf_open_error(error: Exception, *, password_supplied: bool) -> exc.PdfSanitizerError:
    if isinstance(error, pikepdf.PasswordError):
        if password_supplied:
            return exc.IncorrectPasswordError(f"pikepdf rejected the supplied password: {error}")
        return exc.EncryptedPdfError(f"Document requires a password: {error}")
    return exc.CorruptedPdfError(f"pikepdf could not open the document: {error}")


def open_pikepdf(pdf_bytes: bytes, *, password: str | None) -> pikepdf.Pdf:
    """Open ``pdf_bytes`` with pikepdf, translating its exceptions into our
    own taxonomy. This is the primary classifier used across the package
    for "is this a valid, decryptable PDF" -- see security.py/renderer.py
    module docstrings for why pikepdf (not pdfium) plays this role.
    """
    try:
        # pikepdf.open() accepts a path or a seekable file-like object, not
        # raw bytes directly, so wrap in BytesIO.
        return pikepdf.open(io.BytesIO(pdf_bytes), password=password or "")
    except pikepdf.PasswordError as error:
        raise _classify_pikepdf_open_error(error, password_supplied=bool(password)) from error
    except pikepdf.PdfError as error:
        raise _classify_pikepdf_open_error(error, password_supplied=bool(password)) from error
    except Exception as error:  # pragma: no cover - defensive catch-all
        raise exc.CorruptedPdfError(f"Unexpected error opening document: {error}") from error


def _extract_text_domains(
    pdf_bytes: bytes,
    *,
    password: str | None,
    page_limit: int,
    max_findings: int,
    max_raw_len: int,
) -> list[DomainFinding]:
    """Best-effort: any failure here degrades to an empty list rather than
    failing the whole inspection -- text extraction is a reporting nicety,
    not a safety mechanism (see module docstring).
    """
    findings: list[DomainFinding] = []
    try:
        document = pdfium.PdfDocument(pdf_bytes, password=password or None)
    except Exception:
        return findings
    try:
        page_count = min(len(document), page_limit)
        for index in range(page_count):
            if len(findings) >= max_findings:
                break
            try:
                page = document[index]
            except Exception:
                continue
            try:
                text = page.get_textpage().get_text_range()
            except Exception:
                text = ""
            finally:
                try:
                    page.close()
                except Exception:
                    pass
            for url in find_urls_in_text(text):
                if len(findings) >= max_findings:
                    break
                findings.append(
                    DomainFinding(
                        source_type=DomainSourceType.TEXT,
                        domain=extract_hostname(url),
                        raw_value=truncate_text(url, max_raw_len),
                        page_index=index,
                        object_ref=None,
                    )
                )
    except Exception:
        return findings
    finally:
        try:
            document.close()
        except Exception:
            pass
    return findings


def build_domain_report(
    pdf: pikepdf.Pdf,
    pdf_bytes: bytes,
    *,
    password: str | None,
    max_entries: int,
    max_raw_len: int,
) -> DomainReport:
    structural = find_domain_findings(pdf, max_raw_len=max_raw_len, max_findings=max_entries)
    remaining = max(0, max_entries - len(structural))
    textual: list[DomainFinding] = []
    if remaining > 0:
        try:
            page_limit = len(pdf.pages)
        except Exception:
            page_limit = 0
        textual = _extract_text_domains(
            pdf_bytes,
            password=password,
            page_limit=page_limit,
            max_findings=remaining,
            max_raw_len=max_raw_len,
        )

    all_findings = structural + textual
    truncated = len(all_findings) >= max_entries
    all_findings = all_findings[:max_entries]

    unique_domains = sorted({f.domain for f in all_findings if f.domain})
    return DomainReport(findings=all_findings, unique_domains=unique_domains, truncated=truncated)


def inspect(
    pdf_bytes: bytes,
    *,
    filename: str | None,
    password: str | None,
    domain_report_max_entries: int,
    domain_report_max_raw_value_len: int,
) -> InspectionReport:
    """Full read-only inspection of an untrusted PDF. Raises
    :class:`~pdf_sanitizer.exceptions.PdfSanitizerError` subclasses on
    fundamentally invalid input (not a PDF, corrupted, encrypted without a
    usable password); otherwise always returns a complete report.
    """
    with open_pikepdf(pdf_bytes, password=password) as pdf:
        try:
            page_count = len(pdf.pages)
        except Exception:
            page_count = None

        structural_scan = scan_object_graph(pdf)
        domain_report = build_domain_report(
            pdf,
            pdf_bytes,
            password=password,
            max_entries=domain_report_max_entries,
            max_raw_len=domain_report_max_raw_value_len,
        )

        # `category` holds the literal key name for key-based findings (e.g.
        # "JavaScript", "OpenAction"); for Type/Subtype/Action-subtype
        # findings the useful value lives in `matched_token` instead (see
        # scanning.scan_object_graph). Union both, slash-stripped, so the
        # summary flags below are correct either way.
        signals = {f.category.lstrip("/") for f in structural_scan.findings}
        signals |= {f.matched_token.lstrip("/") for f in structural_scan.findings}
        try:
            embedded_files_count = len(pdf.attachments)
        except Exception:
            embedded_files_count = 0
        try:
            acroform_present = "/AcroForm" in pdf.Root
        except Exception:
            acroform_present = False
        try:
            pdf_version = str(pdf.pdf_version)
        except Exception:
            pdf_version = None

        notes: list[str] = []
        try:
            if pdf.is_encrypted:
                notes.append(
                    "Document reports itself as encrypted (opened successfully, "
                    "e.g. an empty user password or an explicitly supplied password)."
                )
        except Exception:
            pass

        return InspectionReport(
            filename=filename,
            size_bytes=len(pdf_bytes),
            is_encrypted=bool(getattr(pdf, "is_encrypted", False)),
            page_count=page_count,
            pdf_version=pdf_version,
            structural_scan=structural_scan,
            domain_report=domain_report,
            javascript_present=("JavaScript" in signals or "JS" in signals),
            open_action_present=("OpenAction" in signals),
            additional_actions_present=("AA" in signals),
            embedded_files_count=embedded_files_count,
            acroform_present=acroform_present,
            xfa_present=("XFA" in signals),
            richmedia_or_multimedia_present=bool(
                signals & {"RichMedia", "Movie", "Sound", "3D", "FileAttachment"}
            ),
            notes=notes,
        )


# --------------------------------------------------------------------------- #
# Isolated entrypoint -- standalone inspection (CLI `inspect`, API
# POST /inspect) touches the same untrusted content as sanitization and
# gets the same process isolation, not just the sanitize pipeline.
# --------------------------------------------------------------------------- #


def _inspect_in_worker(pdf_bytes: bytes, filename: str | None, password: str | None, options: dict) -> dict:
    """Executed inside the isolated subprocess -- see security.run_isolated."""
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
    report = inspect(
        pdf_bytes,
        filename=filename,
        password=password,
        domain_report_max_entries=settings.domain_report_max_entries,
        domain_report_max_raw_value_len=settings.domain_report_max_raw_value_len,
    )
    return {"report": report}


def inspect_isolated(
    pdf_bytes: bytes,
    *,
    filename: str | None = None,
    password: str | None = None,
    settings: Settings | None = None,
) -> InspectionReport:
    """Same as :func:`inspect`, but runs inside an isolated, time- and
    memory-bounded subprocess (see ``security.run_isolated``). This is
    what the CLI ``inspect`` command and the API's ``POST /inspect``
    endpoint use -- read-only inspection still means fully parsing an
    untrusted file, which deserves the same isolation as sanitization.
    """
    settings = settings or Settings()
    security.assert_looks_like_pdf(pdf_bytes)
    if len(pdf_bytes) > settings.max_input_bytes:
        raise exc.FileTooLargeError(
            f"{len(pdf_bytes)} bytes exceeds limit of {settings.max_input_bytes}.",
            user_message=(
                f"Input PDF is {format_size(len(pdf_bytes))}, exceeding the configured "
                f"limit of {format_size(settings.max_input_bytes)}."
            ),
        )
    options = settings.model_dump(mode="json")
    result = security.run_isolated(
        _inspect_in_worker,
        args=(pdf_bytes, filename, password, options),
        timeout_seconds=settings.processing_timeout_seconds,
        max_memory_bytes=security.worker_rlimit_bytes(settings.max_memory_bytes),
    )
    return result["report"]
