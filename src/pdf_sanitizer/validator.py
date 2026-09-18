"""Validate the RECONSTRUCTED (sanitized) PDF before it is ever returned to
a caller.

This is the actual security gate of the whole pipeline. Everything else
(the inspector's report on the original file, the renderer's fidelity)
is best-effort and diagnostic; **this module is what decides whether
output is released**, per the project brief: "Se alguma verificação
crítica falhar, o resultado deve ser rejeitado."

Checks performed, all structure-aware (see ``scanning.py``'s docstring for
why this is not a naive text search):

1. The output re-opens cleanly with pikepdf (structural integrity).
2. The output re-opens and reports a sane page count with pdfium
   (cross-parser agreement / renderability).
3. A full structural scan (``scanning.scan_object_graph``) finds **zero**
   dangerous keys/types/action-subtypes anywhere in the object graph.
4. There are zero attachments (``pdf.attachments``).
5. Every page has non-empty content.
6. The page count matches what the sanitizer intended to produce.
7. The output size is within the configured limit.

If any check in this list fails, ``passed=False`` and the caller
(``sanitizer.py``) must discard the output and raise
:class:`~pdf_sanitizer.exceptions.SanitizedOutputInvalidError` /
:class:`~pdf_sanitizer.exceptions.SanitizedOutputTooLargeError`. No partial
or "best effort" output is ever released.
"""

from __future__ import annotations

import io

import pikepdf
import pypdfium2 as pdfium

from pdf_sanitizer.models import ValidationCheck, ValidationReport
from pdf_sanitizer.scanning import scan_object_graph
from pdf_sanitizer.sizes import format_size


def _check_page_has_content(page: "pikepdf.Page") -> bool:
    try:
        contents = page.obj.get("/Contents")
    except Exception:
        return False
    if contents is None:
        return False
    try:
        if isinstance(contents, pikepdf.Array):
            total = 0
            for stream in contents:
                total += len(stream.read_bytes())
            return total > 0
        return len(contents.read_bytes()) > 0
    except Exception:
        return False


def validate(
    sanitized_bytes: bytes,
    *,
    expected_page_count: int,
    max_output_bytes: int,
) -> ValidationReport:
    checks: list[ValidationCheck] = []
    rejection_reason: str | None = None
    output_page_count: int | None = None

    size_ok = len(sanitized_bytes) <= max_output_bytes
    checks.append(
        ValidationCheck(
            name="output_size_within_limit",
            passed=size_ok,
            detail=f"{format_size(len(sanitized_bytes))} (limit {format_size(max_output_bytes)}).",
        )
    )
    if not size_ok:
        rejection_reason = "Sanitized output exceeds the maximum allowed size."

    # --- pikepdf re-open: structural integrity -------------------------------
    pdf: pikepdf.Pdf | None = None
    try:
        pdf = pikepdf.open(io.BytesIO(sanitized_bytes))
        checks.append(ValidationCheck(name="pikepdf_reopen", passed=True, detail="Reopened successfully."))
    except Exception as error:
        checks.append(ValidationCheck(name="pikepdf_reopen", passed=False, detail=f"{type(error).__name__}: {error}"))
        rejection_reason = rejection_reason or "Sanitized output failed to reopen (structural integrity check)."

    structural_scan_result = None
    if pdf is not None:
        try:
            with pdf:
                try:
                    output_page_count = len(pdf.pages)
                except Exception:
                    output_page_count = None
                page_count_ok = output_page_count == expected_page_count
                checks.append(
                    ValidationCheck(
                        name="page_count_matches_expected",
                        passed=page_count_ok,
                        detail=f"expected={expected_page_count}, actual={output_page_count}.",
                    )
                )
                if not page_count_ok:
                    rejection_reason = rejection_reason or "Sanitized page count does not match the expected count."

                try:
                    pages_with_content = [
                        i for i, page in enumerate(pdf.pages) if _check_page_has_content(page)
                    ]
                    all_pages_have_content = len(pages_with_content) == (output_page_count or 0)
                except Exception:
                    all_pages_have_content = False
                checks.append(
                    ValidationCheck(
                        name="all_pages_have_content",
                        passed=all_pages_have_content,
                        detail="Every page has a non-empty content stream."
                        if all_pages_have_content
                        else "At least one page has an empty or unreadable content stream.",
                    )
                )
                if not all_pages_have_content:
                    rejection_reason = rejection_reason or "At least one sanitized page has no content."

                try:
                    attachment_count = len(pdf.attachments)
                except Exception:
                    attachment_count = -1
                no_attachments = attachment_count == 0
                checks.append(
                    ValidationCheck(
                        name="no_attachments",
                        passed=no_attachments,
                        detail=f"attachments={attachment_count}.",
                    )
                )
                if not no_attachments:
                    rejection_reason = rejection_reason or "Sanitized output unexpectedly contains attachments."

                structural_scan_result = scan_object_graph(pdf)
                clean = structural_scan_result.is_clean
                checks.append(
                    ValidationCheck(
                        name="no_dangerous_objects",
                        passed=clean,
                        detail="No dangerous keys/types/action-subtypes found."
                        if clean
                        else f"{len(structural_scan_result.findings)} dangerous object(s) found: "
                        + ", ".join(sorted({f.matched_token or f.category for f in structural_scan_result.findings}))[:500],
                    )
                )
                if not clean:
                    rejection_reason = rejection_reason or "Sanitized output still contains active/interactive objects."
        except Exception as error:
            checks.append(
                ValidationCheck(
                    name="post_open_inspection",
                    passed=False,
                    detail=f"{type(error).__name__}: {error}",
                )
            )
            rejection_reason = rejection_reason or "Sanitized output could not be fully inspected after reopening."

    if structural_scan_result is None:
        from pdf_sanitizer.models import StructuralScanResult

        structural_scan_result = StructuralScanResult(findings=[], objects_visited=0, truncated=False)

    # --- pdfium re-open: cross-parser agreement / renderability --------------
    pdfium_ok = False
    pdfium_detail = ""
    try:
        document = pdfium.PdfDocument(sanitized_bytes)
        try:
            n = len(document)
            sizes_ok = True
            for i in range(n):
                page = document[i]
                try:
                    w, h = page.get_size()
                    if w <= 0 or h <= 0:
                        sizes_ok = False
                finally:
                    page.close()
            pdfium_ok = n == expected_page_count and sizes_ok
            pdfium_detail = f"pdfium reports {n} page(s), all with positive dimensions: {sizes_ok}."
        finally:
            document.close()
    except Exception as error:
        pdfium_detail = f"{type(error).__name__}: {error}"
    checks.append(ValidationCheck(name="pdfium_reopen_and_size_check", passed=pdfium_ok, detail=pdfium_detail))
    if not pdfium_ok:
        rejection_reason = rejection_reason or "Sanitized output failed the independent pdfium re-open check."

    passed = all(check.passed for check in checks)
    return ValidationReport(
        passed=passed,
        checks=checks,
        structural_scan=structural_scan_result,
        rejection_reason=None if passed else rejection_reason,
        rejection_code=None if passed else "sanitized_output_invalid",
        output_size_bytes=len(sanitized_bytes),
        output_page_count=output_page_count,
    )
