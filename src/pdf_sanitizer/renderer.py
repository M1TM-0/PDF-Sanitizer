"""Render untrusted PDF pages to raster images via PDFium (pypdfium2).

This is the core of the "look only at pixels" defense: every page is
rendered to a flat bitmap and *everything else* -- interactive objects,
actions, scripts, embedded files, form fields, links, annotations'
underlying object structure -- is discarded once the pixels are captured.
PDFium (via pypdfium2) never evaluates PDF JavaScript; there is no script
engine anywhere in this rendering path.

LIMITATION -- read this before trusting the tool blindly: rendering still
requires *parsing* the untrusted file with a real, fairly complex C++ PDF
parser (PDFium). A memory-safety bug in that parser could in principle be
triggered by a malicious page before sanitization has done anything. This
is precisely why rendering happens inside the isolated, resource-limited
worker process (``security.run_isolated``) and, in production, inside the
network-less, non-root, capability-dropped container described in the
Dockerfile and README. Sanitization reduces what an attacker gains *after*
a successful parse; it does not make the parser itself invulnerable. See
the README section "O que ainda pode dar errado".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

import pypdfium2 as pdfium
from PIL import Image

from pdf_sanitizer import exceptions as exc


@dataclass(frozen=True)
class RenderedPage:
    index: int
    width_pt: float
    height_pt: float
    image: Image.Image


class PdfRenderer:
    """Thin, defensively-coded wrapper around pypdfium2 page rendering."""

    def __init__(self, *, dpi: int, max_page_dimension_pt: float) -> None:
        if dpi <= 0:
            raise ValueError("dpi must be positive")
        self._dpi = dpi
        self._max_page_dimension_pt = max_page_dimension_pt

    def render_pages(
        self,
        pdf_bytes: bytes,
        *,
        password: str | None,
        max_pages: int,
    ) -> Iterator[RenderedPage]:
        """Yield one :class:`RenderedPage` per page, in order.

        Raises subclasses of :class:`~pdf_sanitizer.exceptions.PdfSanitizerError`;
        never lets a raw pypdfium2/PIL exception escape.
        """
        try:
            document = pdfium.PdfDocument(pdf_bytes, password=password)
        except pdfium.PdfiumError as error:
            raise self._classify_open_error(error, password_supplied=bool(password)) from error
        except FileNotFoundError as error:  # pragma: no cover - bytes input, defensive only
            raise exc.CorruptedPdfError(f"pdfium could not load in-memory document: {error}") from error

        try:
            page_count = len(document)
            if page_count == 0:
                raise exc.EmptyPdfError("Document has zero pages.")
            if page_count > max_pages:
                raise exc.TooManyPagesError(
                    f"Document has {page_count} pages; configured limit is {max_pages}."
                )

            scale = self._dpi / 72.0  # PDFium scale is relative to 72 DPI (1 PDF unit = 1/72 in)
            for index in range(page_count):
                yield self._render_one(document, index, scale)
        finally:
            document.close()

    def _render_one(self, document: "pdfium.PdfDocument", index: int, scale: float) -> RenderedPage:
        try:
            page = document[index]
        except pdfium.PdfiumError as error:
            raise exc.RenderError(f"Failed to load page {index}: {error}") from error

        try:
            width_pt, height_pt = page.get_size()
            if width_pt <= 0 or height_pt <= 0:
                raise exc.RenderError(f"Page {index} reported non-positive size ({width_pt}x{height_pt}).")
            if width_pt > self._max_page_dimension_pt or height_pt > self._max_page_dimension_pt:
                raise exc.PageTooLargeError(
                    f"Page {index} is {width_pt:.1f}x{height_pt:.1f}pt; "
                    f"limit is {self._max_page_dimension_pt:.1f}pt per edge."
                )
            try:
                bitmap = page.render(scale=scale)
                pil_image = bitmap.to_pil().convert("RGB")
            except exc.PdfSanitizerError:
                raise
            except Exception as error:
                raise exc.RenderError(f"Failed to render page {index}: {error}") from error
            return RenderedPage(index=index, width_pt=width_pt, height_pt=height_pt, image=pil_image)
        finally:
            page.close()

    @staticmethod
    def _classify_open_error(error: Exception, *, password_supplied: bool) -> exc.PdfSanitizerError:
        # We rely primarily on pikepdf (see inspector.py / sanitizer.py) to
        # classify corrupted-vs-encrypted-vs-needs-password *before* the
        # renderer is ever invoked. If pdfium disagrees with pikepdf at this
        # later stage, that is itself informative (a genuine cross-parser
        # discrepancy) and we surface it as a corruption/render error rather
        # than guessing at pdfium's internal error taxonomy.
        message = str(error).lower()
        if "password" in message:
            if password_supplied:
                return exc.IncorrectPasswordError(f"pdfium rejected the supplied password: {error}")
            return exc.EncryptedPdfError(f"pdfium reports the document requires a password: {error}")
        return exc.CorruptedPdfError(f"pdfium failed to open the document: {error}")
