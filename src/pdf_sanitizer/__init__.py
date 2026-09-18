"""pdf_sanitizer: defense-in-depth sanitization of untrusted PDF files.

Strategy: render every page of an untrusted PDF to a raster image using a
hardened PDF renderer (PDFium via pypdfium2), then assemble a brand-new
PDF from those images (img2pdf). Nothing from the original file's object
structure -- JavaScript, actions, forms, links, embedded files,
multimedia -- survives into the output, because the output was never
built from the original's objects in the first place.

This tool reduces risk; it does not make any PDF, or any parser that
touches one, perfectly safe. Read the README ("Limitations" and
"Auditoria final" sections) before relying on it in production.
"""

from __future__ import annotations

__version__ = "0.2.0"

__all__ = ["__version__"]
