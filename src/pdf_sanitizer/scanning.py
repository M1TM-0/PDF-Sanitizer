"""Structure-aware scanning of a pikepdf object graph.

This module is deliberately *not* a text/byte-level regex scan of the raw
PDF file. Regexing raw PDF bytes for tokens like ``/JavaScript`` produces
both false positives (the token appears inside a compressed stream, a
comment, or unrelated binary data and is never actually interpreted as a
key) and false negatives (compressed object streams, PDF 1.5+ hide most of
the object graph from a naive byte scan entirely).

Instead we let ``pikepdf``/``qpdf`` do the real parsing (decompression,
cross-reference resolution, encoding) and then walk the resulting object
graph, checking:

1. **Key presence** -- e.g. a dictionary that has a ``/JavaScript`` key.
2. **Type/Subtype/Action-type values** -- some dangerous features are not
   expressed as a distinctively-named key but as the *value* of ``/Type``,
   ``/Subtype`` or ``/S`` (e.g. an embedded-file stream is a dictionary
   with ``/Type /EmbeddedFile``; a URI action is a dictionary with
   ``/S /URI``).

Two passes are made over every PDF that is scanned:

* A **reachability walk** starting at the document catalog (``/Root``),
  which is what a well-behaved viewer would traverse.
* A **linear scan** of every indirect object in the file (``pdf.objects``),
  which also catches objects that exist in the file but are not reachable
  from the catalog. Some malicious PDFs deliberately hide payloads this
  way, hoping a viewer's repair/recovery logic resurrects them while a
  naive "walk from the root" scanner misses them.

Both the inspector (reports on the *original*, untrusted PDF) and the
validator (gates release of the *reconstructed* PDF) use
:func:`scan_object_graph`. Domain/URL extraction (:func:`find_domain_findings`)
is only meaningful on the original PDF and is used by the inspector alone.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

import pikepdf

from pdf_sanitizer.models import DangerousObjectFinding, DomainFinding, DomainSourceType, StructuralScanResult

# --------------------------------------------------------------------------- #
# Dangerous-object vocabulary
#
# Mapped explicitly to the tokens requested in the project specification, and
# to *where in the PDF object model* each token actually appears (key name
# vs. a Type/Subtype/Action-subtype value) per ISO 32000-1/2.
# --------------------------------------------------------------------------- #

#: Dangerous simply because the *key* is present in a dictionary.
DANGEROUS_KEYS = frozenset(
    {
        "/JavaScript",  # catalog /Names /JavaScript name tree
        "/JS",  # a JavaScript action's script
        "/OpenAction",  # document-open action
        "/AA",  # additional-actions dictionary (catalog, page, field, annot)
        "/URI",  # both the /URI action's key and /Root/URI (base URI) entry
        "/Launch",  # sometimes used directly as a key in malformed/legacy files
        "/SubmitForm",
        "/GoToR",
        "/EmbeddedFiles",  # catalog /Names /EmbeddedFiles name tree
        "/XFA",  # AcroForm XFA forms
    }
)

#: Dangerous because the *value* of /Type identifies the object as one of these.
DANGEROUS_TYPE_VALUES = frozenset({"/Filespec", "/EmbeddedFile"})

#: Dangerous because the *value* of /Subtype identifies an annotation/object as one of these.
DANGEROUS_SUBTYPE_VALUES = frozenset({"/RichMedia", "/Movie", "/Sound", "/3D", "/FileAttachment"})

#: Dangerous because the *value* of /S (action subtype) identifies an action as one of these.
DANGEROUS_ACTION_SUBTYPES = frozenset(
    {"/JavaScript", "/Launch", "/SubmitForm", "/GoToR", "/URI", "/ImportData", "/GoToE"}
)

MAX_SCAN_OBJECTS = 200_000
MAX_SCAN_DEPTH = 64

_URL_RE = re.compile(r"""(?ix) \b (?: https?://|www\.) [^\s<>"'\)\]]+ """)


def _objgen_str(obj: Any) -> str:
    try:
        g = obj.objgen
        return f"{g[0]} {g[1]} R"
    except Exception:
        return "unknown"


def _safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return "<unreadable>"


def extract_hostname(raw: str) -> str | None:
    """Best-effort hostname extraction. Returns ``None`` if ``raw`` does not
    look like a URL at all -- callers decide what to do with plain strings.
    """
    raw = raw.strip()
    if not raw:
        return None
    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def truncate_text(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: max(0, limit - 3)] + "..."


def find_urls_in_text(text: str) -> list[str]:
    """Regex-based URL discovery in already-extracted, plain text.

    This is applied to text obtained through a real text-extraction API
    (pypdfium2's text page, see ``inspector.py``) -- never to raw PDF
    bytes -- so it does not suffer the false-positive/false-negative
    problems of scanning a whole binary file with a text regex.
    """
    return [m.group(0) for m in _URL_RE.finditer(text)]


def read_text_value(obj: Any) -> str:
    """Best-effort text decoding of a pikepdf String or Stream object. Never raises."""
    try:
        if isinstance(obj, pikepdf.Stream):
            data = obj.read_bytes()
            for enc in ("utf-16", "utf-8", "latin-1"):
                try:
                    return data.decode(enc)
                except (UnicodeDecodeError, LookupError):
                    continue
            return data.decode("latin-1", errors="replace")
        return str(obj)
    except Exception:
        return ""


def _iter_name_tree(tree: Any) -> Iterable[tuple[str, Any]]:
    try:
        yield from tree.items()
        return
    except AttributeError:
        pass
    except Exception:
        return
    try:
        for key in tree.keys():
            try:
                yield key, tree[key]
            except Exception:
                continue
    except Exception:
        return


# --------------------------------------------------------------------------- #
# Dangerous-object structural scan
# --------------------------------------------------------------------------- #


def scan_object_graph(
    pdf: "pikepdf.Pdf",
    *,
    max_objects: int = MAX_SCAN_OBJECTS,
    max_depth: int = MAX_SCAN_DEPTH,
) -> StructuralScanResult:
    """Walk ``pdf``'s object graph looking for dangerous keys/types.

    Bounded by ``max_objects`` and ``max_depth`` so that an adversarial,
    deeply-nested or cyclic object graph cannot make this scan run
    unboundedly -- the caller (``sanitizer.py``) also runs the whole
    pipeline under a wall-clock timeout via ``security.run_isolated``,
    this is a second, independent bound.
    """
    findings: list[DangerousObjectFinding] = []
    visited: set[tuple[int, int]] = set()
    state = {"visited_count": 0, "truncated": False}

    def visit(node: Any, depth: int) -> None:
        if state["truncated"] or depth > max_depth:
            return
        try:
            is_container = isinstance(node, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array))
        except Exception:
            is_container = False
        if not is_container:
            return

        try:
            if node.is_indirect:
                key = node.objgen
                if key in visited:
                    return
                visited.add(key)
        except Exception:
            pass

        state["visited_count"] += 1
        if state["visited_count"] > max_objects:
            state["truncated"] = True
            return

        if isinstance(node, pikepdf.Array):
            for item in node:
                visit(item, depth + 1)
            return

        try:
            keys = [str(k) for k in node.keys()]
        except Exception:
            keys = []

        for key in keys:
            if key in DANGEROUS_KEYS:
                findings.append(
                    DangerousObjectFinding(
                        category=key.lstrip("/"),
                        matched_token=key,
                        object_ref=_objgen_str(node),
                        context=f"dictionary key {key} present",
                    )
                )

        for special_key, dangerous_values, label in (
            ("/Type", DANGEROUS_TYPE_VALUES, "Type"),
            ("/Subtype", DANGEROUS_SUBTYPE_VALUES, "Subtype"),
            ("/S", DANGEROUS_ACTION_SUBTYPES, "ActionSubtype"),
        ):
            try:
                present = special_key in node
            except Exception:
                present = False
            if not present:
                continue
            try:
                value = _safe_str(node[special_key])
            except Exception:
                continue
            if value in dangerous_values:
                findings.append(
                    DangerousObjectFinding(
                        category=label,
                        matched_token=value,
                        object_ref=_objgen_str(node),
                        context=f"{special_key} == {value}",
                    )
                )

        for key in keys:
            try:
                child = node[key]
            except Exception:
                continue
            visit(child, depth + 1)

    try:
        visit(pdf.Root, 0)
    except Exception:
        pass

    try:
        for obj in pdf.objects:
            if state["truncated"]:
                break
            visit(obj, 0)
    except Exception:
        pass

    return StructuralScanResult(
        findings=findings,
        objects_visited=state["visited_count"],
        truncated=state["truncated"],
    )


# --------------------------------------------------------------------------- #
# Domain / URL extraction (reporting only -- see module docstring)
# --------------------------------------------------------------------------- #


def find_domain_findings(
    pdf: "pikepdf.Pdf",
    *,
    max_raw_len: int = 300,
    max_findings: int = 5000,
) -> list[DomainFinding]:
    """Best-effort extraction of URL/domain references from actions,
    annotations, and JavaScript in ``pdf``. Text-layer URLs are handled
    separately in ``inspector.py`` (they require the rendering library's
    text extraction, which this module deliberately does not depend on).
    """
    findings: list[DomainFinding] = []
    visited_actions: set[tuple[int, int]] = set()

    def add(source_type: DomainSourceType, raw_value: str, page_index: int | None, object_ref: str | None) -> None:
        if len(findings) >= max_findings:
            return
        raw_value = raw_value.strip()
        if not raw_value:
            return
        looks_like_url = "://" in raw_value or raw_value.lower().startswith("www.")
        findings.append(
            DomainFinding(
                source_type=source_type,
                domain=extract_hostname(raw_value) if looks_like_url else None,
                raw_value=truncate_text(raw_value, max_raw_len),
                page_index=page_index,
                object_ref=object_ref,
            )
        )

    def inspect_action(action: Any, page_index: int | None, depth: int = 0) -> None:
        if action is None or depth > 32 or len(findings) >= max_findings:
            return
        try:
            if action.is_indirect:
                key = action.objgen
                if key in visited_actions:
                    return
                visited_actions.add(key)
        except Exception:
            pass

        try:
            subtype = _safe_str(action.get("/S")) if "/S" in action else ""
        except Exception:
            subtype = ""
        ref = _objgen_str(action)

        try:
            has_uri = "/URI" in action
        except Exception:
            has_uri = False
        if subtype == "/URI" or has_uri:
            try:
                add(
                    DomainSourceType.ANNOTATION_URI if page_index is not None else DomainSourceType.ACTION_URI,
                    read_text_value(action["/URI"]),
                    page_index,
                    ref,
                )
            except Exception:
                pass

        if subtype == "/Launch":
            try:
                target = action.get("/F")
                value = read_text_value(target) if target is not None else "(launch action, no /F target)"
            except Exception:
                value = "(launch action, target unreadable)"
            add(DomainSourceType.LAUNCH_ACTION, value, page_index, ref)

        if subtype in ("/GoToR", "/GoToE"):
            try:
                target = action.get("/F")
                value = read_text_value(target) if target is not None else "(remote go-to action)"
            except Exception:
                value = "(remote go-to action, target unreadable)"
            add(DomainSourceType.GOTOR_ACTION, value, page_index, ref)

        if subtype == "/SubmitForm":
            try:
                target = action.get("/F")
                value = read_text_value(target) if target is not None else "(submit-form action)"
            except Exception:
                value = "(submit-form action, target unreadable)"
            add(DomainSourceType.SUBMIT_FORM, value, page_index, ref)

        try:
            has_js = "/JS" in action
        except Exception:
            has_js = False
        if subtype == "/JavaScript" or has_js:
            try:
                script = read_text_value(action["/JS"])
                for match in _URL_RE.finditer(script):
                    add(DomainSourceType.JAVASCRIPT, match.group(0), page_index, ref)
            except Exception:
                pass

        try:
            nxt = action.get("/Next")
        except Exception:
            nxt = None
        if nxt is not None:
            items: Iterable[Any]
            try:
                items = list(nxt) if isinstance(nxt, pikepdf.Array) else [nxt]
            except Exception:
                items = [nxt]
            for item in items:
                inspect_action(item, page_index, depth + 1)

    # Catalog-level OpenAction + AA
    try:
        if "/OpenAction" in pdf.Root:
            inspect_action(pdf.Root.OpenAction, None)
    except Exception:
        pass
    try:
        if "/AA" in pdf.Root:
            for _, action in _iter_dict(pdf.Root.AA):
                inspect_action(action, None)
    except Exception:
        pass

    # Document-level JavaScript name tree
    try:
        names = pdf.Root.get("/Names")
        if names is not None and "/JavaScript" in names:
            for _, action in _iter_name_tree(pikepdf.NameTree(names.JavaScript)):
                inspect_action(action, None)
    except Exception:
        pass

    # Embedded files (presence only -- not a domain, but a relevant location)
    try:
        for name in pdf.attachments:
            add(DomainSourceType.EMBEDDED_FILE, f"embedded file: {name}", None, None)
    except Exception:
        pass

    # Per-page annotations and page-level /AA
    try:
        for page_index, page in enumerate(pdf.pages):
            try:
                if "/AA" in page.obj:
                    for _, action in _iter_dict(page.obj.AA):
                        inspect_action(action, page_index)
            except Exception:
                pass
            try:
                annots = page.obj.get("/Annots")
            except Exception:
                annots = None
            if not annots:
                continue
            try:
                annot_iter = list(annots)
            except Exception:
                annot_iter = []
            for annot in annot_iter:
                try:
                    if "/A" in annot:
                        inspect_action(annot["/A"], page_index)
                except Exception:
                    pass
    except Exception:
        pass

    return findings


def _iter_dict(dict_obj: Any) -> Iterable[tuple[str, Any]]:
    try:
        for k in dict_obj.keys():
            try:
                yield str(k), dict_obj[k]
            except Exception:
                continue
    except Exception:
        return
