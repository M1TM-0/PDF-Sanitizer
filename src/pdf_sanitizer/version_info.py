"""Shared version-reporting helper.

Kept as a small, dependency-light module (no coupling to ``cli.py`` beyond
what it needs) so ``pdf-sanitizer version`` stays cheap and side-effect
free.
"""

from __future__ import annotations

import platform
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version

from pdf_sanitizer import __version__
from pdf_sanitizer.models import VersionInfo

#: Distribution names as they appear on PyPI, used for importlib.metadata lookup.
TRACKED_LIBRARIES: list[str] = [
    "pikepdf",
    "pypdfium2",
    "img2pdf",
    "pillow",
    "pydantic",
    "pydantic-settings",
    "typer",
]


def collect_version_info() -> VersionInfo:
    libraries: dict[str, str] = {}
    for name in TRACKED_LIBRARIES:
        try:
            libraries[name] = pkg_version(name)
        except PackageNotFoundError:
            libraries[name] = "not installed"
    return VersionInfo(
        pdf_sanitizer_version=__version__,
        python_version=platform.python_version(),
        library_versions=libraries,
    )
