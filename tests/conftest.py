from __future__ import annotations

from pathlib import Path

import pytest

from pdf_sanitizer.config import Settings


@pytest.fixture(autouse=True)
def _isolated_persisted_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every test at a per-test, guaranteed-nonexistent persisted
    config file.

    Without this, ``Settings()`` (constructed with no explicit kwargs, as
    many CLI/unit tests do) would resolve the persisted-config path to
    ``./.env`` in whatever directory pytest is invoked from -- which, in
    this repository, is a real, committed file (see repo root ``.env``,
    intentionally shipped with the recommended defaults for
    docker-compose's sake). Tests must never read *or write* that file.
    """
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(tmp_path / "unused-test-config.env"))


@pytest.fixture
def fast_settings(tmp_path: Path) -> Settings:
    """Settings tuned for a fast, hermetic test run: small limits, short
    timeouts, and a temp dir scoped to pytest's own tmp_path so nothing
    leaks between tests or into the real system temp directory.
    """
    return Settings(
        max_input_bytes=20 * 1024 * 1024,
        max_pages=50,
        max_page_dimension_pt=14_400.0,
        render_dpi=72,
        max_render_dpi=150,
        max_output_bytes=50 * 1024 * 1024,
        processing_timeout_seconds=20,
        max_memory_bytes=512 * 1024 * 1024,
        domain_report_max_entries=200,
        temp_dir=tmp_path / "pdf_sanitizer_tmp",
        log_level="DEBUG",
        log_json=False,
    )


@pytest.fixture(autouse=True)
def _quiet_logging():
    """Configure logging once so tests don't spam stdout with JSON lines."""
    from pdf_sanitizer.logging_utils import configure_logging

    configure_logging(level="WARNING", json_output=False)
    yield
