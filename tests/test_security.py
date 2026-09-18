"""Unit tests for :mod:`pdf_sanitizer.security`: filesystem safety helpers
and the isolated-subprocess execution model.

The worker functions used with ``run_isolated`` below are defined at
module level (not inside test functions) because the "spawn" start method
needs to pickle a reference to them by import path.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from pdf_sanitizer import exceptions as exc
from pdf_sanitizer import security


def _ok_worker(x: int) -> dict:
    return {"doubled": x * 2}


def _raising_worker() -> dict:
    raise exc.CorruptedPdfError("synthetic failure for test_run_isolated_reraises_typed_exception")


def _sleep_worker(seconds: float) -> dict:
    time.sleep(seconds)
    return {"slept": seconds}


def _crash_worker() -> dict:
    os._exit(1)  # simulate an abrupt crash that bypasses normal exception handling


def _large_result_worker(num_bytes: int) -> dict:
    return {"payload": b"\x00" * num_bytes}


# --------------------------------------------------------------------------- #
# Magic-byte sniffing
# --------------------------------------------------------------------------- #


def test_looks_like_pdf_accepts_valid_header_and_trailer() -> None:
    assert security.looks_like_pdf(b"%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF")


def test_looks_like_pdf_rejects_missing_header() -> None:
    assert not security.looks_like_pdf(b"not a pdf at all, just text\n%%EOF")


def test_looks_like_pdf_rejects_empty_bytes() -> None:
    assert not security.looks_like_pdf(b"")


def test_assert_looks_like_pdf_raises_not_a_pdf_error() -> None:
    with pytest.raises(exc.NotAPdfError):
        security.assert_looks_like_pdf(b"definitely not a pdf")


# --------------------------------------------------------------------------- #
# Filename handling
# --------------------------------------------------------------------------- #


def test_secure_random_filename_has_no_attacker_controlled_content() -> None:
    name = security.secure_random_filename()
    assert name.endswith(".pdf")
    assert "/" not in name and "\\" not in name


@pytest.mark.parametrize(
    "raw_name",
    [
        "../../etc/passwd",
        "/etc/passwd",
        "..\\..\\windows\\system32\\evil.pdf",
        "a" * 500 + ".pdf",
        "",
        None,
    ],
)
def test_sanitize_display_filename_never_contains_path_separators(raw_name) -> None:
    cleaned = security.sanitize_display_filename(raw_name)
    assert "/" not in cleaned
    assert "\\" not in cleaned
    assert len(cleaned) <= 120
    assert cleaned  # never empty


# --------------------------------------------------------------------------- #
# Path traversal
# --------------------------------------------------------------------------- #


def test_assert_within_directory_allows_nested_path(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    nested = base / "sub" / "file.pdf"
    resolved = security.assert_within_directory(nested, base)
    assert str(resolved).startswith(str(base.resolve()))


def test_assert_within_directory_blocks_traversal(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside" / "secret.txt"
    with pytest.raises(exc.PathTraversalError):
        security.assert_within_directory(outside, base)


def test_assert_within_directory_blocks_dotdot_traversal(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    traversal = base / ".." / "outside.txt"
    with pytest.raises(exc.PathTraversalError):
        security.assert_within_directory(traversal, base)


# --------------------------------------------------------------------------- #
# Temp directory lifecycle
# --------------------------------------------------------------------------- #


def test_isolated_temp_dir_is_removed_on_success(tmp_path: Path) -> None:
    captured: dict = {}
    with security.isolated_temp_dir(tmp_path) as work_dir:
        captured["path"] = work_dir
        (work_dir / "scratch.txt").write_text("data")
        assert work_dir.exists()
    assert not captured["path"].exists()


def test_isolated_temp_dir_is_removed_on_exception(tmp_path: Path) -> None:
    captured: dict = {}
    with pytest.raises(RuntimeError):
        with security.isolated_temp_dir(tmp_path) as work_dir:
            captured["path"] = work_dir
            raise RuntimeError("boom")
    assert not captured["path"].exists()


# --------------------------------------------------------------------------- #
# Isolated subprocess execution
# --------------------------------------------------------------------------- #


def test_run_isolated_returns_result() -> None:
    result = security.run_isolated(_ok_worker, args=(21,), timeout_seconds=10, max_memory_bytes=None)
    assert result == {"doubled": 42}


def test_run_isolated_reraises_typed_exception() -> None:
    with pytest.raises(exc.CorruptedPdfError):
        security.run_isolated(_raising_worker, timeout_seconds=10, max_memory_bytes=None)


def test_run_isolated_enforces_timeout() -> None:
    start = time.monotonic()
    with pytest.raises(exc.ProcessingTimeoutError):
        security.run_isolated(_sleep_worker, args=(5,), timeout_seconds=1, max_memory_bytes=None)
    elapsed = time.monotonic() - start
    assert elapsed < 5, "worker should have been killed well before its 5s sleep completed"


def test_run_isolated_detects_worker_crash() -> None:
    with pytest.raises(exc.WorkerCrashedError):
        security.run_isolated(_crash_worker, timeout_seconds=10, max_memory_bytes=None)


def test_run_isolated_handles_a_result_larger_than_the_pipe_buffer() -> None:
    """Regression test for a deadlock: multiprocessing.Queue is backed by
    an OS pipe with a limited kernel buffer (commonly 64KiB on Linux).
    run_isolated used to call process.join(timeout_seconds) *before*
    draining the result queue, so any result bigger than that buffer
    deadlocked (child blocked writing, parent blocked joining) until the
    wall-clock timeout fired and the child was killed -- turning a
    perfectly successful sanitization of any non-trivial real-world PDF
    into a spurious ProcessingTimeoutError. 8 MiB comfortably exceeds any
    realistic pipe buffer size.
    """
    start = time.monotonic()
    result = security.run_isolated(
        _large_result_worker, args=(8 * 1024 * 1024,), timeout_seconds=15, max_memory_bytes=None
    )
    elapsed = time.monotonic() - start
    assert len(result["payload"]) == 8 * 1024 * 1024
    assert elapsed < 10, f"should complete in well under the 15s timeout, took {elapsed:.1f}s"


# --------------------------------------------------------------------------- #
# Worker RLIMIT_AS derivation from the single "memory" budget
# --------------------------------------------------------------------------- #


def test_worker_rlimit_bytes_is_none_when_disabled() -> None:
    assert security.worker_rlimit_bytes(None) is None


def test_worker_rlimit_bytes_leaves_headroom_below_configured_value() -> None:
    configured = 2 * 1024**3
    derived = security.worker_rlimit_bytes(configured)
    assert derived is not None
    assert 0 < derived < configured


def test_worker_rlimit_bytes_never_collapses_to_zero_for_small_budgets() -> None:
    derived = security.worker_rlimit_bytes(1024)
    assert derived is not None
    assert derived >= 1
