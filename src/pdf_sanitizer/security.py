"""Security primitives used by the rest of the package.

This module intentionally has no dependency on any PDF-parsing library. It
only deals with: filesystem safety, magic-byte sniffing, and running
untrusted work in an isolated, time- and memory-bounded subprocess.

Process isolation model
------------------------
``run_isolated`` starts a **fresh** subprocess (multiprocessing "spawn"
context, not "fork") for every single sanitization job. "spawn" re-imports
the interpreter from scratch in the child, so the child does not inherit
open file descriptors, locks, or memory state from the parent -- only the
picklable arguments we explicitly pass it.

Inside the child, before a single byte of the untrusted PDF is touched, we
apply POSIX resource limits (``RLIMIT_AS`` for address space, ``RLIMIT_CPU``
for CPU time) as a *secondary* defense. These are best-effort:

* They only work on POSIX systems (Linux/macOS), not Windows.
* They bound *this Python process*, not arbitrary host resources such as
  disk I/O or open file descriptors.
* They are not a substitute for OS-level sandboxing. The primary boundary
  is the container described in the Dockerfile / README (``--network
  none``, dropped capabilities, non-root user, read-only filesystem,
  cgroup memory/CPU limits). See the README "Limitations" section.

The wall-clock timeout is enforced independently by the parent process via
``Process.join(timeout)`` followed by ``terminate()``/``kill()`` -- this is
the mechanism that actually guarantees termination, since a worker stuck in
a C extension (e.g. a pathological PDF triggering a renderer loop) may not
honor RLIMIT_CPU or Python-level signals promptly.
"""

from __future__ import annotations

import contextlib
import multiprocessing
import multiprocessing.queues
import os
import queue
import shutil
import stat
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator

from pdf_sanitizer import exceptions as exc

PDF_MAGIC = b"%PDF-"
PDF_EOF_MARKER = b"%%EOF"
_HEADER_SEARCH_WINDOW = 1024  # PDF spec: header must appear within the first 1024 bytes
_EOF_SEARCH_WINDOW = 2048  # be generous; trailing junk after %%EOF is common and harmless


def looks_like_pdf(data: bytes) -> bool:
    """Cheap, dependency-free structural sniff test.

    This is *not* a validation step (a well-formed header does not imply a
    parseable PDF) -- it only lets us reject obviously-wrong uploads (a
    JPEG, an HTML page, a zip bomb, ...) with a specific, fast error before
    we ever hand the bytes to a parser.
    """
    if not data:
        return False
    head = data[:_HEADER_SEARCH_WINDOW]
    if PDF_MAGIC not in head:
        return False
    tail = data[-_EOF_SEARCH_WINDOW:]
    return PDF_EOF_MARKER in tail


def assert_looks_like_pdf(data: bytes) -> None:
    if not looks_like_pdf(data):
        raise exc.NotAPdfError(
            "Uploaded data does not contain a PDF header/trailer within the expected window."
        )


def secure_random_filename(suffix: str = ".pdf") -> str:
    """A filename with no attacker-controlled characters whatsoever."""
    if not suffix.startswith("."):
        suffix = "." + suffix
    return f"{uuid.uuid4().hex}{suffix}"


def sanitize_display_filename(original_name: str | None, *, max_len: int = 120) -> str:
    """Turn a user-supplied filename into something safe to put in *logs and
    reports only*. This value must never be used to construct a filesystem
    path -- use :func:`secure_random_filename` for that.
    """
    if not original_name:
        return "upload.pdf"
    name = os.path.basename(original_name)  # strip any directory components
    name = name.replace("\x00", "")
    allowed = []
    for ch in name:
        if ch.isalnum() or ch in (".", "-", "_", " "):
            allowed.append(ch)
    cleaned = "".join(allowed).strip() or "upload.pdf"
    return cleaned[:max_len]


def assert_within_directory(path: Path, base: Path) -> Path:
    """Resolve ``path`` and guarantee it is inside ``base``.

    Raises :class:`~pdf_sanitizer.exceptions.PathTraversalError` otherwise.
    Always call this before opening any path that was influenced, even
    indirectly, by external input.
    """
    resolved_base = base.resolve(strict=False)
    resolved_path = path.resolve(strict=False)
    try:
        is_inside = resolved_path.is_relative_to(resolved_base)
    except AttributeError:  # pragma: no cover - Python < 3.9 fallback
        is_inside = str(resolved_path).startswith(str(resolved_base) + os.sep)
    if not is_inside:
        raise exc.PathTraversalError(
            f"Resolved path {resolved_path} escapes base directory {resolved_base}"
        )
    return resolved_path


@contextlib.contextmanager
def isolated_temp_dir(base: Path) -> Iterator[Path]:
    """Create a private, restrictively-permissioned temp directory and
    guarantee its removal (including all contents) on the way out, even if
    an exception is raised inside the ``with`` block.
    """
    base.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(base, stat.S_IRWXU)  # 0700, best effort
    work_dir = Path(tempfile.mkdtemp(prefix="job-", dir=str(base)))
    try:
        os.chmod(work_dir, stat.S_IRWXU)
        yield work_dir
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


#: Fraction of the configured memory budget (Settings.max_memory_bytes,
#: which also drives the container's cgroup mem_limit -- see
#: docker-compose.yml) actually handed to the worker's own RLIMIT_AS.
#: Deliberately less than 100%: this project intentionally wants the
#: worker's *own* accounting to run out first, so a memory-hungry
#: malicious PDF is reported as a clean, typed OutOfMemoryError instead
#: of racing the kernel's cgroup OOM-killer (WorkerCrashedError, far
#: less informative). See README "Nota sobre os dois limites de
#: memória".
_WORKER_RLIMIT_FRACTION = 0.85
_WORKER_RLIMIT_MIN_BYTES = 64 * 1024 * 1024  # never carve out less than this much headroom


def worker_rlimit_bytes(configured_memory_bytes: int | None) -> int | None:
    """Derive the worker's POSIX RLIMIT_AS from the single user-facing
    "memory" budget (``Settings.max_memory_bytes``).

    Returns ``None`` unchanged (RLIMIT_AS disabled) when the configured
    budget itself is ``None``. Otherwise returns a value strictly less
    than ``configured_memory_bytes`` (see ``_WORKER_RLIMIT_FRACTION``),
    floored so a very small configured budget still leaves the worker a
    usable amount of memory rather than an unusably tiny RLIMIT_AS.
    """
    if configured_memory_bytes is None:
        return None
    headroom = max(_WORKER_RLIMIT_MIN_BYTES, int(configured_memory_bytes * (1 - _WORKER_RLIMIT_FRACTION)))
    derived = configured_memory_bytes - headroom
    return max(1, derived)


def _apply_resource_limits(max_memory_bytes: int | None, max_cpu_seconds: int | None) -> None:
    """Best-effort POSIX resource limits. Never raises: a platform that does
    not support ``resource`` (e.g. Windows) simply skips this step, relying
    entirely on the container / timeout boundary instead.
    """
    if sys.platform == "win32":
        return
    try:
        import resource
    except ImportError:  # pragma: no cover
        return

    if max_memory_bytes is not None:
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_AS, (max_memory_bytes, max_memory_bytes))
    if max_cpu_seconds is not None:
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_seconds, max_cpu_seconds))


def _child_entrypoint(
    target: Callable[..., dict],
    args: tuple,
    kwargs: dict,
    result_queue: multiprocessing.queues.Queue,
    max_memory_bytes: int | None,
    max_cpu_seconds: int | None,
) -> None:
    """Runs inside the child process. Never lets an exception escape
    uncaught -- everything is turned into a picklable, safe payload.
    """
    _apply_resource_limits(max_memory_bytes, max_cpu_seconds)
    try:
        result = target(*args, **kwargs)
        result_queue.put(("ok", result))
    except exc.PdfSanitizerError as e:
        result_queue.put(
            (
                "error",
                {
                    "exc_type": type(e).__name__,
                    "code": e.code,
                    "message": str(e.message),
                    "user_message": e.user_message,
                },
            )
        )
    except MemoryError as e:  # pragma: no cover - depends on RLIMIT_AS firing
        result_queue.put(
            (
                "error",
                {
                    "exc_type": "OutOfMemoryError",
                    "code": "out_of_memory",
                    "message": repr(e),
                    "user_message": exc.OutOfMemoryError.default_user_message,
                },
            )
        )
    except BaseException as e:  # noqa: BLE001 - deliberate: this is a safety net
        result_queue.put(
            (
                "error",
                {
                    "exc_type": "ProcessingError",
                    "code": "processing_error",
                    "message": f"{type(e).__name__}: {e}",
                    "user_message": exc.ProcessingError.default_user_message,
                },
            )
        )


_EXC_TYPE_MAP: dict[str, type[exc.PdfSanitizerError]] = {
    cls.__name__: cls
    for cls in [
        exc.NotAPdfError,
        exc.CorruptedPdfError,
        exc.EncryptedPdfError,
        exc.IncorrectPasswordError,
        exc.EmptyPdfError,
        exc.FileTooLargeError,
        exc.TooManyPagesError,
        exc.PageTooLargeError,
        exc.ProcessingError,
        exc.ProcessingTimeoutError,
        exc.OutOfMemoryError,
        exc.RenderError,
        exc.ReconstructionError,
        exc.WorkerCrashedError,
        exc.ValidationError,
        exc.SanitizedOutputInvalidError,
        exc.SanitizedOutputTooLargeError,
        exc.SecurityError,
        exc.PathTraversalError,
        exc.UnsupportedMediaTypeError,
    ]
}


def _rehydrate_exception(payload: dict) -> exc.PdfSanitizerError:
    cls = _EXC_TYPE_MAP.get(payload.get("exc_type", ""), exc.ProcessingError)
    return cls(payload.get("message", "unknown error"), user_message=payload.get("user_message"))


def run_isolated(
    target: Callable[..., dict],
    args: tuple = (),
    kwargs: dict | None = None,
    *,
    timeout_seconds: int,
    max_memory_bytes: int | None,
    max_cpu_seconds: int | None = None,
) -> dict:
    """Run ``target(*args, **kwargs)`` in a fresh, isolated subprocess.

    ``target`` must be a module-level function (picklable for the "spawn"
    start method) and must return a picklable, plain-Python value (dict of
    primitives -- not a Pydantic model, not an open file handle).

    Raises :class:`ProcessingTimeoutError`, :class:`WorkerCrashedError`, or
    re-raises whatever :class:`PdfSanitizerError` subclass the child
    reported.
    """
    kwargs = kwargs or {}
    if max_cpu_seconds is None:
        # Give the CPU-time limit a little headroom over the wall-clock
        # timeout so that RLIMIT_CPU acting first doesn't mask a clean,
        # informative wall-clock timeout from the parent.
        max_cpu_seconds = max(1, int(timeout_seconds * 1.5))

    ctx = multiprocessing.get_context("spawn")
    result_queue: multiprocessing.queues.Queue = ctx.Queue()
    process = ctx.Process(
        target=_child_entrypoint,
        args=(target, args, kwargs, result_queue, max_memory_bytes, max_cpu_seconds),
        daemon=True,
    )
    process.start()

    # Read the result BEFORE joining, not after. multiprocessing.Queue is
    # backed by an OS pipe with a limited kernel buffer (commonly 64KiB on
    # Linux); once a result larger than that is put() on the queue, the
    # child's feeder thread blocks on the underlying write() until a
    # reader drains it. Calling process.join(timeout_seconds) first (as
    # this function used to) means the parent never reads the queue until
    # the child has already exited -- for any sanitized PDF whose pickled
    # result exceeds the pipe buffer, parent and child deadlock until the
    # wall-clock timeout fires. This bit real, non-trivial PDFs (the
    # exact large/high-DPI/many-page files this project's limits exist to
    # support) even though it never showed up against the tiny fixtures
    # in the pre-existing test suite. See tests/test_size_optimization.py.
    try:
        status, payload = result_queue.get(timeout=timeout_seconds)
    except queue.Empty:
        # No result within the wall-clock budget. Two distinct cases:
        # the worker is still legitimately running (a genuine timeout,
        # terminate it), or it already died without ever reaching
        # result_queue.put -- e.g. OOM-killed by the OS (WorkerCrashedError).
        if process.is_alive():
            process.terminate()
            process.join(5)
            if process.is_alive():  # pragma: no cover - rare, SIGTERM ignored
                process.kill()
                process.join(5)
            raise exc.ProcessingTimeoutError(
                f"Worker exceeded {timeout_seconds}s wall-clock timeout and was killed."
            ) from None
        exit_code = process.exitcode
        raise exc.WorkerCrashedError(
            f"Worker process exited (code={exit_code}) without producing a result. "
            "This usually means it was killed by the OS (commonly OOM-killer)."
        ) from None
    finally:
        result_queue.close()
        with contextlib.suppress(Exception):
            result_queue.join_thread()

    # A result was already received -- the child should exit almost
    # immediately afterwards. This join is just process cleanup (avoiding
    # a zombie), not part of the timeout budget, hence the short bound.
    process.join(5)
    if process.is_alive():  # pragma: no cover - defensive, child stuck after put()
        process.terminate()
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join(5)

    if status == "error":
        raise _rehydrate_exception(payload)
    return payload  # status == "ok"


def any_type(value: Any) -> Any:  # pragma: no cover - typing helper, unused at runtime
    return value
