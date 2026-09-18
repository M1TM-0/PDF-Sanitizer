"""Structured logging.

Rules enforced by convention here (see the project brief's "LOGS"
section) -- callers are responsible for only ever passing already-safe
values into :func:`log_event`:

* Never log the full PDF content or raw bytes.
* Never log secrets, tokens, credentials, or environment variable values.
* Log filenames only in their sanitized display form
  (:func:`pdf_sanitizer.security.sanitize_display_filename`), never a raw
  attacker-controlled string, and never a filesystem path.
* Every record is emitted as a single JSON object per line (when
  ``json_output=True``) so it is trivially parseable by log aggregators.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from typing import Any


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(extra)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(*, level: str = "INFO", json_output: bool = True) -> None:
    """Call once at process startup (CLI entrypoint, API startup event)."""
    root = logging.getLogger("pdf_sanitizer")
    root.setLevel(level.upper())
    root.handlers.clear()
    handler = logging.StreamHandler(stream=sys.stdout)
    if json_output:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"pdf_sanitizer.{name}")


def log_event(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    """Emit one structured event.

    Example::

        log_event(logger, logging.INFO, "upload_received", job_id=job_id, size_bytes=n)
    """
    logger.log(level, event, extra={"extra_fields": {"event": event, **fields}})


def new_job_id() -> str:
    return uuid.uuid4().hex
