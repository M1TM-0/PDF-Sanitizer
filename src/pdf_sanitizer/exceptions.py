"""Exception hierarchy for pdf_sanitizer.

Design goal: every exception carries two messages.

* ``message`` -- may contain internal detail (exception repr, object ids,
  etc.). This is what gets written to the structured logs. It must never be
  sent to an HTTP client.
* ``user_message`` -- a short, generic, safe sentence that can be returned
  to a CLI user or an API caller. It never contains stack traces, file
  paths, library internals, or attacker-controlled strings.

``cli.py`` only ever surfaces ``user_message`` (plus ``code``) to the
terminal. ``message`` is logged internally via ``logging_utils``.
"""

from __future__ import annotations


class PdfSanitizerError(Exception):
    """Base class for every error raised by pdf_sanitizer."""

    code: str = "internal_error"
    default_user_message: str = "An internal error occurred while processing the file."

    def __init__(self, message: str, *, user_message: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.user_message = user_message or self.default_user_message

    def __repr__(self) -> str:  # pragma: no cover - convenience only
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


# --------------------------------------------------------------------------- #
# Input validation errors (problems with the file the caller supplied)
# --------------------------------------------------------------------------- #


class InvalidInputError(PdfSanitizerError):
    """The supplied input cannot be processed as-is."""

    code = "invalid_input"
    default_user_message = "The uploaded file could not be accepted."


class NotAPdfError(InvalidInputError):
    code = "not_a_pdf"
    default_user_message = "The uploaded file is not a PDF document."


class CorruptedPdfError(InvalidInputError):
    code = "corrupted_pdf"
    default_user_message = "The PDF file is corrupted or could not be parsed."


class EncryptedPdfError(InvalidInputError):
    code = "encrypted_pdf"
    default_user_message = (
        "The PDF is password-protected or encrypted. Encrypted files are "
        "rejected by default; use the CLI with --password if you trust the "
        "source and need to decrypt it locally."
    )


class IncorrectPasswordError(InvalidInputError):
    code = "incorrect_password"
    default_user_message = "The supplied password did not open the PDF."


class EmptyPdfError(InvalidInputError):
    code = "empty_pdf"
    default_user_message = "The PDF contains no pages."


class FileTooLargeError(InvalidInputError):
    code = "file_too_large"
    default_user_message = "The uploaded file exceeds the maximum allowed size."


class TooManyPagesError(InvalidInputError):
    code = "too_many_pages"
    default_user_message = "The PDF has more pages than the configured limit."


class PageTooLargeError(InvalidInputError):
    code = "page_too_large"
    default_user_message = "A page in the PDF exceeds the maximum allowed dimensions."


# --------------------------------------------------------------------------- #
# Processing errors (something went wrong while sanitizing)
# --------------------------------------------------------------------------- #


class ProcessingError(PdfSanitizerError):
    code = "processing_error"
    default_user_message = "The file could not be processed."


class ProcessingTimeoutError(ProcessingError):
    code = "processing_timeout"
    default_user_message = "Processing took too long and was aborted."


class OutOfMemoryError(ProcessingError):
    code = "out_of_memory"
    default_user_message = "Processing exceeded the memory limit and was aborted."


class RenderError(ProcessingError):
    code = "render_error"
    default_user_message = "A page could not be rendered safely."


class ReconstructionError(ProcessingError):
    code = "reconstruction_error"
    default_user_message = "The sanitized PDF could not be assembled."


class WorkerCrashedError(ProcessingError):
    code = "worker_crashed"
    default_user_message = "The isolated processing worker terminated unexpectedly."


# --------------------------------------------------------------------------- #
# Output validation errors (the rebuilt PDF failed the safety checks)
# --------------------------------------------------------------------------- #


class ValidationError(PdfSanitizerError):
    code = "validation_error"
    default_user_message = "The sanitized output failed validation and was discarded."


class SanitizedOutputInvalidError(ValidationError):
    code = "sanitized_output_invalid"
    default_user_message = (
        "The sanitized PDF did not pass post-processing validation and was "
        "discarded. No output was produced."
    )


class SanitizedOutputTooLargeError(ValidationError):
    code = "sanitized_output_too_large"
    default_user_message = "The sanitized PDF exceeds the maximum allowed output size."


# --------------------------------------------------------------------------- #
# Security / API-layer errors
# --------------------------------------------------------------------------- #


class SecurityError(PdfSanitizerError):
    code = "security_error"
    default_user_message = "The request was rejected for security reasons."


class PathTraversalError(SecurityError):
    code = "path_traversal"
    default_user_message = "The requested path is not allowed."


class UnsupportedMediaTypeError(SecurityError):
    code = "unsupported_media_type"
    default_user_message = "The upload's content type is not accepted."
