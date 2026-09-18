"""Typed data models shared across the whole package.

Everything that crosses a process boundary (the isolated worker) or is
surfaced by the CLI is represented here as a Pydantic model so that it
has a predictable, serializable, documented shape.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class DomainSourceType(str, Enum):
    """Where inside the PDF a URL/domain reference was found.

    This classification is best-effort. It exists to produce a useful
    triage report, not as a security boundary -- see the module docstring
    of ``inspector.py`` and the project README for details.
    """

    TEXT = "text"
    ANNOTATION_URI = "annotation_uri"
    ACTION_URI = "action_uri"
    JAVASCRIPT = "javascript"
    LAUNCH_ACTION = "launch_action"
    GOTOR_ACTION = "gotor_action"
    SUBMIT_FORM = "submit_form_action"
    EMBEDDED_FILE = "embedded_file"
    OTHER_EXTERNAL_REFERENCE = "other_external_reference"


class DomainFinding(BaseModel):
    """A single URL/domain reference found in the original, untrusted PDF."""

    source_type: DomainSourceType
    domain: Optional[str] = Field(
        default=None, description="Hostname extracted from the URL, if any."
    )
    raw_value: str = Field(
        description="The raw string as found in the PDF, truncated for the report."
    )
    page_index: Optional[int] = Field(
        default=None, description="0-based page index, if the finding is page-scoped."
    )
    object_ref: Optional[str] = Field(
        default=None, description="PDF indirect object id ('objgen') the finding came from."
    )


class DomainReport(BaseModel):
    findings: list[DomainFinding] = Field(default_factory=list)
    unique_domains: list[str] = Field(default_factory=list)
    truncated: bool = Field(
        default=False,
        description="True if the number of findings exceeded the configured cap and was truncated.",
    )

    @property
    def total_findings(self) -> int:
        return len(self.findings)


class DangerousObjectFinding(BaseModel):
    """A structural indicator of active/interactive content found in a PDF."""

    category: str = Field(description="e.g. 'JavaScript', 'OpenAction', 'EmbeddedFile'.")
    matched_token: str = Field(description="The PDF name/key/type value that matched.")
    object_ref: str = Field(description="PDF indirect object id ('objgen').")
    context: str = Field(default="", description="Short, safe human-readable context.")


class StructuralScanResult(BaseModel):
    findings: list[DangerousObjectFinding] = Field(default_factory=list)
    objects_visited: int = 0
    truncated: bool = False

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0


class InspectionReport(BaseModel):
    """Read-only report about the ORIGINAL, untrusted PDF.

    Produced by ``inspector.py``. Never used to decide whether output is
    safe -- only ``validator.py``'s scan of the *reconstructed* PDF gates
    release of a result.
    """

    filename: Optional[str] = None
    size_bytes: int
    is_encrypted: bool
    page_count: Optional[int] = None
    pdf_version: Optional[str] = None
    structural_scan: StructuralScanResult
    domain_report: DomainReport
    javascript_present: bool
    open_action_present: bool
    additional_actions_present: bool
    embedded_files_count: int
    acroform_present: bool
    xfa_present: bool
    richmedia_or_multimedia_present: bool
    notes: list[str] = Field(default_factory=list)


class ValidationCheck(BaseModel):
    name: str
    passed: bool
    detail: str = ""


class ValidationReport(BaseModel):
    passed: bool
    checks: list[ValidationCheck] = Field(default_factory=list)
    structural_scan: StructuralScanResult
    rejection_reason: Optional[str] = None
    rejection_code: Optional[str] = Field(
        default=None,
        description="Short machine-readable reason, e.g. 'output_too_large' or "
        "'sanitized_output_invalid' -- what the CLI prints after 'ERROR: '.",
    )
    output_size_bytes: Optional[int] = None
    output_page_count: Optional[int] = None


class SanitizationReport(BaseModel):
    """Full report returned for a completed (accepted or rejected) job."""

    original_filename: Optional[str] = None
    original_size_bytes: int
    original_page_count: Optional[int] = None
    sanitized_size_bytes: Optional[int] = None
    sanitized_page_count: Optional[int] = None
    render_dpi: int
    processing_time_seconds: float
    removed_features: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    domain_report: DomainReport
    validation_report: ValidationReport
    accepted: bool

    def summary(self) -> dict:
        """Compact dict safe to embed in an HTTP response header."""
        return {
            "accepted": self.accepted,
            "original_pages": self.original_page_count,
            "sanitized_pages": self.sanitized_page_count,
            "original_size_bytes": self.original_size_bytes,
            "sanitized_size_bytes": self.sanitized_size_bytes,
            "processing_time_seconds": round(self.processing_time_seconds, 3),
            "domain_findings": self.domain_report.total_findings,
            "removed_features": self.removed_features,
            "warnings": self.warnings,
        }


class VersionInfo(BaseModel):
    pdf_sanitizer_version: str
    python_version: str
    library_versions: dict[str, str]
