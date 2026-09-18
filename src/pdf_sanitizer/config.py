"""Runtime configuration.

Every limit is overridable through an environment variable prefixed with
``PDF_SANITIZER_``, **and** through the persisted config file managed by
``pdf-sanitizer config`` / ``./sanitize config`` (see
``persistent_config.py`` for the file format and precedence rules).
Nothing here is a secret; no credentials are read or stored by this
package.

Example::

    export PDF_SANITIZER_MAX_INPUT_BYTES=20971520   # 20 MiB
    export PDF_SANITIZER_MAX_PAGES=100
    export PDF_SANITIZER_PROCESSING_TIMEOUT_SECONDS=30

Precedence, highest first: explicit constructor kwargs (``Settings(max_pages=5)``,
what the test suite uses throughout) > real OS environment variables >
the persisted config file > the field default below. Field defaults
here are themselves the project's recommended configuration (see
README "Configuração rápida") -- a fresh checkout with no persisted
config file and no environment overrides already behaves the
recommended way.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from pdf_sanitizer import sizes
from pdf_sanitizer.persistent_config import load_persisted_config

#: Env-var names this project used before a given field was renamed.
#: Kept as accepted *aliases* (never the primary/documented name) purely
#: so an existing deployment's environment does not silently stop
#: working after an upgrade. New configuration should use the current
#: names (see persistent_config.MANAGED_SETTINGS / the README table).
_LEGACY_ENV_ALIASES: dict[str, str] = {
    "PDF_SANITIZER_MAX_UPLOAD_BYTES": "max_input_bytes",
    "PDF_SANITIZER_MAX_WORKER_MEMORY_BYTES": "max_memory_bytes",
}


def _env_names_for_field(field_name: str) -> list[str]:
    """All environment variable names that can populate ``field_name``:
    the canonical ``PDF_SANITIZER_<FIELD>`` name plus any legacy alias.
    """
    canonical = f"PDF_SANITIZER_{field_name.upper()}"
    aliases = [env for env, target in _LEGACY_ENV_ALIASES.items() if target == field_name]
    return [canonical, *aliases]


def _parse_size_field(value: Any) -> Any:
    if value is None:
        return None
    return sizes.parse_size(value)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PDF_SANITIZER_",
        env_file=None,  # the persisted config file is layered in __init__ below, not via pydantic-settings' own dotenv support
        extra="ignore",
        frozen=True,
        # Fields with an explicit validation_alias (max_input_bytes,
        # max_memory_bytes -- kept for legacy env-var names, see
        # _LEGACY_ENV_ALIASES) must still be constructible by their plain
        # Python field name (Settings(max_input_bytes=...)), since that is
        # how the whole codebase and test suite instantiate Settings
        # directly. Without this, passing the field name as a keyword
        # would silently be dropped (extra="ignore") instead of applied.
        populate_by_name=True,
    )

    # --- Input limits -------------------------------------------------------------
    max_input_bytes: int = Field(
        default=524_288_000,
        ge=1,
        description="500 MiB default. Accepts a human-readable size ('500M', '1G') "
        "anywhere it can be set (env var, persisted config, CLI).",
        validation_alias=AliasChoices(*_env_names_for_field("max_input_bytes")),
    )
    max_pages: int = Field(default=300, ge=1)
    max_page_dimension_pt: float = Field(
        default=14_400.0,
        description="PDF spec maximum page edge is 14400pt (200in). Pages larger than "
        "this are rejected rather than silently clamped.",
    )

    # --- Rendering ---------------------------------------------------------------
    render_dpi: int = Field(default=150, ge=36, le=600)
    max_render_dpi: int = Field(default=300, ge=36, le=600)
    output_image_format: Literal["png", "jpeg"] = Field(
        default="jpeg",
        description="Page raster format for the reconstructed PDF. JPEG is the "
        "default: dramatically smaller output for photographic/scanned pages, at a "
        "small, configurable (jpeg_quality) fidelity cost. Neither format changes "
        "the security model -- see README 'Arquitetura'.",
    )
    jpeg_quality: int = Field(default=90, ge=1, le=100)

    # --- Output limits -------------------------------------------------------------
    max_output_bytes: int = Field(
        default=3 * 1024**3,  # 3 GiB
        ge=1,
        description="3 GiB default. Sanitized output exceeding this is rejected and "
        "discarded -- never written partially.",
    )

    # --- Time / memory limits (defense in depth; the container is the primary
    #     boundary, see README "Sandbox" section) --------------------------------
    processing_timeout_seconds: int = Field(default=600, ge=1)
    max_memory_bytes: int | None = Field(
        default=2 * 1024**3,  # 2 GiB
        description="The RAM budget for one sanitization job. Drives BOTH the "
        "container's cgroup mem_limit/memswap_limit (docker-compose.yml, via "
        "${PDF_SANITIZER_MAX_MEMORY_BYTES}) and, with a safety margin subtracted "
        "(see security.worker_rlimit_bytes), the POSIX RLIMIT_AS applied inside the "
        "isolated worker process. Set to null/None to disable the in-process "
        "RLIMIT_AS entirely (e.g. on platforms without the resource module) -- the "
        "container cgroup limit still applies.",
        validation_alias=AliasChoices(*_env_names_for_field("max_memory_bytes")),
    )

    # --- Filesystem (Docker-facing; see docker-compose.yml's tmpfs mount) --------
    tmpfs_size: int = Field(
        default=2 * 1024**3,  # 2 GiB
        ge=1,
        description="Size of the tmpfs backing the isolated per-job temp directory "
        "(rendered page images before reconstruction). Only meaningful when running "
        "under docker-compose.yml / the ./sanitize wrapper; the Python package "
        "itself does not create a tmpfs. Independent of max_input_bytes -- driven "
        "by page count x DPI, not by the raw size of the input file.",
    )

    # --- Domain report --------------------------------------------------------------
    domain_report_max_entries: int = Field(default=1000, ge=0)
    domain_report_max_raw_value_len: int = Field(default=300, ge=16)

    # --- Filesystem ---------------------------------------------------------------
    temp_dir: Path = Field(default_factory=lambda: Path(tempfile.gettempdir()) / "pdf_sanitizer")

    # --- Logging -----------------------------------------------------------------
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=True)

    @field_validator("max_input_bytes", "max_output_bytes", "tmpfs_size", mode="before")
    @classmethod
    def _validate_required_size(cls, v: Any) -> Any:
        return sizes.parse_size(v)

    @field_validator("max_memory_bytes", mode="before")
    @classmethod
    def _validate_optional_size(cls, v: Any) -> Any:
        return _parse_size_field(v)

    @field_validator("max_render_dpi")
    @classmethod
    def _dpi_ceiling_at_least_default(cls, v: int, info):
        default_dpi = info.data.get("render_dpi", 150)
        if v < default_dpi:
            raise ValueError("max_render_dpi must be >= render_dpi")
        return v

    def __init__(self, **overrides: Any) -> None:
        """Layer in the persisted config file *below* real environment
        variables and *below* whatever the caller passed explicitly.

        For every field not already present in ``overrides`` and not
        already set via a real process environment variable (checked
        under both its canonical name and any legacy alias, see
        ``_env_names_for_field``), fill in a value from the persisted
        config file if one exists there. Pydantic-settings' own
        environment-variable resolution still runs normally underneath
        for anything left unset here, so a real env var set *after* the
        persisted file was written still wins, exactly like a
        conventional `.env` file.
        """
        persisted = load_persisted_config()
        if persisted:
            file_field_kwargs: dict[str, Any] = {}
            for field_name in type(self).model_fields:
                if field_name in overrides:
                    continue
                if any(env_name in os.environ for env_name in _env_names_for_field(field_name)):
                    continue
                for env_name in _env_names_for_field(field_name):
                    if env_name in persisted:
                        file_field_kwargs[field_name] = persisted[env_name]
                        break
            overrides = {**file_field_kwargs, **overrides}
        super().__init__(**overrides)


def get_settings() -> Settings:
    """Return a fresh Settings instance (re-reads environment variables
    and the persisted config file).

    Not cached on purpose: the CLI and the test suite both construct
    ad-hoc Settings with overrides, and caching would make that surprising.
    """
    return Settings()
