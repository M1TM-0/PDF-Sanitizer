"""Persisted configuration: the single on-disk source of truth for the
limits/knobs that used to require editing ``docker-compose.yml`` by hand.

Design
------
Every value lives in **one** plain ``KEY=VALUE`` file (default: ``.env``
in the current working directory -- the same file ``docker compose``
itself auto-loads for ``${VAR}`` interpolation when invoked from the
project directory, see ``docker-compose.yml``). There is no second copy
of any value anywhere:

* :func:`pdf_sanitizer.config.Settings` reads this file directly (via
  :func:`load_persisted_config`, wired up in ``config.py``) so the CLI's
  ``sanitize``/``inspect``/``validate`` commands, and any direct use of
  the Python API, automatically pick up whatever was last persisted --
  no extra flag needed.
* ``docker-compose.yml`` reads the *same* file for both its own
  resource-limit fields (``mem_limit``, the ``tmpfs`` ``size=`` option)
  and the container's environment variables, via Compose's native
  ``${VAR:-default}`` interpolation. Each fallback default there matches
  the corresponding :class:`~pdf_sanitizer.config.Settings` field
  default exactly, so a missing/deleted ``.env`` file is not an error --
  behavior is simply "use the built-in defaults" everywhere at once.
* ``pdf-sanitizer config get/set/reset`` (``cli.py``) is the only code
  that writes this file, and always validates+normalizes every value
  first (see :data:`MANAGED_SETTINGS` and :func:`normalize_for_storage`)
  -- no raw, unvalidated string ever reaches the file, so nothing here
  can be used to inject arbitrary parameters into Docker Compose or a
  shell (see the project brief's "Segurança do arquivo de configuração").

Precedence, highest first: explicit Python kwargs (``Settings(max_pages=5)``,
used throughout the test suite) > real OS environment variables > this
persisted file > the field's built-in default. See
``config.py``'s ``Settings.__init__`` for where that ordering is applied.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from pdf_sanitizer import sizes

#: Overrides where the persisted config file lives. Sitting in one
#: dedicated variable (rather than being hardcoded) lets the test suite
#: point this at a throwaway ``tmp_path`` so tests never read or write a
#: developer's real project ``.env`` file.
CONFIG_PATH_ENV_VAR = "PDF_SANITIZER_CONFIG_FILE"

#: Default filename, resolved relative to the current working directory
#: -- deliberately the exact same resolution rule `docker compose` itself
#: uses for its project-directory `.env` auto-load, so running
#: `pdf-sanitizer config ...` from the same directory as
#: `docker-compose.yml` edits the file Compose will actually read.
DEFAULT_CONFIG_FILENAME = ".env"

_HEADER = """\
# Persisted pdf-sanitizer configuration.
#
# Generated and managed by `pdf-sanitizer config` / `./sanitize config`
# (see README "Configuração rápida"). Local runtime state, not meant to
# be committed (see .env.example for the version-controlled template of
# available keys, and this project's .gitignore).
#
# Do not hand-edit values into anything other than plain `KEY=VALUE`
# (no quotes, no shell expansion, no inline comments) -- both this
# project's own config loader and `docker compose`'s `.env` parser
# expect exactly that, and arbitrary content here is never passed to a
# shell or evaluated, only parsed as one string field at a time.
#
# Removing this file (or `pdf-sanitizer config reset`) reverts every
# value below to its built-in default -- see README "Limites
# configuráveis".
"""


@dataclass(frozen=True)
class ManagedSetting:
    """One row of the ``config``-CLI-visible settings registry."""

    field: str  #: attribute name on Settings
    env_name: str  #: e.g. "PDF_SANITIZER_MAX_PAGES"
    cli_key: str  #: kebab-case key, e.g. "max-pages" (flag: --max-pages)
    label: str  #: human label for `config`/`status` display, e.g. "Pages"
    kind: str  #: "int" | "size" | "format"
    unit_suffix: str = ""  #: appended to the plain-int display, e.g. "seconds"

    def parse(self, raw: int | str) -> int | str:
        """Validate+normalize a raw user-supplied value for this setting.

        Returns the canonical Python value (``int`` for "int"/"size",
        the lowercase format string for "format"). Raises ``ValueError``
        (including :class:`~pdf_sanitizer.sizes.SizeParseError`) on
        anything invalid -- callers (the CLI) are expected to catch that
        and print a clean error instead of a traceback.
        """
        if self.kind == "size":
            return sizes.parse_size(raw)
        if self.kind == "int":
            return int(str(raw).strip())
        if self.kind == "format":
            normalized = str(raw).strip().lower()
            if normalized not in ("png", "jpeg"):
                raise ValueError(f"Invalid image format {raw!r}: expected 'png' or 'jpeg'.")
            return normalized
        raise AssertionError(f"unknown ManagedSetting kind: {self.kind!r}")  # pragma: no cover

    def display(self, value: int | str) -> str:
        if self.kind == "size":
            return sizes.format_size(int(value))
        if self.kind == "int":
            suffix = f" {self.unit_suffix}" if self.unit_suffix else ""
            return f"{value}{suffix}"
        return str(value)

    def storage_string(self, value: int | str) -> str:
        """Canonical string written to the persisted file / used for
        docker-compose interpolation -- always a plain integer byte
        count for "size"/"int" fields, never a human-readable suffix, so
        there is exactly one on-disk representation per value.
        """
        if self.kind in ("size", "int"):
            return str(int(value))
        return str(value)


#: The complete, ordered list of settings exposed by `pdf-sanitizer
#: config` / `./sanitize config`. Order here is display order.
MANAGED_SETTINGS: list[ManagedSetting] = [
    ManagedSetting("max_pages", "PDF_SANITIZER_MAX_PAGES", "max-pages", "Pages", "int"),
    ManagedSetting("max_input_bytes", "PDF_SANITIZER_MAX_INPUT_BYTES", "max-input-size", "Input limit", "size"),
    ManagedSetting("max_output_bytes", "PDF_SANITIZER_MAX_OUTPUT_BYTES", "max-output-size", "Output limit", "size"),
    ManagedSetting("max_memory_bytes", "PDF_SANITIZER_MAX_MEMORY_BYTES", "memory", "RAM", "size"),
    ManagedSetting(
        "processing_timeout_seconds",
        "PDF_SANITIZER_PROCESSING_TIMEOUT_SECONDS",
        "timeout",
        "Timeout",
        "int",
        unit_suffix="seconds",
    ),
    ManagedSetting("render_dpi", "PDF_SANITIZER_RENDER_DPI", "dpi", "DPI", "int"),
    ManagedSetting(
        "output_image_format", "PDF_SANITIZER_OUTPUT_IMAGE_FORMAT", "format", "Image format", "format"
    ),
    ManagedSetting("jpeg_quality", "PDF_SANITIZER_JPEG_QUALITY", "jpeg-quality", "JPEG quality", "int"),
    ManagedSetting("tmpfs_size", "PDF_SANITIZER_TMPFS_SIZE", "tmpfs", "TMPFS", "size"),
]

#: Lookup helpers built from the registry above.
BY_CLI_KEY: dict[str, ManagedSetting] = {m.cli_key: m for m in MANAGED_SETTINGS}
BY_FIELD: dict[str, ManagedSetting] = {m.field: m for m in MANAGED_SETTINGS}
BY_ENV_NAME: dict[str, ManagedSetting] = {m.env_name: m for m in MANAGED_SETTINGS}


def resolve_config_path() -> Path:
    """Where the persisted config file lives for *this* invocation.

    Not cached -- resolved fresh every call, same philosophy as
    ``config.get_settings()``, so tests can flip
    ``PDF_SANITIZER_CONFIG_FILE`` per-test via ``monkeypatch``.
    """
    override = os.environ.get(CONFIG_PATH_ENV_VAR)
    if override:
        return Path(override)
    return Path.cwd() / DEFAULT_CONFIG_FILENAME


def load_persisted_config(path: Path | None = None) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines from the persisted config file.

    Best-effort and defensive: a missing file yields an empty dict (not
    an error -- "no persisted overrides" is a completely normal state).
    Malformed lines (no ``=``, blank, ``#``-comments) are silently
    skipped rather than raising, since this file may be hand-edited.
    Unrecognized keys are kept in the returned dict (so generic settings
    beyond the `config`-CLI-managed subset still work, see module
    docstring) -- validation of *known, managed* keys happens in
    :func:`normalize_for_storage` / the CLI, not here.
    """
    target = path or resolve_config_path()
    result: dict[str, str] = {}
    try:
        raw_text = target.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, OSError):
        return result
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        # Strip a single layer of matching quotes, the one bit of `.env`
        # syntax we tolerate on read (docker compose's own parser does
        # the same) -- never required for values this module writes.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[key] = value
    return result


def write_persisted_config(values: dict[str, str], path: Path | None = None) -> Path:
    """Atomically write ``values`` (env-var-name -> canonical string) as
    the *complete* persisted config file, replacing whatever was there.

    Callers are expected to have already validated/normalized every
    value (see :meth:`ManagedSetting.parse` /
    :meth:`ManagedSetting.storage_string`) -- this function does not
    re-validate, it only serializes known-good strings. Writes are
    atomic (temp file + ``os.replace``) so a crash mid-write can never
    leave a half-written config file for Docker Compose or this
    project's own loader to trip over. Permissions are restricted to the
    owner (0600); this file holds no secrets, but a project config file
    still has no reason to be world-writable.
    """
    target = path or resolve_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    lines = [_HEADER]
    for managed in MANAGED_SETTINGS:
        if managed.env_name in values:
            lines.append(f"{managed.env_name}={values[managed.env_name]}")
    # Preserve any additional, non-managed keys the file already had
    # (e.g. PDF_SANITIZER_LOG_LEVEL hand-added by an operator) rather
    # than silently discarding them on the next `config set`.
    for key, value in values.items():
        if key not in BY_ENV_NAME:
            lines.append(f"{key}={value}")
    content = "\n".join(lines) + "\n"

    tmp_path = target.with_suffix(target.suffix + f".tmp{os.getpid()}")
    tmp_path.write_text(content, encoding="utf-8")
    with __import__("contextlib").suppress(OSError):
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp_path, target)
    return target


def reset_persisted_config(path: Path | None = None) -> bool:
    """Delete the persisted config file, if any.

    Returns ``True`` if a file was actually removed. After this,
    every setting reverts to its built-in :class:`~pdf_sanitizer.config.Settings`
    default (which is itself already the recommended configuration, see
    README "Configuração rápida") for any value not still overridden by
    a real environment variable -- deleting the file never touches the
    process's real environment.
    """
    target = path or resolve_config_path()
    try:
        target.unlink()
        return True
    except FileNotFoundError:
        return False


def normalize_for_storage(managed: ManagedSetting, raw_value: str) -> str:
    """Validate ``raw_value`` for ``managed`` and return its canonical
    on-disk string form. Raises ``ValueError`` on invalid input.
    """
    parsed = managed.parse(raw_value)
    return managed.storage_string(parsed)
