"""Human-readable byte size parsing/formatting, shared by config, the CLI,
and docker-compose integration.

Single source of truth for what "500M" or "3G" means in this project:
**binary** (1024-based) units, matching Docker's own `--memory`/`mem_limit`
convention and this project's pre-existing "500 MiB default" documentation
for the upload limit. ``500M`` therefore means exactly
``500 * 1024 * 1024 = 524288000`` bytes -- the same number the project
already used as a literal before this module existed (see
``config.py``/README history).

Every size-like setting (``max_input_bytes``, ``max_output_bytes``,
``max_memory_bytes``) accepts *either* a plain integer number of bytes
(``524288000``) *or* a human-readable string (``"500M"``, ``"3G"``,
``"512Mi"``, ``"1.5G"``) -- both forms are accepted from environment
variables, the persisted config file, and CLI flags alike, via
:func:`parse_size`. Values are always normalized to a canonical integer
byte count before being stored anywhere (the persisted config file, the
in-memory :class:`~pdf_sanitizer.config.Settings`), so there is exactly
one representation on disk -- see ``persistent_config.py``.
"""

from __future__ import annotations

import re

#: Recognized unit suffixes, case-insensitive. Binary (1024-based)
#: throughout, and "i"/"b"/"ib" suffix variants are all treated as
#: synonyms of the same binary unit (i.e. "M", "MB", "MiB" are identical
#: here) -- this project does not distinguish decimal (1000-based) units
#: anywhere, so there is no ambiguity in practice.
_UNITS: dict[str, int] = {
    "": 1,
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "ki": 1024,
    "kib": 1024,
    "m": 1024**2,
    "mb": 1024**2,
    "mi": 1024**2,
    "mib": 1024**2,
    "g": 1024**3,
    "gb": 1024**3,
    "gi": 1024**3,
    "gib": 1024**3,
    "t": 1024**4,
    "tb": 1024**4,
    "ti": 1024**4,
    "tib": 1024**4,
}

_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]{0,3})\s*$")

#: Units used for pretty-printing, largest first, binary/IEC names --
#: matches the exact wording used in error messages throughout the
#: project brief ("500 MiB", "1.88 GiB", ...).
_DISPLAY_UNITS: list[tuple[str, int]] = [
    ("TiB", 1024**4),
    ("GiB", 1024**3),
    ("MiB", 1024**2),
    ("KiB", 1024),
]

#: Units used when emitting a compact, Docker-syntax size string (for
#: ``mem_limit``/``tmpfs size=`` in docker-compose.yml). Docker's own
#: parser accepts a bare byte count too, but a short suffixed form is
#: friendlier to read in a generated `.env` file.
_DOCKER_UNITS: list[tuple[str, int]] = [
    ("g", 1024**3),
    ("m", 1024**2),
    ("k", 1024),
]


class SizeParseError(ValueError):
    """Raised for any input that cannot be parsed as a byte size.

    Subclasses :class:`ValueError` so it composes cleanly with Pydantic
    field validators (which wrap any ``ValueError`` raised inside a
    validator into a normal, well-formatted ``ValidationError``).
    """


def parse_size(value: int | float | str) -> int:
    """Parse ``value`` into a non-negative integer number of bytes.

    Accepts a plain non-negative ``int``, or a ``str`` such as
    ``"524288000"``, ``"500M"``, ``"3G"``, ``"512Mi"``, ``"1.5G"``
    (case-insensitive unit, optional fractional number as long as the
    resulting byte count is a whole number). Raises :class:`SizeParseError`
    for anything else -- negative numbers, garbage strings, unknown
    units, or fractional byte counts.
    """
    if isinstance(value, bool):  # bool is an int subclass; reject explicitly
        raise SizeParseError(f"Invalid size value: {value!r}")
    if isinstance(value, int):
        if value < 0:
            raise SizeParseError(f"Size must not be negative: {value!r}")
        return value
    if isinstance(value, float):
        if value < 0 or value != int(value):
            raise SizeParseError(f"Size must be a non-negative whole number of bytes: {value!r}")
        return int(value)
    if isinstance(value, str):
        match = _SIZE_RE.match(value)
        if not match:
            raise SizeParseError(
                f"Invalid size {value!r}: expected e.g. '524288000', '500M', '3G', '1.5G'."
            )
        number_part, unit_part = match.groups()
        unit_key = unit_part.lower()
        if unit_key not in _UNITS:
            raise SizeParseError(
                f"Unknown size unit {unit_part!r} in {value!r}. "
                f"Supported: (none)/B, K/KB/KiB, M/MB/MiB, G/GB/GiB, T/TB/TiB."
            )
        raw_bytes = float(number_part) * _UNITS[unit_key]
        if raw_bytes != int(raw_bytes):
            raise SizeParseError(f"Size {value!r} does not resolve to a whole number of bytes.")
        result = int(raw_bytes)
        if result < 0:
            raise SizeParseError(f"Size must not be negative: {value!r}")
        return result
    raise SizeParseError(f"Cannot parse a size from {type(value).__name__}: {value!r}")


def format_size(num_bytes: int) -> str:
    """Render ``num_bytes`` the way this project's error messages and CLI
    output do: the largest binary unit for which the value is >= 1,
    trimmed to an integer when exact, otherwise 2 decimal places.

    ``format_size(524288000) == "500 MiB"``,
    ``format_size(3221225472) == "3 GiB"``.
    """
    if num_bytes < 0:
        raise SizeParseError(f"Size must not be negative: {num_bytes!r}")
    for name, factor in _DISPLAY_UNITS:
        if num_bytes >= factor:
            value = num_bytes / factor
            if value == int(value):
                return f"{int(value)} {name}"
            return f"{value:.2f} {name}"
    return f"{num_bytes} B"


def to_docker_size_string(num_bytes: int) -> str:
    """Render ``num_bytes`` as a compact Docker-syntax size string
    (``"2g"``, ``"512m"``, ``"524288000"``) suitable for
    ``docker-compose.yml``'s ``mem_limit``/``tmpfs size=`` values.

    Prefers the largest unit that divides evenly; falls back to a bare
    byte count (which Docker also accepts) if the value doesn't divide
    evenly into KiB/MiB/GiB.
    """
    if num_bytes < 0:
        raise SizeParseError(f"Size must not be negative: {num_bytes!r}")
    for suffix, factor in _DOCKER_UNITS:
        if num_bytes != 0 and num_bytes % factor == 0:
            return f"{num_bytes // factor}{suffix}"
    return str(num_bytes)
