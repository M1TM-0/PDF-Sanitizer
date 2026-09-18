"""Professional CLI for pdf_sanitizer, built on Typer.

::

    pdf-sanitizer sanitize input.pdf -o output.pdf
    pdf-sanitizer inspect input.pdf
    pdf-sanitizer validate output.pdf
    pdf-sanitizer config
    pdf-sanitizer status
    pdf-sanitizer version

``python -m pdf_sanitizer <command> ...`` works identically (see
``__main__.py``). Every command exits non-zero on failure so it is safe
to use directly in shell scripts / CI pipelines.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from pdf_sanitizer import exceptions as exc
from pdf_sanitizer import inspector, sanitizer, validator
from pdf_sanitizer.config import Settings
from pdf_sanitizer.logging_utils import configure_logging
from pdf_sanitizer.models import InspectionReport, ValidationReport
from pdf_sanitizer.persistent_config import (
    BY_CLI_KEY,
    MANAGED_SETTINGS,
    reset_persisted_config,
    resolve_config_path,
    write_persisted_config,
)
from pdf_sanitizer.sizes import format_size

app = typer.Typer(
    name="pdf-sanitizer",
    help=(
        "Sanitize untrusted PDF files by rendering every page to an image and "
        "reconstructing a brand-new PDF from the images. See the README for the "
        "full security model, sandboxing instructions, and limitations."
    ),
    no_args_is_help=True,
    add_completion=False,
)

config_app = typer.Typer(
    name="config",
    help="Get, set, or reset the persisted configuration (limits, DPI, image "
    "format/quality, ...) -- no docker-compose.yml or shell edits required. "
    "See README 'Limites configuráveis' / 'Configuração rápida'.",
    no_args_is_help=False,
    add_completion=False,
)
app.add_typer(config_app, name="config")


def _read_password(password: Optional[str], password_stdin: bool) -> Optional[str]:
    if password_stdin:
        line = sys.stdin.readline().rstrip("\n")
        return line or None
    return password


def _die(message: str, code: int = 1) -> typer.Exit:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    return typer.Exit(code=code)


def _fail(code: str, message: str, exit_code: int = 1) -> typer.Exit:
    """Print the project's standard two-line machine/human error format::

        ERROR: input_too_large
        Input PDF is 742 MiB, exceeding the configured limit of 500 MiB.
    """
    typer.secho(f"ERROR: {code}", fg=typer.colors.RED, bold=True, err=True)
    typer.echo(message, err=True)
    return typer.Exit(code=exit_code)


def _print_validation_report(report: ValidationReport) -> None:
    status, color = ("PASSED", typer.colors.GREEN) if report.passed else ("REJECTED", typer.colors.RED)
    typer.secho(f"validation: {status}", fg=color, bold=True)
    for check in report.checks:
        mark = "OK  " if check.passed else "FAIL"
        typer.echo(f"  [{mark}] {check.name}: {check.detail}")
    if not report.passed and report.rejection_reason:
        typer.echo(f"reason: {report.rejection_reason}")


def _print_inspection_report(report: InspectionReport) -> None:
    typer.echo(f"file: {report.filename or '(unknown)'}  ({report.size_bytes} bytes)")
    typer.echo(
        f"pages: {report.page_count}   pdf_version: {report.pdf_version}   encrypted: {report.is_encrypted}"
    )
    typer.echo(
        f"javascript={report.javascript_present}  open_action={report.open_action_present}  "
        f"additional_actions={report.additional_actions_present}  acroform={report.acroform_present}  "
        f"xfa={report.xfa_present}  richmedia_or_multimedia={report.richmedia_or_multimedia_present}  "
        f"embedded_files={report.embedded_files_count}"
    )
    scan = report.structural_scan
    typer.echo(
        f"structural scan: {len(scan.findings)} finding(s) across {scan.objects_visited} object(s)"
        + (" [TRUNCATED]" if scan.truncated else "")
    )
    for finding in scan.findings[:50]:
        typer.echo(f"  - {finding.category} ({finding.matched_token}) in {finding.object_ref}: {finding.context}")
    if len(scan.findings) > 50:
        typer.echo(f"  ... and {len(scan.findings) - 50} more (use --json for the full list)")

    domains = report.domain_report
    typer.echo(
        f"domain report: {domains.total_findings} finding(s), {len(domains.unique_domains)} unique domain(s)"
        + (" [TRUNCATED]" if domains.truncated else "")
    )
    for finding in domains.findings[:50]:
        location = f"page {finding.page_index}" if finding.page_index is not None else (finding.object_ref or "-")
        typer.echo(
            f"  - [{finding.source_type.value}] host={finding.domain or '(none)'}  "
            f"loc={location}  raw={finding.raw_value!r}"
        )
    if domains.total_findings > 50:
        typer.echo(f"  ... and {domains.total_findings - 50} more (use --json for the full list)")
    for note in report.notes:
        typer.echo(f"note: {note}")


def _print_config_snapshot(settings: Settings, *, json_output: bool = False) -> None:
    config_path = resolve_config_path()
    if json_output:
        payload = {m.field: getattr(settings, m.field) for m in MANAGED_SETTINGS}
        payload["config_file"] = str(config_path)
        payload["config_file_exists"] = config_path.exists()
        typer.echo(json.dumps(payload, indent=2))
        return
    for managed in MANAGED_SETTINGS:
        value = getattr(settings, managed.field)
        typer.echo(f"{managed.label}: {managed.display(value)}")
    state = "in use" if config_path.exists() else "not created yet -- using built-in defaults"
    typer.echo(f"Config file: {config_path} ({state})")


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging on stderr."),
) -> None:
    configure_logging(level="DEBUG" if verbose else "INFO", json_output=False)


@app.command("status")
def cmd_status(
    json_output: bool = typer.Option(False, "--json", help="Print the configuration as JSON."),
) -> None:
    """Show the current effective configuration. Alias for `config get`."""
    _print_config_snapshot(Settings(), json_output=json_output)


@config_app.callback(invoke_without_command=True)
def config_root(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json", help="Print the configuration as JSON."),
) -> None:
    """With no subcommand, show the current effective configuration (same as `config get`)."""
    if ctx.invoked_subcommand is None:
        _print_config_snapshot(Settings(), json_output=json_output)


@config_app.command("get")
def config_get(
    json_output: bool = typer.Option(False, "--json", help="Print the configuration as JSON."),
) -> None:
    """Show the current effective configuration: persisted file, then real
    environment variables, then built-in defaults -- see README.
    """
    _print_config_snapshot(Settings(), json_output=json_output)


@config_app.command("set")
def config_set(
    key: Optional[str] = typer.Argument(
        None, help="Setting name (e.g. 'max-pages'), for the `config set KEY VALUE` form."
    ),
    value: Optional[str] = typer.Argument(None, help="New value, for the `config set KEY VALUE` form."),
    max_pages: Optional[str] = typer.Option(None, "--max-pages", help="Maximum number of pages processed."),
    max_input_size: Optional[str] = typer.Option(
        None, "--max-input-size", help="Maximum input PDF size, e.g. '500M', '1G'."
    ),
    max_output_size: Optional[str] = typer.Option(
        None, "--max-output-size", help="Maximum sanitized output size, e.g. '3G'."
    ),
    memory: Optional[str] = typer.Option(
        None, "--memory", help="RAM budget, e.g. '4G' -- container mem_limit AND the worker's RLIMIT_AS."
    ),
    timeout: Optional[str] = typer.Option(None, "--timeout", help="Processing timeout, in seconds."),
    dpi: Optional[str] = typer.Option(None, "--dpi", help="Render DPI (e.g. 120, 150, 200)."),
    image_format: Optional[str] = typer.Option(
        None, "--format", help="Output raster format for reconstructed pages: 'png' or 'jpeg'."
    ),
    jpeg_quality: Optional[str] = typer.Option(None, "--jpeg-quality", help="JPEG quality, 1-100."),
    tmpfs: Optional[str] = typer.Option(
        None, "--tmpfs", help="tmpfs size for the isolated per-job work directory, e.g. '2G'."
    ),
) -> None:
    """Persist one or more settings at once.

    Either as flags (any subset, in any combination)::

        pdf-sanitizer config set --max-pages 1000 --dpi 150 --format jpeg

    or as a single `KEY VALUE` pair, using the same names without `--`::

        pdf-sanitizer config set max-pages 1000

    Sizes accept human-readable suffixes ('500M', '1G', '3G'). All
    provided values are validated together before anything is written --
    on any invalid value, nothing is written (all-or-nothing) and the
    previous configuration is left untouched.
    """
    requested: dict[str, str] = {}
    for cli_key, raw in (
        ("max-pages", max_pages),
        ("max-input-size", max_input_size),
        ("max-output-size", max_output_size),
        ("memory", memory),
        ("timeout", timeout),
        ("dpi", dpi),
        ("format", image_format),
        ("jpeg-quality", jpeg_quality),
        ("tmpfs", tmpfs),
    ):
        if raw is not None:
            requested[cli_key] = raw

    if key is not None:
        if value is None:
            raise _die(f"'{key}' was given without a value; usage: config set {key} <value>")
        requested[key] = value
    elif value is not None:
        raise _die("a value was given without a setting name")

    if not requested:
        raise _die("no settings provided -- see `pdf-sanitizer config set --help`")

    normalized: dict[str, str] = {}
    for cli_key, raw in requested.items():
        managed = BY_CLI_KEY.get(cli_key)
        if managed is None:
            valid = ", ".join(sorted(BY_CLI_KEY))
            raise _die(f"unknown setting '{cli_key}'. Valid settings: {valid}")
        try:
            parsed_value = managed.parse(raw)
        except ValueError as error:
            raise _die(f"invalid value for '{cli_key}': {error}")
        normalized[managed.env_name] = managed.storage_string(parsed_value)

    current_settings = Settings()
    full_snapshot: dict[str, str] = {
        m.env_name: m.storage_string(getattr(current_settings, m.field)) for m in MANAGED_SETTINGS
    }
    full_snapshot.update(normalized)

    # Validate the FULL resulting snapshot together (not just the fields
    # that changed) so cross-field constraints are caught before anything
    # is written -- nothing is ever persisted half-valid.
    try:
        Settings(**{m.field: full_snapshot[m.env_name] for m in MANAGED_SETTINGS})
    except Exception as error:
        raise _die(f"invalid configuration: {error}")

    path = write_persisted_config(full_snapshot)
    typer.secho(f"OK: updated {path}", fg=typer.colors.GREEN)
    _print_config_snapshot(Settings())


@config_app.command("reset")
def config_reset() -> None:
    """Delete the persisted configuration file. Every setting reverts to
    its built-in default (already the recommended configuration, see
    README) for anything not still overridden by a real environment
    variable.
    """
    path = resolve_config_path()
    removed = reset_persisted_config()
    if removed:
        typer.secho(f"OK: removed {path}. Settings reverted to built-in defaults.", fg=typer.colors.GREEN)
    else:
        typer.echo(f"Nothing to reset: {path} does not exist -- already using built-in defaults.")
    _print_config_snapshot(Settings())


@app.command("sanitize")
def cmd_sanitize(
    input_path: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True, help="Untrusted input PDF."
    ),
    output: Path = typer.Option(..., "--output", "-o", help="Path to write the sanitized PDF."),
    password: Optional[str] = typer.Option(
        None,
        "--password",
        help="Password for an encrypted input PDF. Visible in shell history/process "
        "list -- prefer --password-stdin.",
    ),
    password_stdin: bool = typer.Option(
        False, "--password-stdin", help="Read the password from stdin instead of the command line."
    ),
    dpi: Optional[int] = typer.Option(
        None, "--dpi", help="Override the render DPI (clamped to the configured maximum)."
    ),
    json_report: Optional[Path] = typer.Option(
        None, "--json-report", help="Also write the full JSON sanitization report to this path."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite --output if it already exists."),
) -> None:
    """Sanitize INPUT and write a new, reconstructed PDF to --output.

    Exit codes: 0 = accepted and written, 1 = input-level error
    (not a PDF, too large, corrupted, encrypted, timeout, ...), 2 =
    processing completed but the reconstructed PDF failed validation and
    was discarded (nothing written to --output).
    """
    if output.exists() and not force:
        raise _die(f"output file already exists: {output} (use --force to overwrite)")

    settings = Settings()
    size = input_path.stat().st_size
    if size > settings.max_input_bytes:
        raise _fail(
            "input_too_large",
            f"Input PDF is {format_size(size)}, exceeding the configured limit of "
            f"{format_size(settings.max_input_bytes)}.",
        )

    pw = _read_password(password, password_stdin)
    data = input_path.read_bytes()

    try:
        result = sanitizer.sanitize(
            data, filename=input_path.name, password=pw, settings=settings, dpi_override=dpi
        )
    except exc.PdfSanitizerError as error:
        raise _fail(error.code, error.user_message)

    if json_report is not None:
        json_report.write_text(result.report.model_dump_json(indent=2), encoding="utf-8")

    if not result.accepted:
        vr = result.report.validation_report
        typer.secho(
            f"ERROR: {vr.rejection_code or 'sanitized_output_invalid'}",
            fg=typer.colors.RED,
            bold=True,
            err=True,
        )
        typer.echo(
            "Sanitized output failed validation and was discarded. Nothing was written.", err=True
        )
        typer.echo(vr.rejection_reason or "unknown reason", err=True)
        if vr.checks:
            typer.echo("validation details:", err=True)
            for check in vr.checks:
                mark = "OK  " if check.passed else "FAIL"
                typer.echo(f"  [{mark}] {check.name}: {check.detail}", err=True)
        raise typer.Exit(code=2)

    assert result.sanitized_pdf_bytes is not None
    output.write_bytes(result.sanitized_pdf_bytes)

    typer.secho(
        f"OK: wrote {output} ({format_size(len(result.sanitized_pdf_bytes))}, "
        f"{result.report.sanitized_page_count} page(s), "
        f"{result.report.processing_time_seconds:.2f}s).",
        fg=typer.colors.GREEN,
    )
    if result.report.domain_report.total_findings:
        typer.echo(
            f"{result.report.domain_report.total_findings} domain/URL reference(s) were found in the "
            f"original file and were removed. Run `pdf-sanitizer inspect {input_path}` for details."
        )
    for note in result.report.warnings:
        typer.secho(f"warning: {note}", fg=typer.colors.YELLOW)


@app.command("validate")
def cmd_validate(
    input_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, help="PDF to validate."),
    json_output: bool = typer.Option(False, "--json", help="Print the full validation report as JSON."),
) -> None:
    """Run the same structural safety checks used to gate sanitizer output
    against an arbitrary PDF file (e.g. re-check a sanitized file later, or
    audit any other PDF). Exit code 0 = passed, 1 = failed/rejected.
    """
    settings = Settings()
    data = input_path.read_bytes()

    try:
        import pikepdf

        with pikepdf.open(input_path) as pdf:
            expected_pages = len(pdf.pages)
    except Exception as error:
        raise _die(f"could not open input as a PDF: {error}")

    report = validator.validate(
        data, expected_page_count=expected_pages, max_output_bytes=settings.max_output_bytes
    )

    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _print_validation_report(report)

    raise typer.Exit(code=0 if report.passed else 1)


@app.command("inspect")
def cmd_inspect(
    input_path: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True, help="Untrusted PDF to inspect."
    ),
    password: Optional[str] = typer.Option(None, "--password"),
    password_stdin: bool = typer.Option(False, "--password-stdin"),
    json_output: bool = typer.Option(False, "--json", help="Print the full inspection report as JSON."),
) -> None:
    """Read-only report on an untrusted PDF: structure, encryption, and a
    best-effort domain/URL report. Never writes or modifies anything.
    """
    settings = Settings()
    size = input_path.stat().st_size
    if size > settings.max_input_bytes:
        raise _fail(
            "input_too_large",
            f"Input PDF is {format_size(size)}, exceeding the configured limit of "
            f"{format_size(settings.max_input_bytes)}.",
        )

    pw = _read_password(password, password_stdin)
    data = input_path.read_bytes()

    try:
        report = inspector.inspect_isolated(
            data, filename=input_path.name, password=pw, settings=settings
        )
    except exc.PdfSanitizerError as error:
        raise _fail(error.code, error.user_message)

    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _print_inspection_report(report)


@app.command("version")
def cmd_version() -> None:
    """Print pdf_sanitizer and key library versions."""
    from pdf_sanitizer.version_info import collect_version_info

    info = collect_version_info()
    typer.echo(f"pdf-sanitizer {info.pdf_sanitizer_version}")
    typer.echo(f"python {info.python_version}")
    for name, lib_version in info.library_versions.items():
        typer.echo(f"  {name}: {lib_version}")


if __name__ == "__main__":  # pragma: no cover
    app()
