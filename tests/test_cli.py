"""CLI smoke tests using Typer's CliRunner."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pdf_sanitizer.cli import app
from tests import pdf_factory as pf

runner = CliRunner()


def test_sanitize_command_writes_output(tmp_path: Path) -> None:
    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(pf.pdf_normal(1))
    output_path = tmp_path / "output.pdf"

    result = runner.invoke(app, ["sanitize", str(input_path), "-o", str(output_path)])

    assert result.exit_code == 0, result.output
    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_sanitize_command_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(pf.pdf_normal(1))
    output_path = tmp_path / "output.pdf"
    output_path.write_bytes(b"pre-existing")

    result = runner.invoke(app, ["sanitize", str(input_path), "-o", str(output_path)])

    assert result.exit_code != 0
    assert output_path.read_bytes() == b"pre-existing"


def test_sanitize_command_with_force_overwrites(tmp_path: Path) -> None:
    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(pf.pdf_normal(1))
    output_path = tmp_path / "output.pdf"
    output_path.write_bytes(b"pre-existing")

    result = runner.invoke(app, ["sanitize", str(input_path), "-o", str(output_path), "--force"])

    assert result.exit_code == 0, result.output
    assert output_path.read_bytes() != b"pre-existing"


def test_sanitize_command_rejects_non_pdf(tmp_path: Path) -> None:
    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(pf.not_a_pdf_bytes())
    output_path = tmp_path / "output.pdf"

    result = runner.invoke(app, ["sanitize", str(input_path), "-o", str(output_path)])

    assert result.exit_code != 0
    assert not output_path.exists()


def test_inspect_command_reports_javascript(tmp_path: Path) -> None:
    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(pf.pdf_with_javascript())

    result = runner.invoke(app, ["inspect", str(input_path), "--json"])

    assert result.exit_code == 0, result.output
    assert '"javascript_present": true' in result.output


def test_validate_command_on_sanitized_output(tmp_path: Path) -> None:
    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(pf.pdf_with_javascript())
    output_path = tmp_path / "output.pdf"

    sanitize_result = runner.invoke(app, ["sanitize", str(input_path), "-o", str(output_path)])
    assert sanitize_result.exit_code == 0, sanitize_result.output

    validate_result = runner.invoke(app, ["validate", str(output_path)])
    assert validate_result.exit_code == 0, validate_result.output
    assert "PASSED" in validate_result.output


def test_validate_command_fails_on_dangerous_pdf(tmp_path: Path) -> None:
    dangerous_path = tmp_path / "dangerous.pdf"
    dangerous_path.write_bytes(pf.pdf_with_javascript())

    result = runner.invoke(app, ["validate", str(dangerous_path)])

    assert result.exit_code == 1
    assert "REJECTED" in result.output


def test_version_command_runs() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "pdf-sanitizer" in result.output


# --------------------------------------------------------------------------- #
# `config` / `status` commands
# --------------------------------------------------------------------------- #


def test_config_command_shows_recommended_defaults_with_no_persisted_file() -> None:
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0, result.output
    assert "Pages: 300" in result.output
    assert "Input limit: 500 MiB" in result.output
    assert "Output limit: 3 GiB" in result.output
    assert "RAM: 2 GiB" in result.output
    assert "Timeout: 600 seconds" in result.output
    assert "DPI: 150" in result.output
    assert "Image format: jpeg" in result.output
    assert "JPEG quality: 90" in result.output
    assert "not created yet" in result.output


def test_status_command_matches_config_get() -> None:
    config_result = runner.invoke(app, ["config", "get"])
    status_result = runner.invoke(app, ["status"])
    assert config_result.exit_code == status_result.exit_code == 0
    assert config_result.output == status_result.output


def test_config_set_with_flags_then_get_reflects_new_values() -> None:
    set_result = runner.invoke(
        app,
        [
            "config",
            "set",
            "--max-pages",
            "1000",
            "--max-input-size",
            "500M",
            "--max-output-size",
            "3G",
            "--memory",
            "4G",
            "--timeout",
            "600",
            "--dpi",
            "150",
            "--format",
            "jpeg",
            "--jpeg-quality",
            "90",
        ],
    )
    assert set_result.exit_code == 0, set_result.output
    assert "OK" in set_result.output

    get_result = runner.invoke(app, ["config", "get"])
    assert "Pages: 1000" in get_result.output
    assert "RAM: 4 GiB" in get_result.output


def test_config_set_with_positional_key_value_form() -> None:
    result = runner.invoke(app, ["config", "set", "dpi", "120"])
    assert result.exit_code == 0, result.output
    get_result = runner.invoke(app, ["config", "get"])
    assert "DPI: 120" in get_result.output


def test_config_set_rejects_invalid_value_and_writes_nothing() -> None:
    before = runner.invoke(app, ["config", "get"]).output
    result = runner.invoke(app, ["config", "set", "--jpeg-quality", "150"])
    assert result.exit_code != 0
    after = runner.invoke(app, ["config", "get"]).output
    assert before == after  # all-or-nothing: nothing was persisted


def test_config_set_rejects_unknown_setting_name() -> None:
    result = runner.invoke(app, ["config", "set", "not-a-real-setting", "5"])
    assert result.exit_code != 0
    assert "unknown setting" in result.output


def test_config_reset_reverts_to_defaults() -> None:
    runner.invoke(app, ["config", "set", "--max-pages", "1000"])
    assert "Pages: 1000" in runner.invoke(app, ["config", "get"]).output

    reset_result = runner.invoke(app, ["config", "reset"])
    assert reset_result.exit_code == 0, reset_result.output

    after = runner.invoke(app, ["config", "get"]).output
    assert "Pages: 300" in after
    assert "not created yet" in after


def test_config_get_json_output_is_valid_json() -> None:
    import json

    result = runner.invoke(app, ["config", "get", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["max_pages"] == 300
    assert payload["output_image_format"] == "jpeg"
    assert "config_file" in payload


def test_sanitize_command_still_works_after_config_set(tmp_path: Path) -> None:
    """Compatibility: existing invocations keep working unchanged once
    persisted config exists, with no extra flags required (item 15).
    """
    runner.invoke(app, ["config", "set", "--dpi", "100", "--format", "png"])

    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(pf.pdf_normal(1))
    output_path = tmp_path / "output.pdf"

    result = runner.invoke(app, ["sanitize", str(input_path), "-o", str(output_path)])
    assert result.exit_code == 0, result.output
    assert output_path.exists() and output_path.stat().st_size > 0
