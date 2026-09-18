from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from pdf_sanitizer.config import Settings
from pdf_sanitizer.persistent_config import (
    BY_CLI_KEY,
    load_persisted_config,
    reset_persisted_config,
    resolve_config_path,
    write_persisted_config,
)
from pdf_sanitizer.sizes import SizeParseError, format_size, parse_size, to_docker_size_string


# --------------------------------------------------------------------------- #
# Built-in defaults == the project's recommended configuration
# --------------------------------------------------------------------------- #


def test_defaults_match_recommended_configuration() -> None:
    settings = Settings()
    assert settings.max_pages == 300
    assert settings.max_input_bytes == 524_288_000  # 500 MiB
    assert settings.max_output_bytes == 3 * 1024**3  # 3 GiB
    assert settings.max_memory_bytes == 2 * 1024**3  # 2 GiB
    assert settings.processing_timeout_seconds == 600
    assert settings.render_dpi == 150
    assert settings.output_image_format == "jpeg"
    assert settings.jpeg_quality == 90
    assert settings.tmpfs_size == 2 * 1024**3  # 2 GiB


def test_settings_has_no_leftover_api_concurrency_setting() -> None:
    assert not hasattr(Settings(), "api_max_concurrent_jobs")


# --------------------------------------------------------------------------- #
# max_input_bytes (formerly max_upload_bytes) -- env var + legacy alias
# --------------------------------------------------------------------------- #


def test_max_input_bytes_is_overridable_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDF_SANITIZER_MAX_INPUT_BYTES", "1048576")
    assert Settings().max_input_bytes == 1_048_576


def test_max_input_bytes_accepts_human_readable_size() -> None:
    assert Settings(max_input_bytes="500M").max_input_bytes == 524_288_000
    assert Settings(max_input_bytes="1G").max_input_bytes == 1024**3


def test_legacy_max_upload_bytes_env_var_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDF_SANITIZER_MAX_UPLOAD_BYTES", "2097152")
    assert Settings().max_input_bytes == 2_097_152


def test_legacy_max_worker_memory_bytes_env_var_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDF_SANITIZER_MAX_WORKER_MEMORY_BYTES", "268435456")
    assert Settings().max_memory_bytes == 268_435_456


def test_canonical_env_var_wins_over_legacy_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDF_SANITIZER_MAX_UPLOAD_BYTES", "111")
    monkeypatch.setenv("PDF_SANITIZER_MAX_INPUT_BYTES", "222")
    assert Settings().max_input_bytes == 222


# --------------------------------------------------------------------------- #
# Image format / JPEG quality / DPI validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["png", "jpeg"])
def test_valid_output_image_formats_are_accepted(value: str) -> None:
    assert Settings(output_image_format=value).output_image_format == value


def test_invalid_output_image_format_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(output_image_format="gif")


@pytest.mark.parametrize("quality", [1, 50, 100])
def test_valid_jpeg_quality_is_accepted(quality: int) -> None:
    assert Settings(jpeg_quality=quality).jpeg_quality == quality


@pytest.mark.parametrize("quality", [0, -1, 101, 1000])
def test_invalid_jpeg_quality_is_rejected(quality: int) -> None:
    with pytest.raises(ValidationError):
        Settings(jpeg_quality=quality)


@pytest.mark.parametrize("dpi", [36, 120, 150, 200, 300])
def test_valid_dpi_is_accepted(dpi: int) -> None:
    assert Settings(render_dpi=dpi).render_dpi == dpi


@pytest.mark.parametrize("dpi", [0, 35, -150, 601])
def test_invalid_dpi_is_rejected(dpi: int) -> None:
    with pytest.raises(ValidationError):
        Settings(render_dpi=dpi)


def test_max_render_dpi_below_render_dpi_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(render_dpi=200, max_render_dpi=150)


# --------------------------------------------------------------------------- #
# Other limits
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", [1, 300, 1000])
def test_valid_max_pages_is_accepted(value: int) -> None:
    assert Settings(max_pages=value).max_pages == value


@pytest.mark.parametrize("value", [0, -1])
def test_invalid_max_pages_is_rejected(value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(max_pages=value)


def test_max_input_bytes_accepts_human_sizes_from_the_brief() -> None:
    assert Settings(max_input_bytes="524288000").max_input_bytes == 524_288_000


def test_max_output_bytes_accepts_human_sizes_from_the_brief() -> None:
    assert Settings(max_output_bytes="3221225472").max_output_bytes == 3_221_225_472
    assert Settings(max_output_bytes="3G").max_output_bytes == 3_221_225_472


@pytest.mark.parametrize("value", [1, 600, 3600])
def test_valid_timeout_is_accepted(value: int) -> None:
    assert Settings(processing_timeout_seconds=value).processing_timeout_seconds == value


@pytest.mark.parametrize("value", [0, -1])
def test_invalid_timeout_is_rejected(value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(processing_timeout_seconds=value)


def test_memory_limit_none_disables_rlimit() -> None:
    assert Settings(max_memory_bytes=None).max_memory_bytes is None


@pytest.mark.parametrize("value", ["1G", "4G", 2 * 1024**3])
def test_valid_memory_limit_is_accepted(value) -> None:
    settings = Settings(max_memory_bytes=value)
    assert settings.max_memory_bytes == parse_size(value) if isinstance(value, str) else value


# --------------------------------------------------------------------------- #
# sizes.py: parse_size / format_size / to_docker_size_string
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("500M", 524_288_000),
        ("1G", 1024**3),
        ("3G", 3 * 1024**3),
        ("512Mi", 512 * 1024**2),
        ("1.5G", int(1.5 * 1024**3)),
        ("524288000", 524_288_000),
        (524_288_000, 524_288_000),
        ("0", 0),
        ("2k", 2048),
        ("4t", 4 * 1024**4),
    ],
)
def test_parse_size_accepts_valid_values(raw, expected: int) -> None:
    assert parse_size(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "abc", "-5M", "5X", "5.5", "1.5.5G", None, [], {}],
)
def test_parse_size_rejects_invalid_values(raw) -> None:
    with pytest.raises((SizeParseError, TypeError)):
        parse_size(raw)


def test_parse_size_rejects_negative_int() -> None:
    with pytest.raises(SizeParseError):
        parse_size(-1)


def test_parse_size_rejects_bool() -> None:
    with pytest.raises(SizeParseError):
        parse_size(True)


@pytest.mark.parametrize(
    ("num_bytes", "expected"),
    [
        (524_288_000, "500 MiB"),
        (3 * 1024**3, "3 GiB"),
        (4 * 1024**3, "4 GiB"),
        (150, "150 B"),
        (1024, "1 KiB"),
    ],
)
def test_format_size_matches_expected_strings(num_bytes: int, expected: str) -> None:
    assert format_size(num_bytes) == expected


def test_format_size_uses_two_decimals_for_non_exact_values() -> None:
    value = format_size(2_018_634_198)
    assert value.endswith(" GiB")
    assert "1.88" in value


def test_to_docker_size_string_prefers_largest_exact_unit() -> None:
    assert to_docker_size_string(2 * 1024**3) == "2g"
    assert to_docker_size_string(512 * 1024**2) == "512m"
    assert to_docker_size_string(0) == "0"


# --------------------------------------------------------------------------- #
# Persisted configuration file: load / write / reset, and Settings layering
# --------------------------------------------------------------------------- #


def test_settings_uses_persisted_config_when_no_env_or_kwarg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / ".env"
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(config_path))
    write_persisted_config(
        {
            "PDF_SANITIZER_MAX_PAGES": "1000",
            "PDF_SANITIZER_RENDER_DPI": "200",
            "PDF_SANITIZER_JPEG_QUALITY": "80",
        }
    )
    settings = Settings()
    assert settings.max_pages == 1000
    assert settings.render_dpi == 200
    assert settings.jpeg_quality == 80
    # Untouched fields still fall back to their built-in default.
    assert settings.max_output_bytes == 3 * 1024**3


def test_real_env_var_wins_over_persisted_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / ".env"
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(config_path))
    write_persisted_config({"PDF_SANITIZER_RENDER_DPI": "200"})
    monkeypatch.setenv("PDF_SANITIZER_RENDER_DPI", "99")
    assert Settings().render_dpi == 99


def test_explicit_kwarg_wins_over_persisted_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / ".env"
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(config_path))
    write_persisted_config({"PDF_SANITIZER_RENDER_DPI": "200"})
    assert Settings(render_dpi=42).render_dpi == 42


def test_missing_persisted_file_is_not_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(tmp_path / "does-not-exist.env"))
    assert load_persisted_config() == {}
    assert Settings().max_pages == 300  # built-in default, untouched


def test_reset_persisted_config_removes_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / ".env"
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(config_path))
    write_persisted_config({"PDF_SANITIZER_MAX_PAGES": "1000"})
    assert config_path.exists()
    assert reset_persisted_config() is True
    assert not config_path.exists()
    assert Settings().max_pages == 300


def test_reset_persisted_config_on_missing_file_returns_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(tmp_path / "nope.env"))
    assert reset_persisted_config() is False


def test_write_persisted_config_is_a_complete_overwrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / ".env"
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(config_path))
    write_persisted_config({"PDF_SANITIZER_MAX_PAGES": "1000", "PDF_SANITIZER_RENDER_DPI": "200"})
    write_persisted_config({"PDF_SANITIZER_MAX_PAGES": "500"})
    persisted = load_persisted_config()
    assert persisted["PDF_SANITIZER_MAX_PAGES"] == "500"
    assert "PDF_SANITIZER_RENDER_DPI" not in persisted


def test_persisted_config_file_has_restrictive_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import stat

    config_path = tmp_path / ".env"
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(config_path))
    write_persisted_config({"PDF_SANITIZER_MAX_PAGES": "1000"})
    mode = stat.S_IMODE(config_path.stat().st_mode)
    assert mode == stat.S_IRUSR | stat.S_IWUSR


def test_resolve_config_path_defaults_to_cwd_dot_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PDF_SANITIZER_CONFIG_FILE", raising=False)
    assert resolve_config_path() == Path.cwd() / ".env"


def test_load_persisted_config_ignores_comments_and_blank_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / ".env"
    config_path.write_text(
        "# a comment\n\nPDF_SANITIZER_MAX_PAGES=42\n   \nnot_a_valid_line\nPDF_SANITIZER_RENDER_DPI=150\n"
    )
    monkeypatch.setenv("PDF_SANITIZER_CONFIG_FILE", str(config_path))
    persisted = load_persisted_config()
    assert persisted == {"PDF_SANITIZER_MAX_PAGES": "42", "PDF_SANITIZER_RENDER_DPI": "150"}


# --------------------------------------------------------------------------- #
# ManagedSetting registry: every CLI key parses/validates/displays sensibly
# --------------------------------------------------------------------------- #


def test_every_managed_setting_round_trips_through_settings() -> None:
    """Each `config`-CLI-exposed field is a real Settings field and its
    parsed value can construct a valid Settings instance.
    """
    settings = Settings()
    for managed in BY_CLI_KEY.values():
        current = getattr(settings, managed.field)
        assert managed.display(current)  # never raises, never empty


@pytest.mark.parametrize("cli_key", list(BY_CLI_KEY))
def test_managed_setting_parse_rejects_garbage(cli_key: str) -> None:
    managed = BY_CLI_KEY[cli_key]
    with pytest.raises(ValueError):
        managed.parse("not-a-number-or-format")
