"""Kiểm thử CLI Phase 1: help, version, validate-config, exit codes."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from sigma2wazuh.cli import main
from sigma2wazuh.logging_setup import LOGGER_NAME


def _write_config(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def _valid_payload() -> dict:
    return {
        "project": {"name": "cli-demo"},
        "paths": {
            "rules_root": "input/sigma_rules",
            "output": "output",
            "reports": "reports",
        },
        "logging": {"level": "WARNING"},
    }


def test_cli_help_exits_zero() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0


def test_cli_version_exits_zero() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0


def test_validate_config_ok() -> None:
    assert main(["validate-config"]) == 0


def test_validate_config_bad_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("project:\n  name: x\n", encoding="utf-8")
    code = main(["--config", str(bad), "validate-config"])
    captured = capsys.readouterr()
    assert code == 1
    assert "ConfigError" in captured.err


def test_config_override_flag(tmp_path: Path) -> None:
    cfg = _write_config(tmp_path / "ok.yaml", _valid_payload())
    # load_config vẫn cần tìm project root qua pyproject.toml từ CWD (repo thật).
    assert main(["--config", str(cfg), "validate-config"]) == 0


def test_cli_log_level_overrides_config(tmp_path: Path) -> None:
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    cfg = _write_config(tmp_path / "warn.yaml", _valid_payload())
    assert main(["--config", str(cfg), "--log-level", "DEBUG", "validate-config"]) == 0
    assert logger.level == logging.DEBUG


def test_argparse_unknown_exits_two() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["validate-config", "--unknown"])
    assert excinfo.value.code == 2


def test_help_does_not_list_convert(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    help_text = capsys.readouterr().out
    assert "validate-config" in help_text
    # Không có subcommand convert; từ "converter" trong mô tả vẫn được phép.
    assert "{convert}" not in help_text
    assert "\n  convert " not in help_text
