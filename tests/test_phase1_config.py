"""Kiểm thử tải và validate cấu hình Phase 1."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sigma2wazuh.config import ConfigError, find_project_root, load_config, validate_raw


def _write_config(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def _valid_payload() -> dict:
    return {
        "project": {"name": "demo"},
        "paths": {
            "rules_root": "input/sigma_rules",
            "output": "output",
            "reports": "reports",
        },
        "logging": {"level": "INFO"},
        "wazuh": {
            "rule_id_base": 100000,
            "if_sid": 61603,
            "level_map": {
                "informational": 3,
                "low": 5,
                "medium": 8,
                "high": 12,
                "critical": 15,
            },
        },
    }


def test_package_importable() -> None:
    import sigma2wazuh

    assert sigma2wazuh.__version__ == "0.8.0"


def test_default_config_loads() -> None:
    root = find_project_root()
    cfg = load_config(project_root=root)
    assert cfg.project_name == "sigma2wazuh"
    assert cfg.rules_root == (root / "input" / "sigma_rules").resolve()
    assert cfg.output_dir == (root / "output").resolve()
    assert cfg.reports_dir == (root / "reports").resolve()
    assert cfg.logging_level == "INFO"
    assert cfg.wazuh_rule_id_base == 100000
    assert cfg.wazuh_if_sid == 61603
    assert cfg.wazuh_level_map["medium"] == 8
    assert cfg.wazuh_level_map["critical"] == 15


def test_missing_key_raises() -> None:
    payload = _valid_payload()
    del payload["paths"]["output"]
    with pytest.raises(ConfigError, match="paths.output"):
        validate_raw(payload)


def test_wrong_type_raises() -> None:
    payload = _valid_payload()
    payload["logging"]["level"] = 1
    with pytest.raises(ConfigError, match="logging.level"):
        validate_raw(payload)


def test_invalid_level_raises() -> None:
    payload = _valid_payload()
    payload["logging"]["level"] = "VERBOSE"
    with pytest.raises(ConfigError, match="Invalid logging.level"):
        validate_raw(payload)


def test_relative_paths_resolve_to_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Giả lập project root riêng; CWD cố tình khác root để chứng minh không resolve theo CWD.
    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    other_cwd = tmp_path / "elsewhere"
    other_cwd.mkdir()
    monkeypatch.chdir(other_cwd)

    cfg_path = _write_config(project / "config" / "t.yaml", _valid_payload())
    cfg = load_config(cfg_path, project_root=project)
    assert cfg.output_dir == (project / "output").resolve()
    assert not str(cfg.output_dir).startswith(str(other_cwd.resolve()))


def test_config_file_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Config file not found"):
        load_config(tmp_path / "nope.yaml", project_root=tmp_path)


def test_pyproject_pins_match_requirements() -> None:
    root = find_project_root()
    req_pins: list[str] = []
    for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            req_pins.append(stripped)

    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    for pin in req_pins:
        assert pin in pyproject, f"pyproject.toml missing pin {pin}"
    assert req_pins == [
        "pysigma==2.0.2",
        "PyYAML==6.0.3",
        "pytest==8.4.2",
    ]
