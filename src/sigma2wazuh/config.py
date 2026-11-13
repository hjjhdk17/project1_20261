"""Đọc và kiểm tra cấu hình YAML của dự án."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

# Tên file cấu hình mặc định nằm dưới project root.
DEFAULT_CONFIG_RELATIVE = Path("config") / "default.yaml"

# Các mức logging được chấp nhận (khớp stdlib logging).
_ALLOWED_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


class ConfigError(Exception):
    """Lỗi tải hoặc kiểm tra cấu hình — CLI map sang exit code 1."""


@dataclass(frozen=True)
class ProjectConfig:
    """Cấu hình đã kiểm tra; đường dẫn đã resolve thành absolute theo project root."""

    project_name: str
    rules_root: Path
    output_dir: Path
    reports_dir: Path
    logging_level: str
    # Phase 5 — sinh XML Wazuh (từ nhánh wazuh: trong YAML).
    wazuh_rule_id_base: int
    wazuh_if_sid: int
    wazuh_level_map: Mapping[str, int]


def find_project_root(start: Path | None = None) -> Path:
    """Walk-up từ ``start`` (hoặc CWD) đến thư mục chứa ``pyproject.toml``.

    Không dùng CWD để resolve path trong YAML; chỉ dùng CWD làm điểm bắt đầu tìm root.
    """
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise ConfigError(
        f"Cannot find project root (no pyproject.toml) starting from {current}"
    )


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    """Đảm bảo ``value`` là mapping YAML; nếu không thì báo lỗi rõ key."""
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a mapping, got {type(value).__name__}")
    return value


def _require_str(data: dict[str, Any], key: str, label: str) -> str:
    """Lấy một key bắt buộc kiểu string không rỗng."""
    if key not in data:
        raise ConfigError(f"Missing required key: {label}")
    value = data[key]
    if not isinstance(value, str):
        raise ConfigError(
            f"Key {label} must be a string, got {type(value).__name__}"
        )
    if not value.strip():
        raise ConfigError(f"Key {label} must be a non-empty path string")
    return value


def _require_int(data: dict[str, Any], key: str, label: str) -> int:
    """Lấy một key bắt buộc kiểu int (YAML có thể trả int)."""
    if key not in data:
        raise ConfigError(f"Missing required key: {label}")
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(
            f"Key {label} must be an integer, got {type(value).__name__}"
        )
    return value


def _resolve_path(project_root: Path, relative: str, label: str) -> Path:
    """Resolve path trong YAML theo project root (không theo CWD)."""
    path = Path(relative)
    if path.is_absolute():
        return path
    if not relative.strip():
        raise ConfigError(f"Key {label} must be a non-empty path string")
    return (project_root / path).resolve()


def _parse_wazuh(section: dict[str, Any]) -> dict[str, Any]:
    """Kiểm tra nhánh wazuh: rule_id_base, if_sid, level_map."""
    rule_id_base = _require_int(section, "rule_id_base", "wazuh.rule_id_base")
    if_sid = _require_int(section, "if_sid", "wazuh.if_sid")
    if rule_id_base < 0 or if_sid < 0:
        raise ConfigError("wazuh.rule_id_base and wazuh.if_sid must be >= 0")

    raw_map = _require_mapping(section.get("level_map"), "wazuh.level_map")
    if not raw_map:
        raise ConfigError("wazuh.level_map must be a non-empty mapping")
    level_map: dict[str, int] = {}
    for key, value in raw_map.items():
        if not isinstance(key, str) or not key.strip():
            raise ConfigError(
                f"wazuh.level_map keys must be non-empty strings, got {key!r}"
            )
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(
                f"wazuh.level_map[{key!r}] must be an integer, "
                f"got {type(value).__name__}"
            )
        if value < 0 or value > 16:
            raise ConfigError(
                f"wazuh.level_map[{key!r}]={value} out of Wazuh level range 0..16"
            )
        level_map[key.strip().lower()] = value
    return {
        "rule_id_base": rule_id_base,
        "if_sid": if_sid,
        "level_map": level_map,
    }


def validate_raw(data: object) -> dict[str, Any]:
    """Kiểm tra cấu trúc thô của YAML trước khi resolve path.

    Trả về dict đã chuẩn hóa (các nhánh con vẫn là dict) để ``load_config`` dùng tiếp.
    """
    root = _require_mapping(data, "Config root")

    project = _require_mapping(root.get("project"), "project")
    _require_str(project, "name", "project.name")

    paths = _require_mapping(root.get("paths"), "paths")
    _require_str(paths, "rules_root", "paths.rules_root")
    _require_str(paths, "output", "paths.output")
    _require_str(paths, "reports", "paths.reports")

    logging_section = _require_mapping(root.get("logging"), "logging")
    level = _require_str(logging_section, "level", "logging.level").upper()
    if level not in _ALLOWED_LEVELS:
        allowed = "|".join(sorted(_ALLOWED_LEVELS))
        raise ConfigError(
            f"Invalid logging.level: {logging_section['level']!r}; "
            f"expected {allowed}"
        )
    # Chuẩn hóa level về chữ hoa để downstream dùng thống nhất.
    logging_section = dict(logging_section)
    logging_section["level"] = level

    wazuh = _parse_wazuh(_require_mapping(root.get("wazuh"), "wazuh"))
    return {
        "project": project,
        "paths": paths,
        "logging": logging_section,
        "wazuh": wazuh,
    }


def load_config(
    config_path: Path | None = None,
    *,
    project_root: Path | None = None,
) -> ProjectConfig:
    """Đọc file YAML, kiểm tra key/kiểu, resolve path theo project root."""
    root = project_root if project_root is not None else find_project_root()
    path = config_path if config_path is not None else root / DEFAULT_CONFIG_RELATIVE
    path = path.expanduser()
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in config file {path}: {exc}") from exc

    checked = validate_raw(raw)
    wazuh = checked["wazuh"]
    return ProjectConfig(
        project_name=checked["project"]["name"].strip(),
        rules_root=_resolve_path(root, checked["paths"]["rules_root"], "paths.rules_root"),
        output_dir=_resolve_path(root, checked["paths"]["output"], "paths.output"),
        reports_dir=_resolve_path(root, checked["paths"]["reports"], "paths.reports"),
        logging_level=checked["logging"]["level"],
        wazuh_rule_id_base=wazuh["rule_id_base"],
        wazuh_if_sid=wazuh["if_sid"],
        wazuh_level_map=dict(wazuh["level_map"]),
    )
