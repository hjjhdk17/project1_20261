"""Phase 3: phân loại rule ELIGIBLE / UNSUPPORTED / FAILED.

Reuse parse_batch từ Phase 2. Không map field, không sinh Wazuh XML.
Phase 4 tái dùng match_mvp_condition / resolve_rule_file và đọc ``detection``
đã gắn sẵn trên record (không đọc lại file trong mapper).
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Sequence

import yaml

from sigma2wazuh.parsing import parse_batch, reason_histogram, report_meta

# Allowlist MVP (SRS §8). Exact match (không có |) luôn được phép.
ALLOWED_FIELDS = frozenset(
    {"Image", "CommandLine", "ParentImage", "OriginalFileName", "User"}
)
ALLOWED_MODIFIERS = frozenset(
    {"endswith", "startswith", "contains", "contains|all"}
)

# Condition shapes đã công bố (chuỗi đã normalize whitespace).
_RE_SINGLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RE_ALL_OF = re.compile(r"^all of ([A-Za-z_][A-Za-z0-9_]*)\*$")
_RE_ONE_OF = re.compile(r"^1 of ([A-Za-z_][A-Za-z0-9_]*)\*$")
_RE_AND_NOT = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*) and not ([A-Za-z_][A-Za-z0-9_]*)$"
)


def _normalize_condition(condition: str) -> str:
    return " ".join(condition.split())


def extract_features(detection: object) -> dict[str, Any]:
    """Trích field, modifier chain và condition từ khối detection YAML."""
    fields: set[str] = set()
    modifiers: set[str] = set()
    selection_names: list[str] = []
    condition: str | None = None
    keyword_search = False
    list_of_maps = False
    empty_selection = False

    if not isinstance(detection, dict):
        return {
            "fields": [],
            "modifiers": [],
            "selection_names": [],
            "condition": None,
            "keyword_search": False,
            "list_of_maps": False,
            "empty_selection": False,
        }

    for key, value in detection.items():
        if key == "condition":
            if isinstance(value, str):
                condition = _normalize_condition(value)
            continue

        selection_names.append(key)
        # Phân loại shape selection trước khi flatten field.
        if isinstance(value, list):
            if not value:
                empty_selection = True  # selection: []
            if any(isinstance(b, dict) for b in value):
                list_of_maps = True  # OR ngầm — không hỗ trợ (giống condition `or`)
            if any(not isinstance(b, dict) for b in value):
                keyword_search = True  # list string / scalar
            blocks = value
        elif isinstance(value, dict):
            if not value:
                empty_selection = True  # selection: {}
            blocks = [value]
        elif value is None:
            empty_selection = True  # selection: null
            blocks = []
        else:
            keyword_search = True  # keyword search dạng scalar
            blocks = []

        for block in blocks:
            if not isinstance(block, dict):
                continue
            for field_key in block:
                if not isinstance(field_key, str):
                    continue
                if "|" in field_key:
                    name, mod = field_key.split("|", 1)
                    fields.add(name)
                    modifiers.add(mod)
                else:
                    fields.add(field_key)

    return {
        "fields": sorted(fields),
        "modifiers": sorted(modifiers),
        "selection_names": sorted(selection_names),
        "condition": condition,
        "keyword_search": keyword_search,
        "list_of_maps": list_of_maps,
        "empty_selection": empty_selection,
    }


def match_mvp_condition(
    condition: str | None, selection_names: list[str]
) -> dict[str, Any] | None:
    """Nhận diện 1 trong 4 condition shape MVP.

    Trả dict ``kind`` hoặc None nếu không khớp / selection thiếu.
    Mapper Phase 4 dựng cây AND/OR/NOT từ kết quả này — không viết regex riêng.
    """
    if condition is None or not condition.strip():
        return None

    names = set(selection_names)

    if _RE_SINGLE.match(condition):
        if condition not in names:
            return None
        return {"kind": "single", "name": condition}

    match = _RE_ALL_OF.match(condition)
    if match:
        prefix = match.group(1)
        matched = sorted(n for n in selection_names if n.startswith(prefix))
        if not matched:
            return None
        return {"kind": "all_of", "prefix": prefix, "names": matched}

    match = _RE_ONE_OF.match(condition)
    if match:
        prefix = match.group(1)
        matched = sorted(n for n in selection_names if n.startswith(prefix))
        if not matched:
            return None
        return {"kind": "one_of", "prefix": prefix, "names": matched}

    match = _RE_AND_NOT.match(condition)
    if match:
        left, right = match.group(1), match.group(2)
        if left not in names or right not in names:
            return None
        return {"kind": "and_not", "left": left, "right": right}

    return None


def _condition_allowed(condition: str | None, selection_names: list[str]) -> bool:
    """True nếu condition khớp một shape MVP (wrapper mỏng quanh match_mvp_condition)."""
    return match_mvp_condition(condition, selection_names) is not None


def classify(features: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    """So features với allowlist. Trả ELIGIBLE|UNSUPPORTED (FAILED chỉ từ analyze_batch)."""
    unsupported: list[dict[str, str]] = []

    if features.get("keyword_search"):
        unsupported.append(
            {
                "code": "KEYWORD_SEARCH_UNSUPPORTED",
                "message": "Keyword search (non-map selection values) is out of MVP scope.",
            }
        )
    if features.get("list_of_maps"):
        unsupported.append(
            {
                "code": "LIST_OF_MAPS_UNSUPPORTED",
                "message": "List-of-maps selection (implicit OR) is out of MVP scope.",
            }
        )
    if features.get("empty_selection"):
        unsupported.append(
            {
                "code": "EMPTY_SELECTION",
                "message": "Empty selection map/list has no matchable fields.",
            }
        )

    for field in features["fields"]:
        if field not in ALLOWED_FIELDS:
            unsupported.append(
                {
                    "code": "FIELD_UNSUPPORTED",
                    "message": f"Field not in allowlist: {field}",
                }
            )

    for mod in features["modifiers"]:
        if mod not in ALLOWED_MODIFIERS:
            unsupported.append(
                {
                    "code": "MODIFIER_UNSUPPORTED",
                    "message": f"Modifier not in allowlist: {mod}",
                }
            )

    condition = features["condition"]
    if not _condition_allowed(condition, features["selection_names"]):
        unsupported.append(
            {
                "code": "CONDITION_UNSUPPORTED",
                "message": f"Condition shape not in allowlist: {condition!r}",
            }
        )

    if unsupported:
        return "UNSUPPORTED", unsupported
    return "ELIGIBLE", []


def resolve_rule_file(
    record: dict[str, Any],
    *,
    path_base: Path | None,
    input_path: Path,
) -> Path | None:
    """Ghép lại path file từ rule_path trong record parse."""
    rule_path = record.get("rule_path")
    if not isinstance(rule_path, str) or not rule_path:
        return None
    path = Path(rule_path)
    if path.is_file():
        return path.resolve()
    if path_base is not None:
        candidate = (path_base / rule_path).resolve()
        if candidate.is_file():
            return candidate
    # Fallback: rule_path tương đối so với thư mục input.
    if input_path.is_dir():
        candidate = (input_path / rule_path).resolve()
        if candidate.is_file():
            return candidate
    return None


def analyze_batch(
    input_path: Path | Sequence[Path],
    *,
    path_base: Path | None = None,
    source_commit: str | None = None,
) -> dict[str, Any]:
    """Parse rồi classify. Parse lỗi → support_status null; lỗi tool → FAILED.

    Khi đọc YAML thành công, gắn ``detection`` vào record để Phase 4 map
    không cần đọc lại file.
    """
    started = time.perf_counter()
    parsed = parse_batch(
        input_path, path_base=path_base, source_commit=source_commit
    )
    raw_input = parsed["input"]
    if isinstance(raw_input, str):
        input_resolved = Path(raw_input)
    elif raw_input:
        input_resolved = Path(raw_input[0])
    else:
        input_resolved = Path(".")

    records: list[dict[str, Any]] = []
    eligible = unsupported = failed = 0

    for record in parsed["records"]:
        item = dict(record)
        if item.get("parse_status") != "OK":
            item["support_status"] = None
            item["features"] = None
            item["unsupported_features"] = []
            item["detection"] = None
            failed += 1
            records.append(item)
            continue

        path = resolve_rule_file(
            item, path_base=path_base, input_path=input_resolved
        )
        if path is None:
            # Lỗi công cụ (không đọc lại được file) → FAILED, không tính UNSUPPORTED.
            item["support_status"] = "FAILED"
            item["features"] = None
            item["unsupported_features"] = [
                {
                    "code": "SOURCE_UNAVAILABLE",
                    "message": "Cannot re-read rule file for feature extraction.",
                }
            ]
            item["detection"] = None
            failed += 1
            records.append(item)
            continue

        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            # Lỗi I/O/YAML lúc extract → FAILED (SRS: khác UNSUPPORTED).
            item["support_status"] = "FAILED"
            item["features"] = None
            item["unsupported_features"] = [
                {
                    "code": "FEATURE_EXTRACT_ERROR",
                    "message": f"{type(exc).__name__}: {exc}",
                }
            ]
            item["detection"] = None
            failed += 1
            records.append(item)
            continue

        detection = data.get("detection") if isinstance(data, dict) else None
        features = extract_features(detection)
        status, reasons = classify(features)
        item["support_status"] = status
        item["features"] = features
        item["unsupported_features"] = reasons
        item["detection"] = detection  # Phase 4 đọc từ đây
        if status == "ELIGIBLE":
            eligible += 1
        else:
            unsupported += 1
        records.append(item)

    return {
        **report_meta(started),
        "input": parsed["input"],
        "records": records,
        "summary": {
            "total": len(records),
            "parse_ok": sum(1 for r in records if r.get("parse_status") == "OK"),
            "eligible": eligible,
            "unsupported": unsupported,
            "failed": failed,
            "reasons": reason_histogram(records),
        },
    }


__all__ = [
    "ALLOWED_FIELDS",
    "ALLOWED_MODIFIERS",
    "analyze_batch",
    "classify",
    "extract_features",
    "match_mvp_condition",
    "resolve_rule_file",
]
