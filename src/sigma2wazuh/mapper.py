"""Phase 4: map rule ELIGIBLE sang IR mỏng (JSON).

Reuse analyze_batch. Không sinh Wazuh XML (Phase 5).
Không đọc lại file rule — dùng ``detection`` đã gắn trên record.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Sequence

import yaml
from sigma.types import SigmaString

from sigma2wazuh.parsing import reason_histogram, report_meta
from sigma2wazuh.support_analyzer import analyze_batch, match_mvp_condition

# Modifier Sigma → op trong IR.
_MODIFIER_TO_OP = {
    "endswith": "endswith",
    "startswith": "startswith",
    "contains": "contains",
    "contains|all": "contains_all",
}


def load_field_mapping(path: Path) -> dict[str, str]:
    """Đọc config/field_mapping.yaml → {SigmaField: wazuh_field}."""
    path = path.expanduser().resolve()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("fields"), dict):
        raise ValueError(f"Invalid field mapping file: {path}")
    out: dict[str, str] = {}
    for sigma_name, spec in data["fields"].items():
        if not isinstance(spec, dict) or "wazuh_field" not in spec:
            raise ValueError(f"Missing wazuh_field for {sigma_name!r} in {path}")
        out[str(sigma_name)] = str(spec["wazuh_field"])
    return out


def _as_value_list(raw: object) -> list[Any]:
    if isinstance(raw, list):
        return list(raw)
    return [raw]


def _diag(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _decode_sigma_values(
    values: list[Any],
    sigma_field: str,
) -> tuple[list[Any] | None, list[dict[str, str]]]:
    """int giữ nguyên; str → SigmaString một lần: contains_special → FAILED, else to_plain.

    Không check wildcard trên chuỗi đã decode (to_plain làm * wildcard và \\* literal
    đều thành '*'). Dùng contains_special() trước; IR lấy to_plain(regex=True) để
    không re-escape * / ? (cần cho literal đã escape trong Sigma).
    """
    out: list[Any] = []
    for v in values:
        if isinstance(v, int):
            out.append(v)
            continue
        s = SigmaString(v)
        if s.contains_special():
            return None, [
                _diag(
                    "WILDCARD_UNSUPPORTED",
                    f"Wildcard * or ? in values for field {sigma_field!r}: {values!r}",
                )
            ]
        # regex=True: literal thật (vd a\\*b → a*b), không gắn lại \\ trước * / ?.
        out.append(s.to_plain(regex=True))
    return out, []


def _make_pred(
    sigma_field: str,
    op: str,
    values: list[Any],
    field_map: dict[str, str],
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    """Tạo một node pred; lỗi mapping/wildcard/value → (None, diagnostics)."""
    if sigma_field not in field_map:
        return None, [
            _diag(
                "FIELD_MAPPING_MISSING",
                f"No wazuh_field mapping for Sigma field {sigma_field!r}",
            )
        ]
    # null / list rỗng / kiểu lạ → Phase 5 sẽ sinh rule sai (eq null, regex rỗng).
    if not values or any(type(v) not in (str, int) for v in values):
        return None, [
            _diag(
                "VALUE_UNSUPPORTED",
                f"Empty or non-str/int values for field {sigma_field!r}: {values!r}",
            )
        ]
    decoded, wild_err = _decode_sigma_values(values, sigma_field)
    if wild_err or decoded is None:
        return None, wild_err
    # Chuỗi rỗng sau decode → regex flag-only; MVP không match field rỗng (D-19).
    if any(isinstance(v, str) and v == "" for v in decoded):
        return None, [
            _diag(
                "VALUE_UNSUPPORTED",
                f"Empty or non-str/int values for field {sigma_field!r}: {values!r}",
            )
        ]
    return {
        "type": "pred",
        "sigma_field": sigma_field,
        "target_field": field_map[sigma_field],
        "op": op,
        "values": decoded,
        "case_insensitive": True,
    }, []


def _field_key_to_node(
    field_key: str,
    raw: object,
    field_map: dict[str, str],
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    """Một khóa selection (field hoặc field|mod) → node pred / or."""
    if "|" in field_key:
        sigma_field, mod = field_key.split("|", 1)
    else:
        sigma_field, mod = field_key, ""

    values = _as_value_list(raw)
    if mod == "contains|all":
        return _make_pred(sigma_field, "contains_all", values, field_map)

    if mod:
        op = _MODIFIER_TO_OP.get(mod)
        if op is None:
            return None, [
                _diag(
                    "MODIFIER_UNSUPPORTED",
                    f"Unknown or unsupported modifier {mod!r} on field {sigma_field!r}",
                )
            ]
    else:
        op = "eq"
    # List value (không phải contains|all) = OR các pred đơn.
    if len(values) > 1:
        children: list[dict[str, Any]] = []
        diags: list[dict[str, str]] = []
        for value in values:
            node, err = _make_pred(sigma_field, op, [value], field_map)
            if err:
                return None, err
            assert node is not None
            children.append(node)
        return {"type": "or", "children": children}, diags
    return _make_pred(sigma_field, op, values, field_map)


def build_selection_node(
    block: object, field_map: dict[str, str]
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    """Selection map → AND các field; ELIGIBLE chỉ còn dict (không list-of-maps)."""
    if not isinstance(block, dict) or not block:
        return None, [
            _diag("SELECTION_BUILD_ERROR", "Selection must be a non-empty map.")
        ]

    children: list[dict[str, Any]] = []
    for field_key, raw in block.items():
        if not isinstance(field_key, str):
            return None, [
                _diag("SELECTION_BUILD_ERROR", f"Non-string field key: {field_key!r}")
            ]
        node, err = _field_key_to_node(field_key, raw, field_map)
        if err:
            return None, err
        assert node is not None
        children.append(node)

    return {"type": "and", "children": children}, []


def build_condition_tree(match: dict[str, Any]) -> dict[str, Any]:
    """Dựng cây condition từ kết quả match_mvp_condition (không regex mới)."""
    kind = match["kind"]
    if kind == "single":
        return {"type": "ref", "selection": match["name"]}
    if kind == "all_of":
        return {
            "type": "and",
            "children": [{"type": "ref", "selection": n} for n in match["names"]],
        }
    if kind == "one_of":
        return {
            "type": "or",
            "children": [{"type": "ref", "selection": n} for n in match["names"]],
        }
    if kind == "and_not":
        return {
            "type": "and",
            "children": [
                {"type": "ref", "selection": match["left"]},
                {
                    "type": "not",
                    "child": {"type": "ref", "selection": match["right"]},
                },
            ],
        }
    raise ValueError(f"Unexpected condition kind: {kind!r}")


def _build_ir(
    record: dict[str, Any],
    detection: dict[str, Any],
    field_map: dict[str, str],
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    """Xây IR đầy đủ từ detection; lỗi → (None, diagnostics)."""
    features = record.get("features")
    if not isinstance(features, dict):
        return None, [
            _diag(
                "FEATURES_MISSING",
                "ELIGIBLE record has no features dict from analyze_batch.",
            )
        ]
    selection_names = features["selection_names"]
    condition_str = features["condition"]
    matched = match_mvp_condition(condition_str, selection_names)
    if matched is None:
        return None, [
            _diag(
                "CONDITION_SHAPE_UNEXPECTED",
                f"ELIGIBLE rule condition not recognized: {condition_str!r}",
            )
        ]

    selections: dict[str, Any] = {}
    for name in selection_names:
        node, err = build_selection_node(detection.get(name), field_map)
        if err:
            return None, err
        selections[name] = node

    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    logsource = metadata.get("logsource") if isinstance(metadata.get("logsource"), dict) else {}

    ir = {
        "source": {
            "rule_path": record.get("rule_path"),
            "sha256": record.get("sha256"),
            "source_commit": record.get("source_commit"),
        },
        "metadata": {
            "title": metadata.get("title"),
            "id": metadata.get("id"),
            "level": metadata.get("level"),
        },
        "logsource": {
            "product": logsource.get("product"),
            "category": logsource.get("category"),
        },
        "selections": selections,
        "condition": build_condition_tree(matched),
    }
    return ir, []


def map_record(
    record: dict[str, Any], field_map: dict[str, str]
) -> dict[str, Any]:
    """Gắn map_status / ir / map_diagnostics lên một record analyze."""
    item = dict(record)
    support = item.get("support_status")

    if support is None or support == "FAILED":
        item["map_status"] = "SKIPPED_FAILED"
        item["ir"] = None
        item["map_diagnostics"] = []
        return item

    if support == "UNSUPPORTED":
        item["map_status"] = "SKIPPED_UNSUPPORTED"
        item["ir"] = None
        item["map_diagnostics"] = []
        return item

    if support != "ELIGIBLE":
        item["map_status"] = "FAILED"
        item["ir"] = None
        item["map_diagnostics"] = [
            _diag("SELECTION_BUILD_ERROR", f"Unexpected support_status: {support!r}")
        ]
        return item

    detection = item.get("detection")
    if not isinstance(detection, dict):
        item["map_status"] = "FAILED"
        item["ir"] = None
        item["map_diagnostics"] = [
            _diag(
                "DETECTION_MISSING",
                "ELIGIBLE record has no detection dict from analyze_batch.",
            )
        ]
        return item

    ir, diags = _build_ir(item, detection, field_map)
    if diags or ir is None:
        item["map_status"] = "FAILED"
        item["ir"] = None
        item["map_diagnostics"] = diags
        return item

    item["map_status"] = "MAPPED"
    item["ir"] = ir
    item["map_diagnostics"] = []
    return item


def map_batch(
    input_path: Path | Sequence[Path],
    *,
    path_base: Path | None = None,
    source_commit: str | None = None,
    field_mapping_path: Path | None = None,
) -> dict[str, Any]:
    """Analyze rồi map ELIGIBLE → IR. Không đọc lại file rule."""
    started = time.perf_counter()
    analyzed = analyze_batch(
        input_path, path_base=path_base, source_commit=source_commit
    )

    if field_mapping_path is None:
        raise ValueError("field_mapping_path is required")
    field_map = load_field_mapping(field_mapping_path)

    records = [map_record(r, field_map) for r in analyzed["records"]]

    mapped = sum(1 for r in records if r["map_status"] == "MAPPED")
    skipped_unsupported = sum(
        1 for r in records if r["map_status"] == "SKIPPED_UNSUPPORTED"
    )
    skipped_failed = sum(1 for r in records if r["map_status"] == "SKIPPED_FAILED")
    map_failed = sum(1 for r in records if r["map_status"] == "FAILED")

    return {
        **report_meta(started),
        "input": analyzed["input"],
        "field_mapping": field_mapping_path.resolve().as_posix(),
        "records": records,
        "summary": {
            "total": len(records),
            "mapped": mapped,
            "skipped_unsupported": skipped_unsupported,
            "skipped_failed": skipped_failed,
            "map_failed": map_failed,
            "reasons": reason_histogram(records),
        },
    }


__all__ = [
    "build_condition_tree",
    "build_selection_node",
    "load_field_mapping",
    "map_batch",
    "map_record",
]
