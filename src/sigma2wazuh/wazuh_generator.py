"""Phase 5: sinh Wazuh XML từ IR Phase 4 + validate cơ bản.

Reuse map_batch. Không parse lại Sigma. Không sửa mapper.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from sigma2wazuh import __version__
from sigma2wazuh.mapper import map_batch
from sigma2wazuh.parsing import write_report

# Tên group bọc toàn batch (cố định theo phạm vi MVP process_creation).
_GROUP_NAME = "sigma,windows,process_creation,"


def _diag(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _escape_value_for_wazuh(value: object) -> str:
    r"""Literal IR → pattern cho field Wazuh win.eventdata.* (decode Sigma ở mapper).

    (b) Nhân đôi mỗi \ — lab Sysmon EID 1: field lưu \ Windows thành \\ 
        (docs/evidence/u01-sysmon-eid1-alert-excerpt.json; xác nhận 13/11 windows11-lab).
    (c) re.escape
    (d) \& → \x26, < → \x3C, > → \x3E (Wazuh XML không decode entity)
    """
    # (b) khớp dạng lưu trong alert (hai dấu \), trước khi escape regex.
    doubled = str(value).replace("\\", "\\\\")
    # (c)
    escaped = re.escape(doubled)
    # (d) re.escape biến & → \&; < và > giữ nguyên — tránh ElementTree ghi &amp;/&lt;/&gt;.
    return (
        escaped.replace(r"\&", r"\x26")
        .replace("<", r"\x3C")
        .replace(">", r"\x3E")
    )


def pattern_for_pred(pred: dict[str, Any]) -> str:
    """Một pred IR → chuỗi regex PCRE2-ish (escape từng value; neo theo op)."""
    op = pred["op"]
    values = pred["values"]
    escaped = [_escape_value_for_wazuh(v) for v in values]
    case_i = bool(pred.get("case_insensitive"))

    if op == "contains_all":
        # Lookahead độc lập; (?s) để . khớp cả xuống dòng.
        body = "(?s)" + "".join(f"(?=.*{e})" for e in escaped)
    elif op == "eq":
        body = f"^({'|'.join(escaped)})$" if len(escaped) > 1 else f"^{escaped[0]}$"
    elif op == "startswith":
        body = f"^({'|'.join(escaped)})" if len(escaped) > 1 else f"^{escaped[0]}"
    elif op == "endswith":
        body = f"({'|'.join(escaped)})$" if len(escaped) > 1 else f"{escaped[0]}$"
    elif op == "contains":
        body = f"({'|'.join(escaped)})" if len(escaped) > 1 else escaped[0]
    else:
        raise ValueError(f"Unsupported pred op: {op!r}")

    return f"(?i){body}" if case_i else body


def _count_preds(node: dict[str, Any]) -> int:
    """Đếm lá pred trong cây selection (AND/OR/pred)."""
    kind = node.get("type")
    if kind == "pred":
        return 1
    if kind in ("and", "or"):
        return sum(_count_preds(c) for c in node.get("children", []))
    return 0


def _single_pred(node: dict[str, Any]) -> dict[str, Any] | None:
    """Trả pred duy nhất nếu node chỉ còn đúng 1 pred; không thì None."""
    if _count_preds(node) != 1:
        return None
    kind = node.get("type")
    if kind == "pred":
        return node
    if kind in ("and", "or"):
        for child in node.get("children", []):
            found = _single_pred(child)
            if found is not None:
                return found
    return None


def _field_element(
    name: str, pattern: str, *, negate: bool = False
) -> ET.Element:
    """Tạo thẻ <field name=... type=pcre2> [negate=yes]."""
    attrs: dict[str, str] = {"name": name, "type": "pcre2"}
    if negate:
        attrs["negate"] = "yes"
    el = ET.Element("field", attrs)
    el.text = pattern
    return el


def fields_from_selection(
    node: dict[str, Any], *, negate: bool = False
) -> tuple[list[ET.Element] | None, str | None]:
    """Selection IR → list <field>; lỗi → (None, reason_code).

    AND → nhiều field. OR cùng field+op (list value) → một field (v1|v2).
    """
    kind = node.get("type")
    if kind == "pred":
        return [_field_element(node["target_field"], pattern_for_pred(node), negate=negate)], None

    if kind == "or":
        children = node.get("children") or []
        if not children or any(c.get("type") != "pred" for c in children):
            return None, "OR_NESTED_UNSUPPORTED"
        fields = {c["target_field"] for c in children}
        ops = {c["op"] for c in children}
        if len(fields) != 1 or len(ops) != 1:
            return None, "OR_NESTED_UNSUPPORTED"
        # Gộp value + giữ case_insensitive nếu mọi pred đều bật.
        merged = {
            "type": "pred",
            "target_field": children[0]["target_field"],
            "op": children[0]["op"],
            "values": [v for c in children for v in c["values"]],
            "case_insensitive": all(c.get("case_insensitive") for c in children),
        }
        return [
            _field_element(
                merged["target_field"], pattern_for_pred(merged), negate=negate
            )
        ], None

    if kind == "and":
        out: list[ET.Element] = []
        for child in node.get("children") or []:
            parts, err = fields_from_selection(child, negate=negate)
            if err:
                return None, err
            assert parts is not None
            out.extend(parts)
        return out, None

    return None, "SELECTION_SHAPE_UNSUPPORTED"


def _has_duplicate_field_names(fields: list[ET.Element]) -> bool:
    names = [f.get("name") for f in fields]
    return len(names) != len(set(names))


def _resolve_ref(
    selections: dict[str, Any], ref_node: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    """ref → selection node; thiếu tên → reason."""
    name = ref_node.get("selection")
    if not isinstance(name, str) or name not in selections:
        return None, "SELECTION_REF_MISSING"
    return selections[name], None


def plan_rules(
    ir: dict[str, Any],
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Áp policy condition → list rule_plan hoặc (None, reason).

    Mỗi plan: {\"fields\": [Element], \"description\": str, \"info\": str, ...meta}.
    Chưa gắn rule id.
    """
    selections = ir.get("selections") or {}
    cond = ir.get("condition")
    if not isinstance(cond, dict):
        return None, "CONDITION_MISSING"

    meta = ir.get("metadata") if isinstance(ir.get("metadata"), dict) else {}
    source = ir.get("source") if isinstance(ir.get("source"), dict) else {}
    title = meta.get("title") or "Untitled Sigma rule"
    sigma_id = meta.get("id") or ""
    sha256 = source.get("sha256") or ""
    info_text = f"sigma_id={sigma_id}; sha256={sha256}"

    def _plan_from_fields(
        fields: list[ET.Element],
    ) -> tuple[list[dict[str, Any]] | None, str | None]:
        if not fields:
            return None, "EMPTY_FIELDS"
        if _has_duplicate_field_names(fields):
            return None, "DUPLICATE_FIELD_UNSUPPORTED"
        return [
            {
                "fields": fields,
                "description": str(title),
                "info": info_text,
                "sigma_id": sigma_id,
                "sha256": sha256,
            }
        ], None

    # OR gốc các ref (1 of ...) → tách mỗi nhánh một rule.
    if cond.get("type") == "or":
        children = cond.get("children") or []
        if not children or any(c.get("type") != "ref" for c in children):
            return None, "OR_NESTED_UNSUPPORTED"
        plans: list[dict[str, Any]] = []
        for child in children:
            sel, err = _resolve_ref(selections, child)
            if err:
                return None, err
            assert sel is not None
            fields, ferr = fields_from_selection(sel)
            if ferr:
                return None, ferr
            assert fields is not None
            if _has_duplicate_field_names(fields):
                return None, "DUPLICATE_FIELD_UNSUPPORTED"
            plans.append(
                {
                    "fields": fields,
                    "description": str(title),
                    "info": info_text,
                    "sigma_id": sigma_id,
                    "sha256": sha256,
                }
            )
        return plans, None

    # ref đơn.
    if cond.get("type") == "ref":
        sel, err = _resolve_ref(selections, cond)
        if err:
            return None, err
        assert sel is not None
        fields, ferr = fields_from_selection(sel)
        if ferr:
            return None, ferr
        assert fields is not None
        return _plan_from_fields(fields)

    # AND: các ref dương + not(ref) (shape MVP and_not / all_of).
    if cond.get("type") == "and":
        fields: list[ET.Element] = []
        for child in cond.get("children") or []:
            if child.get("type") == "ref":
                sel, err = _resolve_ref(selections, child)
                if err:
                    return None, err
                assert sel is not None
                parts, ferr = fields_from_selection(sel)
                if ferr:
                    return None, ferr
                assert parts is not None
                fields.extend(parts)
            elif child.get("type") == "not":
                inner = child.get("child")
                if not isinstance(inner, dict) or inner.get("type") != "ref":
                    return None, "OR_NESTED_UNSUPPORTED"
                sel, err = _resolve_ref(selections, inner)
                if err:
                    return None, err
                assert sel is not None
                if _count_preds(sel) != 1:
                    return None, "NOT_MULTI_FIELD_UNSUPPORTED"
                pred = _single_pred(sel)
                if pred is None:
                    return None, "NOT_MULTI_FIELD_UNSUPPORTED"
                fields.append(
                    _field_element(
                        pred["target_field"],
                        pattern_for_pred(pred),
                        negate=True,
                    )
                )
            else:
                # OR/AND lồng ngoài MVP → từ chối (không sinh gần đúng).
                return None, "OR_NESTED_UNSUPPORTED"
        return _plan_from_fields(fields)

    if cond.get("type") == "not":
        return None, "OR_NESTED_UNSUPPORTED"

    return None, "CONDITION_SHAPE_UNSUPPORTED"


def allocate_ids(n: int, base: int, used: set[int]) -> list[int]:
    """Cấp n ID tuần tự bắt đầu từ base, bỏ qua ID đã dùng; deterministic."""
    if n <= 0:
        return []
    out: list[int] = []
    candidate = base
    while len(out) < n:
        if candidate not in used:
            out.append(candidate)
            used.add(candidate)
        candidate += 1
    return out


def build_rule_element(
    plan: dict[str, Any],
    rule_id: int,
    if_sid: int,
    level: int,
) -> ET.Element:
    """plan + id/level/if_sid → một thẻ <rule> (ElementTree)."""
    rule = ET.Element("rule", {"id": str(rule_id), "level": str(level)})
    if_sid_el = ET.SubElement(rule, "if_sid")
    if_sid_el.text = str(if_sid)
    for field in plan["fields"]:
        rule.append(field)
    desc = ET.SubElement(rule, "description")
    desc.text = plan["description"]
    info = ET.SubElement(rule, "info", {"type": "text"})
    info.text = plan["info"]
    return rule


def _level_for_ir(
    ir: dict[str, Any], level_map: Mapping[str, int]
) -> tuple[int | None, str | None]:
    meta = ir.get("metadata") if isinstance(ir.get("metadata"), dict) else {}
    raw = meta.get("level")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None, "LEVEL_UNSUPPORTED"
    key = str(raw).strip().lower()
    if key not in level_map:
        return None, "LEVEL_UNSUPPORTED"
    return level_map[key], None


def _base_report_record(record: dict[str, Any]) -> dict[str, Any]:
    """Giữ provenance P4 + khung conversion."""
    return {
        "rule_path": record.get("rule_path"),
        "sha256": record.get("sha256"),
        "parse_status": record.get("parse_status"),
        "support_status": record.get("support_status"),
        "map_status": record.get("map_status"),
        "conversion_status": None,
        "reason": None,
        "rule_ids": [],
        "xml_valid": None,
        "diagnostics": [],
    }


def generate_batch(
    records: list[dict[str, Any]],
    *,
    rule_id_base: int,
    if_sid: int,
    level_map: Mapping[str, int],
) -> tuple[ET.Element, list[dict[str, Any]]]:
    """MAPPED → plan/XML; khác → SKIPPED. Sort theo rule_path rồi cấp ID."""
    root = ET.Element("group", {"name": _GROUP_NAME})
    report_records: list[dict[str, Any]] = []
    used_ids: set[int] = set()

    # Deterministic: cùng batch → cùng thứ tự ID.
    ordered = sorted(
        enumerate(records),
        key=lambda pair: (str(pair[1].get("rule_path") or ""), pair[0]),
    )
    # Giữ thứ tự report theo input gốc; XML theo sort path.
    by_index: dict[int, dict[str, Any]] = {}

    for index, record in ordered:
        item = _base_report_record(record)
        if record.get("map_status") != "MAPPED":
            item["conversion_status"] = "SKIPPED"
            item["reason"] = None
            by_index[index] = item
            continue

        ir = record.get("ir")
        if not isinstance(ir, dict):
            item["conversion_status"] = "FAILED"
            item["reason"] = "IR_MISSING"
            item["diagnostics"] = [_diag("IR_MISSING", "MAPPED record has no ir dict")]
            by_index[index] = item
            continue

        level, level_err = _level_for_ir(ir, level_map)
        if level_err:
            item["conversion_status"] = "FAILED"
            item["reason"] = level_err
            item["diagnostics"] = [
                _diag(level_err, f"Unsupported or missing Sigma level: {ir.get('metadata')}")
            ]
            by_index[index] = item
            continue

        plans, reason = plan_rules(ir)
        if reason or plans is None:
            item["conversion_status"] = "UNSUPPORTED"
            item["reason"] = reason or "PLAN_FAILED"
            by_index[index] = item
            continue

        ids = allocate_ids(len(plans), rule_id_base, used_ids)
        for plan, rid in zip(plans, ids, strict=True):
            root.append(build_rule_element(plan, rid, if_sid, level))
        item["conversion_status"] = "SUCCESS"
        item["reason"] = None
        item["rule_ids"] = ids
        by_index[index] = item

    for i in range(len(records)):
        report_records.append(by_index[i])
    return root, report_records


def _validate_rule_element(rule: ET.Element) -> list[dict[str, str]]:
    """Kiểm tra một <rule>: thẻ bắt buộc, field type, regex compile (Python re)."""
    diags: list[dict[str, str]] = []
    rid = rule.get("id")
    if not rid:
        diags.append(_diag("RULE_ID_MISSING", "A <rule> has no id attribute"))

    level = rule.get("level")
    if level is None or level == "":
        diags.append(_diag("RULE_LEVEL_MISSING", f"Rule {rid} missing level"))

    if_sid_el = rule.find("if_sid")
    if if_sid_el is None or not (if_sid_el.text or "").strip():
        diags.append(_diag("IF_SID_MISSING", f"Rule {rid} missing if_sid"))

    fields = rule.findall("field")
    if not fields:
        diags.append(_diag("FIELD_MISSING", f"Rule {rid} has no <field>"))
    for field in fields:
        name = field.get("name")
        if not name:
            diags.append(_diag("FIELD_NAME_MISSING", f"Rule {rid} field without name"))
        if field.get("type") != "pcre2":
            diags.append(
                _diag(
                    "FIELD_TYPE_INVALID",
                    f"Rule {rid} field type={field.get('type')!r}",
                )
            )
        pattern = field.text or ""
        try:
            re.compile(pattern)
        except re.error as exc:
            diags.append(
                _diag(
                    "REGEX_COMPILE_ERROR",
                    f"Rule {rid} field {name!r}: {exc}",
                )
            )

    desc = rule.find("description")
    if desc is None or not (desc.text or "").strip():
        diags.append(_diag("DESCRIPTION_MISSING", f"Rule {rid} missing description"))

    return diags


def _collect_xml_diagnostics(
    root: ET.Element,
) -> tuple[list[dict[str, str]], dict[str, list[dict[str, str]]]]:
    """Parse lại XML; tách lỗi toàn cục vs lỗi theo rule id (key luôn str)."""
    global_diags: list[dict[str, str]] = []
    by_rule_id: dict[str, list[dict[str, str]]] = {}
    try:
        xml_bytes = ET.tostring(root, encoding="utf-8")
        parsed = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        return [_diag("XML_PARSE_ERROR", str(exc))], {}

    if parsed.tag != "group":
        global_diags.append(
            _diag("GROUP_MISSING", f"Root tag is {parsed.tag!r}, expected group")
        )

    seen_ids: set[str] = set()
    rules = list(parsed.findall("rule"))
    if root.findall("rule") and not rules and not global_diags:
        global_diags.append(_diag("RULES_MISSING", "No <rule> elements under group"))

    for rule in rules:
        rid = rule.get("id")
        # Trùng ID / thiếu ID → không gắn chắc record → lỗi toàn cục.
        if rid:
            if rid in seen_ids:
                global_diags.append(
                    _diag("RULE_ID_DUPLICATE", f"Duplicate rule id {rid}")
                )
            seen_ids.add(rid)
        rule_diags = _validate_rule_element(rule)
        if not rid:
            global_diags.extend(rule_diags)
        elif rule_diags:
            by_rule_id.setdefault(rid, []).extend(rule_diags)

    return global_diags, by_rule_id


def validate_xml_tree(root: ET.Element) -> tuple[bool, list[dict[str, str]]]:
    """Parse lại XML; kiểm tra thẻ bắt buộc, ID unique, regex compile (Python re)."""
    global_diags, by_rule_id = _collect_xml_diagnostics(root)
    diags = list(global_diags)
    for rid in sorted(by_rule_id):
        diags.extend(by_rule_id[rid])
    return (len(diags) == 0), diags


def _remove_rules_by_ids(root: ET.Element, id_strs: set[str]) -> None:
    """Gỡ các <rule> có id thuộc tập (id đã chuẩn hóa str)."""
    for child in list(root):
        if child.tag == "rule" and child.get("id") in id_strs:
            root.remove(child)


def apply_xml_validation(
    root: ET.Element,
    records: list[dict[str, Any]],
) -> tuple[bool, list[dict[str, str]]]:
    """Validate theo record: rule lỗi → FAILED + gỡ đúng rule; lỗi global → fail cả batch.

    Trả (ok, diagnostics_batch). ok=False chỉ khi lỗi toàn cục.
    diagnostics_batch: lỗi global đầy đủ, hoặc summary ngắn records_failed_validation.
    """
    global_diags, by_rule_id = _collect_xml_diagnostics(root)

    if global_diags:
        for item in records:
            if item["conversion_status"] == "SUCCESS":
                item["xml_valid"] = False
                item["diagnostics"] = list(global_diags)
                item["conversion_status"] = "FAILED"
                item["reason"] = "XML_VALIDATION_FAILED"
                item["rule_ids"] = []
            else:
                item["xml_valid"] = None
        # Không xuất XML khi lỗi toàn cục.
        for child in list(root):
            root.remove(child)
        return False, list(global_diags)

    failed_count = 0
    for item in records:
        if item["conversion_status"] != "SUCCESS":
            item["xml_valid"] = None
            continue

        # rule_ids (int) vs attribute XML (str) — luôn so khớp bằng str.
        id_strs = [str(rid) for rid in item["rule_ids"]]
        diags: list[dict[str, str]] = []
        for rid in id_strs:
            diags.extend(by_rule_id.get(rid, []))

        if diags:
            failed_count += 1
            item["xml_valid"] = False
            item["diagnostics"] = diags
            item["conversion_status"] = "FAILED"
            item["reason"] = "XML_VALIDATION_FAILED"
            _remove_rules_by_ids(root, set(id_strs))
            item["rule_ids"] = []
        else:
            item["xml_valid"] = True

    batch_diags: list[dict[str, str]] = []
    if failed_count:
        batch_diags.append(
            _diag(
                "RECORDS_FAILED_VALIDATION",
                f"records_failed_validation={failed_count}",
            )
        )
    return True, batch_diags


def convert_batch(
    mapped: dict[str, Any],
    *,
    rule_id_base: int,
    if_sid: int,
    level_map: Mapping[str, int],
) -> dict[str, Any]:
    """Từ report map_batch → XML root + report conversion (kèm validate)."""
    records = list(mapped.get("records") or [])
    root, report_records = generate_batch(
        records,
        rule_id_base=rule_id_base,
        if_sid=if_sid,
        level_map=level_map,
    )
    ok, diags = apply_xml_validation(root, report_records)

    success = sum(1 for r in report_records if r["conversion_status"] == "SUCCESS")
    unsupported = sum(
        1 for r in report_records if r["conversion_status"] == "UNSUPPORTED"
    )
    failed = sum(1 for r in report_records if r["conversion_status"] == "FAILED")
    skipped = sum(1 for r in report_records if r["conversion_status"] == "SKIPPED")
    total = len(report_records)

    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_version": __version__,
        "input": mapped.get("input"),
        "field_mapping": mapped.get("field_mapping"),
        "wazuh": {
            "rule_id_base": rule_id_base,
            "if_sid": if_sid,
            "level_map": dict(level_map),
        },
        "xml_validation": {
            "ok": ok,
            "diagnostics": diags,
            "note": (
                "xml_valid means ElementTree parse + required tags + unique ids "
                "+ Python re.compile only; it does NOT mean Wazuh loaded the rule "
                "or that detection is correct."
            ),
        },
        "xml_root": root,
        "records": report_records,
        "summary": {
            "total": total,
            "success": success,
            "unsupported": unsupported,
            "failed": failed,
            "skipped": skipped,
            "rule_elements": len(root.findall("rule")),
        },
    }


def xml_to_string(root: ET.Element) -> str:
    """Serialize group XML (có indent; không timestamp)."""
    ET.indent(root, space="  ")
    body = ET.tostring(root, encoding="unicode")
    return body + ("\n" if not body.endswith("\n") else "")


def write_outputs(
    report: dict[str, Any],
    xml_path: Path,
    report_path: Path,
) -> None:
    """Ghi phase5-rules.xml + phase5-report.json (bỏ xml_root khỏi JSON)."""
    root = report["xml_root"]
    xml_path = xml_path.expanduser()
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    xml_path.write_text(xml_to_string(root), encoding="utf-8")

    serializable = {k: v for k, v in report.items() if k != "xml_root"}
    write_report(serializable, report_path)


def convert_from_input(
    input_path: Path,
    *,
    path_base: Path | None = None,
    field_mapping_path: Path,
    rule_id_base: int,
    if_sid: int,
    level_map: Mapping[str, int],
) -> dict[str, Any]:
    """map_batch rồi convert_batch (điểm vào cho CLI convert)."""
    mapped = map_batch(
        input_path,
        path_base=path_base,
        field_mapping_path=field_mapping_path,
    )
    return convert_batch(
        mapped,
        rule_id_base=rule_id_base,
        if_sid=if_sid,
        level_map=level_map,
    )


__all__ = [
    "allocate_ids",
    "apply_xml_validation",
    "build_rule_element",
    "convert_batch",
    "convert_from_input",
    "fields_from_selection",
    "generate_batch",
    "pattern_for_pred",
    "plan_rules",
    "validate_xml_tree",
    "write_outputs",
    "xml_to_string",
]
