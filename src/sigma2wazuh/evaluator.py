"""Phase 6: đối chiếu event giả với XML đã sinh.

Chỉ đánh giá <field type="pcre2">. Giả định event đã qua if_sid (không xét thẻ đó).
Pattern lấy nguyên text do wazuh_generator sinh — không dịch op Sigma lần nữa.
"""

from __future__ import annotations

import re
from typing import Mapping
from xml.etree import ElementTree as ET

# Metadata, không phải điều kiện.
_METADATA_TAGS = frozenset({"description", "info", "group", "mitre"})


class MatcherError(ValueError):
    """XML có điều kiện matcher không đánh giá được. Không bỏ qua thẻ lạ."""


def match_rules(root: ET.Element, event: Mapping[str, str]) -> list[str]:
    """ID các <rule> khớp event. Đọc pattern có sẵn, không dựng regex mới.

    Thiếu field trong event → rule không khớp, kể cả negate="yes".
    """
    if root.tag == "group":
        rules = list(root.findall("rule"))
    elif root.tag == "rule":
        rules = [root]
    else:
        raise MatcherError(f"Root không hỗ trợ: <{root.tag}>")

    hits: list[str] = []
    for rule in rules:
        rid = _require_id(rule)
        if _rule_matches(rule, event, rid):
            hits.append(rid)
    return sorted(hits, key=int)


def _require_id(rule: ET.Element) -> str:
    rid = rule.get("id")
    if not rid or not rid.isdigit():
        raise MatcherError(f"Một <rule> không có id số: {rid!r}")
    return rid


def _rule_matches(rule: ET.Element, event: Mapping[str, str], rid: str) -> bool:
    """Mọi <field> phải khớp. Duyệt hết con để thẻ lạ vẫn raise, không return sớm."""
    checks: list[bool] = []
    for child in list(rule):
        tag = child.tag
        if tag == "if_sid":
            # Không đánh giá: caller giả định event đã khớp parent 61603.
            continue
        if tag in _METADATA_TAGS:
            continue
        if tag == "field":
            checks.append(_field_matches(child, event, rid))
            continue
        raise MatcherError(
            f"Rule {rid} có thẻ điều kiện không hỗ trợ: <{tag}>"
        )
    if not checks:
        raise MatcherError(f"Rule {rid} không có <field> để đánh giá")
    return all(checks)


def _field_matches(field: ET.Element, event: Mapping[str, str], rid: str) -> bool:
    if field.get("type") != "pcre2":
        raise MatcherError(
            f"Rule {rid} <field> type={field.get('type')!r} — chỉ hỗ trợ type=\"pcre2\""
        )
    name = field.get("name")
    if not name:
        raise MatcherError(f"Rule {rid} <field> thiếu name")
    pattern = field.text or ""
    if not pattern.strip():
        raise MatcherError(f"Rule {rid} <field name={name!r}> thiếu pattern")
    negate = field.get("negate")
    if negate is not None and negate != "yes":
        raise MatcherError(
            f"Rule {rid} <field name={name!r}> negate={negate!r} không hỗ trợ"
        )
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise MatcherError(
            f"Rule {rid} <field name={name!r}> regex không compile: {exc}"
        ) from exc

    # Thiếu key: không khớp, kể cả negate. Không đoán semantics Wazuh.
    if name not in event:
        return False
    value = event[name]
    if not isinstance(value, str):
        raise MatcherError(
            f"Event field {name!r} phải là str, nhận {type(value).__name__}"
        )
    found = compiled.search(value) is not None
    if negate == "yes":
        return not found
    return found
