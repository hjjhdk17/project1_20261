"""Phase 6: matcher local trên XML đã sinh. Không cần lab."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from sigma2wazuh.evaluator import MatcherError, match_rules
from sigma2wazuh.mapper import map_batch
from sigma2wazuh.wazuh_generator import convert_batch

ROOT = Path(__file__).resolve().parents[1]
PHASE3 = Path(__file__).resolve().parent / "fixtures" / "phase3"
CURATED = ROOT / "input" / "sigma_rules" / "curated"
FIELD_MAPPING = ROOT / "config" / "field_mapping.yaml"

LEVEL_MAP = {
    "informational": 3,
    "low": 5,
    "medium": 8,
    "high": 12,
    "critical": 15,
}

IMAGE = "win.eventdata.image"
PARENT = "win.eventdata.parentImage"
CMDLINE = "win.eventdata.commandLine"
USER = "win.eventdata.user"


def _convert(path: Path) -> ET.Element:
    mapped = map_batch(
        path,
        path_base=path.parent if path.is_file() else path,
        field_mapping_path=FIELD_MAPPING,
    )
    report = convert_batch(
        mapped,
        rule_id_base=100000,
        if_sid=61603,
        level_map=LEVEL_MAP,
    )
    assert report["summary"]["success"] >= 1
    return report["xml_root"]


def test_endswith_positive_negative_case_and_backslash() -> None:
    root = _convert(PHASE3 / "eligible_endswith.yml")
    # Dạng lab: một \ Windows lưu thành hai ký tự \.
    stored = r"C:\\Windows\\System32\\cmd.exe"
    assert match_rules(root, {IMAGE: stored}) == ["100000"]
    assert match_rules(root, {IMAGE: stored.lower()}) == ["100000"]
    assert match_rules(root, {IMAGE: r"C:\\Windows\\System32\\notepad.exe"}) == []
    # Một dấu \ không phải dạng field Wazuh — pattern đã nhân đôi ở generator.
    assert match_rules(root, {IMAGE: r"C:\Windows\System32\cmd.exe"}) == []
    assert match_rules(root, {}) == []


def test_startswith_and_user_and_missing_field() -> None:
    root = _convert(PHASE3 / "eligible_startswith_user.yml")
    good = {PARENT: r"C:\\Windows\\System32\\cmd.exe", USER: "SYSTEM"}
    assert match_rules(root, good) == ["100000"]
    assert match_rules(root, {**good, USER: "system"}) == ["100000"]
    assert match_rules(root, {**good, USER: "Alice"}) == []
    # Thiếu User: không fire dù ParentImage đúng.
    assert match_rules(root, {PARENT: good[PARENT]}) == []


def test_contains_all_needs_every_token() -> None:
    root = _convert(PHASE3 / "eligible_contains_all.yml")
    assert match_rules(root, {CMDLINE: "powershell -enc bypass"}) == ["100000"]
    assert match_rules(root, {CMDLINE: "powershell -ENC BYPASS"}) == ["100000"]
    assert match_rules(root, {CMDLINE: "powershell -enc"}) == []


def test_and_not_filter_and_missing_negated_field() -> None:
    root = _convert(PHASE3 / "eligible_and_not.yml")
    image = r"C:\\Windows\\System32\\msiexec.exe"
    other_parent = r"C:\\Windows\\System32\\cmd.exe"
    explorer = r"C:\\Windows\\explorer.exe"
    assert match_rules(root, {IMAGE: image, PARENT: other_parent}) == ["100000"]
    assert match_rules(root, {IMAGE: image, PARENT: explorer}) == []
    # Thiếu ParentImage: negate không được coi là khớp.
    assert match_rules(root, {IMAGE: image}) == []
    assert match_rules(root, {IMAGE: r"C:\\Windows\\System32\\cmd.exe", PARENT: other_parent}) == []


def test_all_of_requires_both_fields() -> None:
    root = _convert(PHASE3 / "eligible_all_of.yml")
    image = r"C:\\Tools\\unregmp2.exe"
    assert match_rules(root, {IMAGE: image, CMDLINE: "unregmp2.exe /j"}) == ["100000"]
    assert match_rules(root, {IMAGE: image, CMDLINE: "unregmp2.exe"}) == []
    assert match_rules(root, {IMAGE: image}) == []


def test_one_of_fires_only_matching_branch() -> None:
    root = _convert(PHASE3 / "eligible_one_of.yml")
    ids = [rule.get("id") for rule in root.findall("rule")]
    assert ids == ["100000", "100001"]
    only_original_file_name = match_rules(
        root, {"win.eventdata.originalFileName": "dumpstack.log"}
    )
    only_cli = match_rules(root, {CMDLINE: "copy DumpStack.log"})
    assert only_original_file_name == ["100000"]
    assert only_cli == ["100001"]
    assert match_rules(root, {CMDLINE: "nothing"}) == []


def test_curated_eq_backslash_stored_form() -> None:
    """Rule curated eq path: khớp dạng \\ của lab, không khớp một dấu \\."""
    root = _convert(CURATED / "proc_creation_win_wpbbin_potential_persistence.yml")
    stored = r"C:\\Windows\\System32\\wpbbin.exe"
    assert match_rules(root, {IMAGE: stored}) == ["100000"]
    assert match_rules(root, {IMAGE: stored.lower()}) == ["100000"]
    assert match_rules(root, {IMAGE: r"C:\Windows\System32\wpbbin.exe"}) == []
    assert match_rules(root, {IMAGE: r"C:\\Windows\\System32\\cmd.exe"}) == []


def test_unsupported_field_or_condition_raises() -> None:
    """type khác pcre2 hoặc thẻ điều kiện lạ → lỗi, không bỏ qua."""
    bad_type = ET.Element("rule", {"id": "100000", "level": "8"})
    ET.SubElement(bad_type, "if_sid").text = "61603"
    field = ET.SubElement(
        bad_type, "field", {"name": IMAGE, "type": "osregex"}
    )
    field.text = "cmd"
    ET.SubElement(bad_type, "description").text = "x"
    with pytest.raises(MatcherError, match="pcre2"):
        match_rules(bad_type, {IMAGE: "cmd"})

    unknown = ET.Element("rule", {"id": "100001", "level": "8"})
    ET.SubElement(unknown, "match").text = "cmd"
    ok = ET.SubElement(unknown, "field", {"name": IMAGE, "type": "pcre2"})
    ok.text = r"(?i)cmd"
    with pytest.raises(MatcherError, match="không hỗ trợ"):
        match_rules(unknown, {IMAGE: "cmd"})
