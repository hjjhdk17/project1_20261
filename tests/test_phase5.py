"""Kiểm thử Phase 5: IR → Wazuh XML + validate; CLI convert."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from sigma2wazuh import __version__
from sigma2wazuh.cli import main
from sigma2wazuh.config import find_project_root, load_config
from sigma2wazuh.mapper import map_batch
from sigma2wazuh.wazuh_generator import (
    allocate_ids,
    convert_batch,
    convert_from_input,
    pattern_for_pred,
    plan_rules,
    validate_xml_tree,
    write_outputs,
    xml_to_string,
)

ROOT = Path(__file__).resolve().parents[1]
PHASE3 = Path(__file__).resolve().parent / "fixtures" / "phase3"
PHASE4 = Path(__file__).resolve().parent / "fixtures" / "phase4"
CURATED = ROOT / "input" / "sigma_rules" / "curated"
FIELD_MAPPING = ROOT / "config" / "field_mapping.yaml"

LEVEL_MAP = {
    "informational": 3,
    "low": 5,
    "medium": 8,
    "high": 12,
    "critical": 15,
}


def _assert_summary_invariant(summary: dict) -> None:
    assert summary["total"] == (
        summary["success"]
        + summary["unsupported"]
        + summary["failed"]
        + summary["skipped"]
    )


def _convert_path(path: Path) -> dict:
    mapped = map_batch(
        path, path_base=path.parent if path.is_file() else path, field_mapping_path=FIELD_MAPPING
    )
    # path_base: với file đơn dùng parent; với dir dùng chính dir — map_batch cần ổn định.
    return convert_batch(
        mapped,
        rule_id_base=100000,
        if_sid=61603,
        level_map=LEVEL_MAP,
    )


def _pred(
    field: str,
    op: str,
    values: list,
    *,
    case_insensitive: bool = True,
) -> dict:
    return {
        "type": "pred",
        "sigma_field": field.split(".")[-1],
        "target_field": field,
        "op": op,
        "values": values,
        "case_insensitive": case_insensitive,
    }


def test_pattern_ops_and_case_insensitive() -> None:
    eq = pattern_for_pred(_pred("win.eventdata.user", "eq", ["SYSTEM"]))
    assert eq == r"(?i)^SYSTEM$"

    starts = pattern_for_pred(
        _pred("win.eventdata.parentImage", "startswith", [r"C:\Windows"])
    )
    assert starts.startswith("(?i)^")
    assert r"C:\\Windows" in starts

    ends = pattern_for_pred(
        _pred("win.eventdata.image", "endswith", [r"\cmd.exe"])
    )
    assert ends.endswith(r"\\cmd\.exe$") or ends.endswith(r"cmd\.exe$")
    assert ends.startswith("(?i)")

    contains = pattern_for_pred(
        _pred("win.eventdata.commandLine", "contains", ["DumpStack.log"])
    )
    assert contains == r"(?i)DumpStack\.log"

    all_pat = pattern_for_pred(
        _pred("win.eventdata.commandLine", "contains_all", ["-enc", "bypass"])
    )
    assert all_pat == r"(?i)(?=.*\-enc)(?=.*bypass)"

    multi = pattern_for_pred(
        _pred("win.eventdata.image", "endswith", [r"\a.exe", r"\b.exe"])
    )
    assert multi.startswith("(?i)")
    assert multi.endswith("$")
    assert "|" in multi


def test_pattern_escape_specials() -> None:
    # Escape regex + ký tự XML sẽ do ElementTree xử lý khi serialize.
    raw = r"a.\b(c)&<d>"
    pat = pattern_for_pred(_pred("win.eventdata.commandLine", "contains", [raw]))
    assert r"\." in pat
    assert r"\(" in pat
    assert "&" in pat or r"\&" in pat
    re.compile(pat)


def test_and_not_xml_shape() -> None:
    report = _convert_path(PHASE3 / "eligible_and_not.yml")
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["success"] == 1
    root = report["xml_root"]
    rules = root.findall("rule")
    assert len(rules) == 1
    rule = rules[0]
    assert rule.get("id") == "100000"
    assert rule.get("level") == "8"
    assert rule.findtext("if_sid") == "61603"
    fields = rule.findall("field")
    assert len(fields) == 2
    assert fields[0].get("name") == "win.eventdata.image"
    assert fields[0].get("negate") is None
    assert fields[0].text == r"(?i)\\msiexec\.exe$"
    assert fields[1].get("name") == "win.eventdata.parentImage"
    assert fields[1].get("negate") == "yes"
    assert fields[1].text == r"(?i)\\explorer\.exe$"
    assert rule.findtext("description") == "Phase3 Fixture Eligible And Not"
    info = rule.find("info")
    assert info is not None and info.get("type") == "text"
    assert "55555555-5555-5555-5555-555555555555" in (info.text or "")
    assert report["records"][0]["xml_valid"] is True


def test_one_of_splits_two_rules() -> None:
    report = _convert_path(PHASE3 / "eligible_one_of.yml")
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["success"] == 1
    assert report["summary"]["rule_elements"] == 2
    rules = report["xml_root"].findall("rule")
    assert [r.get("id") for r in rules] == ["100000", "100001"]
    assert all(r.get("level") == "5" for r in rules)
    assert all(
        r.findtext("description") == "Phase3 Fixture Eligible One Of" for r in rules
    )
    names = {r.find("field").get("name") for r in rules}
    assert names == {
        "win.eventdata.originalFileName",
        "win.eventdata.commandLine",
    }
    assert report["records"][0]["rule_ids"] == [100000, 100001]


def test_contains_all_and_startswith_eq() -> None:
    all_rep = _convert_path(PHASE3 / "eligible_contains_all.yml")
    field = all_rep["xml_root"].find("./rule/field")
    assert field is not None
    assert field.text == r"(?i)(?=.*\-enc)(?=.*bypass)"

    start_rep = _convert_path(PHASE3 / "eligible_startswith_user.yml")
    fields = start_rep["xml_root"].findall("./rule/field")
    by_name = {f.get("name"): f.text for f in fields}
    assert by_name["win.eventdata.parentImage"].startswith("(?i)^")
    assert by_name["win.eventdata.user"] == r"(?i)^SYSTEM$"


def test_not_multi_field_unsupported() -> None:
    # IR synthetics: filter OR ≥2 pred → NOT_MULTI (policy Cách A).
    ir = {
        "metadata": {"title": "t", "id": "x", "level": "low"},
        "source": {"sha256": "abc"},
        "selections": {
            "selection": {
                "type": "and",
                "children": [_pred("win.eventdata.image", "endswith", [r"\a.exe"])],
            },
            "filter": {
                "type": "or",
                "children": [
                    _pred("win.eventdata.parentImage", "endswith", [r"\x.exe"]),
                    _pred("win.eventdata.parentImage", "endswith", [r"\y.exe"]),
                ],
            },
        },
        "condition": {
            "type": "and",
            "children": [
                {"type": "ref", "selection": "selection"},
                {
                    "type": "not",
                    "child": {"type": "ref", "selection": "filter"},
                },
            ],
        },
    }
    plans, reason = plan_rules(ir)
    assert plans is None
    assert reason == "NOT_MULTI_FIELD_UNSUPPORTED"


def test_duplicate_field_unsupported() -> None:
    ir = {
        "metadata": {"title": "dup", "id": "y", "level": "low"},
        "source": {"sha256": "def"},
        "selections": {
            "selection_a": {
                "type": "and",
                "children": [
                    _pred("win.eventdata.commandLine", "contains", ["foo"]),
                ],
            },
            "selection_b": {
                "type": "and",
                "children": [
                    _pred("win.eventdata.commandLine", "contains", ["bar"]),
                ],
            },
        },
        "condition": {
            "type": "and",
            "children": [
                {"type": "ref", "selection": "selection_a"},
                {"type": "ref", "selection": "selection_b"},
            ],
        },
    }
    plans, reason = plan_rules(ir)
    assert plans is None
    assert reason == "DUPLICATE_FIELD_UNSUPPORTED"


def test_level_unsupported_failed() -> None:
    mapped = map_batch(
        PHASE3 / "eligible_endswith.yml",
        path_base=PHASE3,
        field_mapping_path=FIELD_MAPPING,
    )
    # Xóa level trên IR để ép FAILED.
    mapped["records"][0]["ir"]["metadata"]["level"] = None
    report = convert_batch(
        mapped, rule_id_base=100000, if_sid=61603, level_map=LEVEL_MAP
    )
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["failed"] == 1
    assert report["records"][0]["conversion_status"] == "FAILED"
    assert report["records"][0]["reason"] == "LEVEL_UNSUPPORTED"
    assert report["xml_root"].findall("rule") == []


def test_skipped_non_mapped_no_xml() -> None:
    report = _convert_path(PHASE3 / "unsupported_field.yml")
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["skipped"] == 1
    assert report["summary"]["success"] == 0
    assert report["xml_root"].findall("rule") == []
    assert report["records"][0]["conversion_status"] == "SKIPPED"


def test_wildcard_map_failed_is_skipped() -> None:
    report = _convert_path(PHASE4 / "wildcard_contains.yml")
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["skipped"] == 1
    assert report["records"][0]["map_status"] == "FAILED"
    assert report["xml_root"].findall("rule") == []


def test_allocate_ids_unique_deterministic() -> None:
    used: set[int] = set()
    first = allocate_ids(3, 100000, used)
    assert first == [100000, 100001, 100002]
    second = allocate_ids(2, 100000, used)
    assert second == [100003, 100004]
    assert used == {100000, 100001, 100002, 100003, 100004}


def test_ids_deterministic_by_rule_path() -> None:
    # Batch nhiều file: ID theo sort rule_path, không theo thứ tự discover lạ.
    report = convert_from_input(
        PHASE3,
        path_base=PHASE3,
        field_mapping_path=FIELD_MAPPING,
        rule_id_base=100000,
        if_sid=61603,
        level_map=LEVEL_MAP,
    )
    _assert_summary_invariant(report["summary"])
    success = [r for r in report["records"] if r["conversion_status"] == "SUCCESS"]
    assert success
    paths = [r["rule_path"] for r in success]
    assert paths == sorted(paths)
    # ID tăng theo thứ tự success đã sort path (generate_batch sort rồi cấp).
    ids = [rid for r in success for rid in r["rule_ids"]]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    assert report["xml_validation"]["ok"] is True


def test_validate_xml_tree_ok() -> None:
    report = _convert_path(PHASE3 / "eligible_endswith.yml")
    ok, diags = validate_xml_tree(report["xml_root"])
    assert ok is True
    assert diags == []
    # Serialize không chứa timestamp; parse lại được.
    text = xml_to_string(report["xml_root"])
    assert "generated_at" not in text
    ET.fromstring(text)


def test_cli_convert_fixtures(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    xml_out = tmp_path / "rules.xml"
    report_out = tmp_path / "report.json"
    code = main(
        [
            "convert",
            "--input",
            str(PHASE3 / "eligible_and_not.yml"),
            "--output-xml",
            str(xml_out),
            "--output-report",
            str(report_out),
            "--field-mapping",
            str(FIELD_MAPPING),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "Convert OK:" in captured.out
    assert xml_out.is_file()
    data = json.loads(report_out.read_text(encoding="utf-8"))
    _assert_summary_invariant(data["summary"])
    assert data["tool_version"] == __version__
    assert data["summary"]["success"] == 1
    tree = ET.parse(xml_out)
    assert tree.getroot().tag == "group"
    assert tree.getroot().find("rule") is not None


def test_cli_convert_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["convert", "--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "--output-xml" in out
    assert "--output-report" in out


def test_curated_convert_smoke(tmp_path: Path) -> None:
    cfg = load_config(project_root=ROOT)
    report = convert_from_input(
        CURATED,
        path_base=ROOT / "input" / "sigma_rules",
        field_mapping_path=FIELD_MAPPING,
        rule_id_base=cfg.wazuh_rule_id_base,
        if_sid=cfg.wazuh_if_sid,
        level_map=cfg.wazuh_level_map,
    )
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["total"] == 23
    # Ước lượng Architecture Review: 11 SUCCESS, 0 UNSUPPORTED P5, rest skipped.
    assert report["summary"]["success"] == 11
    assert report["summary"]["unsupported"] == 0
    assert report["summary"]["failed"] == 0
    assert report["summary"]["skipped"] == 12
    assert report["summary"]["rule_elements"] == 12
    assert report["xml_validation"]["ok"] is True

    xml_path = tmp_path / "phase5-rules.xml"
    json_path = tmp_path / "phase5-report.json"
    write_outputs(report, xml_path, json_path)
    assert xml_path.is_file() and json_path.is_file()
