"""Phase 7: báo cáo batch, exit code, ghi file, ký tự XML không hợp lệ."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from sigma2wazuh import __version__
from sigma2wazuh.cli import main
from sigma2wazuh.config import find_project_root, load_config
from sigma2wazuh.parsing import parse_batch, parse_one
from sigma2wazuh.wazuh_generator import convert_from_input, xml_to_string

ROOT = Path(__file__).resolve().parents[1]
PHASE2 = ROOT / "tests" / "fixtures" / "phase2"
PHASE3 = ROOT / "tests" / "fixtures" / "phase3"
PHASE7 = ROOT / "tests" / "fixtures" / "phase7"
FIELD_MAPPING = ROOT / "config" / "field_mapping.yaml"
CURATED = ROOT / "input" / "sigma_rules" / "curated"
CORPUS = ROOT / "input" / "sigma_rules" / "windows" / "process_creation"
GOOD = PHASE3 / "eligible_endswith.yml"
BAD_YAML = PHASE2 / "bad_yaml.yml"
BAD_CHAR = PHASE7 / "xml_invalid_image.yml"

LEVEL_MAP = {
    "informational": 3,
    "low": 5,
    "medium": 8,
    "high": 12,
    "critical": 15,
}


def _assert_invariant(summary: dict) -> None:
    assert summary["total"] == (
        summary["success"]
        + summary["unsupported"]
        + summary["failed"]
        + summary["skipped"]
    )


def _convert(tmp_path: Path, *inputs: Path, force: bool = False) -> tuple[int, Path, Path]:
    xml_path = tmp_path / "rules.xml"
    report_path = tmp_path / "report.json"
    args = ["convert", "--field-mapping", str(FIELD_MAPPING)]
    for item in inputs:
        args.extend(["--input", str(item)])
    args.extend(["--output-xml", str(xml_path), "--output-report", str(report_path)])
    if force:
        args.append("--force")
    code = main(args)
    return code, xml_path, report_path


def test_rule_path_posix_inside_and_outside_root(tmp_path: Path) -> None:
    root = find_project_root()
    inside = parse_one(GOOD, path_base=root)
    assert inside["rule_path"] == GOOD.resolve().relative_to(root).as_posix()
    assert "\\" not in inside["rule_path"]

    outside = tmp_path / "outside.yml"
    outside.write_text("title: x\n", encoding="utf-8")
    record = parse_one(outside, path_base=root)
    assert record["rule_path"] == outside.resolve().as_posix()
    assert record["rule_path"].startswith("/")


def test_inputs_deduped_and_sorted_by_rule_path(tmp_path: Path) -> None:
    first = tmp_path / "b_rule.yml"
    second = tmp_path / "a_rule.yml"
    first.write_text("not: yaml: [\n", encoding="utf-8")
    second.write_text("not: yaml: [\n", encoding="utf-8")
    report = parse_batch([first, second, first], path_base=tmp_path)
    assert [item["rule_path"] for item in report["records"]] == ["a_rule.yml", "b_rule.yml"]
    assert isinstance(report["input"], list)
    assert report["input"][0] == first.resolve().as_posix()
    assert report["summary"]["reasons"]


def test_report_has_runtime_fields() -> None:
    report = parse_batch(GOOD, path_base=find_project_root())
    assert report["tool_version"] == __version__
    assert report["python_version"]
    assert report["pysigma_version"]
    assert isinstance(report["elapsed_ms"], int)
    assert report["generated_at_utc"]


def test_repeat_convert_records_summary_xml_stable() -> None:
    kwargs = {
        "path_base": find_project_root(),
        "field_mapping_path": FIELD_MAPPING,
        "rule_id_base": 100000,
        "if_sid": 61603,
        "level_map": LEVEL_MAP,
    }
    first = convert_from_input(GOOD, **kwargs)
    second = convert_from_input(GOOD, **kwargs)
    assert first["records"] == second["records"]
    assert first["summary"] == second["summary"]
    xml = xml_to_string(first["xml_root"])
    assert xml == xml_to_string(second["xml_root"])
    assert "generated_at" not in xml
    assert "elapsed_ms" not in xml


def test_cli_curated_convert(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, xml_path, report_path = _convert(tmp_path, CURATED)
    captured = capsys.readouterr()
    assert code == 0
    assert "Convert OK:" in captured.out
    data = json.loads(report_path.read_text(encoding="utf-8"))
    _assert_invariant(data["summary"])
    assert data["summary"]["total"] == 23
    assert data["summary"]["failed"] == 0
    assert data["tool_version"] == __version__
    assert "python_version" in data
    assert "pysigma_version" in data
    assert "elapsed_ms" in data
    assert isinstance(data["summary"]["reasons"], dict)
    tree = ET.parse(xml_path)
    assert tree.getroot().tag == "group"
    assert len(tree.getroot().findall("rule")) == data["summary"]["rule_elements"]


def test_cli_bad_yaml_exits_3(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, xml_path, report_path = _convert(tmp_path, BAD_YAML)
    captured = capsys.readouterr()
    assert code == 3
    assert "Convert finished:" in captured.out
    assert "OK" not in captured.out
    assert "OK" not in captured.err
    data = json.loads(report_path.read_text(encoding="utf-8"))
    _assert_invariant(data["summary"])
    record = data["records"][0]
    assert record["parse_status"] == "FAILED"
    assert record["conversion_status"] == "SKIPPED"
    assert xml_path.is_file()
    assert ET.parse(xml_path).getroot().findall("rule") == []


def test_cli_invalid_xml_char_keeps_sibling(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, xml_path, report_path = _convert(tmp_path, GOOD, BAD_CHAR)
    captured = capsys.readouterr()
    assert code == 3
    assert "Convert finished:" in captured.out
    assert "OK" not in captured.out
    assert "OK" not in captured.err

    data = json.loads(report_path.read_text(encoding="utf-8"))
    _assert_invariant(data["summary"])
    by_name = {Path(item["rule_path"]).name: item for item in data["records"]}
    good = by_name["eligible_endswith.yml"]
    bad = by_name["xml_invalid_image.yml"]
    assert good["conversion_status"] == "SUCCESS"
    assert good["rule_ids"] == [100000]
    assert bad["conversion_status"] == "FAILED"
    assert bad["reason"] == "XML_INVALID_CHAR"
    assert bad["rule_ids"] == []

    text = xml_path.read_text(encoding="utf-8")
    assert "\x01" not in text
    root = ET.fromstring(text)
    rules = root.findall("rule")
    assert [rule.get("id") for rule in rules] == ["100000"]
    assert "Phase3 Fixture Eligible Endswith" in text


def test_ampersand_in_image_still_converts(tmp_path: Path) -> None:
    rule = tmp_path / "amp.yml"
    rule.write_text(
        """title: Ampersand is legal XML
id: 88888888-8888-8888-8888-888888888888
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: "a&b<c>"
    condition: selection
level: low
""",
        encoding="utf-8",
    )
    report = convert_from_input(
        rule,
        path_base=tmp_path,
        field_mapping_path=FIELD_MAPPING,
        rule_id_base=100000,
        if_sid=61603,
        level_map=LEVEL_MAP,
    )
    assert report["records"][0]["conversion_status"] == "SUCCESS"
    text = xml_to_string(report["xml_root"])
    ET.fromstring(text)
    assert r"\x26" in text
    assert r"\x3C" in text


def test_refuse_overwrite_checks_every_dest_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    xml_path = tmp_path / "rules.xml"
    report_path = tmp_path / "report.json"
    xml_path.write_text("sentinel-xml", encoding="utf-8")
    code = main(
        [
            "convert",
            "--input",
            str(GOOD),
            "--output-xml",
            str(xml_path),
            "--output-report",
            str(report_path),
            "--field-mapping",
            str(FIELD_MAPPING),
        ]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "OutputError:" in captured.err
    assert xml_path.read_text(encoding="utf-8") == "sentinel-xml"
    assert not report_path.exists()


def test_force_replaces_both_files(tmp_path: Path) -> None:
    xml_path = tmp_path / "rules.xml"
    report_path = tmp_path / "report.json"
    xml_path.write_text("sentinel-xml", encoding="utf-8")
    report_path.write_text("sentinel-json", encoding="utf-8")
    code = main(
        [
            "convert",
            "--input",
            str(GOOD),
            "--output-xml",
            str(xml_path),
            "--output-report",
            str(report_path),
            "--field-mapping",
            str(FIELD_MAPPING),
            "--force",
        ]
    )
    assert code == 0
    assert "sentinel-xml" not in xml_path.read_text(encoding="utf-8")
    assert "sentinel-json" not in report_path.read_text(encoding="utf-8")
    ET.parse(xml_path)


def test_same_output_path_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dest = tmp_path / "same.xml"
    code = main(
        [
            "convert",
            "--input",
            str(GOOD),
            "--output-xml",
            str(dest),
            "--output-report",
            str(dest),
            "--field-mapping",
            str(FIELD_MAPPING),
            "--force",
        ]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "same file" in captured.err
    assert not dest.exists()


@pytest.mark.slow
def test_corpus_convert_summary() -> None:
    cfg = load_config(project_root=ROOT)
    report = convert_from_input(
        CORPUS,
        path_base=ROOT / "input" / "sigma_rules",
        field_mapping_path=FIELD_MAPPING,
        rule_id_base=cfg.wazuh_rule_id_base,
        if_sid=cfg.wazuh_if_sid,
        level_map=cfg.wazuh_level_map,
    )
    summary = report["summary"]
    _assert_invariant(summary)
    assert summary["total"] == 1193
    text = xml_to_string(report["xml_root"])
    assert "\x01" not in text
    assert len(ET.fromstring(text).findall("rule")) == summary["rule_elements"]
