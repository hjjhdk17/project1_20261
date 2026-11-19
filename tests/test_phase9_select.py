"""Phase 9: cắt XML deploy theo id, chỉ record SUCCESS và xml_valid."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from phase9_select_rules import (
    PHASE9_RULE_IDS,
    SelectError,
    select_rules,
    sha256_file,
    write_deploy,
)

ALLOW = (100000, 100002)


def _tree() -> ET.Element:
    xml = """<group name="sigma,">
  <rule id="100000" level="8"><description>keep</description></rule>
  <rule id="100001" level="8"><description>drop</description></rule>
  <rule id="100002" level="8"><description>keep-two</description></rule>
</group>
"""
    return ET.fromstring(xml)


def _report() -> dict:
    def rec(path: str, status: str, valid: bool | None, ids: list[int]) -> dict:
        return {
            "rule_path": path,
            "sha256": "abc",
            "conversion_status": status,
            "xml_valid": valid,
            "rule_ids": ids,
        }

    return {
        "records": [
            rec("a.yml", "SUCCESS", True, [100000]),
            rec("b.yml", "SUCCESS", True, [100001]),
            rec("c.yml", "SUCCESS", True, [100002]),
        ]
    }


def test_allowlist_is_the_seven_locked_ids():
    assert PHASE9_RULE_IDS == (
        100000,
        100002,
        100004,
        100006,
        100007,
        100008,
        100011,
    )


def test_select_keeps_source_order_and_drops_other_success():
    out = select_rules(_tree(), _report(), ALLOW)
    ids = [rule.get("id") for rule in out.findall("rule")]
    assert ids == ["100000", "100002"]
    assert out.get("name") == "sigma,"


def test_rejects_unsupported_even_if_id_is_allowed():
    report = _report()
    report["records"][0]["conversion_status"] = "UNSUPPORTED"
    report["records"][0]["xml_valid"] = False
    with pytest.raises(SelectError, match="100000"):
        select_rules(_tree(), report, ALLOW)


def test_rejects_xml_valid_false():
    report = _report()
    report["records"][2]["xml_valid"] = False
    with pytest.raises(SelectError, match="xml_valid"):
        select_rules(_tree(), report, ALLOW)


def test_missing_id_writes_nothing(tmp_path: Path):
    source = tmp_path / "src.xml"
    report_path = tmp_path / "src.json"
    deploy = tmp_path / "deploy.xml"
    manifest = tmp_path / "manifest.json"
    source.write_text(
        ET.tostring(_tree(), encoding="unicode"),
        encoding="utf-8",
    )
    report_path.write_text(json.dumps(_report()), encoding="utf-8")
    with pytest.raises(SelectError, match="thiếu id"):
        write_deploy(
            source,
            report_path,
            deploy,
            manifest,
            allow=PHASE9_RULE_IDS,
            generated_at_utc="2026-11-19T00:00:00Z",
        )
    assert not deploy.exists()
    assert not manifest.exists()


def test_write_records_both_sha256(tmp_path: Path):
    source = tmp_path / "src.xml"
    report_path = tmp_path / "src.json"
    deploy = tmp_path / "deploy.xml"
    manifest_path = tmp_path / "manifest.json"
    source.write_bytes(ET.tostring(_tree(), encoding="utf-8"))
    report_path.write_text(json.dumps(_report()), encoding="utf-8")
    manifest = write_deploy(
        source,
        report_path,
        deploy,
        manifest_path,
        allow=ALLOW,
        generated_at_utc="2026-11-19T00:00:00Z",
    )
    assert manifest["source_xml_sha256"] == sha256_file(source)
    assert manifest["deploy_xml_sha256"] == sha256_file(deploy)
    assert manifest["rule_ids"] == [100000, 100002]
    saved = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert saved["deploy_xml_sha256"] == manifest["deploy_xml_sha256"]
    assert "does not mean Wazuh loaded" in saved["note"]
    ids = [rule.get("id") for rule in ET.parse(deploy).getroot().findall("rule")]
    assert ids == ["100000", "100002"]


def test_refuses_existing_output_without_force(tmp_path: Path):
    source = tmp_path / "src.xml"
    report_path = tmp_path / "src.json"
    deploy = tmp_path / "deploy.xml"
    manifest_path = tmp_path / "manifest.json"
    source.write_bytes(ET.tostring(_tree(), encoding="utf-8"))
    report_path.write_text(json.dumps(_report()), encoding="utf-8")
    deploy.write_text("<group></group>\n", encoding="utf-8")
    with pytest.raises(SelectError, match="--force"):
        write_deploy(source, report_path, deploy, manifest_path, allow=ALLOW)
    assert deploy.read_text(encoding="utf-8") == "<group></group>\n"
