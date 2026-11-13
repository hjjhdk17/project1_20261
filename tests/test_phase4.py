"""Kiểm thử Phase 4: map ELIGIBLE → IR mỏng; CLI map."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sigma2wazuh import __version__
from sigma2wazuh.cli import main
from sigma2wazuh.config import find_project_root
from sigma2wazuh.mapper import build_selection_node, load_field_mapping, map_batch
from sigma2wazuh.support_analyzer import ALLOWED_FIELDS

ROOT = Path(__file__).resolve().parents[1]
PHASE3 = Path(__file__).resolve().parent / "fixtures" / "phase3"
PHASE4 = Path(__file__).resolve().parent / "fixtures" / "phase4"
PHASE2 = Path(__file__).resolve().parent / "fixtures" / "phase2"
CURATED = ROOT / "input" / "sigma_rules" / "curated"
FIELD_MAPPING = ROOT / "config" / "field_mapping.yaml"


def _assert_summary_invariant(summary: dict) -> None:
    assert summary["total"] == (
        summary["mapped"]
        + summary["skipped_unsupported"]
        + summary["skipped_failed"]
        + summary["map_failed"]
    )


def test_allowlist_fields_covered_by_mapping() -> None:
    mapping = load_field_mapping(FIELD_MAPPING)
    missing = sorted(ALLOWED_FIELDS - set(mapping))
    assert missing == [], f"field_mapping.yaml thiếu: {missing}"


def test_map_endswith_ir_shape() -> None:
    report = map_batch(
        PHASE3 / "eligible_endswith.yml",
        path_base=PHASE3,
        field_mapping_path=FIELD_MAPPING,
    )
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["mapped"] == 1
    record = report["records"][0]
    assert record["map_status"] == "MAPPED"
    ir = record["ir"]
    assert ir["selections"]["selection"]["type"] == "and"
    pred = ir["selections"]["selection"]["children"][0]
    assert pred["type"] == "pred"
    assert pred["sigma_field"] == "Image"
    assert pred["target_field"] == "win.eventdata.image"
    assert pred["op"] == "endswith"
    assert pred["values"] == ["\\cmd.exe"]
    assert pred["case_insensitive"] is True
    assert ir["condition"] == {"type": "ref", "selection": "selection"}


def test_map_contains_all() -> None:
    report = map_batch(
        PHASE3 / "eligible_contains_all.yml",
        path_base=PHASE3,
        field_mapping_path=FIELD_MAPPING,
    )
    pred = report["records"][0]["ir"]["selections"]["selection"]["children"][0]
    assert pred["op"] == "contains_all"
    assert pred["values"] == ["-enc", "bypass"]
    assert pred["target_field"] == "win.eventdata.commandLine"


def test_map_and_not_preserves_not() -> None:
    report = map_batch(
        PHASE3 / "eligible_and_not.yml",
        path_base=PHASE3,
        field_mapping_path=FIELD_MAPPING,
    )
    cond = report["records"][0]["ir"]["condition"]
    assert cond["type"] == "and"
    assert cond["children"][0] == {"type": "ref", "selection": "selection"}
    assert cond["children"][1]["type"] == "not"
    assert cond["children"][1]["child"] == {"type": "ref", "selection": "filter"}
    assert "filter" in report["records"][0]["ir"]["selections"]


def test_map_all_of_and_one_of() -> None:
    all_of = map_batch(
        PHASE3 / "eligible_all_of.yml",
        path_base=PHASE3,
        field_mapping_path=FIELD_MAPPING,
    )["records"][0]["ir"]["condition"]
    assert all_of["type"] == "and"
    assert {c["selection"] for c in all_of["children"]} == {
        "selection_cli",
        "selection_img",
    }

    one_of = map_batch(
        PHASE3 / "eligible_one_of.yml",
        path_base=PHASE3,
        field_mapping_path=FIELD_MAPPING,
    )["records"][0]["ir"]["condition"]
    assert one_of["type"] == "or"
    assert {c["selection"] for c in one_of["children"]} == {
        "selectionA",
        "selectionB",
    }


def test_map_startswith_and_exact_user() -> None:
    report = map_batch(
        PHASE3 / "eligible_startswith_user.yml",
        path_base=PHASE3,
        field_mapping_path=FIELD_MAPPING,
    )
    children = report["records"][0]["ir"]["selections"]["selection"]["children"]
    ops = {c["sigma_field"]: c["op"] for c in children}
    assert ops["ParentImage"] == "startswith"
    assert ops["User"] == "eq"
    assert all(c["case_insensitive"] is True for c in children)


def test_map_skips_unsupported_and_parse_failed() -> None:
    # Trộn P3 (có unsupported) + P2 (parse fail).
    report = map_batch(
        PHASE3,
        path_base=PHASE3,
        field_mapping_path=FIELD_MAPPING,
    )
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["skipped_unsupported"] >= 3
    assert report["summary"]["mapped"] >= 6
    assert report["tool_version"] == __version__

    failed_parse = map_batch(
        PHASE2,
        path_base=PHASE2,
        field_mapping_path=FIELD_MAPPING,
    )
    _assert_summary_invariant(failed_parse["summary"])
    assert failed_parse["summary"]["skipped_failed"] >= 1
    assert all(
        r["map_status"] == "SKIPPED_FAILED"
        for r in failed_parse["records"]
        if r.get("parse_status") == "FAILED"
    )


def test_wildcard_map_failed() -> None:
    report = map_batch(
        PHASE4 / "wildcard_contains.yml",
        path_base=PHASE4,
        field_mapping_path=FIELD_MAPPING,
    )
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["map_failed"] == 1
    record = report["records"][0]
    assert record["support_status"] == "ELIGIBLE"
    assert record["map_status"] == "FAILED"
    assert record["ir"] is None
    assert any(d["code"] == "WILDCARD_UNSUPPORTED" for d in record["map_diagnostics"])


def test_sigma_decode_backslash_and_literal_star() -> None:
    """Decode SigmaString: path 1 \\ giữ nguyên; UNC \\\\ → \\ ; \\* literal vs * wildcard."""
    mapping = load_field_mapping(FIELD_MAPPING)

    path_node, path_err = build_selection_node(
        {"Image": r"C:\Windows\x.exe"}, mapping
    )
    assert path_err == []
    assert path_node is not None
    assert path_node["children"][0]["values"] == [r"C:\Windows\x.exe"]

    # Hai \\ trước server (dạng sau YAML) → IR một \\server\share.
    unc_node, unc_err = build_selection_node(
        {"Image": r"\\server\share"}, mapping
    )
    assert unc_err == []
    assert unc_node is not None
    assert unc_node["children"][0]["values"] == [r"\server\share"]

    lit_node, lit_err = build_selection_node(
        {"CommandLine|contains": r"a\*b"}, mapping
    )
    assert lit_err == []
    assert lit_node is not None
    assert lit_node["children"][0]["values"] == ["a*b"]
    assert lit_node["children"][0]["op"] == "contains"

    wild_node, wild_err = build_selection_node(
        {"CommandLine|contains": "a*b"}, mapping
    )
    assert wild_node is None
    assert any(d["code"] == "WILDCARD_UNSUPPORTED" for d in wild_err)


def test_value_unsupported_null_and_empty_list() -> None:
    """null / list rỗng vẫn ELIGIBLE ở Phase 3 nhưng mapper phải FAILED."""
    report = map_batch(
        PHASE4 / "value_null.yml",
        path_base=PHASE4,
        field_mapping_path=FIELD_MAPPING,
    )
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["map_failed"] == 1
    record = report["records"][0]
    assert record["support_status"] == "ELIGIBLE"
    assert record["map_status"] == "FAILED"
    assert record["ir"] is None
    assert any(d["code"] == "VALUE_UNSUPPORTED" for d in record["map_diagnostics"])

    mapping = load_field_mapping(FIELD_MAPPING)
    empty_node, empty_err = build_selection_node(
        {"Image|endswith": []}, mapping
    )
    assert empty_node is None
    assert any(d["code"] == "VALUE_UNSUPPORTED" for d in empty_err)

    blank_node, blank_err = build_selection_node(
        {"CommandLine|contains": ""}, mapping
    )
    assert blank_node is None
    assert any(d["code"] == "VALUE_UNSUPPORTED" for d in blank_err)

    bad_mod_node, bad_mod_err = build_selection_node(
        {"Image|re": "cmd"}, mapping
    )
    assert bad_mod_node is None
    assert any(d["code"] == "MODIFIER_UNSUPPORTED" for d in bad_mod_err)


def test_missing_field_mapping_map_failed() -> None:
    report = map_batch(
        PHASE4 / "eligible_needs_user.yml",
        path_base=PHASE4,
        field_mapping_path=PHASE4 / "mapping_incomplete.yaml",
    )
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["map_failed"] == 1
    record = report["records"][0]
    assert record["map_status"] == "FAILED"
    assert any(d["code"] == "FIELD_MAPPING_MISSING" for d in record["map_diagnostics"])


def test_analyze_attaches_detection_for_eligible() -> None:
    from sigma2wazuh.support_analyzer import analyze_batch

    report = analyze_batch(PHASE3 / "eligible_endswith.yml", path_base=PHASE3)
    record = report["records"][0]
    assert record["support_status"] == "ELIGIBLE"
    assert isinstance(record.get("detection"), dict)
    assert "selection" in record["detection"]


def test_cli_map_fixtures(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "phase4.json"
    code = main(
        [
            "map",
            "--input",
            str(PHASE3),
            "--output",
            str(out),
            "--field-mapping",
            str(FIELD_MAPPING),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "Map OK:" in captured.out
    data = json.loads(out.read_text(encoding="utf-8"))
    _assert_summary_invariant(data["summary"])
    assert data["summary"]["mapped"] >= 1


def test_cli_map_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["map", "--help"])
    assert excinfo.value.code == 0
    assert "--input" in capsys.readouterr().out


def test_curated_map_smoke() -> None:
    report = map_batch(
        CURATED,
        path_base=find_project_root() / "input" / "sigma_rules",
        field_mapping_path=FIELD_MAPPING,
    )
    _assert_summary_invariant(report["summary"])
    assert report["summary"]["total"] == 23
    assert report["summary"]["skipped_failed"] == 0
    # curated có 1 ELIGIBLE chứa wildcard (scecli\0*) → ít nhất 1 map_failed.
    assert report["summary"]["map_failed"] >= 1
    assert report["summary"]["mapped"] >= 1
    assert report["summary"]["skipped_unsupported"] >= 1
