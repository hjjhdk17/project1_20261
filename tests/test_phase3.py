"""Kiểm thử Phase 3: extract features, classify, CLI analyze."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from sigma2wazuh.cli import main
from sigma2wazuh.support_analyzer import (
    analyze_batch,
    classify,
    extract_features,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "phase3"
PHASE2 = Path(__file__).resolve().parent / "fixtures" / "phase2"
CURATED = (
    Path(__file__).resolve().parents[1] / "input" / "sigma_rules" / "curated"
)


def _detection(name: str) -> dict:
    data = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    return data["detection"]


@pytest.mark.parametrize(
    "name",
    [
        "eligible_endswith.yml",
        "eligible_contains_all.yml",
        "eligible_and_not.yml",
        "eligible_all_of.yml",
        "eligible_one_of.yml",
        "eligible_startswith_user.yml",
    ],
)
def test_eligible_fixtures(name: str) -> None:
    features = extract_features(_detection(name))
    status, reasons = classify(features)
    assert status == "ELIGIBLE", reasons
    assert reasons == []


def test_unsupported_windash() -> None:
    features = extract_features(_detection("unsupported_windash.yml"))
    status, reasons = classify(features)
    assert status == "UNSUPPORTED"
    assert any(item["code"] == "MODIFIER_UNSUPPORTED" for item in reasons)


def test_unsupported_field() -> None:
    features = extract_features(_detection("unsupported_field.yml"))
    status, reasons = classify(features)
    assert status == "UNSUPPORTED"
    assert any(item["code"] == "FIELD_UNSUPPORTED" for item in reasons)
    assert "Hashes" in features["fields"]


def test_unsupported_condition_or() -> None:
    features = extract_features(_detection("unsupported_condition_or.yml"))
    status, reasons = classify(features)
    assert status == "UNSUPPORTED"
    assert any(item["code"] == "CONDITION_UNSUPPORTED" for item in reasons)


def test_keyword_search_unsupported() -> None:
    detection = {"keywords": ["mimikatz"], "condition": "keywords"}
    features = extract_features(detection)
    status, reasons = classify(features)
    assert status == "UNSUPPORTED"
    assert any(item["code"] == "KEYWORD_SEARCH_UNSUPPORTED" for item in reasons)


def test_list_of_maps_unsupported() -> None:
    detection = {
        "selection": [
            {"Image|endswith": "a.exe"},
            {"CommandLine|contains": "x"},
        ],
        "condition": "selection",
    }
    features = extract_features(detection)
    status, reasons = classify(features)
    assert status == "UNSUPPORTED"
    assert any(item["code"] == "LIST_OF_MAPS_UNSUPPORTED" for item in reasons)


def test_empty_selection_unsupported() -> None:
    detection = {"selection": {}, "condition": "selection"}
    features = extract_features(detection)
    status, reasons = classify(features)
    assert status == "UNSUPPORTED"
    assert any(item["code"] == "EMPTY_SELECTION" for item in reasons)


def test_tool_error_is_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Parse OK nhưng không resolve lại được file → FAILED, không cộng unsupported.
    import sigma2wazuh.support_analyzer as sa

    monkeypatch.setattr(sa, "_resolve_rule_file", lambda *a, **k: None)
    report = analyze_batch(FIXTURES, path_base=FIXTURES)
    failed = [r for r in report["records"] if r["support_status"] == "FAILED"]
    assert failed
    assert all(
        any(u["code"] == "SOURCE_UNAVAILABLE" for u in r["unsupported_features"])
        for r in failed
    )
    assert report["summary"]["failed"] == len(failed)
    assert report["summary"]["unsupported"] == 0
    assert report["summary"]["eligible"] == 0


def test_extract_fields_and_modifiers() -> None:
    features = extract_features(_detection("eligible_contains_all.yml"))
    assert features["fields"] == ["CommandLine"]
    assert features["modifiers"] == ["contains|all"]
    assert features["condition"] == "selection"


def test_analyze_batch_mixed_fixtures() -> None:
    report = analyze_batch(FIXTURES, path_base=FIXTURES)
    summary = report["summary"]
    assert summary["total"] == summary["eligible"] + summary["unsupported"] + summary[
        "failed"
    ]
    assert summary["eligible"] >= 6
    assert summary["unsupported"] >= 3
    assert summary["failed"] == 0


def test_analyze_reuses_parse_failures() -> None:
    report = analyze_batch(PHASE2, path_base=PHASE2)
    failed = [r for r in report["records"] if r["parse_status"] == "FAILED"]
    assert failed
    for record in failed:
        assert record["support_status"] is None
        assert record["features"] is None


def test_cli_analyze_fixtures(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "phase3.json"
    code = main(["analyze", "--input", str(FIXTURES), "--output", str(out)])
    captured = capsys.readouterr()
    assert code == 0
    assert "Analyze OK:" in captured.out
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "eligible" in data["summary"]
    assert data["summary"]["eligible"] >= 1


def test_cli_analyze_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["analyze", "--help"])
    assert excinfo.value.code == 0
    assert "--input" in capsys.readouterr().out


def test_help_lists_analyze_not_convert(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    help_text = capsys.readouterr().out
    assert "analyze" in help_text
    assert "{convert}" not in help_text


def test_curated_analyze_smoke() -> None:
    report = analyze_batch(CURATED, path_base=CURATED.parent)
    assert report["summary"]["failed"] == 0
    assert report["summary"]["total"] == 23
    assert report["summary"]["eligible"] + report["summary"]["unsupported"] == 23
    # Ít nhất một rule curated ngoài allowlist (windash / field / condition).
    assert report["summary"]["unsupported"] >= 1
    assert report["summary"]["eligible"] >= 1
