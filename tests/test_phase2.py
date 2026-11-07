"""Kiểm thử Phase 2: loader, parser, CLI parse, batch isolation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sigma2wazuh.cli import main
from sigma2wazuh.parsing import discover_rule_files, parse_batch, parse_one, write_report

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "phase2"
CURATED = (
    Path(__file__).resolve().parents[1]
    / "input"
    / "sigma_rules"
    / "curated"
)


def test_discover_sorts_and_finds_yaml() -> None:
    files = discover_rule_files(FIXTURES)
    names = [path.name for path in files]
    assert names == sorted(names)
    assert "good_simple.yml" in names
    assert "bad_yaml.yml" in names


def test_parse_good_simple() -> None:
    result = parse_one(FIXTURES / "good_simple.yml", path_base=FIXTURES)
    assert result["parse_status"] == "OK"
    assert result["failure_stage"] is None
    assert result["sha256"]
    assert result["metadata"]["title"] == "Phase2 Fixture Good Simple"
    assert result["metadata"]["id"] == "11111111-1111-1111-1111-111111111111"


def test_parse_optional_metadata_absent_fields_are_null() -> None:
    result = parse_one(FIXTURES / "good_optional_metadata.yml", path_base=FIXTURES)
    assert result["parse_status"] == "OK"
    meta = result["metadata"]
    assert meta["description"] is None
    assert meta["author"] is None
    assert meta["tags"] is None
    assert meta["falsepositives"] is None


def test_parse_bad_yaml() -> None:
    result = parse_one(FIXTURES / "bad_yaml.yml", path_base=FIXTURES)
    assert result["parse_status"] == "FAILED"
    assert result["failure_stage"] == "yaml"


def test_parse_empty_file() -> None:
    result = parse_one(FIXTURES / "empty.yml", path_base=FIXTURES)
    assert result["parse_status"] == "FAILED"
    assert result["failure_stage"] == "empty"


def test_parse_not_sigma_rule() -> None:
    result = parse_one(FIXTURES / "not_a_sigma_rule.yml", path_base=FIXTURES)
    assert result["parse_status"] == "FAILED"
    assert result["failure_stage"] == "pysigma"


def test_missing_path() -> None:
    result = parse_one(FIXTURES / "does_not_exist.yml", path_base=FIXTURES)
    assert result["parse_status"] == "FAILED"
    assert result["failure_stage"] == "missing_path"


def test_empty_directory(tmp_path: Path) -> None:
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()
    report = parse_batch(empty_dir, path_base=tmp_path)
    assert report["summary"] == {"total": 0, "ok": 0, "failed": 0}
    assert report["records"] == []


def test_batch_mixed_does_not_stop() -> None:
    report = parse_batch(FIXTURES, path_base=FIXTURES)
    summary = report["summary"]
    assert summary["total"] == summary["ok"] + summary["failed"]
    assert summary["ok"] >= 2
    assert summary["failed"] >= 3
    # Đủ record, không thiếu file đã discover.
    assert len(report["records"]) == summary["total"]


def test_write_report_roundtrip(tmp_path: Path) -> None:
    report = parse_batch(FIXTURES / "good_simple.yml", path_base=FIXTURES)
    out = tmp_path / "out.json"
    write_report(report, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["summary"]["ok"] == 1
    assert loaded["records"][0]["parse_status"] == "OK"


@pytest.mark.parametrize(
    "name",
    [
        "proc_creation_win_wpbbin_potential_persistence.yml",
        "proc_creation_win_device_credential_deployment.yml",
        "proc_creation_win_lolbin_utilityfunctions.yml",
    ],
)
def test_curated_smoke(name: str) -> None:
    path = CURATED / name
    assert path.is_file(), f"missing curated rule: {name}"
    result = parse_one(path, path_base=CURATED.parent)
    assert result["parse_status"] == "OK", result.get("diagnostics")


def test_cli_parse_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["parse", "--help"])
    assert excinfo.value.code == 0
    assert "--input" in capsys.readouterr().out


def test_cli_parse_fixtures(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "phase2.json"
    code = main(["parse", "--input", str(FIXTURES), "--output", str(out)])
    captured = capsys.readouterr()
    assert code == 0
    assert "Parse OK:" in captured.out
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == data["summary"]["ok"] + data["summary"]["failed"]
    assert data["summary"]["failed"] >= 1


def test_help_lists_parse_not_convert(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    help_text = capsys.readouterr().out
    assert "parse" in help_text
    assert "validate-config" in help_text
    assert "{convert}" not in help_text
    assert "\n  convert " not in help_text
