"""Tests for the Phase 0 dataset tools.

Fixtures are temporary and are not part of the SigmaHQ corpus.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import build_curated_set
import build_manifest
import sigma_dataset_lib as lib
import validate_sigma_dataset as validator

RULE_A = """\
title: Fixture A
id: 11111111-1111-4111-8111-111111111111
status: stable
level: low
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: 'C:\\\\Windows\\\\System32\\\\whoami.exe'
    condition: selection
"""

RULE_B = """\
title: Fixture B
id: 22222222-2222-4222-8222-222222222222
status: stable
level: medium
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"""

NOT_SIGMA = """\
title: Just a mapping
hello: world
"""

DUPLICATE_KEY = """\
title: first
title: second
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: 'C:\\\\Windows\\\\notepad.exe'
    condition: selection
"""


def write_rule(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_sigma_is_parsed_and_plain_yaml_is_not(tmp_path: Path) -> None:
    rule_path = write_rule(tmp_path, "rule.yml", RULE_A)
    plain_path = write_rule(tmp_path, "plain.yml", NOT_SIGMA)

    rule = lib.inspect_rule_file(rule_path, tmp_path)
    plain = lib.inspect_rule_file(plain_path, tmp_path)

    assert rule["yaml_status"] == "OK"
    assert rule["pysigma_status"] == "PYSIGMA_OK"
    assert rule["id"] == "11111111-1111-4111-8111-111111111111"
    assert rule["logsource"]["product"] == "windows"
    assert plain["yaml_status"] == "OK"
    assert plain["pysigma_status"] != "PYSIGMA_OK"
    assert plain["pysigma_status"] not in lib.PYSIGMA_NOT_RUN
    assert any(item.startswith("MISSING_OR_INVALID_DETECTION") for item in plain["errors"])


def test_invalid_yaml_has_an_explicit_diagnostic(tmp_path: Path) -> None:
    path = write_rule(tmp_path, "broken.yml", "title: [\n")
    record = lib.inspect_rule_file(path, tmp_path)
    assert record["yaml_status"] == "ERROR"
    assert record["pysigma_status"] == "NOT_RUN_YAML_FAILED"
    assert record["errors"]
    assert "YAML" in record["errors"][0]


def test_duplicate_ids_are_reported(tmp_path: Path) -> None:
    write_rule(tmp_path, "a.yml", RULE_A)
    write_rule(tmp_path, "b.yml", RULE_A.replace("Fixture A", "Fixture A copy"))
    records = [lib.inspect_rule_file(path, tmp_path) for path in lib.iter_yaml_files(tmp_path)]
    duplicates = lib.duplicate_ids(records)
    assert duplicates == {
        "11111111-1111-4111-8111-111111111111": ["a.yml", "b.yml"],
    }


def test_duplicate_yaml_key_is_distinct_from_safe_load(tmp_path: Path) -> None:
    path = write_rule(tmp_path, "dup.yml", DUPLICATE_KEY)
    record = lib.inspect_rule_file(path, tmp_path)
    assert record["yaml_status"] == "OK"
    assert record["sigma_yaml_loader_status"] == "ERROR"
    assert any("Duplicate key" in item for item in record["errors"])


def test_logsource_mismatch_is_a_warning_not_a_parse_failure(tmp_path: Path) -> None:
    text = RULE_A.replace("product: windows", "product: linux")
    path = write_rule(tmp_path, "other.yml", text)
    record = lib.inspect_rule_file(path, tmp_path)
    assert record["yaml_status"] == "OK"
    assert record["pysigma_status"] == "PYSIGMA_OK"
    assert any(item.startswith("LOGSOURCE_PRODUCT_NOT_WINDOWS") for item in record["warnings"])
    assert lib.error_severity(record) is False


def test_missing_pysigma_is_reported(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setitem(sys.modules, "sigma", None)
    monkeypatch.setitem(sys.modules, "sigma.collection", None)
    monkeypatch.setitem(sys.modules, "sigma.rule", None)
    monkeypatch.setitem(sys.modules, "sigma.rule.base", None)
    path = write_rule(tmp_path, "rule.yml", RULE_A)
    record = lib.inspect_rule_file(path, tmp_path)
    assert record["yaml_status"] == "OK"
    assert record["pysigma_status"] == "NOT_RUN_PYSIGMA_MISSING"
    assert record["pysigma_status"] != "PYSIGMA_OK"


def test_manifest_hashes_match_files_and_counts(tmp_path: Path) -> None:
    rules_root = tmp_path / "rules"
    write_rule(rules_root, "a.yml", RULE_A)
    write_rule(rules_root, "b.yml", RULE_B)
    metadata = tmp_path / "collection_metadata.json"
    manifest_path = tmp_path / "manifest.json"
    metadata.write_text(
        json.dumps(
            {
                "source_repo": "https://example.invalid/sigma",
                "source_path": "rules/windows/process_creation",
                "default_branch": "master",
                "source_commit": "abc",
                "collected_at_utc": "2026-11-02T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    assert build_manifest.main(
        [
            "--rules-root",
            str(rules_root),
            "--path-base",
            str(rules_root),
            "--metadata",
            str(metadata),
            "--output",
            str(manifest_path),
        ]
    ) == 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["summary"]["yaml_file_count"] == 2
    assert manifest["source_commit"] == "abc"
    for entry in manifest["rules"]:
        path = rules_root / entry["relative_path"]
        assert path.is_file()
        assert lib.sha256_file(path) == entry["sha256"]
        assert entry["pysigma_status"] == "PYSIGMA_OK"


def test_checksum_mismatch_and_second_run_are_stable(tmp_path: Path) -> None:
    rules_root = tmp_path / "rules"
    write_rule(rules_root, "a.yml", RULE_A)
    metadata = tmp_path / "collection_metadata.json"
    manifest_path = tmp_path / "manifest.json"
    metadata.write_text(
        json.dumps({"source_repo": "https://example.invalid/sigma", "source_commit": "abc", "collected_at_utc": "2026-11-02T00:00:00Z"}),
        encoding="utf-8",
    )
    build_manifest.main(
        ["--rules-root", str(rules_root), "--path-base", str(rules_root), "--metadata", str(metadata), "--output", str(manifest_path)]
    )
    first_json = tmp_path / "first.json"
    second_json = tmp_path / "second.json"
    first_md = tmp_path / "first.md"
    second_md = tmp_path / "second.md"
    args = [
        "--rules-root",
        str(rules_root),
        "--path-base",
        str(rules_root),
        "--manifest",
        str(manifest_path),
        "--json-output",
        str(first_json),
        "--markdown-output",
        str(first_md),
    ]
    assert validator.main(args) == 0
    args[7] = str(second_json)
    args[9] = str(second_md)
    assert validator.main(args) == 0
    first = json.loads(first_json.read_text(encoding="utf-8"))
    second = json.loads(second_json.read_text(encoding="utf-8"))
    assert lib.drop_variable_fields(first, {"generated_at_utc"}) == lib.drop_variable_fields(
        second, {"generated_at_utc"}
    )

    write_rule(rules_root, "a.yml", RULE_A + "\n# changed\n")
    changed_json = tmp_path / "changed.json"
    changed_md = tmp_path / "changed.md"
    code = validator.main(
        [
            "--rules-root",
            str(rules_root),
            "--path-base",
            str(rules_root),
            "--manifest",
            str(manifest_path),
            "--json-output",
            str(changed_json),
            "--markdown-output",
            str(changed_md),
        ]
    )
    changed = json.loads(changed_json.read_text(encoding="utf-8"))
    assert code == 1
    assert changed["integrity"]["checksum_mismatches"]
    assert changed["summary"]["integrity_passed"] is False


def test_manifest_path_traversal_is_rejected(tmp_path: Path) -> None:
    rules_root = tmp_path / "rules"
    write_rule(rules_root, "a.yml", RULE_A)
    manifest = {
        "source_commit": "abc",
        "source_repo": "https://example.invalid/sigma",
        "rules": [
            {"relative_path": "../outside.yml", "sha256": "0" * 64, "size_bytes": 1},
            {
                "relative_path": "a.yml",
                "sha256": lib.sha256_file(rules_root / "a.yml"),
                "size_bytes": (rules_root / "a.yml").stat().st_size,
            },
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    report = validator.validate_corpus(rules_root, rules_root, manifest_path)
    assert report["integrity"]["unsafe_manifest_paths"] == ["../outside.yml"]
    assert report["summary"]["integrity_passed"] is False


def test_stage_copies_bytes_and_refuses_to_overwrite_differences(tmp_path: Path) -> None:
    source = tmp_path / "export"
    dest = tmp_path / "dest"
    write_rule(source, "proc.yml", RULE_A)
    (source / "readme.md").write_text("not a rule\n", encoding="utf-8")
    upstream = [
        "rules/windows/process_creation/proc.yml",
        "rules/windows/process_creation/readme.md",
    ]
    result = lib.stage_yaml_tree(source, dest, upstream, {"source_commit": "abc"})
    assert result["errors"] == []
    assert result["yaml_files_collected"] == 1
    copied = dest / "proc.yml"
    assert copied.read_bytes() == (source / "proc.yml").read_bytes()
    assert result["non_yaml_files_skipped"] == [
        {"upstream_path": "rules/windows/process_creation/readme.md", "reason": "non_yaml"}
    ]

    copied.write_text("different\n", encoding="utf-8")
    again = lib.stage_yaml_tree(source, dest, upstream, {"source_commit": "abc"})
    assert any("was not overwritten" in item for item in again["errors"])
    assert copied.read_text(encoding="utf-8") == "different\n"


def test_curated_selector_uses_real_records_and_records_gaps() -> None:
    image = {
        "relative_path": "windows/process_creation/image.yml",
        "upstream_path": "rules/windows/process_creation/image.yml",
        "sha256": "a" * 64,
        "size_bytes": 100,
        "title": "Image exact",
        "id": "11111111-1111-4111-8111-111111111111",
        "status": "stable",
        "yaml_status": "OK",
        "pysigma_status": "PYSIGMA_OK",
        "errors": [],
        "logsource": {"product": "windows", "category": "process_creation"},
        "features": {
            "selection_count": 1,
            "selection_names": ["selection"],
            "selection_shapes": {"field_map": 1},
            "fields": {"Image": 1},
            "field_keys": {"Image": 1},
            "modifier_chains": {},
            "modifier_tokens": {},
            "multi_value_fields": 0,
            "multi_field_selections": 0,
            "keyword_selections": 0,
            "keyword_modifier_keys": 0,
            "condition_text": "selection",
            "condition_flags": [],
            "parser": {"wildcard_strings": 0, "placeholder_strings": 0},
        },
    }
    larger = dict(image)
    larger["relative_path"] = "windows/process_creation/larger.yml"
    larger["size_bytes"] = 500
    larger["id"] = "22222222-2222-4222-8222-222222222222"
    selected, gaps = build_curated_set.select_curated([larger, image], limit=30)
    simple = [item for item in selected if item["bucket"] == "simple_image"]
    assert len(simple) == 1
    assert simple[0]["source_relative_path"].endswith("image.yml")
    assert simple[0]["expected_support_status"] is None
    assert any(gap.startswith("regex_modifier:") for gap in gaps)


def test_unsafe_relative_path_helper() -> None:
    assert lib.is_relative_safe("windows/process_creation/rule.yml")
    assert not lib.is_relative_safe("../rule.yml")
    assert not lib.is_relative_safe("/etc/passwd")
    with pytest.raises(ValueError):
        lib.resolve_within(Path("/tmp"), "../rule.yml")
