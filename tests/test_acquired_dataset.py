"""Checks against the acquired SigmaHQ snapshot.

These tests are skipped only when Phase 0 acquisition has not been run.
The Phase 0 report must show them as executed, not skipped.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import sigma_dataset_lib as lib
import validate_sigma_dataset as validator

ROOT = Path(__file__).resolve().parents[1]
PATH_BASE = ROOT / "input" / "sigma_rules"
RULES = PATH_BASE / "windows" / "process_creation"
MANIFEST_PATH = PATH_BASE / "manifest.json"
METADATA_PATH = PATH_BASE / "collection_metadata.json"
CURATED_PATH = PATH_BASE / "curated_selection.json"
INVENTORY_PATH = PATH_BASE / "feature_inventory.json"


def _require(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"Phase 0 artifact is not present yet: {path.relative_to(ROOT)}")


def test_manifest_matches_filesystem_bytes() -> None:
    _require(MANIFEST_PATH)
    _require(METADATA_PATH)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    files = list(lib.iter_yaml_files(RULES))
    assert manifest["summary"]["yaml_file_count"] == len(files)
    assert len(manifest["rules"]) == len(files)
    assert manifest["source_commit"] == metadata["source_commit"]
    assert len(manifest["source_commit"]) == 40
    by_path = {entry["relative_path"]: entry for entry in manifest["rules"]}
    meta_by_path = {entry["relative_path"]: entry for entry in metadata["files"]}
    assert set(by_path) == set(meta_by_path)
    for path in files:
        relative = lib.relative_to_base(path, PATH_BASE)
        entry = by_path[relative]
        assert path.is_file()
        digest = lib.sha256_file(path)
        assert digest == entry["sha256"]
        assert digest == meta_by_path[relative]["sha256"]
        assert entry["size_bytes"] == path.stat().st_size
        assert ".." not in Path(relative).parts


def test_curated_rules_are_upstream_bytes_with_provenance() -> None:
    _require(CURATED_PATH)
    _require(MANIFEST_PATH)
    selection = json.loads(CURATED_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    by_path = {entry["relative_path"]: entry for entry in manifest["rules"]}
    assert selection["rules"]
    assert selection["source_commit"] == manifest["source_commit"]
    assert selection["unexpected_curated_files"] == []
    names = set()
    for item in selection["rules"]:
        assert item["expected_support_status"] is None
        assert item["sigma_id"]
        assert item["title"]
        assert item["selection_reason"]
        assert item["sha256"]
        source = PATH_BASE / item["source_relative_path"]
        curated = PATH_BASE / item["curated_relative_path"]
        assert source.is_file()
        assert curated.is_file()
        assert curated.read_bytes() == source.read_bytes()
        assert lib.sha256_file(curated) == item["sha256"]
        assert by_path[item["source_relative_path"]]["sha256"] == item["sha256"]
        assert by_path[item["source_relative_path"]]["id"] == item["sigma_id"]
        names.add(curated.name)
    on_disk = {path.name for path in (PATH_BASE / "curated").glob("*.yml")}
    assert on_disk == names


def test_validation_is_stable_across_two_runs(tmp_path: Path) -> None:
    _require(MANIFEST_PATH)
    first_json = tmp_path / "first.json"
    second_json = tmp_path / "second.json"
    args = [
        "--rules-root",
        str(RULES),
        "--path-base",
        str(PATH_BASE),
        "--manifest",
        str(MANIFEST_PATH),
        "--json-output",
        str(first_json),
        "--markdown-output",
        str(tmp_path / "first.md"),
    ]
    first_code = validator.main(args)
    args[7] = str(second_json)
    args[9] = str(tmp_path / "second.md")
    second_code = validator.main(args)
    assert first_code == second_code
    first = json.loads(first_json.read_text(encoding="utf-8"))
    second = json.loads(second_json.read_text(encoding="utf-8"))
    assert lib.drop_variable_fields(first, {"generated_at_utc"}) == lib.drop_variable_fields(
        second,
        {"generated_at_utc"},
    )
    assert first["summary"]["integrity_passed"] is True
    assert INVENTORY_PATH.is_file()
