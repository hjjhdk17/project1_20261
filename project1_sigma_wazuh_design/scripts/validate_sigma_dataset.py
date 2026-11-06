#!/usr/bin/env python3
"""Validate a local Sigma rule corpus and write a JSON inventory.

This script checks filesystem integrity, YAML syntax, basic Sigma metadata,
and (when available) pySigma parsing. It is a project helper, not a replacement
for SigmaHQ's complete rule validation pipeline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import yaml


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def try_pysigma_parse(text: str) -> tuple[str, str | None]:
    """Try parsing a Sigma document using pySigma when its API is available."""
    try:
        from sigma.collection import SigmaCollection  # type: ignore
    except ImportError:
        return "NOT_RUN_PYSIGMA_MISSING", None

    try:
        collection = SigmaCollection.from_yaml(text)
        if len(collection.rules) < 1:
            return "PYSIGMA_EMPTY", "No Sigma rules returned by parser."
        return "PYSIGMA_OK", None
    except Exception as exc:  # one malformed rule must not stop the inventory
        return "PYSIGMA_ERROR", f"{type(exc).__name__}: {exc}"


def validate_file(path: Path, root: Path) -> dict[str, Any]:
    """Validate one rule file and return a JSON-serializable record."""
    record: dict[str, Any] = {
        "relative_path": path.relative_to(root).as_posix(),
        "exists": path.is_file(),
        "sha256": sha256_file(path),
        "yaml_status": "NOT_RUN",
        "pysigma_status": "NOT_RUN",
        "errors": [],
    }

    try:
        text = path.read_text(encoding="utf-8")
        document = yaml.safe_load(text)
        if not isinstance(document, dict):
            raise ValueError("Top-level YAML document must be a mapping.")
        record["yaml_status"] = "OK"
        record["title"] = document.get("title")
        record["id"] = document.get("id")
        record["status"] = document.get("status")
        record["level"] = document.get("level")
        record["logsource"] = document.get("logsource")
        record["has_detection"] = isinstance(document.get("detection"), dict)

        if not document.get("title"):
            record["errors"].append("MISSING_TITLE")
        if not isinstance(document.get("detection"), dict):
            record["errors"].append("MISSING_OR_INVALID_DETECTION")
        logsource = document.get("logsource")
        if isinstance(logsource, dict):
            if logsource.get("product") != "windows":
                record["errors"].append("LOGSOURCE_PRODUCT_NOT_WINDOWS")
            if logsource.get("category") != "process_creation":
                record["errors"].append("LOGSOURCE_CATEGORY_NOT_PROCESS_CREATION")

        sigma_status, sigma_error = try_pysigma_parse(text)
        record["pysigma_status"] = sigma_status
        if sigma_error:
            record["errors"].append(sigma_error)
    except Exception as exc:
        record["yaml_status"] = "ERROR"
        record["errors"].append(f"{type(exc).__name__}: {exc}")

    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="Directory containing YAML rules.")
    parser.add_argument("--output", required=True, type=Path, help="JSON report output path.")
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    if not root.is_dir():
        parser.error(f"Rule directory does not exist: {root}")

    paths = sorted(
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    )
    records = [validate_file(path, root) for path in paths]

    ids: dict[str, list[str]] = {}
    for record in records:
        rule_id = record.get("id")
        if isinstance(rule_id, str) and rule_id:
            ids.setdefault(rule_id, []).append(record["relative_path"])
    duplicate_ids = {
        rule_id: rule_paths for rule_id, rule_paths in ids.items() if len(rule_paths) > 1
    }

    summary = {
        "root": str(root),
        "discovered_files": len(records),
        "yaml_ok": sum(record["yaml_status"] == "OK" for record in records),
        "yaml_error": sum(record["yaml_status"] == "ERROR" for record in records),
        "pysigma_ok": sum(record["pysigma_status"] == "PYSIGMA_OK" for record in records),
        "pysigma_error": sum(record["pysigma_status"] == "PYSIGMA_ERROR" for record in records),
        "pysigma_not_run": sum(record["pysigma_status"] == "NOT_RUN_PYSIGMA_MISSING" for record in records),
        "duplicate_sigma_ids": duplicate_ids,
    }

    output = {
        "summary": summary,
        "rules": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\nDetailed report: {args.output}")
    return 1 if summary["yaml_error"] or duplicate_ids else 0


if __name__ == "__main__":
    raise SystemExit(main())
