#!/usr/bin/env python3
"""Build a manifest from the collected Sigma YAML files."""

from __future__ import annotations

import argparse
from pathlib import Path

from sigma_dataset_lib import (
    SCHEMA_VERSION,
    count_status,
    duplicate_ids,
    inspect_rule_file,
    iter_yaml_files,
    json_dump,
    load_json,
    manifest_rule,
    tool_versions,
    utc_now,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-root", required=True, type=Path)
    parser.add_argument("--path-base", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rules_root = args.rules_root.expanduser().resolve()
    path_base = args.path_base.expanduser().resolve()
    if not rules_root.is_dir():
        raise SystemExit(f"Rule directory does not exist: {rules_root}")
    collection = load_json(args.metadata)
    records = [inspect_rule_file(path, path_base) for path in iter_yaml_files(rules_root)]
    rules = [manifest_rule(record) for record in records]
    duplicates = duplicate_ids(rules)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "path_base": "input/sigma_rules",
        "source_repo": collection.get("source_repo"),
        "source_path": collection.get("source_path"),
        "default_branch": collection.get("default_branch"),
        "source_commit": collection.get("source_commit"),
        "collected_at_utc": collection.get("collected_at_utc"),
        "manifest_generated_at_utc": utc_now(),
        "tool_versions": tool_versions(),
        "summary": {
            "yaml_file_count": len(rules),
            "yaml_status": count_status(rules, "yaml_status"),
            "pysigma_status": count_status(rules, "pysigma_status"),
            "sigma_yaml_loader_status": count_status(rules, "sigma_yaml_loader_status"),
            "duplicate_id_count": len(duplicates),
        },
        "duplicate_ids": duplicates,
        "rules": rules,
        "schema_notes": [
            "relative_path is relative to input/sigma_rules.",
            "yaml_status and pysigma_status are independent.",
            "PYSIGMA_OK requires one SigmaRule and a successful condition parse.",
            "sigma_yaml_loader_status uses SigmaYAMLLoader, which SigmaCollection.from_yaml does not call.",
            "null means the field was absent or could not be read. It is not a fabricated value.",
            "manifest_generated_at_utc changes on every run. collected_at_utc comes from the collection metadata.",
        ],
    }
    json_dump(args.output, manifest)
    print(
        f"Wrote {len(rules)} rules to {args.output} "
        f"(yaml {manifest['summary']['yaml_status']}, pySigma {manifest['summary']['pysigma_status']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
