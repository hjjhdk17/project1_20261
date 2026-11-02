#!/usr/bin/env python3
"""Write the feature inventory for the collected process-creation rules."""

from __future__ import annotations

import argparse
from pathlib import Path

from feature_inventory import METHODOLOGY, render_feature_markdown, summarize_features
from sigma_dataset_lib import (
    SCHEMA_VERSION,
    inspect_rule_file,
    iter_yaml_files,
    json_dump,
    load_json,
    tool_versions,
    utc_now,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-root", required=True, type=Path)
    parser.add_argument("--path-base", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    collection = load_json(args.metadata)
    records = [
        inspect_rule_file(path, args.path_base.resolve())
        for path in iter_yaml_files(args.rules_root.resolve())
    ]
    inventory = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "intentionally_variable_fields": ["generated_at_utc"],
        "source_repo": collection.get("source_repo"),
        "source_path": collection.get("source_path"),
        "source_commit": collection.get("source_commit"),
        "tool_versions": tool_versions(),
        "file_count": len(records),
        "methodology": METHODOLOGY,
        "summary": summarize_features(records),
        "per_rule": records,
    }
    json_dump(args.json_output, inventory)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.write_text(render_feature_markdown(inventory), encoding="utf-8")
    print(
        f"Inventoried {len(records)} files. "
        f"Syntactic {inventory['summary']['yaml_files_in_syntactic_counts']}, "
        f"pySigma {inventory['summary']['pysigma_ok_files_in_parser_counts']}."
    )
    print(f"JSON inventory: {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
