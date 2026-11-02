#!/usr/bin/env python3
"""Copy an exported Sigma tree and write collection metadata.

The script does not contact the network. collect_sigma_rules.sh is responsible
for the clone and for exporting blob bytes with git archive.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from sigma_dataset_lib import json_dump, stage_yaml_tree, utc_now


def _utc(value: str) -> str:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _relative(path: Path, root: Path | None) -> str:
    if root is None:
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--dest", required=True, type=Path)
    parser.add_argument("--upstream-list", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--source-repo", required=True)
    parser.add_argument("--source-path", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--default-branch", required=True)
    parser.add_argument("--commit-file", required=True, type=Path)
    parser.add_argument("--clone-dir", required=True, type=Path)
    parser.add_argument("--git-version", required=True)
    parser.add_argument("--collected-at-utc", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    commit_lines = args.commit_file.read_text(encoding="utf-8").splitlines()
    if len(commit_lines) < 2:
        print("Commit file must contain a subject line and a committer timestamp.", file=sys.stderr)
        return 2
    subject, committer = commit_lines[0], commit_lines[1]
    collected_at = args.collected_at_utc or utc_now()
    root = args.project_root
    metadata = {
        "source_repo": args.source_repo,
        "source_path": args.source_path,
        "default_branch": args.default_branch,
        "source_commit": args.source_commit,
        "commit_subject": subject,
        "commit_committer_date": committer,
        "commit_committer_date_utc": _utc(committer),
        "collected_at_utc": collected_at,
        "collection_method": "git sparse checkout, detached checkout of the resolved commit, git archive of the tree",
        "clone_dir": _relative(args.clone_dir, root),
        "destination_dir": _relative(args.dest, root),
        "git_version": args.git_version,
        "notes": [
            "The commit is checked out by SHA. A later move of the default branch does not change this snapshot.",
            "Rule bytes come from git archive, not from a worktree that a smudge filter could rewrite.",
            "Non-YAML files in the upstream tree are recorded and are not copied into the corpus.",
            "Existing destination files with different bytes are left unchanged and reported as errors.",
        ],
    }
    upstream_list = args.upstream_list.read_text(encoding="utf-8").splitlines()
    result = stage_yaml_tree(args.source, args.dest, upstream_list, metadata)
    json_dump(args.metadata, result)
    print(
        f"Collected {result['yaml_files_collected']} YAML files "
        f"at {result['source_commit']} into {result['destination_dir']}"
    )
    if result["errors"]:
        print(f"Collection errors: {len(result['errors'])}", file=sys.stderr)
        for item in result["errors"][:20]:
            print(f"- {item}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
