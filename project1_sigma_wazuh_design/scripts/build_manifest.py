#!/usr/bin/env python3
"""Create a source/checksum manifest for a collected Sigma rule directory."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--source-repo", default="https://github.com/SigmaHQ/sigma")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    if not root.is_dir():
        parser.error(f"Directory does not exist: {root}")

    rules = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
            rules.append({
                "relative_path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            })

    manifest = {
        "source_repo": args.source_repo,
        "source_commit": args.source_commit,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "rule_count": len(rules),
        "rules": rules,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(rules)} file entries to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
