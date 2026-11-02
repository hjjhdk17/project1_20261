#!/usr/bin/env python3
"""Validate the collected Sigma corpus against its manifest.

The report distinguishes integrity failures, YAML results, pySigma results,
warnings, and checks that did not run. A second run on unchanged inputs
matches the first run except for generated_at_utc.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from sigma_dataset_lib import (
    SCHEMA_VERSION,
    count_status,
    duplicate_ids,
    error_severity,
    inspect_rule_file,
    is_relative_safe,
    iter_yaml_files,
    json_dump,
    load_json,
    manifest_rule,
    relative_to_base,
    resolve_within,
    tool_versions,
    utc_now,
)

COMPARE_FIELDS = (
    "sha256",
    "size_bytes",
    "title",
    "id",
    "status",
    "level",
    "yaml_status",
    "pysigma_status",
    "sigma_yaml_loader_status",
)
VARIABLE_FIELDS = {"generated_at_utc"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-root", required=True, type=Path)
    parser.add_argument("--path-base", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    return parser


def _logsource_key(value: Any) -> str:
    if not isinstance(value, dict):
        return repr(value)
    return repr(
        (
            value.get("product"),
            value.get("category"),
            value.get("service"),
            value.get("definition"),
        )
    )


def validate_corpus(
    rules_root: Path,
    path_base: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    """Re-read the corpus and compare it with the manifest."""
    integrity: dict[str, Any] = {
        "rules_root_exists": rules_root.is_dir(),
        "manifest_loaded": False,
        "filesystem_yaml_count": 0,
        "manifest_rule_count": 0,
        "counts_match": False,
        "missing_files": [],
        "unexpected_files": [],
        "checksum_mismatches": [],
        "record_mismatches": [],
        "path_traversal_attempts": [],
        "unsafe_manifest_paths": [],
    }
    if not rules_root.is_dir():
        return _report(integrity, [], {}, ["Rule directory does not exist."])

    try:
        manifest = load_json(manifest_path)
        integrity["manifest_loaded"] = isinstance(manifest, dict) and isinstance(
            manifest.get("rules"), list
        )
    except (OSError, ValueError) as exc:
        return _report(integrity, [], {}, [f"Could not read manifest: {exc}"])
    if not integrity["manifest_loaded"]:
        return _report(integrity, [], manifest if isinstance(manifest, dict) else {}, ["Manifest has no rules list."])

    filesystem = {
        relative_to_base(path, path_base): path for path in iter_yaml_files(rules_root)
    }
    integrity["filesystem_yaml_count"] = len(filesystem)
    manifest_rules = manifest["rules"]
    integrity["manifest_rule_count"] = len(manifest_rules)
    manifest_paths: dict[str, dict[str, Any]] = {}

    for entry in manifest_rules:
        relative = entry.get("relative_path")
        if not isinstance(relative, str) or not is_relative_safe(relative):
            integrity["unsafe_manifest_paths"].append(relative)
            continue
        try:
            resolved = resolve_within(path_base, relative)
        except ValueError as exc:
            integrity["path_traversal_attempts"].append(str(exc))
            continue
        if relative in manifest_paths:
            integrity["record_mismatches"].append(f"Duplicate manifest path: {relative}")
        manifest_paths[relative] = entry
        if not resolved.is_file():
            integrity["missing_files"].append(relative)

    inspected_by_path = {
        relative: inspect_rule_file(path, path_base) for relative, path in filesystem.items()
    }
    for relative, actual in inspected_by_path.items():
        if relative not in manifest_paths:
            integrity["unexpected_files"].append(relative)
            continue
        expected = manifest_paths[relative].get("sha256")
        if actual["sha256"] != expected:
            integrity["checksum_mismatches"].append(
                {
                    "relative_path": relative,
                    "manifest_sha256": expected,
                    "actual_sha256": actual["sha256"],
                }
            )
        fresh = manifest_rule(actual)
        for field in COMPARE_FIELDS:
            if fresh.get(field) != manifest_paths[relative].get(field):
                integrity["record_mismatches"].append(
                    {
                        "relative_path": relative,
                        "field": field,
                        "manifest": manifest_paths[relative].get(field),
                        "recomputed": fresh.get(field),
                    }
                )
                break
        if _logsource_key(fresh.get("logsource")) != _logsource_key(
            manifest_paths[relative].get("logsource")
        ):
            integrity["record_mismatches"].append(
                {
                    "relative_path": relative,
                    "field": "logsource",
                    "manifest": manifest_paths[relative].get("logsource"),
                    "recomputed": fresh.get("logsource"),
                }
            )

    integrity["counts_match"] = (
        integrity["filesystem_yaml_count"] == integrity["manifest_rule_count"]
        and not integrity["missing_files"]
        and not integrity["unexpected_files"]
    )
    return _report(integrity, list(inspected_by_path.values()), manifest, [])


def _report(
    integrity: dict[str, Any],
    records: list[dict[str, Any]],
    manifest: dict[str, Any],
    blockers: list[str],
) -> dict[str, Any]:
    duplicates = duplicate_ids(records)
    warning_counts: dict[str, int] = {}
    for record in records:
        for warning in record["warnings"]:
            code = warning.split(":", 1)[0]
            warning_counts[code] = warning_counts.get(code, 0) + 1
    error_records = [record for record in records if error_severity(record)]
    integrity_failed = bool(blockers) or any(
        integrity[key]
        for key in (
            "missing_files",
            "unexpected_files",
            "checksum_mismatches",
            "record_mismatches",
            "path_traversal_attempts",
            "unsafe_manifest_paths",
        )
    ) or not integrity["rules_root_exists"] or not integrity["counts_match"]
    summary = {
        "filesystem_yaml_count": integrity["filesystem_yaml_count"],
        "manifest_rule_count": integrity["manifest_rule_count"],
        "yaml_status": count_status(records, "yaml_status") if records else {},
        "pysigma_status": count_status(records, "pysigma_status") if records else {},
        "sigma_yaml_loader_status": count_status(records, "sigma_yaml_loader_status") if records else {},
        "error_severity_files": len(error_records),
        "warning_counts": dict(sorted(warning_counts.items())),
        "duplicate_id_count": len(duplicates),
        "integrity_passed": not integrity_failed,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "intentionally_variable_fields": sorted(VARIABLE_FIELDS),
        "tool_versions": tool_versions(),
        "source_commit": manifest.get("source_commit"),
        "source_repo": manifest.get("source_repo"),
        "summary": summary,
        "integrity": integrity,
        "duplicate_ids": duplicates,
        "blockers": blockers,
        "error_files": [
            {
                "relative_path": record["relative_path"],
                "yaml_status": record["yaml_status"],
                "pysigma_status": record["pysigma_status"],
                "errors": record["errors"],
            }
            for record in error_records
        ],
        "checks": {
            "file_integrity": "executed" if integrity["manifest_loaded"] else "not_completed",
            "yaml_validation": "executed" if records else "not_completed",
            "pysigma_parsing": _pysigma_check(records),
            "duplicate_ids": "executed" if records else "not_completed",
            "logsource_and_detection": "executed" if records else "not_completed",
            "sigmahq_full_lint_suite": "not_run",
        },
        "notes": [
            "yaml_status OK does not imply pysigma_status PYSIGMA_OK.",
            "Logsource mismatches are warnings. They do not change yaml_status or pysigma_status.",
            "sigma-cli's full SigmaHQ validator configuration was not run.",
            "generated_at_utc is the only intentionally variable field.",
        ],
    }


def _pysigma_check(records: list[dict[str, Any]]) -> str:
    if not records:
        return "not_completed"
    statuses = {record["pysigma_status"] for record in records}
    if statuses == {"NOT_RUN_PYSIGMA_MISSING"}:
        return "not_run_pysigma_missing"
    if statuses <= {"NOT_RUN_YAML_FAILED", "NOT_RUN_PYSIGMA_MISSING"}:
        return "not_run"
    return "executed"


def render_validation_markdown(report: dict[str, Any]) -> str:
    """Render the human-readable validation report."""
    summary = report["summary"]
    integrity = report["integrity"]
    lines = [
        "# Phase 0 dataset validation",
        "",
        f"- Generated at (UTC): `{report['generated_at_utc']}`",
        f"- Source commit: `{report.get('source_commit')}`",
        f"- Integrity passed: `{summary['integrity_passed']}`",
        f"- Tool versions: `{report['tool_versions']}`",
        "",
        "## Counts",
        "",
        f"- Files on disk: {summary['filesystem_yaml_count']}",
        f"- Manifest entries: {summary['manifest_rule_count']}",
        f"- YAML status: `{summary['yaml_status']}`",
        f"- pySigma status: `{summary['pysigma_status']}`",
        f"- SigmaYAMLLoader status: `{summary['sigma_yaml_loader_status']}`",
        f"- Files with error-severity findings: {summary['error_severity_files']}",
        f"- Duplicate Sigma IDs: {summary['duplicate_id_count']}",
        f"- Warning counts: `{summary['warning_counts']}`",
        "",
        "## Checks",
        "",
        "| Check | State |",
        "|---|---|",
    ]
    for name, state in report["checks"].items():
        lines.append(f"| `{name}` | {state} |")
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Missing manifest paths: {len(integrity['missing_files'])}",
            f"- Unexpected files: {len(integrity['unexpected_files'])}",
            f"- Checksum mismatches: {len(integrity['checksum_mismatches'])}",
            f"- Record mismatches: {len(integrity['record_mismatches'])}",
            f"- Unsafe paths: {len(integrity['unsafe_manifest_paths'])}",
            f"- Path traversal attempts: {len(integrity['path_traversal_attempts'])}",
            "",
            "YAML parsing and pySigma parsing are separate. A file can be `yaml_status` OK and `pysigma_status` PYSIGMA_ERROR.",
            "",
            "`NOT_RUN_PYSIGMA_MISSING` means the parser was not installed. `NOT_RUN_YAML_FAILED` means pySigma was not asked to parse a file that did not load as YAML.",
            "",
        ]
    )
    if report["duplicate_ids"]:
        lines.append("## Duplicate IDs")
        lines.append("")
        for rule_id, paths in report["duplicate_ids"].items():
            lines.append(f"- `{rule_id}`: {', '.join(paths)}")
        lines.append("")
    else:
        lines.extend(["## Duplicate IDs", "", "No duplicate Sigma IDs were found.", ""])

    lines.extend(["## Error-severity files", ""])
    errors = report["error_files"]
    if not errors:
        lines.append("No error-severity files.")
    else:
        shown = errors[:50]
        for item in shown:
            lines.append(
                f"- `{item['relative_path']}` YAML `{item['yaml_status']}`, "
                f"pySigma `{item['pysigma_status']}`: {'; '.join(item['errors'][:3])}"
            )
        if len(errors) > len(shown):
            lines.append(f"- {len(errors) - len(shown)} more error files are listed in the JSON report.")
    lines.extend(["", "The SigmaHQ sigma-cli lint suite was not run.", ""])
    return "\n".join(lines)


def exit_code(report: dict[str, Any]) -> int:
    """Return 1 when integrity failed, pySigma did not run, or an error was found."""
    if not report["summary"]["integrity_passed"]:
        return 1
    if report["summary"]["error_severity_files"] or report["duplicate_ids"] or report["blockers"]:
        return 1
    if report["summary"]["pysigma_status"].get("NOT_RUN_PYSIGMA_MISSING"):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = validate_corpus(
        args.rules_root.expanduser().resolve(),
        args.path_base.expanduser().resolve(),
        args.manifest.expanduser().resolve(),
    )
    json_dump(args.json_output, report)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.write_text(render_validation_markdown(report), encoding="utf-8")
    print(
        f"Integrity passed: {report['summary']['integrity_passed']}; "
        f"YAML {report['summary']['yaml_status']}; "
        f"pySigma {report['summary']['pysigma_status']}"
    )
    print(f"JSON report: {args.json_output}")
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
