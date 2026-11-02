#!/usr/bin/env python3
"""Copy a small, traceable subset of the collected Sigma rules.

Selection is deterministic: for each feature bucket, take the smallest
eligible file, then the lexicographically first path. A bucket with no real
rule becomes a coverage gap. No synthetic rule is written.

expected_support_status is always null. Complexity is a structural heuristic
for later converter work, not a conversion result.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any, Callable

from sigma_dataset_lib import SCHEMA_VERSION, json_dump, load_json, sha256_file, utc_now

HIGH_TOKENS = {"re", "base64", "base64offset", "windash", "expand", "fieldref", "cidr"}
Predicate = Callable[[dict[str, Any]], bool]


def _features(record: dict[str, Any]) -> dict[str, Any]:
    features = record.get("features")
    return features if isinstance(features, dict) else {}


def parsed_clean(record: dict[str, Any]) -> bool:
    """Return True when the file parsed and matches the corpus logsource."""
    logsource = record.get("logsource") or {}
    if record.get("yaml_status") != "OK" or record.get("pysigma_status") != "PYSIGMA_OK":
        return False
    if record.get("errors"):
        return False
    if not _features(record):
        return False
    return logsource.get("product") == "windows" and logsource.get("category") == "process_creation"


def eligible(record: dict[str, Any], *, statuses: frozenset[str] = frozenset({"stable", "test"})) -> bool:
    """Return True for a clean rule whose status is in the allowed set.

    This snapshot marks most process-creation rules ``test`` and only a few
    ``stable``. ``test`` is a SigmaHQ maturity label, not a parse failure, so
    feature buckets include it. ``experimental`` is left to its own bucket.
    """
    return parsed_clean(record) and record.get("status") in statuses


def _has_key(record: dict[str, Any], field: str, chain: str) -> bool:
    expected = f"{field}|{chain}" if chain else field
    return expected in _features(record).get("field_keys", {})


def _simple_field(record: dict[str, Any], field: str) -> bool:
    features = _features(record)
    return (
        features.get("selection_count") == 1
        and list(features.get("selection_shapes", {})) == ["field_map"]
        and list(features.get("fields", {})) == [field]
        and not features.get("modifier_tokens")
        and not features.get("multi_value_fields")
        and features.get("condition_text") == (features.get("selection_names") or [None])[0]
    )


def _endswith_other(record: dict[str, Any]) -> bool:
    for key in _features(record).get("field_keys", {}):
        field, *modifiers = key.split("|")
        if modifiers == ["endswith"] and field not in {"", "Image"}:
            return True
    return False


def _flags(record: dict[str, Any]) -> set[str]:
    return set(_features(record).get("condition_flags") or [])


def _and_not(record: dict[str, Any]) -> bool:
    flags = _flags(record)
    features = _features(record)
    return (
        "and" in flags
        and "not" in flags
        and "or" not in flags
        and features.get("selection_count", 0) >= 2
    )


def _complex(record: dict[str, Any]) -> bool:
    flags = _flags(record)
    return "parentheses" in flags and len(flags.intersection({"and", "or", "not"})) >= 2


def bucket_predicates() -> list[tuple[str, Predicate]]:
    """Feature buckets, in selection priority order."""
    return [
        ("simple_image", lambda record: eligible(record) and _simple_field(record, "Image")),
        ("simple_commandline", lambda record: eligible(record) and _simple_field(record, "CommandLine")),
        ("image_endswith", lambda record: eligible(record) and _has_key(record, "Image", "endswith")),
        (
            "commandline_contains",
            lambda record: eligible(record) and _has_key(record, "CommandLine", "contains"),
        ),
        (
            "startswith",
            lambda record: eligible(record) and "startswith" in _features(record).get("modifier_tokens", {}),
        ),
        ("endswith_other_field", lambda record: eligible(record) and _endswith_other(record)),
        (
            "contains_all",
            lambda record: eligible(record) and "contains|all" in _features(record).get("modifier_chains", {}),
        ),
        (
            "multi_value",
            lambda record: eligible(record)
            and _features(record).get("multi_value_fields", 0) > 0
            and "all" not in _features(record).get("modifier_tokens", {}),
        ),
        (
            "multi_field",
            lambda record: eligible(record)
            and _features(record).get("multi_field_selections", 0) > 0
            and _features(record).get("selection_count") == 1,
        ),
        ("parent_image", lambda record: eligible(record) and "ParentImage" in _features(record).get("fields", {})),
        (
            "parent_commandline",
            lambda record: eligible(record) and "ParentCommandLine" in _features(record).get("fields", {}),
        ),
        (
            "original_file_name",
            lambda record: eligible(record) and "OriginalFileName" in _features(record).get("fields", {}),
        ),
        ("user_field", lambda record: eligible(record) and "User" in _features(record).get("fields", {})),
        (
            "two_selections_and",
            lambda record: eligible(record)
            and _features(record).get("selection_count") == 2
            and _flags(record) == {"and"},
        ),
        ("one_of", lambda record: eligible(record) and "1_of" in _flags(record)),
        ("all_of", lambda record: eligible(record) and "all_of" in _flags(record)),
        ("selection_and_not", lambda record: eligible(record) and _and_not(record)),
        (
            "list_of_maps",
            lambda record: eligible(record) and "list_of_maps" in _features(record).get("selection_shapes", {}),
        ),
        (
            "keyword",
            lambda record: eligible(record)
            and (
                _features(record).get("keyword_selections", 0) > 0
                or _features(record).get("keyword_modifier_keys", 0) > 0
            ),
        ),
        ("regex_modifier", lambda record: eligible(record) and "re" in _features(record).get("modifier_tokens", {})),
        ("cased_modifier", lambda record: eligible(record) and "cased" in _features(record).get("modifier_tokens", {})),
        (
            "windash_modifier",
            lambda record: eligible(record) and "windash" in _features(record).get("modifier_tokens", {}),
        ),
        (
            "base64offset_modifier",
            lambda record: eligible(record) and "base64offset" in _features(record).get("modifier_tokens", {}),
        ),
        ("complex_boolean", lambda record: eligible(record) and _complex(record)),
        (
            "experimental_status",
            lambda record: eligible(record, statuses=frozenset({"experimental"})),
        ),
        (
            "other_status",
            lambda record: parsed_clean(record)
            and record.get("status") not in {"stable", "test", "experimental"},
        ),
        (
            "parser_wildcard",
            lambda record: eligible(record) and (_features(record).get("parser") or {}).get("wildcard_strings", 0) > 0,
        ),
        (
            "placeholder",
            lambda record: eligible(record)
            and (_features(record).get("parser") or {}).get("placeholder_strings", 0) > 0,
        ),
    ]


def _pick(records: list[dict[str, Any]], chosen: set[str], predicate: Predicate) -> dict[str, Any] | None:
    candidates = [
        record
        for record in records
        if record.get("relative_path") not in chosen and predicate(record)
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda record: (record.get("size_bytes", 0), record["relative_path"]))


def complexity(record: dict[str, Any], bucket: str) -> str:
    """Estimate future mapping complexity from structure only."""
    features = _features(record)
    tokens = set(features.get("modifier_tokens", {}))
    shapes = set(features.get("selection_shapes", {}))
    flags = _flags(record)
    if tokens & HIGH_TOKENS or shapes.intersection({"keyword_list", "scalar", "list_of_maps", "mixed_list"}):
        return "high"
    if bucket in {"complex_boolean", "keyword", "regex_modifier", "base64offset_modifier", "windash_modifier"}:
        return "high"
    if (
        features.get("selection_count", 0) > 1
        or "contains|all" in features.get("modifier_chains", {})
        or flags.intersection({"1_of", "all_of", "not", "parentheses"})
    ):
        return "medium"
    return "low"


def limitations(record: dict[str, Any]) -> list[str]:
    """Describe structural issues a later converter will have to classify."""
    features = _features(record)
    tokens = set(features.get("modifier_tokens", {}))
    notes: list[str] = []
    described = {
        "re": "Uses the re modifier, which is outside the initial SRS modifier priority.",
        "base64": "Uses base64, which is outside the initial SRS modifier priority.",
        "base64offset": "Uses base64offset, which is outside the initial SRS modifier priority.",
        "windash": "Uses windash, which rewrites dash characters before comparison.",
        "expand": "Uses expand, which depends on a placeholder pipeline that is not part of Phase 0.",
        "fieldref": "Uses fieldref, which compares a field with another field.",
        "cidr": "Uses cidr, which is outside the initial SRS modifier priority.",
    }
    for token, note in described.items():
        if token in tokens:
            notes.append(note)
    shapes = features.get("selection_shapes", {})
    if "keyword_list" in shapes or "scalar" in shapes or features.get("keyword_modifier_keys"):
        notes.append("Contains keyword-style detection rather than only field comparisons.")
    if "list_of_maps" in shapes:
        notes.append("Contains a list-of-maps selection, which is an OR of AND-groups.")
    if "parentheses" in _flags(record):
        notes.append("Condition uses parentheses.")
    return notes


def _reason(record: dict[str, Any], bucket: str) -> str:
    features = _features(record)
    condition = features.get("condition_text") or ""
    if len(condition) > 240:
        condition = condition[:240] + "…"
    fields = ", ".join(sorted(features.get("fields", {}))) or "none"
    chains = ", ".join(sorted(features.get("modifier_chains", {}))) or "none"
    return (
        f"Smallest eligible corpus file for the {bucket} bucket. "
        f"Fields: {fields}. Modifier chains: {chains}. Condition: {condition}."
    )


def select_curated(records: list[dict[str, Any]], limit: int = 30) -> tuple[list[dict[str, Any]], list[str]]:
    """Choose at most one unused file per bucket."""
    chosen: set[str] = set()
    selected: list[dict[str, Any]] = []
    gaps: list[str] = []
    for bucket, predicate in bucket_predicates():
        if len(selected) >= limit:
            gaps.append(f"{bucket}: not considered because the selection limit of {limit} was reached")
            continue
        record = _pick(records, chosen, predicate)
        if record is None:
            gaps.append(f"{bucket}: no eligible corpus rule matched this bucket")
            continue
        chosen.add(record["relative_path"])
        features = _features(record)
        filename = Path(record["relative_path"]).name
        selected.append(
            {
                "bucket": bucket,
                "source_relative_path": record["relative_path"],
                "upstream_path": record.get("upstream_path"),
                "curated_relative_path": f"curated/{filename}",
                "sigma_id": record.get("id"),
                "title": record.get("title"),
                "sha256": record.get("sha256"),
                "size_bytes": record.get("size_bytes"),
                "status": record.get("status"),
                "features_represented": [
                    bucket,
                    *sorted(features.get("fields", {})),
                    *sorted(features.get("modifier_chains", {})),
                    *features.get("condition_flags", []),
                ],
                "selection_reason": _reason(record, bucket),
                "expected_future_conversion_complexity": complexity(record, bucket),
                "known_limitations": limitations(record),
                "expected_support_status": None,
            }
        )
    return selected, gaps


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--path-base", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    inventory = load_json(args.inventory)
    collection = load_json(args.metadata)
    records = inventory.get("per_rule")
    if not isinstance(records, list):
        raise SystemExit("Feature inventory does not contain per_rule.")
    selected, gaps = select_curated(records, limit=args.limit)
    path_base = args.path_base.resolve()
    curated_dir = path_base / "curated"
    curated_dir.mkdir(parents=True, exist_ok=True)
    written: set[str] = set()
    for item in selected:
        source = path_base / item["source_relative_path"]
        target = path_base / item["curated_relative_path"]
        payload = source.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        if digest != item["sha256"]:
            raise SystemExit(f"Inventory hash does not match source bytes: {item['source_relative_path']}")
        if target.name in written:
            raise SystemExit(f"Curated filename collision: {target.name}")
        written.add(target.name)
        target.write_bytes(payload)
        if sha256_file(target) != digest:
            raise SystemExit(f"Copy hash mismatch: {target}")

    extras = sorted(
        path.name
        for path in curated_dir.glob("*")
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"} and path.name not in written
    )
    document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "intentionally_variable_fields": ["generated_at_utc"],
        "source_repo": collection.get("source_repo"),
        "source_commit": collection.get("source_commit"),
        "source_path": collection.get("source_path"),
        "inventory_source_commit": inventory.get("source_commit"),
        "selection_method": (
            "For each feature bucket, choose the smallest eligible rule and break ties by relative path. "
            "Feature buckets accept Sigma status stable or test. experimental and any other status "
            "have their own buckets. Eligibility also requires YAML success, pySigma success, "
            "no error-severity findings, and logsource product windows with category process_creation. "
            "Status test is included because it is the majority maturity label in this directory, not a parse failure. "
            "Files are exact byte copies. expected_support_status is null because no converter exists."
        ),
        "selected_count": len(selected),
        "coverage_gaps": gaps,
        "rules": selected,
        "unexpected_curated_files": extras,
        "notes": [
            "Complexity labels are structural heuristics, not converter verdicts.",
            "A coverage gap means the collected corpus had no eligible rule for that bucket.",
        ],
    }
    json_dump(args.output, document)
    print(f"Selected {len(selected)} curated rules. Coverage gaps: {len(gaps)}.")
    if extras:
        print(f"Unexpected files left in curated/: {extras}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
