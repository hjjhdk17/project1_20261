#!/usr/bin/env python3
"""Shared checks for the Phase 0 Sigma snapshot.

YAML parsing and pySigma parsing are separate. A document that loads as YAML
is not reported as a successfully parsed Sigma rule unless pySigma says so.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml

YAML_SUFFIXES = {".yml", ".yaml"}
SCHEMA_VERSION = "1.0"
UPSTREAM_PREFIX = "rules/windows/process_creation"
CORPUS_PREFIX = "windows/process_creation"

# Statuses that mean the pySigma parser was not asked to parse the file.
PYSIGMA_NOT_RUN = {
    "NOT_RUN_PYSIGMA_MISSING",
    "NOT_RUN_YAML_FAILED",
}


def utc_now() -> str:
    """Return the current time as a UTC timestamp with a Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_dump(path: Path, payload: Any) -> None:
    """Write JSON with stable key order and a trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")


def is_relative_safe(relative: str) -> bool:
    """Return True when a manifest path cannot escape its root."""
    if not relative or relative.startswith(("/", "\\")):
        return False
    if "\\" in relative or "\x00" in relative:
        return False
    parts = Path(relative).parts
    return bool(parts) and ".." not in parts


def resolve_within(root: Path, relative: str) -> Path:
    """Resolve a relative path and require it to stay inside root."""
    if not is_relative_safe(relative):
        raise ValueError(f"Unsafe relative path: {relative!r}")
    root_resolved = root.resolve()
    candidate = (root_resolved / relative).resolve()
    candidate.relative_to(root_resolved)
    return candidate


def iter_yaml_files(root: Path) -> list[Path]:
    """Return YAML files under root, sorted, without following directory links."""
    found: list[Path] = []
    root_resolved = root.resolve()
    for path in root_resolved.rglob("*"):
        if path.is_symlink():
            continue
        if path.is_file() and path.suffix.lower() in YAML_SUFFIXES:
            found.append(path)
    return sorted(found)


def relative_to_base(path: Path, base: Path) -> str:
    """Return a forward-slash path relative to base."""
    return path.resolve().relative_to(base.resolve()).as_posix()


def read_text(path: Path) -> tuple[str | None, str | None]:
    """Read UTF-8 text. The file bytes are not rewritten."""
    try:
        return path.read_text(encoding="utf-8"), None
    except UnicodeDecodeError as exc:
        return None, f"UnicodeDecodeError: {exc}"
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"


def load_yaml_documents(text: str) -> tuple[str, list[Any], str | None]:
    """Load every YAML document with safe_load_all.

    Returns ``(status, documents, error)``. Empty streams and parser
    exceptions are YAML errors. A stream of explicit null documents is also
    a YAML error because there is no document to inspect.
    """
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        return "ERROR", [], f"YAMLError: {exc}"
    except Exception as exc:  # a loader bug should still name the file later
        return "ERROR", [], f"{type(exc).__name__}: {exc}"
    if not documents or all(document is None for document in documents):
        return "ERROR", [], "YAML document is empty or null."
    return "OK", documents, None


def sigma_yaml_loader_status(text: str) -> tuple[str, str | None]:
    """Check duplicate keys with pySigma's SigmaYAMLLoader.

    SigmaCollection.from_yaml uses yaml.safe_load_all and does not apply this
    loader. The result is therefore recorded separately from pysigma_status.
    """
    try:
        from sigma.rule.base import SigmaYAMLLoader
    except ImportError:
        return "NOT_RUN_PYSIGMA_MISSING", None
    try:
        list(yaml.load_all(text, Loader=SigmaYAMLLoader))
    except Exception as exc:
        return "ERROR", f"{type(exc).__name__}: {exc}"
    return "OK", None


def parse_pysigma(text: str) -> tuple[str, str | None, Any]:
    """Parse one file with SigmaCollection.from_yaml.

    ``PYSIGMA_OK`` is returned only for exactly one SigmaRule whose condition
    trees can be built. The rule object is returned only in that case.
    """
    try:
        from sigma.collection import SigmaCollection
        from sigma.rule import SigmaRule
    except ImportError:
        return "NOT_RUN_PYSIGMA_MISSING", None, None

    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception as exc:
        return "PYSIGMA_ERROR", f"{type(exc).__name__}: {exc}", None

    if collection.errors:
        message = "; ".join(f"{type(item).__name__}: {item}" for item in collection.errors)
        return "PYSIGMA_ERROR", message, None

    rules = list(collection.rules)
    if not rules and collection.filters:
        return "PYSIGMA_FILTER_ONLY", "SigmaCollection contained only filters.", None
    if not rules:
        return "PYSIGMA_EMPTY", "SigmaCollection returned no rules.", None
    if len(rules) != 1:
        kinds = sorted({type(rule).__name__ for rule in rules})
        return (
            "PYSIGMA_MULTIPLE",
            f"SigmaCollection returned {len(rules)} rules ({', '.join(kinds)}).",
            None,
        )

    rule = rules[0]
    if not isinstance(rule, SigmaRule):
        return "PYSIGMA_NON_RULE", f"Parsed object type is {type(rule).__name__}.", None
    if rule.errors:
        message = "; ".join(f"{type(item).__name__}: {item}" for item in rule.errors)
        return "PYSIGMA_ERROR", message, None

    try:
        for condition in rule.detection.parsed_condition:
            condition.parse(postprocess=True)
    except Exception as exc:
        return "PYSIGMA_ERROR", f"{type(exc).__name__}: {exc}", None
    return "PYSIGMA_OK", None, rule


def _enum_name(value: Any) -> str | None:
    if value is None:
        return None
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name.lower()
    return str(value)


def _json_value(value: Any) -> Any:
    """Convert values that yaml.safe_load may produce into JSON values."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _logsource_record(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    keys = ("product", "category", "service", "definition")
    record: dict[str, Any] = {}
    for key in keys:
        record[key] = _json_value(raw.get(key)) if key in raw else None
        record[f"{key}_present"] = key in raw
    return record


def _blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def structural_findings(documents: list[Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    """Check the fields Phase 0 expects without judging unfamiliar detection syntax.

    Metadata is taken from the first document. Additional documents are a
    warning, not a silent drop. Returns metadata, errors, and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []
    metadata: dict[str, Any] = {
        "title": None,
        "id": None,
        "status": None,
        "level": None,
        "logsource": None,
        "document_count": len(documents),
    }
    if len(documents) > 1:
        warnings.append(f"MULTIPLE_YAML_DOCUMENTS: {len(documents)} documents; metadata is from the first.")

    document = documents[0]
    if not isinstance(document, dict):
        errors.append(
            f"YAML_DOCUMENT_NOT_MAPPING: first document is {type(document).__name__}."
        )
        return metadata, errors, warnings

    metadata["title"] = document.get("title") if isinstance(document.get("title"), str) else None
    raw_id = document.get("id")
    metadata["id"] = raw_id if isinstance(raw_id, str) else None
    metadata["status"] = document.get("status") if isinstance(document.get("status"), str) else None
    metadata["level"] = document.get("level") if isinstance(document.get("level"), str) else None
    metadata["logsource"] = _logsource_record(document.get("logsource"))

    if _blank(document.get("title")):
        errors.append("MISSING_TITLE")
    if "id" not in document or _blank(document.get("id")):
        warnings.append("MISSING_ID")
    elif not isinstance(document.get("id"), str):
        warnings.append(f"ID_NOT_STRING: {type(document.get('id')).__name__}")
    else:
        try:
            UUID(document["id"])
        except ValueError:
            warnings.append("ID_NOT_UUID")
    if "status" not in document or _blank(document.get("status")):
        warnings.append("MISSING_STATUS")
    if "level" not in document or _blank(document.get("level")):
        warnings.append("MISSING_LEVEL")

    if "logsource" not in document or document.get("logsource") is None:
        warnings.append("MISSING_LOGSOURCE")
    elif not isinstance(document.get("logsource"), dict):
        warnings.append("LOGSOURCE_NOT_MAPPING")
    else:
        logsource = document["logsource"]
        product = logsource.get("product")
        category = logsource.get("category")
        if product != "windows":
            warnings.append(f"LOGSOURCE_PRODUCT_NOT_WINDOWS: {product!r}")
        if category != "process_creation":
            warnings.append(f"LOGSOURCE_CATEGORY_NOT_PROCESS_CREATION: {category!r}")

    detection = document.get("detection")
    if not isinstance(detection, dict):
        errors.append("MISSING_OR_INVALID_DETECTION")
    elif "condition" not in detection:
        errors.append("MISSING_CONDITION")
    elif detection.get("condition") in (None, "", []):
        errors.append("MISSING_CONDITION")
    return metadata, errors, warnings


def tool_versions() -> dict[str, str | None]:
    """Return the runtime versions used to read rules."""
    import importlib.metadata as metadata
    import platform

    versions: dict[str, str | None] = {"python": platform.python_version()}
    try:
        versions["pysigma"] = metadata.version("pysigma")
    except metadata.PackageNotFoundError:
        versions["pysigma"] = None
    versions["pyyaml"] = getattr(yaml, "__version__", None)
    return versions


def inspect_rule_file(path: Path, path_base: Path) -> dict[str, Any]:
    """Inspect one YAML file. The returned record is JSON-serializable.

    ``features`` is included for the inventory. Manifest and validation code
    can ignore that key. Parser feature fields stay null when pySigma did not
    return a rule.
    """
    relative_path = relative_to_base(path, path_base)
    corpus_root = CORPUS_PREFIX + "/"
    if relative_path.startswith(corpus_root):
        upstream_path: str | None = f"{UPSTREAM_PREFIX}/{relative_path[len(corpus_root):]}"
    else:
        upstream_path = None
    record: dict[str, Any] = {
        "relative_path": relative_path,
        "upstream_path": upstream_path,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "title": None,
        "id": None,
        "status": None,
        "level": None,
        "logsource": None,
        "document_count": 0,
        "yaml_status": "NOT_RUN",
        "pysigma_status": "NOT_RUN",
        "sigma_yaml_loader_status": "NOT_RUN",
        "errors": [],
        "warnings": [],
        "features": None,
    }

    text, read_error = read_text(path)
    if text is None:
        record["yaml_status"] = "ERROR"
        record["pysigma_status"] = "NOT_RUN_YAML_FAILED"
        record["errors"].append(read_error)
        return record

    yaml_status, documents, yaml_error = load_yaml_documents(text)
    record["yaml_status"] = yaml_status
    if yaml_status != "OK":
        record["pysigma_status"] = "NOT_RUN_YAML_FAILED"
        record["errors"].append(yaml_error)
        loader_status, loader_error = sigma_yaml_loader_status(text)
        record["sigma_yaml_loader_status"] = loader_status
        if loader_error and loader_status == "ERROR":
            record["errors"].append(f"SIGMA_YAML_LOADER: {loader_error}")
        return record

    metadata, errors, warnings = structural_findings(documents)
    record.update(
        {
            "title": metadata["title"],
            "id": metadata["id"],
            "status": metadata["status"],
            "level": metadata["level"],
            "logsource": metadata["logsource"],
            "document_count": metadata["document_count"],
        }
    )
    record["errors"].extend(errors)
    record["warnings"].extend(warnings)

    loader_status, loader_error = sigma_yaml_loader_status(text)
    record["sigma_yaml_loader_status"] = loader_status
    if loader_status == "ERROR" and loader_error:
        record["errors"].append(f"SIGMA_YAML_LOADER: {loader_error}")

    pysigma_status, pysigma_error, rule = parse_pysigma(text)
    record["pysigma_status"] = pysigma_status
    if pysigma_error:
        record["errors"].append(f"{pysigma_status}: {pysigma_error}")

    try:
        from feature_inventory import extract_features

        document = documents[0] if isinstance(documents[0], dict) else None
        record["features"] = extract_features(document, rule)
    except Exception as exc:
        record["features"] = None
        record["errors"].append(f"FEATURE_EXTRACTION_ERROR: {type(exc).__name__}: {exc}")
    return record


def manifest_rule(record: dict[str, Any]) -> dict[str, Any]:
    """Return the manifest view of an inspection record."""
    return {
        "relative_path": record["relative_path"],
        "upstream_path": record["upstream_path"],
        "sha256": record["sha256"],
        "size_bytes": record["size_bytes"],
        "title": record["title"],
        "id": record["id"],
        "status": record["status"],
        "level": record["level"],
        "logsource": record["logsource"],
        "document_count": record["document_count"],
        "yaml_status": record["yaml_status"],
        "pysigma_status": record["pysigma_status"],
        "sigma_yaml_loader_status": record["sigma_yaml_loader_status"],
        "errors": record["errors"],
        "warnings": record["warnings"],
    }


def duplicate_ids(records: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Map a Sigma id to every path that uses it when it appears more than once."""
    grouped: dict[str, list[str]] = {}
    for record in records:
        rule_id = record.get("id")
        if isinstance(rule_id, str) and rule_id:
            grouped.setdefault(rule_id, []).append(record["relative_path"])
    return {
        rule_id: paths
        for rule_id, paths in sorted(grouped.items())
        if len(paths) > 1
    }


def count_status(records: list[dict[str, Any]], field: str) -> dict[str, int]:
    """Count values of one status field."""
    counts: dict[str, int] = {}
    for record in records:
        value = str(record.get(field))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def error_severity(record: dict[str, Any]) -> bool:
    """Return True when the file has an error-severity finding."""
    if record["yaml_status"] == "ERROR":
        return True
    if record["pysigma_status"] not in {"PYSIGMA_OK"} | PYSIGMA_NOT_RUN:
        return True
    if record["sigma_yaml_loader_status"] == "ERROR":
        return True
    return any(
        item.startswith(
            (
                "MISSING_TITLE",
                "MISSING_OR_INVALID_DETECTION",
                "MISSING_CONDITION",
                "YAML_DOCUMENT_NOT_MAPPING",
                "SIGMA_YAML_LOADER",
            )
        )
        for item in record["errors"]
    )


def load_json(path: Path) -> Any:
    """Load a JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))


def stage_yaml_tree(
    source: Path,
    dest: Path,
    upstream_list: list[str],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Copy YAML bytes from an exported git tree into dest.

    Existing destination files are overwritten only when the bytes already
    match. Differing files and unexpected YAML files are reported and left in
    place. Nothing under dest is deleted.
    """
    source = source.resolve()
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    skipped: list[dict[str, str]] = []
    copied: list[dict[str, Any]] = []

    listed = [item.strip() for item in upstream_list if item.strip()]
    prefix = UPSTREAM_PREFIX + "/"
    expected: dict[str, str] = {}
    for upstream in listed:
        if not upstream.startswith(prefix):
            errors.append(f"Upstream path is outside {prefix}: {upstream}")
            continue
        leaf = upstream[len(prefix):]
        if not is_relative_safe(leaf):
            errors.append(f"Unsafe upstream leaf path: {leaf}")
            continue
        expected[leaf] = upstream

    seen_leaves: set[str] = set()
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        leaf = path.relative_to(source).as_posix()
        seen_leaves.add(leaf)
        if leaf not in expected:
            errors.append(f"Exported file is not in the git tree list: {leaf}")
            continue
        if path.suffix.lower() not in YAML_SUFFIXES:
            skipped.append({"upstream_path": expected[leaf], "reason": "non_yaml"})
            continue
        target = dest / leaf
        if not is_relative_safe(leaf):
            errors.append(f"Refusing to copy unsafe path: {leaf}")
            continue
        payload = path.read_bytes()
        if target.exists():
            if target.read_bytes() != payload:
                errors.append(f"Destination differs and was not overwritten: {leaf}")
                continue
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        copied.append(
            {
                "relative_path": f"{CORPUS_PREFIX}/{leaf}",
                "upstream_path": expected[leaf],
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
            }
        )

    for leaf, upstream in sorted(expected.items()):
        if leaf not in seen_leaves:
            errors.append(f"Git tree file missing from export: {upstream}")

    for path in iter_yaml_files(dest):
        leaf = path.relative_to(dest).as_posix()
        if leaf not in expected:
            errors.append(f"Unexpected YAML file already in destination: {leaf}")

    nested = sum(1 for item in copied if "/" in item["upstream_path"][len(prefix):])
    result = {
        "schema_version": SCHEMA_VERSION,
        **metadata,
        "yaml_files_collected": len(copied),
        "nested_yaml_files": nested,
        "non_yaml_files_skipped": skipped,
        "errors": errors,
        "files": copied,
    }
    return result


def drop_variable_fields(payload: Any, variable: set[str]) -> Any:
    """Return a copy of payload without timestamp fields that change between runs."""
    if isinstance(payload, dict):
        return {
            key: drop_variable_fields(value, variable)
            for key, value in payload.items()
            if key not in variable
        }
    if isinstance(payload, list):
        return [drop_variable_fields(item, variable) for item in payload]
    return payload
