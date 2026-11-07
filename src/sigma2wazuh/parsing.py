"""Phase 2: nạp file Sigma, parse bằng pySigma, xuất JSON.

Chỉ làm load + parse. Không map field, không sinh Wazuh XML.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# Phần mở rộng YAML được coi là rule Sigma.
_YAML_SUFFIXES = {".yml", ".yaml"}


def discover_rule_files(input_path: Path) -> list[Path]:
    """Tìm các file .yml/.yaml từ một file hoặc một thư mục.

    - File: trả về đúng file đó (kể cả khi chưa tồn tại — caller xử lý lỗi).
    - Thư mục: quét đệ quy, sắp xếp theo đường dẫn để kết quả ổn định.
    """
    input_path = input_path.expanduser()
    if input_path.is_file() or not input_path.exists():
        return [input_path.resolve()]
    if not input_path.is_dir():
        return [input_path.resolve()]

    files = [
        path.resolve()
        for path in input_path.rglob("*")
        if path.is_file() and path.suffix.lower() in _YAML_SUFFIXES
    ]
    files.sort(key=lambda path: str(path))
    return files


def _relative_path(path: Path, path_base: Path | None) -> str:
    """Đường dẫn ghi trong report: ưu tiên relative theo path_base."""
    path = path.resolve()
    if path_base is None:
        return str(path)
    try:
        return str(path.relative_to(path_base.resolve()))
    except ValueError:
        return str(path)


def _sha256_text(text: str) -> str:
    """SHA-256 của nội dung Unicode đã decode (UTF-8)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _extract_metadata(data: dict[str, Any]) -> dict[str, Any]:
    """Lấy metadata từ mapping YAML. Field thiếu để null, không bịa giá trị."""
    logsource = data.get("logsource")
    if not isinstance(logsource, dict):
        logsource = None
    return {
        "title": data.get("title"),
        "id": data.get("id"),
        "status": data.get("status"),
        "level": data.get("level"),
        "description": data.get("description"),
        "author": data.get("author"),
        "logsource": logsource,
        "tags": data.get("tags"),
        "falsepositives": data.get("falsepositives"),
        "condition": (data.get("detection") or {}).get("condition")
        if isinstance(data.get("detection"), dict)
        else None,
    }


def _fail(
    *,
    rule_path: str,
    sha256: str | None,
    source_commit: str | None,
    stage: str,
    code: str,
    message: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Tạo một record FAILED thống nhất."""
    return {
        "rule_path": rule_path,
        "sha256": sha256,
        "source_commit": source_commit,
        "parse_status": "FAILED",
        "failure_stage": stage,
        "diagnostics": [{"code": code, "message": message}],
        "metadata": metadata,
    }


def parse_one(
    path: Path,
    *,
    path_base: Path | None = None,
    source_commit: str | None = None,
) -> dict[str, Any]:
    """Đọc và parse một file Sigma. Lỗi được trả trong record, không raise."""
    rule_path = _relative_path(path, path_base)

    if not path.is_file():
        return _fail(
            rule_path=rule_path,
            sha256=None,
            source_commit=source_commit,
            stage="missing_path",
            code="FILE_NOT_FOUND",
            message=f"File not found: {path}",
        )

    # Đọc UTF-8; lỗi encoding → FAILED.
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return _fail(
            rule_path=rule_path,
            sha256=None,
            source_commit=source_commit,
            stage="encoding",
            code="ENCODING_ERROR",
            message=str(exc),
        )
    except OSError as exc:
        return _fail(
            rule_path=rule_path,
            sha256=None,
            source_commit=source_commit,
            stage="other",
            code="READ_ERROR",
            message=str(exc),
        )

    digest = _sha256_text(text)

    if not text.strip():
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="empty",
            code="EMPTY_FILE",
            message="File is empty.",
        )

    # Bước YAML: chỉ cần một document dạng mapping.
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="yaml",
            code="YAML_ERROR",
            message=str(exc),
        )

    if data is None:
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="empty",
            code="EMPTY_YAML",
            message="YAML document is empty or null.",
        )
    if not isinstance(data, dict):
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="yaml",
            code="YAML_NOT_MAPPING",
            message=f"Expected a mapping, got {type(data).__name__}.",
        )

    metadata = _extract_metadata(data)

    # Bước pySigma: một SigmaRule + parse condition (giống chuẩn Phase 0).
    try:
        from sigma.collection import SigmaCollection
        from sigma.rule import SigmaRule
    except ImportError as exc:
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="pysigma",
            code="PYSIGMA_MISSING",
            message=str(exc),
            metadata=metadata,
        )

    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception as exc:  # noqa: BLE001 — mọi lỗi parse đều thành record FAILED
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="pysigma",
            code="PYSIGMA_ERROR",
            message=f"{type(exc).__name__}: {exc}",
            metadata=metadata,
        )

    if collection.errors:
        message = "; ".join(f"{type(item).__name__}: {item}" for item in collection.errors)
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="pysigma",
            code="PYSIGMA_ERROR",
            message=message,
            metadata=metadata,
        )

    rules = list(collection.rules)
    if len(rules) != 1 or not isinstance(rules[0], SigmaRule):
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="pysigma",
            code="PYSIGMA_ERROR",
            message=f"Expected exactly one SigmaRule, got {len(rules)} object(s).",
            metadata=metadata,
        )

    rule = rules[0]
    if rule.errors:
        message = "; ".join(f"{type(item).__name__}: {item}" for item in rule.errors)
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="pysigma",
            code="PYSIGMA_ERROR",
            message=message,
            metadata=metadata,
        )

    try:
        for condition in rule.detection.parsed_condition:
            condition.parse(postprocess=True)
    except Exception as exc:  # noqa: BLE001
        return _fail(
            rule_path=rule_path,
            sha256=digest,
            source_commit=source_commit,
            stage="pysigma",
            code="PYSIGMA_CONDITION_ERROR",
            message=f"{type(exc).__name__}: {exc}",
            metadata=metadata,
        )

    return {
        "rule_path": rule_path,
        "sha256": digest,
        "source_commit": source_commit,
        "parse_status": "OK",
        "failure_stage": None,
        "diagnostics": [],
        "metadata": metadata,
    }


def lookup_source_commit(start: Path) -> str | None:
    """Tìm source_commit trong collection_metadata.json gần input (nếu có)."""
    current = start.resolve()
    if current.is_file():
        current = current.parent

    for _ in range(5):
        meta_path = current / "collection_metadata.json"
        if meta_path.is_file():
            try:
                payload = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
            commit = payload.get("source_commit") or payload.get("commit")
            if isinstance(commit, str) and commit.strip():
                return commit.strip()
            return None
        if current.parent == current:
            break
        current = current.parent
    return None


def parse_batch(
    input_path: Path,
    *,
    path_base: Path | None = None,
    source_commit: str | None = None,
) -> dict[str, Any]:
    """Parse một file hoặc cả thư mục. Một rule lỗi không dừng các rule khác."""
    input_path = input_path.expanduser().resolve()
    if source_commit is None:
        source_commit = lookup_source_commit(input_path)

    # Thư mục không tồn tại → một record FAILED, không raise.
    if not input_path.exists():
        records = [
            _fail(
                rule_path=_relative_path(input_path, path_base),
                sha256=None,
                source_commit=source_commit,
                stage="missing_path",
                code="INPUT_NOT_FOUND",
                message=f"Input path not found: {input_path}",
            )
        ]
    else:
        files = discover_rule_files(input_path)
        # Thư mục rỗng (không có YAML): summary 0, không lỗi.
        records = [
            parse_one(path, path_base=path_base, source_commit=source_commit)
            for path in files
        ]

    ok = sum(1 for item in records if item["parse_status"] == "OK")
    failed = len(records) - ok
    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input": str(input_path),
        "records": records,
        "summary": {
            "total": len(records),
            "ok": ok,
            "failed": failed,
        },
    }


def write_report(report: dict[str, Any], output_path: Path) -> None:
    """Ghi báo cáo JSON (UTF-8, indent 2)."""
    output_path = output_path.expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
