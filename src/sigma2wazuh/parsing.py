"""Phase 2: nạp file Sigma, parse bằng pySigma, xuất JSON.

Chỉ làm load + parse. Không map field, không sinh Wazuh XML.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
import time
from datetime import datetime, timezone
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, Sequence

import yaml

from sigma2wazuh import __version__

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
    """Đường dẫn ghi trong report, dạng POSIX.

    Trong path_base → tương đối. Ngoài path_base, hoặc không có path_base → tuyệt đối.
    """
    path = path.resolve()
    if path_base is None:
        return path.as_posix()
    try:
        return path.relative_to(path_base.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


class OutputError(Exception):
    """Không ghi output: đích đã tồn tại, hoặc hai đích trùng path."""


def report_meta(started: float) -> dict[str, Any]:
    """Phần đầu báo cáo. elapsed_ms và generated_at_utc được phép khác giữa hai lần chạy."""
    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "tool_version": __version__,
        "python_version": platform.python_version(),
        "pysigma_version": package_version("pysigma"),
    }


def reason_histogram(records: list[dict[str, Any]]) -> dict[str, int]:
    """Đếm mã lỗi trên từng record, mỗi mã một lần. Khóa sort để summary ổn định."""
    counts: dict[str, int] = {}
    for record in records:
        found: set[str] = set()

        def take(code: object) -> None:
            if isinstance(code, str) and code and code not in found:
                found.add(code)
                counts[code] = counts.get(code, 0) + 1

        take(record.get("reason"))
        for key in ("diagnostics", "map_diagnostics", "unsupported_features"):
            items = record.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict):
                    take(item.get("code"))
        if record.get("conversion_status") == "SKIPPED" and not found:
            take(record.get("map_status"))
    return {code: counts[code] for code in sorted(counts)}


def _as_input_list(input_path: Path | Sequence[Path]) -> list[Path]:
    if isinstance(input_path, Path):
        return [input_path]
    return list(input_path)


def _deduped_resolved(inputs: Sequence[Path]) -> list[Path]:
    """Giữ thứ tự flag, bỏ path resolve trùng."""
    seen: set[Path] = set()
    out: list[Path] = []
    for raw in inputs:
        resolved = raw.expanduser().resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        out.append(resolved)
    return out


def _input_field(inputs: Sequence[Path]) -> str | list[str]:
    values = [path.as_posix() for path in inputs]
    if len(values) == 1:
        return values[0]
    return values


def _collect_rule_targets(
    inputs: Sequence[Path],
    path_base: Path | None,
) -> list[tuple[str, Path, str]]:
    """File YAML và input thiếu. Khử trùng theo resolve, sort theo rule_path."""
    seen: set[Path] = set()
    items: list[tuple[str, Path, str]] = []

    def add(path: Path, kind: str) -> None:
        resolved = path.resolve()
        if resolved in seen:
            return
        seen.add(resolved)
        items.append((_relative_path(resolved, path_base), resolved, kind))

    for raw in inputs:
        resolved = raw.expanduser().resolve()
        if resolved.is_dir():
            if resolved in seen:
                continue
            seen.add(resolved)
            for file in discover_rule_files(resolved):
                add(file, "file")
            continue
        if not resolved.exists():
            add(resolved, "missing")
            continue
        add(resolved, "file")

    items.sort(key=lambda item: item[0])
    return items


def report_to_json(report: dict[str, Any]) -> str:
    """JSON UTF-8. Bỏ xml_root vì không serialize."""
    body = {key: value for key, value in report.items() if key != "xml_root"}
    return json.dumps(body, ensure_ascii=False, indent=2) + "\n"


def commit_outputs(files: Sequence[tuple[Path, str]], *, force: bool) -> None:
    """Ghi mọi đích, hoặc không ghi đích nào.

    Kiểm tra trùng path và file đã tồn tại trước khi tạo file tạm.
    Replace chỉ chạy sau khi mọi file tạm đã ghi xong.
    """
    resolved: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for raw, text in files:
        path = raw.expanduser().resolve()
        if path in seen:
            raise OutputError(f"Output paths resolve to the same file: {path}")
        seen.add(path)
        resolved.append((path, text))

    if not force:
        existing = [path for path, _ in resolved if path.exists()]
        if existing:
            listed = ", ".join(path.as_posix() for path in existing)
            raise OutputError(f"Output already exists (use --force): {listed}")

    temps: list[Path] = []
    try:
        for path, text in resolved:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
            )
            tmp = Path(name)
            temps.append(tmp)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
        for (path, _), tmp in zip(resolved, temps, strict=True):
            os.replace(tmp, path)
        temps.clear()
    finally:
        for tmp in temps:
            tmp.unlink(missing_ok=True)


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
    input_path: Path | Sequence[Path],
    *,
    path_base: Path | None = None,
    source_commit: str | None = None,
) -> dict[str, Any]:
    """Parse một hoặc nhiều file/thư mục. Một rule lỗi không dừng các rule khác.

    Path trùng sau resolve chỉ parse một lần. Record sort theo rule_path.
    """
    started = time.perf_counter()
    inputs = _deduped_resolved(_as_input_list(input_path))
    if source_commit is None:
        for item in inputs:
            source_commit = lookup_source_commit(item)
            if source_commit:
                break

    records: list[dict[str, Any]] = []
    for rule_path, path, kind in _collect_rule_targets(inputs, path_base):
        if kind == "missing":
            records.append(
                _fail(
                    rule_path=rule_path,
                    sha256=None,
                    source_commit=source_commit,
                    stage="missing_path",
                    code="INPUT_NOT_FOUND",
                    message=f"Input path not found: {path}",
                )
            )
            continue
        records.append(
            parse_one(path, path_base=path_base, source_commit=source_commit)
        )

    ok = sum(1 for item in records if item["parse_status"] == "OK")
    failed = len(records) - ok
    return {
        **report_meta(started),
        "input": _input_field(inputs),
        "records": records,
        "summary": {
            "total": len(records),
            "ok": ok,
            "failed": failed,
            "reasons": reason_histogram(records),
        },
    }


def write_report(report: dict[str, Any], output_path: Path) -> None:
    """Ghi báo cáo JSON (UTF-8, indent 2). Ghi thẳng, không kiểm tra --force."""
    output_path = output_path.expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_to_json(report), encoding="utf-8")
