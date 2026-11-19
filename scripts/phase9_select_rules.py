#!/usr/bin/env python3
"""Cắt file deploy Phase 9 từ XML curated đã convert.

Chỉ giữ đúng các rule id đã chốt. Mỗi id phải nằm trên một record
conversion_status SUCCESS và xml_valid true. Thiếu id, status khác, hoặc
xml_valid khác true thì không ghi file. Không sửa XML bằng tay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

# Thứ tự id trong XML curated (sort rule_path, rule_id_base 100000).
PHASE9_RULE_IDS: tuple[int, ...] = (
    100000,
    100002,
    100004,
    100006,
    100007,
    100008,
    100011,
)


class SelectError(Exception):
    """File deploy không được ghi."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _rule_id(rule: ET.Element) -> int:
    raw = rule.get("id")
    if raw is None or not str(raw).strip().isdigit():
        raise SelectError(f"rule thiếu id hợp lệ: {raw!r}")
    return int(raw)


def index_rule_records(report: Mapping[str, Any]) -> dict[int, Mapping[str, Any]]:
    """Map rule id → record. Một id xuất hiện hai lần là lỗi."""
    records = report.get("records")
    if not isinstance(records, list):
        raise SelectError("report thiếu records")
    index: dict[int, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise SelectError("record không phải object")
        raw_ids = record.get("rule_ids") or []
        if not isinstance(raw_ids, Sequence) or isinstance(raw_ids, (str, bytes)):
            raise SelectError(f"rule_ids không phải list: {record.get('rule_path')}")
        for raw in raw_ids:
            if isinstance(raw, bool) or not isinstance(raw, int):
                raise SelectError(f"rule id không phải int: {raw!r}")
            if raw in index:
                raise SelectError(f"rule id {raw} nằm trên hai record")
            index[raw] = record
    return index


def _eligible(record: Mapping[str, Any], rule_id: int) -> None:
    status = record.get("conversion_status")
    valid = record.get("xml_valid")
    if status != "SUCCESS":
        raise SelectError(
            f"rule {rule_id} có conversion_status {status!r}, cần SUCCESS"
        )
    if valid is not True:
        raise SelectError(f"rule {rule_id} có xml_valid {valid!r}, cần true")


def select_rules(
    root: ET.Element,
    report: Mapping[str, Any],
    allow: Sequence[int] = PHASE9_RULE_IDS,
) -> ET.Element:
    """Trả group mới chỉ gồm allowlist. Không sửa cây nguồn."""
    allow_set = set(allow)
    if len(allow_set) != len(tuple(allow)):
        raise SelectError("allowlist có id trùng")
    index = index_rule_records(report)
    chosen: list[ET.Element] = []
    seen: list[int] = []
    for rule in list(root.findall("rule")):
        rule_id = _rule_id(rule)
        if rule_id not in allow_set:
            continue
        record = index.get(rule_id)
        if record is None:
            raise SelectError(f"rule {rule_id} không có record trong report")
        _eligible(record, rule_id)
        chosen.append(ET.fromstring(ET.tostring(rule)))
        seen.append(rule_id)
    if len(seen) != len(set(seen)):
        raise SelectError(f"XML nguồn có id lặp trong allowlist: {seen}")
    missing = [rule_id for rule_id in allow if rule_id not in set(seen)]
    if missing:
        raise SelectError(f"XML nguồn thiếu id: {missing}")
    out = ET.Element(root.tag, dict(root.attrib))
    for rule in chosen:
        out.append(rule)
    return out


def _manifest(
    *,
    source_xml: Path,
    source_sha256: str,
    deploy_xml: Path,
    deploy_sha256: str,
    rule_ids: Sequence[int],
    report: Mapping[str, Any],
    generated_at_utc: str,
) -> dict[str, Any]:
    index = index_rule_records(report)
    rows = []
    for rule_id in rule_ids:
        record = index[rule_id]
        rows.append(
            {
                "rule_id": rule_id,
                "rule_path": record.get("rule_path"),
                "sigma_sha256": record.get("sha256"),
                "conversion_status": record.get("conversion_status"),
                "xml_valid": record.get("xml_valid"),
            }
        )
    return {
        "source_xml": source_xml.as_posix(),
        "source_xml_sha256": source_sha256,
        "deploy_xml": deploy_xml.as_posix(),
        "deploy_xml_sha256": deploy_sha256,
        "rule_ids": list(rule_ids),
        "records": rows,
        "generated_at_utc": generated_at_utc,
        "note": (
            "xml_valid means the source record passed local XML checks. "
            "It does not mean Wazuh loaded the rule or that detection is correct."
        ),
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def write_deploy(
    source_xml: Path,
    source_report: Path,
    deploy_xml: Path,
    manifest_path: Path,
    *,
    force: bool = False,
    allow: Sequence[int] = PHASE9_RULE_IDS,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    """Đọc nguồn, cắt, ghi XML và manifest. Lỗi thì không ghi file nào."""
    source_xml = source_xml.expanduser()
    source_report = source_report.expanduser()
    deploy_xml = deploy_xml.expanduser()
    manifest_path = manifest_path.expanduser()
    if deploy_xml.resolve() == source_xml.resolve():
        raise SelectError("deploy XML trùng đường dẫn file nguồn")
    if manifest_path.resolve() in {deploy_xml.resolve(), source_report.resolve()}:
        raise SelectError("manifest trùng XML hoặc report nguồn")
    for path in (deploy_xml, manifest_path):
        if path.exists() and not force:
            raise SelectError(f"đã có file, cần --force: {path}")

    source_bytes = source_xml.read_bytes()
    report = json.loads(source_report.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise SelectError("report không phải object")
    root = ET.fromstring(source_bytes)
    selected = select_rules(root, report, allow)
    ET.indent(selected, space="  ")
    body = ET.tostring(selected, encoding="unicode")
    if not body.endswith("\n"):
        body += "\n"
    deploy_bytes = body.encode("utf-8")
    rule_ids = [_rule_id(rule) for rule in selected.findall("rule")]
    stamp = generated_at_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = _manifest(
        source_xml=source_xml,
        source_sha256=sha256_bytes(source_bytes),
        deploy_xml=deploy_xml,
        deploy_sha256=sha256_bytes(deploy_bytes),
        rule_ids=rule_ids,
        report=report,
        generated_at_utc=stamp,
    )
    payload = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _atomic_write(deploy_xml, deploy_bytes)
    try:
        _atomic_write(manifest_path, payload)
    except Exception:
        deploy_xml.unlink(missing_ok=True)
        raise
    written = sha256_file(deploy_xml)
    if written != manifest["deploy_xml_sha256"]:
        raise SelectError("SHA-256 file deploy khác manifest")
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-xml", type=Path, required=True)
    parser.add_argument("--source-report", type=Path, required=True)
    parser.add_argument("--output-xml", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = write_deploy(
            args.source_xml,
            args.source_report,
            args.output_xml,
            args.manifest,
            force=args.force,
        )
    except (SelectError, OSError, ET.ParseError, json.JSONDecodeError) as exc:
        print(f"SelectError: {exc}", file=sys.stderr)
        return 1
    print(
        f"rules={len(manifest['rule_ids'])} "
        f"source_sha256={manifest['source_xml_sha256']} "
        f"deploy_sha256={manifest['deploy_xml_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
