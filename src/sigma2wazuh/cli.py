"""CLI: validate-config, parse, analyze, map, convert."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from sigma2wazuh import __version__
from sigma2wazuh.config import ConfigError, find_project_root, load_config
from sigma2wazuh.logging_setup import resolve_level, setup_logging
from sigma2wazuh.mapper import map_batch
from sigma2wazuh.parsing import OutputError, commit_outputs, parse_batch, report_to_json
from sigma2wazuh.support_analyzer import analyze_batch
from sigma2wazuh.wazuh_generator import convert_from_input, xml_to_string


def _status_word(problems: int) -> str:
    """OK chỉ khi không có rule FAILED. Chuỗi này in ra stdout."""
    return "OK" if problems == 0 else "finished"


def _exit_for(problems: int) -> int:
    return 0 if problems == 0 else 3


def _log_word(problems: int) -> str:
    """Log không chứa OK khi có rule FAILED."""
    return "done" if problems == 0 else "finished"


def _convert_problem_count(report: dict[str, Any]) -> int:
    """conversion FAILED, cộng parse/support FAILED (convert ghi các record đó là SKIPPED)."""
    count = int(report["summary"]["failed"])
    for record in report["records"]:
        if record.get("parse_status") == "FAILED" or record.get("support_status") == "FAILED":
            count += 1
    return count


def build_parser() -> argparse.ArgumentParser:
    """Tạo parser gốc với flag global và các subcommand hiện có."""
    parser = argparse.ArgumentParser(
        prog="sigma2wazuh",
        description="Sigma-to-Wazuh converter (Phase 7: batch reports).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to YAML config (default: config/default.yaml under project root).",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Override logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )

    subparsers = parser.add_subparsers(dest="command")

    validate = subparsers.add_parser(
        "validate-config",
        help="Load and validate the configuration file.",
    )
    validate.set_defaults(func=cmd_validate_config)

    parse_cmd = subparsers.add_parser(
        "parse",
        help="Load Sigma YAML file(s) and parse with pySigma; write JSON report.",
    )
    parse_cmd.add_argument(
        "--input",
        required=True,
        type=Path,
        action="append",
        dest="inputs",
        help="Sigma rule file or directory. Repeat to add more. Duplicates are ignored.",
    )
    parse_cmd.add_argument(
        "--output",
        type=Path,
        default=None,
        help="JSON output path (default: <paths.output>/phase2-parse.json).",
    )
    parse_cmd.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )
    parse_cmd.set_defaults(func=cmd_parse)

    analyze_cmd = subparsers.add_parser(
        "analyze",
        help="Parse Sigma rules and classify ELIGIBLE/UNSUPPORTED/FAILED; write JSON.",
    )
    analyze_cmd.add_argument(
        "--input",
        required=True,
        type=Path,
        action="append",
        dest="inputs",
        help="Sigma rule file or directory. Repeat to add more. Duplicates are ignored.",
    )
    analyze_cmd.add_argument(
        "--output",
        type=Path,
        default=None,
        help="JSON output path (default: <paths.output>/phase3-support.json).",
    )
    analyze_cmd.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )
    analyze_cmd.set_defaults(func=cmd_analyze)

    map_cmd = subparsers.add_parser(
        "map",
        help="Analyze then map ELIGIBLE rules to thin IR JSON (no Wazuh XML).",
    )
    map_cmd.add_argument(
        "--input",
        required=True,
        type=Path,
        action="append",
        dest="inputs",
        help="Sigma rule file or directory. Repeat to add more. Duplicates are ignored.",
    )
    map_cmd.add_argument(
        "--output",
        type=Path,
        default=None,
        help="JSON output path (default: <paths.output>/phase4-ir.json).",
    )
    map_cmd.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )
    map_cmd.add_argument(
        "--field-mapping",
        type=Path,
        default=None,
        help="Field mapping YAML (default: config/field_mapping.yaml under project root).",
    )
    map_cmd.set_defaults(func=cmd_map)

    convert_cmd = subparsers.add_parser(
        "convert",
        help="Map ELIGIBLE rules then generate Wazuh XML + conversion JSON report.",
    )
    convert_cmd.add_argument(
        "--input",
        required=True,
        type=Path,
        action="append",
        dest="inputs",
        help="Sigma rule file or directory. Repeat to add more. Duplicates are ignored.",
    )
    convert_cmd.add_argument(
        "--output-xml",
        type=Path,
        default=None,
        help="Wazuh XML output (default: <paths.output>/phase5-rules.xml).",
    )
    convert_cmd.add_argument(
        "--output-report",
        type=Path,
        default=None,
        help="JSON report path (default: <paths.output>/phase5-report.json).",
    )
    convert_cmd.add_argument(
        "--field-mapping",
        type=Path,
        default=None,
        help="Field mapping YAML (default: config/field_mapping.yaml under project root).",
    )
    convert_cmd.add_argument(
        "--force",
        action="store_true",
        help="Overwrite XML and JSON outputs if they already exist.",
    )
    convert_cmd.set_defaults(func=cmd_convert)

    return parser


def cmd_validate_config(args: argparse.Namespace) -> int:
    """Đọc config, gắn logging, in tóm tắt khi hợp lệ."""
    try:
        cfg = load_config(args.config)
        level = resolve_level(
            cli_level=args.log_level,
            config_level=cfg.logging_level,
        )
        logger = setup_logging(level)
        logger.info(
            "Config OK: project=%s rules_root=%s output=%s reports=%s level=%s "
            "wazuh_base=%s if_sid=%s",
            cfg.project_name,
            cfg.rules_root,
            cfg.output_dir,
            cfg.reports_dir,
            cfg.logging_level,
            cfg.wazuh_rule_id_base,
            cfg.wazuh_if_sid,
        )
        print(
            "Config OK: "
            f"project={cfg.project_name} "
            f"rules_root={cfg.rules_root} "
            f"output={cfg.output_dir} "
            f"reports={cfg.reports_dir} "
            f"logging.level={cfg.logging_level} "
            f"wazuh.rule_id_base={cfg.wazuh_rule_id_base} "
            f"wazuh.if_sid={cfg.wazuh_if_sid}"
        )
        return 0
    except ConfigError as exc:
        print(f"ConfigError: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def cmd_parse(args: argparse.Namespace) -> int:
    """Parse file/thư mục Sigma và ghi báo cáo JSON."""
    try:
        cfg = load_config(args.config)
        level = resolve_level(
            cli_level=args.log_level,
            config_level=cfg.logging_level,
        )
        logger = setup_logging(level)

        path_base = find_project_root()
        output_path = (
            args.output.expanduser()
            if args.output is not None
            else cfg.output_dir / "phase2-parse.json"
        )

        report = parse_batch(args.inputs, path_base=path_base)
        commit_outputs([(output_path, report_to_json(report))], force=args.force)

        summary = report["summary"]
        problems = int(summary["failed"])
        logger.info(
            "Parse %s: total=%s ok=%s failed=%s output=%s",
            _log_word(problems),
            summary["total"],
            summary["ok"],
            summary["failed"],
            output_path,
        )
        print(
            f"Parse {_status_word(problems)}: "
            f"total={summary['total']} "
            f"ok={summary['ok']} "
            f"failed={summary['failed']} "
            f"output={output_path}"
        )
        return _exit_for(problems)
    except OutputError as exc:
        print(f"OutputError: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:
        print(f"ConfigError: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def cmd_analyze(args: argparse.Namespace) -> int:
    """Parse + classify support; ghi báo cáo JSON."""
    try:
        cfg = load_config(args.config)
        level = resolve_level(
            cli_level=args.log_level,
            config_level=cfg.logging_level,
        )
        logger = setup_logging(level)

        path_base = find_project_root()
        output_path = (
            args.output.expanduser()
            if args.output is not None
            else cfg.output_dir / "phase3-support.json"
        )

        report = analyze_batch(args.inputs, path_base=path_base)
        commit_outputs([(output_path, report_to_json(report))], force=args.force)

        summary = report["summary"]
        problems = int(summary["failed"])
        logger.info(
            "Analyze %s: total=%s eligible=%s unsupported=%s failed=%s output=%s",
            _log_word(problems),
            summary["total"],
            summary["eligible"],
            summary["unsupported"],
            summary["failed"],
            output_path,
        )
        print(
            f"Analyze {_status_word(problems)}: "
            f"total={summary['total']} "
            f"eligible={summary['eligible']} "
            f"unsupported={summary['unsupported']} "
            f"failed={summary['failed']} "
            f"output={output_path}"
        )
        return _exit_for(problems)
    except OutputError as exc:
        print(f"OutputError: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:
        print(f"ConfigError: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def cmd_map(args: argparse.Namespace) -> int:
    """Analyze + map ELIGIBLE → IR; ghi báo cáo JSON."""
    try:
        cfg = load_config(args.config)
        level = resolve_level(
            cli_level=args.log_level,
            config_level=cfg.logging_level,
        )
        logger = setup_logging(level)

        root = find_project_root()
        output_path = (
            args.output.expanduser()
            if args.output is not None
            else cfg.output_dir / "phase4-ir.json"
        )
        field_mapping = (
            args.field_mapping.expanduser()
            if args.field_mapping is not None
            else root / "config" / "field_mapping.yaml"
        )

        report = map_batch(
            args.inputs,
            path_base=root,
            field_mapping_path=field_mapping,
        )
        commit_outputs([(output_path, report_to_json(report))], force=args.force)

        summary = report["summary"]
        problems = int(summary["map_failed"]) + int(summary["skipped_failed"])
        logger.info(
            "Map %s: total=%s mapped=%s skipped_unsupported=%s "
            "skipped_failed=%s map_failed=%s output=%s",
            _log_word(problems),
            summary["total"],
            summary["mapped"],
            summary["skipped_unsupported"],
            summary["skipped_failed"],
            summary["map_failed"],
            output_path,
        )
        print(
            f"Map {_status_word(problems)}: "
            f"total={summary['total']} "
            f"mapped={summary['mapped']} "
            f"skipped_unsupported={summary['skipped_unsupported']} "
            f"skipped_failed={summary['skipped_failed']} "
            f"map_failed={summary['map_failed']} "
            f"output={output_path}"
        )
        return _exit_for(problems)
    except OutputError as exc:
        print(f"OutputError: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:
        print(f"ConfigError: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def cmd_convert(args: argparse.Namespace) -> int:
    """map_batch + sinh Wazuh XML + report JSON."""
    try:
        cfg = load_config(args.config)
        level = resolve_level(
            cli_level=args.log_level,
            config_level=cfg.logging_level,
        )
        logger = setup_logging(level)

        root = find_project_root()
        xml_path = (
            args.output_xml.expanduser()
            if args.output_xml is not None
            else cfg.output_dir / "phase5-rules.xml"
        )
        report_path = (
            args.output_report.expanduser()
            if args.output_report is not None
            else cfg.output_dir / "phase5-report.json"
        )
        field_mapping = (
            args.field_mapping.expanduser()
            if args.field_mapping is not None
            else root / "config" / "field_mapping.yaml"
        )

        report = convert_from_input(
            args.inputs,
            path_base=root,
            field_mapping_path=field_mapping,
            rule_id_base=cfg.wazuh_rule_id_base,
            if_sid=cfg.wazuh_if_sid,
            level_map=cfg.wazuh_level_map,
        )
        commit_outputs(
            [
                (xml_path, xml_to_string(report["xml_root"])),
                (report_path, report_to_json(report)),
            ],
            force=args.force,
        )

        summary = report["summary"]
        problems = _convert_problem_count(report)
        logger.info(
            "Convert %s: total=%s success=%s unsupported=%s failed=%s "
            "skipped=%s rules=%s xml=%s report=%s",
            _log_word(problems),
            summary["total"],
            summary["success"],
            summary["unsupported"],
            summary["failed"],
            summary["skipped"],
            summary["rule_elements"],
            xml_path,
            report_path,
        )
        print(
            f"Convert {_status_word(problems)}: "
            f"total={summary['total']} "
            f"success={summary['success']} "
            f"unsupported={summary['unsupported']} "
            f"failed={summary['failed']} "
            f"skipped={summary['skipped']} "
            f"rule_elements={summary['rule_elements']} "
            f"xml={xml_path} "
            f"report={report_path}"
        )
        return _exit_for(problems)
    except OutputError as exc:
        print(f"OutputError: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:
        print(f"ConfigError: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    """Điểm vào CLI. Exit 2 do argparse khi cú pháp sai — không bắt SystemExit."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
