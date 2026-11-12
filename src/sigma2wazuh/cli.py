"""CLI: validate-config, parse, analyze, map. Chưa có lệnh convert."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sigma2wazuh import __version__
from sigma2wazuh.config import ConfigError, find_project_root, load_config
from sigma2wazuh.logging_setup import resolve_level, setup_logging
from sigma2wazuh.mapper import map_batch
from sigma2wazuh.parsing import parse_batch, write_report
from sigma2wazuh.support_analyzer import analyze_batch


def build_parser() -> argparse.ArgumentParser:
    """Tạo parser gốc với flag global và các subcommand hiện có."""
    parser = argparse.ArgumentParser(
        prog="sigma2wazuh",
        description="Sigma-to-Wazuh converter (Phase 4: parse + analyze + map IR).",
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
        help="Sigma rule file or directory to parse.",
    )
    parse_cmd.add_argument(
        "--output",
        type=Path,
        default=None,
        help="JSON output path (default: <paths.output>/phase2-parse.json).",
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
        help="Sigma rule file or directory to analyze.",
    )
    analyze_cmd.add_argument(
        "--output",
        type=Path,
        default=None,
        help="JSON output path (default: <paths.output>/phase3-support.json).",
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
        help="Sigma rule file or directory to map.",
    )
    map_cmd.add_argument(
        "--output",
        type=Path,
        default=None,
        help="JSON output path (default: <paths.output>/phase4-ir.json).",
    )
    map_cmd.add_argument(
        "--field-mapping",
        type=Path,
        default=None,
        help="Field mapping YAML (default: config/field_mapping.yaml under project root).",
    )
    map_cmd.set_defaults(func=cmd_map)

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
            "Config OK: project=%s rules_root=%s output=%s reports=%s level=%s",
            cfg.project_name,
            cfg.rules_root,
            cfg.output_dir,
            cfg.reports_dir,
            cfg.logging_level,
        )
        print(
            "Config OK: "
            f"project={cfg.project_name} "
            f"rules_root={cfg.rules_root} "
            f"output={cfg.output_dir} "
            f"reports={cfg.reports_dir} "
            f"logging.level={cfg.logging_level}"
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

        input_path = args.input.expanduser()
        # path_base: ưu tiên project root để path trong JSON gọn và ổn định.
        path_base = find_project_root()
        output_path = (
            args.output.expanduser()
            if args.output is not None
            else cfg.output_dir / "phase2-parse.json"
        )

        report = parse_batch(input_path, path_base=path_base)
        write_report(report, output_path)

        summary = report["summary"]
        logger.info(
            "Parse done: total=%s ok=%s failed=%s output=%s",
            summary["total"],
            summary["ok"],
            summary["failed"],
            output_path,
        )
        print(
            "Parse OK: "
            f"total={summary['total']} "
            f"ok={summary['ok']} "
            f"failed={summary['failed']} "
            f"output={output_path}"
        )
        # Exit 0 khi pipeline chạy xong và đã ghi report (kể cả có rule FAILED).
        return 0
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

        input_path = args.input.expanduser()
        path_base = find_project_root()
        output_path = (
            args.output.expanduser()
            if args.output is not None
            else cfg.output_dir / "phase3-support.json"
        )

        report = analyze_batch(input_path, path_base=path_base)
        write_report(report, output_path)

        summary = report["summary"]
        logger.info(
            "Analyze done: total=%s eligible=%s unsupported=%s failed=%s output=%s",
            summary["total"],
            summary["eligible"],
            summary["unsupported"],
            summary["failed"],
            output_path,
        )
        print(
            "Analyze OK: "
            f"total={summary['total']} "
            f"eligible={summary['eligible']} "
            f"unsupported={summary['unsupported']} "
            f"failed={summary['failed']} "
            f"output={output_path}"
        )
        return 0
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
        input_path = args.input.expanduser()
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
            input_path,
            path_base=root,
            field_mapping_path=field_mapping,
        )
        write_report(report, output_path)

        summary = report["summary"]
        logger.info(
            "Map done: total=%s mapped=%s skipped_unsupported=%s "
            "skipped_failed=%s map_failed=%s output=%s",
            summary["total"],
            summary["mapped"],
            summary["skipped_unsupported"],
            summary["skipped_failed"],
            summary["map_failed"],
            output_path,
        )
        print(
            "Map OK: "
            f"total={summary['total']} "
            f"mapped={summary['mapped']} "
            f"skipped_unsupported={summary['skipped_unsupported']} "
            f"skipped_failed={summary['skipped_failed']} "
            f"map_failed={summary['map_failed']} "
            f"output={output_path}"
        )
        return 0
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
