"""CLI Phase 1: argparse, validate-config; chưa có lệnh convert."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sigma2wazuh import __version__
from sigma2wazuh.config import ConfigError, load_config
from sigma2wazuh.logging_setup import resolve_level, setup_logging


def build_parser() -> argparse.ArgumentParser:
    """Tạo parser gốc với các flag global và subcommand Phase 1."""
    parser = argparse.ArgumentParser(
        prog="sigma2wazuh",
        description="Sigma-to-Wazuh converter (Phase 1: config and tooling only).",
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
    except Exception as exc:  # noqa: BLE001 — CLI boundary: map mọi lỗi thực thi sang exit 1
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
