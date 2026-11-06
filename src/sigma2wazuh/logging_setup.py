"""Cấu hình logging chuẩn cho package (idempotent, không nhân handler)."""

from __future__ import annotations

import logging

LOGGER_NAME = "sigma2wazuh"
DEFAULT_LEVEL_NAME = "INFO"

# Đánh dấu handler do app tạo để setup lần sau không add trùng.
_HANDLER_MARKER = "sigma2wazuh_stream"


def resolve_level(
    *,
    cli_level: str | None,
    config_level: str | None,
    default: str = DEFAULT_LEVEL_NAME,
) -> int:
    """Ưu tiên level: default < config < CLI ``--log-level``."""
    chosen = default
    if config_level:
        chosen = config_level
    if cli_level:
        chosen = cli_level
    numeric = getattr(logging, str(chosen).upper(), None)
    if not isinstance(numeric, int):
        raise ValueError(f"Invalid logging level name: {chosen!r}")
    return numeric


def setup_logging(
    level: str | int | None = None,
    *,
    force: bool = False,
) -> logging.Logger:
    """Gắn một StreamHandler cho logger ``sigma2wazuh`` nếu chưa có.

    Gọi nhiều lần không tạo thêm handler (trừ khi ``force=True`` thì thay level
    và đảm bảo vẫn chỉ còn các handler của app).
    """
    logger = logging.getLogger(LOGGER_NAME)

    if isinstance(level, int):
        numeric = level
    elif level is None:
        numeric = resolve_level(cli_level=None, config_level=None)
    else:
        numeric = resolve_level(cli_level=str(level), config_level=None)

    logger.setLevel(numeric)

    app_handlers = [
        handler
        for handler in logger.handlers
        if getattr(handler, _HANDLER_MARKER, False)
    ]

    if force:
        for handler in app_handlers:
            logger.removeHandler(handler)
            handler.close()
        app_handlers = []

    if not app_handlers:
        handler = logging.StreamHandler()
        handler.setLevel(numeric)
        handler.setFormatter(
            logging.Formatter("%(levelname)s %(name)s: %(message)s")
        )
        setattr(handler, _HANDLER_MARKER, True)
        logger.addHandler(handler)
    else:
        for handler in app_handlers:
            handler.setLevel(numeric)

    # Không lan truyền lên root để tránh nhân đôi dòng log nếu root đã có handler.
    logger.propagate = False
    return logger
