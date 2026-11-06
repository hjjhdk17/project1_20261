"""Kiểm thử logging idempotent và ưu tiên level."""

from __future__ import annotations

import logging

from sigma2wazuh.logging_setup import (
    LOGGER_NAME,
    resolve_level,
    setup_logging,
)


def _app_handlers(logger: logging.Logger) -> list[logging.Handler]:
    return [
        handler
        for handler in logger.handlers
        if getattr(handler, "sigma2wazuh_stream", False)
    ]


def test_logging_no_duplicate_handlers() -> None:
    logger = logging.getLogger(LOGGER_NAME)
    # Dọn handler còn sót từ test khác.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    setup_logging("INFO")
    setup_logging("DEBUG")
    assert len(_app_handlers(logger)) == 1
    assert logger.level == logging.DEBUG


def test_resolve_level_priority() -> None:
    assert resolve_level(cli_level=None, config_level=None) == logging.INFO
    assert resolve_level(cli_level=None, config_level="WARNING") == logging.WARNING
    assert (
        resolve_level(cli_level="DEBUG", config_level="WARNING") == logging.DEBUG
    )


def test_setup_logging_force_replaces_handler() -> None:
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    first = setup_logging("INFO")
    second = setup_logging("ERROR", force=True)
    assert first is second
    assert len(_app_handlers(logger)) == 1
    assert logger.level == logging.ERROR
