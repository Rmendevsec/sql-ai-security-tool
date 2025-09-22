# utils/logger.py
import logging
import sys
from typing import Optional

"""
Logger - Handles logging configuration

Provides:
 - Logger class (can be imported as `from utils.logger import Logger`)
 - setup_logger(name) function
 - convenience functions: log_info, log_warning, log_success
"""

DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Logger:
    """Simple wrapper around Python's logging.Logger with a predictable setup."""

    def __init__(self, name: str = "sql-ai-security-tool", level: int = logging.INFO):
        self._logger = logging.getLogger(name)
        # avoid adding duplicate handlers if the logger is created multiple times
        if not self._logger.handlers:
            self._logger.setLevel(level)

            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(level)

            formatter = logging.Formatter(DEFAULT_FORMAT)
            handler.setFormatter(formatter)

            self._logger.addHandler(handler)

    def info(self, msg: str, *args, **kwargs) -> None:
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        self._logger.error(msg, *args, **kwargs)

    def debug(self, msg: str, *args, **kwargs) -> None:
        self._logger.debug(msg, *args, **kwargs)

    def success(self, msg: str, *args, **kwargs) -> None:
        """Semantic success method — logs as INFO but prefixes with [OK]."""
        self._logger.info(f"[OK] {msg}", *args, **kwargs)


def setup_logger(name: str = "sql-ai-security-tool", level: int = logging.INFO) -> logging.Logger:
    """
    Setup and return a configured stdlib logger (useful if modules prefer raw logging.Logger).
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(level)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(DEFAULT_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


# module-level default wrapper so existing calls continue to work
_default = Logger("sql-ai-security-tool")


def log_info(msg: str) -> None:
    _default.info(msg)


def log_warning(msg: str) -> None:
    _default.warning(msg)


def log_success(msg: str) -> None:
    _default.success(msg)


# optional export list
__all__ = ["Logger", "setup_logger", "log_info", "log_warning", "log_success"]
