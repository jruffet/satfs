# SPDX-License-Identifier: MIT

import sys
import logging
from systemd.journal import JournalHandler

LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRIT": logging.CRITICAL,
    "CRITICAL": logging.CRITICAL,
}

# Global logger instance
logger = logging.getLogger("satfs")
logger.setLevel(logging.DEBUG)
_config_name = None


class CustomFormatter(logging.Formatter):
    """Formatter that injects the config_name into log messages"""

    def format(self, record):
        config_prefix = f"[{_config_name}] " if _config_name else ""
        record.msg = f"{config_prefix}{record.msg}"
        return super().format(record)


class NoColorJournalHandler(JournalHandler):
    def emit(self, record):
        # Override the priority level to prevent journald from applying colors
        record.levelno = logging.INFO
        super().emit(record)


def log_level(level_name: str) -> int:
    """Get logger level using a string"""
    level = LOG_LEVELS.get(level_name.upper())
    if level is None:
        raise ValueError(f"Invalid log level: {level_name}")
    return level


def set_config_name(config_name: str) -> None:
    global _config_name
    _config_name = config_name


def setup_logger(foreground: bool = True):
    """Initialise the logger (stderr + syslog)"""
    global logger

    if not logger.hasHandlers():  # Avoid duplicate handlers
        formatter = CustomFormatter()

        # stderr handler
        if foreground:
            console_handler = logging.StreamHandler(sys.stderr)
            logger.addHandler(console_handler)

        # Journald handler
        journal_handler = NoColorJournalHandler(SYSLOG_IDENTIFIER="satfs")
        journal_handler.setFormatter(formatter)
        logger.addHandler(journal_handler)
