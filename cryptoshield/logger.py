"""
cryptoshield/logger.py
~~~~~~~~~~~~~~~~~~~~~~
Configures a structured logger for the entire application.
Uses Python's standard logging library with a consistent format.
All modules import from here instead of using print().
"""

import logging
import sys
from cryptoshield.config import LOG_LEVEL


def get_logger(name: str) -> logging.Logger:
    """
    Create and return a named logger with consistent formatting.

    :param name: Logger name — typically __name__ of the calling module.
    :returns: Configured Logger instance.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(LOG_LEVEL)

        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(LOG_LEVEL)

        formatter = logging.Formatter(
            fmt="%(asctime)s  [%(levelname)-8s]  %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
