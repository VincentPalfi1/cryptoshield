"""
cryptoshield/config.py
~~~~~~~~~~~~~~~~~~~~~~
Centralized configuration loaded from environment variables.
Never hardcode secrets — use a .env file locally or environment
variables in production.
"""

import os
import logging
from dotenv import load_dotenv

load_dotenv()


def _require(key: str) -> str:
    """
    Fetch a required environment variable.

    :param key: Environment variable name.
    :raises EnvironmentError: If the variable is not set.
    :returns: The variable's string value.
    """
    value = os.getenv(key)
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{key}' is not set. "
            f"Copy .env.example to .env and fill in your values."
        )
    return value


def _optional(key: str, default: str) -> str:
    """
    Fetch an optional environment variable with a fallback default.

    :param key: Environment variable name.
    :param default: Default value if not set.
    :returns: The variable's string value or the default.
    """
    return os.getenv(key, default)


# ── API ───────────────────────────────────────────────────────────────────────
ETHERSCAN_API_KEY   : str = _require("ETHERSCAN_API_KEY")
ETHERSCAN_BASE_URL  : str = "https://api.etherscan.io/v2/api"
CHAIN_ID            : int = int(_optional("CHAIN_ID", "1"))

# ── Analysis parameters ───────────────────────────────────────────────────────
MAX_TX_PAGES        : int   = int(_optional("MAX_TX_PAGES", "3"))
HOP_DEPTH           : int   = int(_optional("HOP_DEPTH", "3"))
HOP_TX_LIMIT        : int   = 1000
REQUEST_DELAY       : float = 0.22       # seconds — respects Etherscan rate limits

# ── Risk thresholds ───────────────────────────────────────────────────────────
THRESHOLD_CRITICAL  : int = 80
THRESHOLD_HIGH      : int = 60
THRESHOLD_MEDIUM    : int = 30

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL: int = getattr(logging, _optional("LOG_LEVEL", "INFO").upper(), logging.INFO)
