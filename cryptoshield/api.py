"""
cryptoshield/api.py
~~~~~~~~~~~~~~~~~~~
Etherscan API v2 client.

Handles all HTTP communication, rate limiting, pagination,
and error handling. No business logic lives here.
"""

from __future__ import annotations

import time
from typing import Any

import requests

from cryptoshield import config
from cryptoshield.logger import get_logger

log = get_logger(__name__)

# Shared requests session for connection pooling
_session = requests.Session()
_session.headers.update({"Accept": "application/json"})


# ── Internal helpers ──────────────────────────────────────────────────────────

def _call(params: dict[str, Any]) -> dict | None:
    """
    Make a single Etherscan API call.

    Injects chainid and apikey automatically.
    Returns the parsed JSON dict or None on failure.

    :param params: Query parameters (without chainid / apikey).
    :returns: Parsed JSON response dict, or None if the request failed.
    """
    params = {
        **params,
        "chainid": config.CHAIN_ID,
        "apikey":  config.ETHERSCAN_API_KEY,
    }

    try:
        response = _session.get(
            config.ETHERSCAN_BASE_URL,
            params=params,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()

    except requests.exceptions.Timeout:
        log.error("Etherscan request timed out (params: %s)", params)
        return None

    except requests.exceptions.HTTPError as exc:
        log.error("Etherscan HTTP error %s: %s", exc.response.status_code, exc)
        return None

    except requests.exceptions.RequestException as exc:
        log.error("Etherscan network error: %s", exc)
        return None

    except ValueError:
        log.error("Etherscan returned non-JSON response.")
        return None

    if data.get("status") == "0":
        message = data.get("result", "Unknown error")
        # "No transactions found" is a normal condition, not an error
        if "No transactions found" in str(message):
            return data
        log.warning("Etherscan API returned status 0: %s", message)
        return None

    return data


# ── Public interface ──────────────────────────────────────────────────────────

def get_balance(address: str) -> str:
    """
    Fetch the current ETH balance of a wallet.

    :param address: Ethereum wallet address.
    :returns: Human-readable balance string (e.g. "1.2345 ETH"),
              or "Unavailable" if the request fails.
    """
    data = _call({
        "module":  "account",
        "action":  "balance",
        "address": address,
        "tag":     "latest",
    })

    if not data:
        return "Unavailable"

    try:
        wei   = int(data["result"])
        ether = wei / 1e18
        return f"{ether:.4f} ETH"
    except (KeyError, ValueError, TypeError) as exc:
        log.warning("Could not parse balance for %s: %s", address, exc)
        return "Unavailable"


def get_transactions(address: str, max_pages: int = config.MAX_TX_PAGES) -> list[dict]:
    """
    Fetch the full normal transaction history for a wallet.

    Automatically paginates up to max_pages × 10,000 transactions.
    Results are sorted newest-first.

    :param address:   Ethereum wallet address.
    :param max_pages: Maximum number of pages to fetch (default from config).
    :returns: List of transaction dicts as returned by Etherscan.
    """
    all_transactions: list[dict] = []

    for page in range(1, max_pages + 1):
        data = _call({
            "module":     "account",
            "action":     "txlist",
            "address":    address,
            "startblock": 0,
            "endblock":   99999999,
            "page":       page,
            "offset":     10000,
            "sort":       "desc",
        })

        if not data:
            break

        batch = data.get("result", [])
        if not isinstance(batch, list):
            break

        all_transactions.extend(batch)
        log.debug("Page %d: fetched %d transactions for %s", page, len(batch), address)

        # Fewer results than page size means we reached the last page
        if len(batch) < 10000:
            break

        time.sleep(config.REQUEST_DELAY)

    return all_transactions


def get_transactions_slim(address: str) -> list[dict]:
    """
    Fetch a limited transaction list for use during hop analysis.

    Only fetches the first page (up to HOP_TX_LIMIT records).
    Used for intermediate wallets to avoid excessive API calls.

    :param address: Ethereum wallet address.
    :returns: List of transaction dicts (up to HOP_TX_LIMIT).
    """
    data = _call({
        "module":     "account",
        "action":     "txlist",
        "address":    address,
        "startblock": 0,
        "endblock":   99999999,
        "page":       1,
        "offset":     config.HOP_TX_LIMIT,
        "sort":       "desc",
    })

    if not data:
        return []

    result = data.get("result", [])
    return result if isinstance(result, list) else []
