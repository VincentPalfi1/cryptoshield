"""
cryptoshield/database.py
~~~~~~~~~~~~~~~~~~~~~~~~
Risk address database.

Contains three tiers of risk addresses:
  - SANCTIONED   : OFAC SDN / EU / UN-listed addresses
  - HIGH_RISK    : Confirmed malicious, not yet officially sanctioned
  - MEDIUM_RISK  : Associated with higher-risk activity

Structure per entry:
  "0x<address>": ("<label>", "<source>")

Sources:
  OFAC-SDN    — US Treasury Office of Foreign Assets Control
  EXPLOIT     — On-chain confirmed exploit / hack
  HIGH-RISK   — Community intelligence / on-chain forensics
  EXCHANGE    — Centralized exchange hot wallet (informational)
"""

from __future__ import annotations
from cryptoshield.logger import get_logger

log = get_logger(__name__)


# ── TIER 1: SANCTIONED ───────────────────────────────────────────────────────
# Addresses directly listed by OFAC, EU, or UN sanctions bodies.

SANCTIONED_ADDRESSES: dict[str, tuple[str, str]] = {

    # Tornado Cash — OFAC sanctioned August 8, 2022
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": ("Tornado Cash",                    "OFAC-SDN"),
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": ("Tornado Cash Router",              "OFAC-SDN"),
    "0xdd4c48c0b24039969fc16d1cdf626eab821d3384": ("Tornado Cash 0.1 ETH Pool",        "OFAC-SDN"),
    "0xd96f2b1c14db8458374d9aca76e26c3950113464": ("Tornado Cash 1 ETH Pool",          "OFAC-SDN"),
    "0x178169b423a011fff22b9e3f3abea13414ddd0f1": ("Tornado Cash 10 ETH Pool",         "OFAC-SDN"),
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": ("Tornado Cash 100 ETH Pool",        "OFAC-SDN"),
    "0xaf4c0b70b2ea9fb7487c7cbb37ada259579fe040": ("Tornado Cash 1000 ETH Pool",       "OFAC-SDN"),
    "0xa60c772958a3ed426c63338e596d686aa7d6a6d0": ("Tornado Cash TORN Token",          "OFAC-SDN"),
    "0x12d66f87a04a9e220c9d696f0f2b4e0a9d342f4b": ("Tornado Cash Proxy",               "OFAC-SDN"),
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": ("Tornado Cash Proxy",               "OFAC-SDN"),
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": ("Tornado Cash Proxy",               "OFAC-SDN"),
    "0x23773e65ed146a459667ad976d7c6d4a360da8ab": ("Tornado Cash Proxy",               "OFAC-SDN"),
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": ("Tornado Cash Staking",             "OFAC-SDN"),
    "0x5efda50f22d34f262c29268506c5fa42cb56a1ce": ("Tornado Cash Governance",          "OFAC-SDN"),

    # Lazarus Group — North Korean state-sponsored hackers
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": ("Lazarus Group",                    "OFAC-SDN"),
    "0xa0e1c89ef1a489c9c7de96311ed5ce5d32c20e4b": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0x3cffd56b47277e3dd5d9e95736564fcf5e22ba7a": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0x53b6936513e738f44fb50d2b9476730c0ab3bfc1": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0x7f367cc41522ce07553e823bf3be79a889debe1b": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0x901bb9583b24d97e995513c6778dc6888ab6870e": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0xa7e5d5a720f06526557c513402f2e6b5fa20b008": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0x7db418b5d567a4e0e8c59ad71be1fce48f3e6107": ("Lazarus Group Wallet",             "OFAC-SDN"),
    "0x72a5843cc08275c8171e582972aa4fda8c397b2a": ("Lazarus Group Wallet",             "OFAC-SDN"),

    # Blender.io — OFAC sanctioned mixer, May 2022
    "0xb6f5ec1a0a9cd1526536d3f0426c429529471f40": ("Blender.io Mixer",                 "OFAC-SDN"),

    # ChipMixer — OFAC sanctioned mixer, March 2023
    "0x502371699497d08d5339c870851898d6ab16a888": ("ChipMixer",                        "OFAC-SDN"),

    # Bitfinex Hack wallets — OFAC sanctioned February 2022
    "0x3096afe7a48f18b5e8a19e08fce2422a8f1aa8b3": ("Bitfinex Hack Wallet",             "OFAC-SDN"),
}

# ── TIER 2: HIGH RISK ────────────────────────────────────────────────────────
# Confirmed exploiters and high-confidence malicious actors.

HIGH_RISK_ADDRESSES: dict[str, tuple[str, str]] = {

    # Bybit Hack — February 2025, $1.5B, attributed to Lazarus Group
    "0x47666fab8bd0ac7003bce3f5c3585383f09486e2": ("Bybit Exploiter",                  "EXPLOIT"),

    # Euler Finance Hack — March 2023, $197M
    "0xb66cd966670d962c227b3eaba30a872dbffd995c": ("Euler Finance Exploiter",          "EXPLOIT"),
    "0x5f259d0b76665c337c6104145894f4d1d2758b8c": ("Euler Finance Exploiter",          "EXPLOIT"),

    # KuCoin Hack — September 2020, $281M
    "0xeb31973e0febf3e3d7058234a5ebbae1ab4b8c23": ("KuCoin Exploiter",                 "EXPLOIT"),

    # Ronin Bridge Hack — March 2022, $625M
    "0xe708f17240732bbfa1baa8513f66b665fbc7ce10": ("Ronin Bridge Exploiter",           "EXPLOIT"),

    # Nomad Bridge Hack — August 2022, $190M
    "0xa62142888aba8370742be823c1782d17a0389da1": ("Nomad Bridge Exploiter",           "EXPLOIT"),

    # Wintermute Hack — September 2022, $160M
    "0xe74b28c2eae8679e3ccc3a94d5d0de83ccb84705": ("Wintermute Exploiter",             "EXPLOIT"),

    # General high-risk
    "0x9bf4001d307dfd62b26a2f1307ee0c0307632d59": ("Suspected Scam Address",           "HIGH-RISK"),
    "0x1967d8af5bd86a497fb3dd7899a020e47560daaf": ("Confirmed Phishing Address",       "HIGH-RISK"),
    "0xfec8a60023265364d066a1212fde3930f6ae8da3": ("Confirmed Phishing Address",       "HIGH-RISK"),
}

# ── TIER 3: MEDIUM RISK ──────────────────────────────────────────────────────
# Informational flags — not necessarily malicious but warrant attention.

MEDIUM_RISK_ADDRESSES: dict[str, tuple[str, str]] = {
    "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be": ("Binance Hot Wallet",               "EXCHANGE"),
    "0xd551234ae421e3bcba99a0da6d736074f22192ff": ("Binance Hot Wallet",               "EXCHANGE"),
    "0x564286362092d8e7936f0549571a803b203aaced": ("Binance Hot Wallet",               "EXCHANGE"),
    "0x0681d8db095565fe8a346fa0277bffde9c0edbbf": ("Binance Hot Wallet",               "EXCHANGE"),
}

# ── Lookup index (built at import time for O(1) lookups) ────────────────────

_INDEX: dict[str, tuple[str, str, str]] = {}

for _addr, (_label, _source) in SANCTIONED_ADDRESSES.items():
    _INDEX[_addr.lower()] = (_label, _source, "SANCTIONED")

for _addr, (_label, _source) in HIGH_RISK_ADDRESSES.items():
    _INDEX[_addr.lower()] = (_label, _source, "HIGH_RISK")

for _addr, (_label, _source) in MEDIUM_RISK_ADDRESSES.items():
    _INDEX[_addr.lower()] = (_label, _source, "MEDIUM_RISK")

log.debug("Risk database loaded: %d sanctioned, %d high-risk, %d medium-risk addresses.",
          len(SANCTIONED_ADDRESSES), len(HIGH_RISK_ADDRESSES), len(MEDIUM_RISK_ADDRESSES))


def lookup(address: str) -> tuple[str, str, str] | None:
    """
    Look up an address in the risk database.

    :param address: Ethereum address (any case).
    :returns: Tuple of (label, source, tier) if found, else None.
              tier is one of: 'SANCTIONED', 'HIGH_RISK', 'MEDIUM_RISK'
    """
    return _INDEX.get(address.lower())


def total_count() -> int:
    """Return the total number of addresses in the database."""
    return len(_INDEX)
