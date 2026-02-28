"""
cryptoshield/analyzer.py
~~~~~~~~~~~~~~~~~~~~~~~~
Core risk analysis engine.

Responsible for:
  - Direct sanctions screening
  - Multi-hop transaction graph traversal
  - Behavioral AML pattern detection
  - Wallet metadata computation
  - Risk score aggregation

No I/O (no print, no API calls) — pure analysis logic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptoshield import config
from cryptoshield import database as db
from cryptoshield import api
from cryptoshield.logger import get_logger

log = get_logger(__name__)


# ── Risk scoring weights ──────────────────────────────────────────────────────

WEIGHTS: dict[str, int] = {
    # Sanctions / confirmed malicious — direct
    "sanctioned_direct":           100,
    "high_risk_direct":             45,
    "medium_risk_direct":           15,

    # Sanctions / confirmed malicious — indirect (hop-based)
    "sanctioned_hop1":              65,
    "sanctioned_hop2":              40,
    "sanctioned_hop3":              20,
    "high_risk_hop1":               25,

    # Behavioral signals
    "rapid_transaction_burst":      25,
    "structuring_pattern":          25,
    "layering_fan_out":             30,
    "new_wallet_high_volume":       20,
    "dormant_then_active":          15,

    # Trust bonuses (reduce score)
    "established_wallet":          -10,
    "very_established_wallet":     -15,
}


# ── Result data structures ────────────────────────────────────────────────────

@dataclass
class DirectFinding:
    """A direct interaction with a sanctioned or high-risk address."""
    counterparty: str
    label:        str
    source:       str
    tier:         str
    weight:       int
    tx_hash:      str
    timestamp:    int


@dataclass
class HopFinding:
    """An indirect connection discovered during hop analysis."""
    hop:     int
    address: str
    label:   str
    source:  str
    tier:    str
    weight:  int


@dataclass
class BehaviorFinding:
    """A detected AML behavioral pattern."""
    pattern_type: str
    description:  str
    severity:     str
    weight:       int


@dataclass
class WalletMetadata:
    """Descriptive statistics about a wallet."""
    tx_count:              int
    first_seen:            str
    last_seen:             str
    wallet_age_days:       float
    outgoing_volume_eth:   str
    counterparty_count:    int
    is_established:        bool
    is_very_established:   bool


@dataclass
class AnalysisResult:
    """Complete analysis result for a wallet."""
    address:           str
    balance:           str
    metadata:          WalletMetadata
    direct_findings:   list[DirectFinding]  = field(default_factory=list)
    hop_findings:      list[HopFinding]     = field(default_factory=list)
    behavior_findings: list[BehaviorFinding] = field(default_factory=list)
    risk_score:        int                  = 0
    verdict:           str                  = "LOW"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _counterparties(address: str, transactions: list[dict]) -> set[str]:
    """
    Extract unique counterparty addresses from a list of transactions.

    :param address:      The wallet being analyzed (excluded from results).
    :param transactions: List of transaction dicts from Etherscan.
    :returns: Set of lowercase counterparty addresses.
    """
    addr_lower = address.lower()
    result: set[str] = set()
    for tx in transactions:
        for field_name in ("to", "from"):
            cp = tx.get(field_name, "")
            if cp and cp.lower() != addr_lower:
                result.add(cp.lower())
    return result


def _format_ts(unix_ts: int) -> str:
    """Format a Unix timestamp as a human-readable UTC string."""
    try:
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OSError, OverflowError, ValueError):
        return "N/A"


# ── Sub-analyzers ─────────────────────────────────────────────────────────────

def compute_metadata(address: str, transactions: list[dict]) -> WalletMetadata:
    """
    Compute descriptive statistics about a wallet.

    :param address:      Wallet address being analyzed.
    :param transactions: Full transaction list from Etherscan.
    :returns: WalletMetadata dataclass.
    """
    addr_lower = address.lower()

    if not transactions:
        return WalletMetadata(
            tx_count=0, first_seen="N/A", last_seen="N/A",
            wallet_age_days=0.0, outgoing_volume_eth="0.0000 ETH",
            counterparty_count=0, is_established=False, is_very_established=False,
        )

    timestamps: list[int] = []
    for tx in transactions:
        try:
            timestamps.append(int(tx["timeStamp"]))
        except (KeyError, ValueError, TypeError):
            continue

    first_ts = min(timestamps) if timestamps else 0
    last_ts  = max(timestamps) if timestamps else 0
    age_days = (time.time() - first_ts) / 86400 if first_ts else 0.0

    outgoing_wei = 0
    for tx in transactions:
        if tx.get("from", "").lower() == addr_lower:
            try:
                outgoing_wei += int(tx.get("value", 0))
            except (ValueError, TypeError):
                continue

    tx_count = len(transactions)

    return WalletMetadata(
        tx_count            = tx_count,
        first_seen          = _format_ts(first_ts),
        last_seen           = _format_ts(last_ts),
        wallet_age_days     = round(age_days, 1),
        outgoing_volume_eth = f"{outgoing_wei / 1e18:.4f} ETH",
        counterparty_count  = len(_counterparties(address, transactions)),
        is_established      = tx_count >= 500  and age_days >= 365,
        is_very_established = tx_count >= 2000 and age_days >= 730,
    )


def screen_direct(address: str, transactions: list[dict]) -> list[DirectFinding]:
    """
    Screen all direct transaction counterparties against the risk database.

    :param address:      Wallet address being analyzed.
    :param transactions: Full transaction list.
    :returns: Deduplicated list of DirectFinding objects, sorted by weight desc.
    """
    addr_lower  = address.lower()
    seen_cp:  dict[str, DirectFinding] = {}

    for tx in transactions:
        for field_name in ("to", "from"):
            cp = tx.get(field_name, "").lower()
            if not cp or cp == addr_lower:
                continue

            match = db.lookup(cp)
            if not match:
                continue

            label, source, tier = match
            weight = (
                WEIGHTS["sanctioned_direct"] if tier == "SANCTIONED" else
                WEIGHTS["high_risk_direct"]   if tier == "HIGH_RISK"  else
                WEIGHTS["medium_risk_direct"]
            )

            finding = DirectFinding(
                counterparty = cp,
                label        = label,
                source       = source,
                tier         = tier,
                weight       = weight,
                tx_hash      = tx.get("hash", "N/A"),
                timestamp    = int(tx.get("timeStamp", 0)),
            )

            # Keep only the highest-weight finding per counterparty
            if cp not in seen_cp or weight > seen_cp[cp].weight:
                seen_cp[cp] = finding

    return sorted(seen_cp.values(), key=lambda f: f.weight, reverse=True)


def analyze_hops(
    address:      str,
    transactions: list[dict],
    depth:        int = config.HOP_DEPTH,
) -> list[HopFinding]:
    """
    Trace the transaction graph outward from a root wallet up to `depth` hops.

    For each hop level, fetches transaction data for counterparties and
    checks whether any of them (or their counterparties) interact with
    sanctioned or high-risk addresses.

    :param address:      Root wallet address.
    :param transactions: Root wallet's transaction list.
    :param depth:        Number of hops to trace (default from config).
    :returns: Deduplicated list of HopFinding objects, sorted by weight desc.
    """
    findings:   dict[str, HopFinding] = {}
    visited:    set[str]              = {address.lower()}
    current_cp: set[str]              = _counterparties(address, transactions)

    for hop in range(1, depth + 1):
        candidates = list(current_cp - visited)[:200]  # Cap at 200 per hop
        if not candidates:
            log.debug("Hop %d: no new addresses to explore.", hop)
            break

        log.info("Hop %d: analyzing %d candidate address(es)...", hop, len(candidates))
        next_cp: set[str] = set()

        sanction_w = {1: WEIGHTS["sanctioned_hop1"],
                      2: WEIGHTS["sanctioned_hop2"],
                      3: WEIGHTS["sanctioned_hop3"]}.get(hop, 10)
        high_w     = WEIGHTS["high_risk_hop1"] if hop == 1 else 0

        for idx, addr in enumerate(candidates, 1):
            visited.add(addr)

            # Check the address itself
            match = db.lookup(addr)
            if match:
                label, source, tier = match
                w = sanction_w if tier == "SANCTIONED" else (
                    high_w if tier == "HIGH_RISK" else 0
                )
                if w > 0:
                    f = HopFinding(hop=hop, address=addr, label=label,
                                   source=source, tier=tier, weight=w)
                    if addr not in findings or w > findings[addr].weight:
                        findings[addr] = f
                continue   # Known bad — no need to fetch its transactions

            # Fetch counterparties for the next hop
            if hop < depth:
                time.sleep(config.REQUEST_DELAY)
                addr_txs = api.get_transactions_slim(addr)
                addr_cp  = _counterparties(addr, addr_txs)
                next_cp.update(addr_cp)

                # Check if any of those counterparties are in our database
                for cp in addr_cp:
                    if cp in visited:
                        continue
                    cp_match = db.lookup(cp)
                    if not cp_match:
                        continue
                    cp_label, cp_source, cp_tier = cp_match
                    next_hop = hop + 1
                    w = {1: WEIGHTS["sanctioned_hop1"],
                         2: WEIGHTS["sanctioned_hop2"],
                         3: WEIGHTS["sanctioned_hop3"]}.get(next_hop, 10) \
                        if cp_tier == "SANCTIONED" else (
                        WEIGHTS["high_risk_hop1"] if cp_tier == "HIGH_RISK" and next_hop == 1 else 0
                    )
                    if w > 0:
                        f = HopFinding(hop=next_hop, address=cp, label=cp_label,
                                       source=cp_source, tier=cp_tier, weight=w)
                        if cp not in findings or w > findings[cp].weight:
                            findings[cp] = f

            if idx % 50 == 0:
                log.info("  Hop %d progress: %d / %d addresses checked...", hop, idx, len(candidates))

        current_cp = next_cp

    return sorted(findings.values(), key=lambda f: (f.weight, -f.hop), reverse=True)


def analyze_behavior(address: str, transactions: list[dict]) -> list[BehaviorFinding]:
    """
    Detect AML-relevant behavioral patterns in a wallet's transaction history.

    Patterns detected:
      - Rapid transaction burst (bot / automated layering)
      - Structuring / smurfing (transactions just below monitoring thresholds)
      - Layering fan-out (rapid fund distribution to many addresses)
      - New wallet with high volume
      - Dormant-then-active pattern

    :param address:      Wallet address being analyzed.
    :param transactions: Full transaction list.
    :returns: List of BehaviorFinding objects.
    """
    addr_lower = address.lower()
    findings:  list[BehaviorFinding] = []

    if not transactions:
        return findings

    timestamps:       list[int] = []
    outgoing_values:  list[int] = []

    for tx in transactions:
        try:
            timestamps.append(int(tx["timeStamp"]))
        except (KeyError, ValueError, TypeError):
            pass
        if tx.get("from", "").lower() == addr_lower:
            try:
                outgoing_values.append(int(tx.get("value", 0)))
            except (ValueError, TypeError):
                pass

    # ── Pattern 1: Rapid Transaction Burst ────────────────────────────────────
    if len(timestamps) >= 10:
        sorted_ts = sorted(timestamps, reverse=True)
        for i in range(len(sorted_ts) - 9):
            window = sorted_ts[i] - sorted_ts[i + 9]
            if window <= 60:
                findings.append(BehaviorFinding(
                    pattern_type = "RAPID_TRANSACTION_BURST",
                    description  = (
                        f"10+ transactions within a {window}-second window detected. "
                        "Consistent with automated layering or bot activity."
                    ),
                    severity = "HIGH",
                    weight   = WEIGHTS["rapid_transaction_burst"],
                ))
                break

    # ── Pattern 2: Structuring (Smurfing) ─────────────────────────────────────
    # Many outgoing transactions in the 0.8–0.99 ETH band
    if outgoing_values:
        band_low  = int(0.80 * 1e18)
        band_high = int(0.99 * 1e18)
        structured = [v for v in outgoing_values if band_low <= v <= band_high]
        if len(structured) >= 5:
            findings.append(BehaviorFinding(
                pattern_type = "STRUCTURING_PATTERN",
                description  = (
                    f"{len(structured)} outgoing transactions in the 0.80–0.99 ETH range. "
                    "Consistent with structuring (smurfing) to avoid detection thresholds."
                ),
                severity = "HIGH",
                weight   = WEIGHTS["structuring_pattern"],
            ))

    # ── Pattern 3: Layering Fan-Out ────────────────────────────────────────────
    recent_outgoing = [
        tx for tx in sorted(transactions, key=lambda x: int(x.get("timeStamp", 0)), reverse=True)[:50]
        if tx.get("from", "").lower() == addr_lower
    ]
    destinations = {tx.get("to", "").lower() for tx in recent_outgoing}
    if len(destinations) >= 15:
        findings.append(BehaviorFinding(
            pattern_type = "LAYERING_FAN_OUT",
            description  = (
                f"Funds sent to {len(destinations)} unique addresses in the last 50 transactions. "
                "Consistent with layering (rapid fund distribution to obscure origin)."
            ),
            severity = "HIGH",
            weight   = WEIGHTS["layering_fan_out"],
        ))

    # ── Pattern 4: New Wallet with High Volume ────────────────────────────────
    if timestamps:
        age_days       = (time.time() - min(timestamps)) / 86400
        total_outgoing = sum(outgoing_values)
        if age_days < 30 and total_outgoing > 5e18:
            findings.append(BehaviorFinding(
                pattern_type = "NEW_WALLET_HIGH_VOLUME",
                description  = (
                    f"Wallet is {age_days:.0f} days old and has moved "
                    f"{total_outgoing / 1e18:.2f} ETH outbound. "
                    "Unusual volume for a new wallet."
                ),
                severity = "MEDIUM",
                weight   = WEIGHTS["new_wallet_high_volume"],
            ))

    # ── Pattern 5: Dormant-Then-Active ────────────────────────────────────────
    if len(timestamps) >= 2:
        sorted_ts  = sorted(timestamps)
        gaps       = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
        max_gap    = max(gaps) / 86400
        last_tx_age = (time.time() - sorted_ts[-1]) / 86400
        if max_gap > 365 and last_tx_age < 90:
            findings.append(BehaviorFinding(
                pattern_type = "DORMANT_THEN_ACTIVE",
                description  = (
                    f"Wallet was inactive for {max_gap:.0f} days and became active "
                    f"within the last {last_tx_age:.0f} days. "
                    "Often associated with reactivation of laundering infrastructure."
                ),
                severity = "MEDIUM",
                weight   = WEIGHTS["dormant_then_active"],
            ))

    return findings


def compute_score(result: AnalysisResult) -> int:
    """
    Aggregate all findings into a single 0–100 risk score.

    :param result: AnalysisResult containing all sub-analysis findings.
    :returns: Integer risk score clamped to [0, 100].
    """
    score = 0

    for f in result.direct_findings:
        score += f.weight

    for f in result.hop_findings:
        score += f.weight

    for f in result.behavior_findings:
        score += f.weight

    if result.metadata.is_very_established:
        score += WEIGHTS["very_established_wallet"]
    elif result.metadata.is_established:
        score += WEIGHTS["established_wallet"]

    return max(0, min(100, score))


def verdict_from_score(score: int) -> str:
    """
    Map a numeric risk score to a verdict string.

    :param score: Integer risk score (0–100).
    :returns: One of: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    """
    if score >= config.THRESHOLD_CRITICAL: return "CRITICAL"
    if score >= config.THRESHOLD_HIGH:     return "HIGH"
    if score >= config.THRESHOLD_MEDIUM:   return "MEDIUM"
    return "LOW"


def run(address: str) -> AnalysisResult:
    """
    Execute the full analysis pipeline for a single wallet address.

    Steps:
      1. Fetch ETH balance
      2. Fetch transaction history
      3. Compute wallet metadata
      4. Run direct sanctions screening
      5. Run multi-hop graph analysis
      6. Run behavioral pattern analysis
      7. Compute final risk score and verdict

    :param address: Ethereum wallet address to analyze.
    :returns: Fully populated AnalysisResult.
    """
    address = address.lower()
    log.info("Starting analysis for %s", address)

    log.info("[1/5] Fetching ETH balance...")
    balance = api.get_balance(address)

    log.info("[2/5] Fetching transaction history (up to %d txs)...", config.MAX_TX_PAGES * 10000)
    transactions = api.get_transactions(address)
    log.info("      %d transaction(s) fetched.", len(transactions))

    log.info("[3/5] Computing wallet metadata...")
    metadata = compute_metadata(address, transactions)

    log.info("[4/5] Running direct sanctions screening...")
    direct = screen_direct(address, transactions)
    log.info("      %d direct match(es) found.", len(direct))

    log.info("[5/5] Running multi-hop graph analysis (%d hops)...", config.HOP_DEPTH)
    hops = analyze_hops(address, transactions)
    log.info("      %d indirect connection(s) found.", len(hops))

    log.info("[5/5] Running behavioral pattern analysis...")
    behavior = analyze_behavior(address, transactions)
    log.info("      %d behavioral flag(s) detected.", len(behavior))

    result = AnalysisResult(
        address           = address,
        balance           = balance,
        metadata          = metadata,
        direct_findings   = direct,
        hop_findings      = hops,
        behavior_findings = behavior,
    )
    result.risk_score = compute_score(result)
    result.verdict    = verdict_from_score(result.risk_score)

    log.info("Analysis complete. Score: %d/100 | Verdict: %s", result.risk_score, result.verdict)
    return result
