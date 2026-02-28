"""
cryptoshield/reporter.py
~~~~~~~~~~~~~~~~~~~~~~~~
Report rendering — terminal output and JSON export.

Takes an AnalysisResult and renders it.
No analysis logic lives here.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from colorama import Fore, Style, init

from cryptoshield import config
from cryptoshield.analyzer import AnalysisResult
from cryptoshield.logger import get_logger

init(autoreset=True)
log = get_logger(__name__)


# ── Terminal helpers ──────────────────────────────────────────────────────────

def _section(title: str) -> None:
    pad = max(1, 54 - len(title))
    print(f"\n{Fore.CYAN}  ┌─ {title} {'─' * pad}┐{Style.RESET_ALL}")


def _section_end() -> None:
    print(f"{Fore.CYAN}  └{'─' * 58}┘{Style.RESET_ALL}")


def _row(label: str, value: str, color: str = "") -> None:
    label_str = f"  │  {Fore.WHITE}{label:<28}{Style.RESET_ALL}"
    value_str = f"{color}{value}{Style.RESET_ALL}" if color else value
    print(f"{label_str}: {value_str}")


def _wrap(text: str, width: int = 68, prefix: str = "  │     ") -> None:
    """Print text wrapped at `width` characters with `prefix` on each line."""
    words, line = text.split(), ""
    for word in words:
        if len(line) + len(word) + 1 > width:
            print(f"{prefix}{line}")
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        print(f"{prefix}{line}")


# ── Banner ────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Print the CryptoShield application banner."""
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║        CryptoShield Intelligence Platform v2.0.0             ║
║        Professional Wallet Risk Analysis Engine              ║
╠══════════════════════════════════════════════════════════════╣
║  Sanctions: OFAC SDN · EU Consolidated · UN Security Council ║
║  Analysis:  Multi-Hop Graph · Behavioral · AML Patterns      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


# ── Terminal report ───────────────────────────────────────────────────────────

def print_report(result: AnalysisResult) -> None:
    """
    Render a full formatted risk report to the terminal.

    :param result: Completed AnalysisResult from the analyzer.
    """
    score   = result.risk_score
    verdict = result.verdict

    # Verdict styling
    if verdict == "CRITICAL":
        color, icon = Fore.RED,    "🔴"
        action = (
            "IMMEDIATE ACTION REQUIRED — Block all transactions.\n"
            "  │     File a Suspicious Activity Report (SAR) with your compliance team.\n"
            "  │     Do not process funds until a full manual review is complete.\n"
            "  │     Consider filing a report with FinCEN (US) or your national FIU."
        )
    elif verdict == "HIGH":
        color, icon = Fore.RED,    "🔴"
        action = (
            "Suspend account pending enhanced due diligence (EDD).\n"
            "  │     Request full KYC documentation and source-of-funds evidence.\n"
            "  │     Monitor all future transactions with elevated scrutiny."
        )
    elif verdict == "MEDIUM":
        color, icon = Fore.YELLOW, "🟡"
        action = (
            "Flag for enhanced due diligence.\n"
            "  │     Request source-of-funds documentation.\n"
            "  │     Apply transaction limits until review is complete."
        )
    else:
        color, icon = Fore.GREEN,  "🟢"
        action = (
            "No immediate action required.\n"
            "  │     Continue standard transaction monitoring per your AML policy."
        )

    fill      = int(score / 5)
    score_bar = f"[{'█' * fill}{'░' * (20 - fill)}]"

    # ── Header ─────────────────────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}  ╔{'═' * 58}╗")
    print(f"  ║{'CRYPTOSHIELD WALLET INTELLIGENCE REPORT':^58}║")
    print(f"  ╚{'═' * 58}╝{Style.RESET_ALL}")

    # ── Identity ───────────────────────────────────────────────────────────────
    _section("WALLET IDENTITY")
    _row("Address",       result.address)
    _row("ETH Balance",   result.balance)
    _row("Analysis Date", datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    _section_end()

    # ── Overview ───────────────────────────────────────────────────────────────
    _section("ACTIVITY OVERVIEW")
    m = result.metadata
    _row("Transactions Analyzed",  f"{m.tx_count:,}")
    _row("First Activity",         m.first_seen)
    _row("Last Activity",          m.last_seen)
    _row("Wallet Age",             f"{m.wallet_age_days} days")
    _row("Outgoing Volume",        m.outgoing_volume_eth)
    _row("Unique Counterparties",  f"{m.counterparty_count:,}")
    _section_end()

    # ── Score ──────────────────────────────────────────────────────────────────
    _section("RISK ASSESSMENT")
    print(f"\n  │  {color}{icon}  VERDICT : {verdict}{Style.RESET_ALL}")
    print(f"  │  {color}Risk Score: {score:>3} / 100  {score_bar}{Style.RESET_ALL}\n")
    _section_end()

    # ── Direct findings ────────────────────────────────────────────────────────
    _section("DIRECT SANCTIONS SCREENING")
    if result.direct_findings:
        for f in result.direct_findings[:10]:
            fc = Fore.RED if f.tier == "SANCTIONED" else Fore.YELLOW
            print(f"  │  {fc}✖  {f.tier:<12} {f.label:<34} [{f.source}]{Style.RESET_ALL}")
            print(f"  │     Address : {f.counterparty}")
            if f.timestamp:
                dt = datetime.fromtimestamp(f.timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
                print(f"  │     Date    : {dt}")
            print(f"  │     Tx Hash : {f.tx_hash[:20]}...")
            print("  │")
        if len(result.direct_findings) > 10:
            print(f"  │  {Fore.YELLOW}  + {len(result.direct_findings) - 10} more (see JSON export){Style.RESET_ALL}")
    else:
        print(f"  │  {Fore.GREEN}✔  No direct matches with sanctioned or high-risk addresses.{Style.RESET_ALL}")
    _section_end()

    # ── Hop findings ───────────────────────────────────────────────────────────
    _section(f"MULTI-HOP GRAPH ANALYSIS  (depth: {config.HOP_DEPTH} hops)")
    if result.hop_findings:
        for f in result.hop_findings[:10]:
            fc = Fore.RED if f.tier == "SANCTIONED" else Fore.YELLOW
            print(f"  │  {fc}⚠  HOP {f.hop}  {f.tier:<12} {f.label:<26} [{f.source}]{Style.RESET_ALL}")
            print(f"  │     Address: {f.address}")
            print("  │")
        if len(result.hop_findings) > 10:
            print(f"  │  {Fore.YELLOW}  + {len(result.hop_findings) - 10} more indirect connections (see JSON export){Style.RESET_ALL}")
    else:
        print(f"  │  {Fore.GREEN}✔  No indirect connections found within {config.HOP_DEPTH} hops.{Style.RESET_ALL}")
    _section_end()

    # ── Behavioral ─────────────────────────────────────────────────────────────
    _section("BEHAVIORAL PATTERN ANALYSIS")
    if result.behavior_findings:
        for f in result.behavior_findings:
            fc = Fore.RED if f.severity == "HIGH" else Fore.YELLOW
            print(f"  │  {fc}⚠  [{f.severity}] {f.pattern_type}{Style.RESET_ALL}")
            _wrap(f.description)
            print("  │")
    else:
        print(f"  │  {Fore.GREEN}✔  No suspicious behavioral patterns detected.{Style.RESET_ALL}")
    _section_end()

    # ── Recommendation ─────────────────────────────────────────────────────────
    _section("COMPLIANCE RECOMMENDATION")
    print(f"  │  {color}{action}{Style.RESET_ALL}")
    _section_end()

    # ── Disclaimer ─────────────────────────────────────────────────────────────
    print(f"\n  {Fore.WHITE}{'─' * 60}")
    print( "  DISCLAIMER: This report is generated by automated analysis")
    print( "  and is intended as a decision-support tool only. It does")
    print( "  not constitute legal advice. Final compliance decisions")
    print(f"  must be reviewed by a qualified AML/compliance professional.{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")


# ── JSON export ───────────────────────────────────────────────────────────────

def export_json(result: AnalysisResult) -> str:
    """
    Export a complete machine-readable JSON report to disk.

    :param result: Completed AnalysisResult.
    :returns: The filename of the exported report.
    """
    report = {
        "report_metadata": {
            "generated_at":    datetime.now(tz=timezone.utc).isoformat(),
            "engine_version":  "2.0.0",
            "chain":           "Ethereum Mainnet",
            "analysis_depth":  f"{config.HOP_DEPTH} hops",
            "disclaimer":      (
                "This report is generated by automated analysis and is intended "
                "as a decision-support tool only. It does not constitute legal advice."
            ),
        },
        "wallet": {
            "address":              result.address,
            "eth_balance":          result.balance,
            "tx_count":             result.metadata.tx_count,
            "first_seen":           result.metadata.first_seen,
            "last_seen":            result.metadata.last_seen,
            "wallet_age_days":      result.metadata.wallet_age_days,
            "outgoing_volume_eth":  result.metadata.outgoing_volume_eth,
            "counterparty_count":   result.metadata.counterparty_count,
        },
        "risk": {
            "score":   result.risk_score,
            "verdict": result.verdict,
        },
        "findings": {
            "direct_sanctions": [
                {
                    "counterparty": f.counterparty,
                    "label":        f.label,
                    "source":       f.source,
                    "tier":         f.tier,
                    "weight":       f.weight,
                    "tx_hash":      f.tx_hash,
                    "timestamp":    f.timestamp,
                }
                for f in result.direct_findings
            ],
            "indirect_connections": [
                {
                    "hop":     f.hop,
                    "address": f.address,
                    "label":   f.label,
                    "source":  f.source,
                    "tier":    f.tier,
                    "weight":  f.weight,
                }
                for f in result.hop_findings
            ],
            "behavioral_patterns": [
                {
                    "pattern_type": f.pattern_type,
                    "description":  f.description,
                    "severity":     f.severity,
                    "weight":       f.weight,
                }
                for f in result.behavior_findings
            ],
        },
    }

    filename = (
        f"report_{result.address[:10]}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    log.info("Report exported to %s", filename)
    return filename
