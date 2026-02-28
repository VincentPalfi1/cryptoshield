"""
tests/test_analyzer.py
~~~~~~~~~~~~~~~~~~~~~~
Unit tests for the core analysis engine.

Tests are isolated from the Etherscan API — all API calls are mocked.
Run with:  pytest tests/ -v
"""

import pytest
from unittest.mock import patch

from cryptoshield.analyzer import (
    compute_metadata,
    screen_direct,
    analyze_behavior,
    compute_score,
    verdict_from_score,
    AnalysisResult,
    WalletMetadata,
    WEIGHTS,
)
from cryptoshield import config


# ── Fixtures ──────────────────────────────────────────────────────────────────

TORNADO_CASH_ROUTER = "0x722122df12d4e14e13ac3b6895a86e84145b6967"
TEST_WALLET         = "0xaabbccdd00112233445566778899aabbccddee00"
SAFE_WALLET         = "0x1234567890abcdef1234567890abcdef12345678"

NOW_TS = 1_700_000_000   # Fixed timestamp for deterministic tests


def make_tx(from_addr: str, to_addr: str, value_wei: int = 0,
            timestamp: int = NOW_TS, tx_hash: str = "0xdeadbeef") -> dict:
    """Helper: create a minimal transaction dict."""
    return {
        "from":      from_addr,
        "to":        to_addr,
        "value":     str(value_wei),
        "timeStamp": str(timestamp),
        "hash":      tx_hash,
    }


# ── compute_metadata ──────────────────────────────────────────────────────────

class TestComputeMetadata:

    def test_empty_transactions_returns_defaults(self):
        meta = compute_metadata(TEST_WALLET, [])
        assert meta.tx_count             == 0
        assert meta.first_seen           == "N/A"
        assert meta.outgoing_volume_eth  == "0.0000 ETH"
        assert meta.is_established       is False

    def test_counts_transactions(self):
        txs  = [make_tx(TEST_WALLET, SAFE_WALLET, timestamp=NOW_TS + i) for i in range(10)]
        meta = compute_metadata(TEST_WALLET, txs)
        assert meta.tx_count == 10

    def test_outgoing_volume_sums_only_outgoing(self):
        txs = [
            make_tx(TEST_WALLET, SAFE_WALLET,  value_wei=int(2e18)),  # outgoing
            make_tx(SAFE_WALLET, TEST_WALLET,  value_wei=int(5e18)),  # incoming — should not count
        ]
        meta = compute_metadata(TEST_WALLET, txs)
        assert meta.outgoing_volume_eth == "2.0000 ETH"

    def test_counterparty_count_deduplicates(self):
        txs = [
            make_tx(TEST_WALLET, SAFE_WALLET),
            make_tx(TEST_WALLET, SAFE_WALLET),   # same counterparty twice
            make_tx(SAFE_WALLET, TEST_WALLET),
        ]
        meta = compute_metadata(TEST_WALLET, txs)
        assert meta.counterparty_count == 1

    def test_wallet_not_established_with_few_transactions(self):
        txs  = [make_tx(TEST_WALLET, SAFE_WALLET) for _ in range(10)]
        meta = compute_metadata(TEST_WALLET, txs)
        assert meta.is_established is False


# ── screen_direct ─────────────────────────────────────────────────────────────

class TestScreenDirect:

    def test_detects_sanctioned_address(self):
        txs     = [make_tx(TEST_WALLET, TORNADO_CASH_ROUTER)]
        results = screen_direct(TEST_WALLET, txs)
        assert len(results) == 1
        assert results[0].tier   == "SANCTIONED"
        assert results[0].weight == WEIGHTS["sanctioned_direct"]

    def test_no_findings_for_clean_wallet(self):
        txs     = [make_tx(TEST_WALLET, SAFE_WALLET)]
        results = screen_direct(TEST_WALLET, txs)
        assert results == []

    def test_deduplicates_same_counterparty(self):
        txs = [
            make_tx(TEST_WALLET, TORNADO_CASH_ROUTER, tx_hash="0xaaa"),
            make_tx(TEST_WALLET, TORNADO_CASH_ROUTER, tx_hash="0xbbb"),
        ]
        results = screen_direct(TEST_WALLET, txs)
        # Should be deduplicated to one finding
        assert len(results) == 1

    def test_ignores_self_transactions(self):
        txs     = [make_tx(TEST_WALLET, TEST_WALLET)]
        results = screen_direct(TEST_WALLET, txs)
        assert results == []

    def test_detects_incoming_sanctioned_tx(self):
        """Funds received from a sanctioned address are also flagged."""
        txs     = [make_tx(TORNADO_CASH_ROUTER, TEST_WALLET)]
        results = screen_direct(TEST_WALLET, txs)
        assert len(results) == 1
        assert results[0].tier == "SANCTIONED"


# ── analyze_behavior ──────────────────────────────────────────────────────────

class TestAnalyzeBehavior:

    def test_no_findings_for_normal_wallet(self):
        txs = [
            make_tx(TEST_WALLET, SAFE_WALLET, timestamp=NOW_TS + i * 3600)
            for i in range(5)
        ]
        findings = analyze_behavior(TEST_WALLET, txs)
        assert findings == []

    def test_detects_rapid_burst(self):
        """10 transactions within 30 seconds should trigger RAPID_TRANSACTION_BURST."""
        txs = [
            make_tx(TEST_WALLET, SAFE_WALLET, timestamp=NOW_TS + i)
            for i in range(10)
        ]
        findings = analyze_behavior(TEST_WALLET, txs)
        types = {f.pattern_type for f in findings}
        assert "RAPID_TRANSACTION_BURST" in types

    def test_detects_structuring(self):
        """5+ outgoing txs in 0.8–0.99 ETH band should trigger STRUCTURING_PATTERN."""
        band_value = int(0.90 * 1e18)
        txs = [
            make_tx(TEST_WALLET, SAFE_WALLET,
                    value_wei=band_value,
                    timestamp=NOW_TS + i * 3600)
            for i in range(6)
        ]
        findings = analyze_behavior(TEST_WALLET, txs)
        types = {f.pattern_type for f in findings}
        assert "STRUCTURING_PATTERN" in types

    def test_empty_transactions_returns_no_findings(self):
        findings = analyze_behavior(TEST_WALLET, [])
        assert findings == []


# ── compute_score ─────────────────────────────────────────────────────────────

class TestComputeScore:

    def _empty_result(self) -> AnalysisResult:
        return AnalysisResult(
            address  = TEST_WALLET,
            balance  = "0.0000 ETH",
            metadata = WalletMetadata(
                tx_count=0, first_seen="N/A", last_seen="N/A",
                wallet_age_days=0, outgoing_volume_eth="0.0000 ETH",
                counterparty_count=0, is_established=False, is_very_established=False,
            ),
        )

    def test_clean_wallet_scores_zero(self):
        result = self._empty_result()
        assert compute_score(result) == 0

    def test_score_clamped_at_100(self):
        """Multiple high-weight findings should not exceed 100."""
        from cryptoshield.analyzer import DirectFinding
        result = self._empty_result()
        # Add many max-weight direct findings
        result.direct_findings = [
            DirectFinding(
                counterparty=f"0x{'a' * 40}",
                label="Test", source="TEST", tier="SANCTIONED",
                weight=WEIGHTS["sanctioned_direct"],
                tx_hash="0x1", timestamp=0,
            )
            for _ in range(10)
        ]
        assert compute_score(result) == 100

    def test_score_clamped_at_zero(self):
        """Score should never go negative."""
        result = self._empty_result()
        result.metadata = WalletMetadata(
            tx_count=5000, first_seen="N/A", last_seen="N/A",
            wallet_age_days=1000, outgoing_volume_eth="0.0000 ETH",
            counterparty_count=0, is_established=True, is_very_established=True,
        )
        assert compute_score(result) >= 0


# ── verdict_from_score ────────────────────────────────────────────────────────

class TestVerdictFromScore:

    def test_low_verdict(self):
        assert verdict_from_score(0)  == "LOW"
        assert verdict_from_score(29) == "LOW"

    def test_medium_verdict(self):
        assert verdict_from_score(config.THRESHOLD_MEDIUM)  == "MEDIUM"
        assert verdict_from_score(config.THRESHOLD_HIGH - 1) == "MEDIUM"

    def test_high_verdict(self):
        assert verdict_from_score(config.THRESHOLD_HIGH)    == "HIGH"
        assert verdict_from_score(config.THRESHOLD_CRITICAL - 1) == "HIGH"

    def test_critical_verdict(self):
        assert verdict_from_score(config.THRESHOLD_CRITICAL) == "CRITICAL"
        assert verdict_from_score(100) == "CRITICAL"
