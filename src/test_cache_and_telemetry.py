"""
Tests for ContractSourceResolver in-memory cache and structured 1-line telemetry logging.

Covers:
1. ContractSourceResolver in-memory cache (src/source_resolver.py):
   - Cache hit avoids duplicate HTTP calls
   - Address normalization (checksum vs lowercase)
   - Chain isolation (same address across different chain IDs)
   - Copy safety / immutability of cached results
   - TTL expiration via monkeypatched time.monotonic
   - Disabled cache (ttl=0 or max_entries=0)
   - Bounded FIFO eviction
   - Unverified / transient errors are not cached
2. Structured 1-line telemetry logging (src/x402_payment.py & src/api.py):
   - build_402_response logs TELEMETRY | event=x402_probe ...
   - POST /mcp logs TELEMETRY | event=mcp_tool_call and event=mcp_rpc (single & batch)
   - _log_mcp_telemetry safely handles non-dict inputs and missing/invalid params
   - Settled x402 POST /preflight logs TELEMETRY | event=x402_settled without leaking secrets
"""

import json
import logging
import os
import sys
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock

import httpx
import pytest
from eth_account import Account
from fastapi.testclient import TestClient
from web3 import Web3

# Ensure project root and src are on sys.path
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = (
    os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
    if os.path.basename(_CURRENT_DIR) == "src"
    else _CURRENT_DIR
)
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from src.api import _log_mcp_telemetry, create_app
from src.engine import ConditionAgentEngine
from src.semantic_evaluator import MockSemanticEvaluator
from src.source_resolver import ContractSourceResolver
from src.storage import AgentStorage
from src.x402_payment import (
    MockX402Facilitator,
    X402Config,
    build_402_response,
    usdc_to_atomic,
)

ADDR_A = "0x1111111111111111111111111111111111111111"
ADDR_B = "0x2222222222222222222222222222222222222222"
ADDR_C = "0x3333333333333333333333333333333333333333"
# Mixed-case EIP-55 checksum address (has both upper and lower hex letters)
ADDR_MIXED = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"


def _make_sourcify_response(contract_name: str = "DemoVault") -> httpx.Response:
    """Build a mock HTTP 200 Sourcify response containing one Solidity file."""
    payload = {
        "status": "full",
        "files": [
            {
                "name": f"contracts/{contract_name}.sol",
                "content": f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract {contract_name} {{}}\n",
            }
        ],
    }
    return httpx.Response(status_code=200, json=payload)


# =====================================================================
# 1. ContractSourceResolver In-Memory Cache Tests
# =====================================================================


class TestContractSourceResolverCache:
    """Tests for ContractSourceResolver._source_cache behavior."""

    @pytest.mark.asyncio
    async def test_cache_hit_avoids_duplicate_http_calls(self):
        resolver = ContractSourceResolver()
        mock_get = AsyncMock(return_value=_make_sourcify_response("VaultOne"))
        resolver._get_request = mock_get  # type: ignore[method-assign]

        res1 = await resolver.fetch_verified_source(8453, ADDR_A)
        res2 = await resolver.fetch_verified_source(8453, ADDR_A)

        assert res1["verified"] is True
        assert res1["provider"] == "sourcify"
        assert res2 == res1
        assert mock_get.await_count == 1

    @pytest.mark.asyncio
    async def test_address_normalization_shares_cache_entry(self):
        resolver = ContractSourceResolver()
        mock_get = AsyncMock(return_value=_make_sourcify_response("NormContract"))
        resolver._get_request = mock_get  # type: ignore[method-assign]

        checksum_addr = Web3.to_checksum_address(ADDR_MIXED)
        lower_addr = ADDR_MIXED.lower()
        assert checksum_addr != lower_addr

        res1 = await resolver.fetch_verified_source(8453, checksum_addr)
        res2 = await resolver.fetch_verified_source(8453, lower_addr)

        assert res1["verified"] is True
        assert res2["verified"] is True
        assert res1["contract_names"] == ["NormContract"]
        assert res2["contract_names"] == ["NormContract"]
        assert mock_get.await_count == 1
        assert len(resolver._source_cache) == 1

    @pytest.mark.asyncio
    async def test_chain_isolation_caches_per_chain_id(self):
        resolver = ContractSourceResolver()

        async def _side_effect(url: str, params: Optional[Dict[str, Any]] = None) -> httpx.Response:
            if "/8453/" in url:
                return _make_sourcify_response("BaseContract")
            return _make_sourcify_response("MainnetContract")

        mock_get = AsyncMock(side_effect=_side_effect)
        resolver._get_request = mock_get  # type: ignore[method-assign]

        res_base = await resolver.fetch_verified_source(8453, ADDR_A)
        res_eth = await resolver.fetch_verified_source(1, ADDR_A)
        # Repeat both to verify cache hits on each chain
        res_base_2 = await resolver.fetch_verified_source(8453, ADDR_A)
        res_eth_2 = await resolver.fetch_verified_source(1, ADDR_A)

        assert res_base["contract_names"] == ["BaseContract"]
        assert res_eth["contract_names"] == ["MainnetContract"]
        assert res_base_2["contract_names"] == ["BaseContract"]
        assert res_eth_2["contract_names"] == ["MainnetContract"]
        assert mock_get.await_count == 2
        assert len(resolver._source_cache) == 2

    @pytest.mark.asyncio
    async def test_copy_safety_mutating_result_does_not_corrupt_cache(self):
        resolver = ContractSourceResolver()
        mock_get = AsyncMock(return_value=_make_sourcify_response("SafeContract"))
        resolver._get_request = mock_get  # type: ignore[method-assign]

        res1 = await resolver.fetch_verified_source(8453, ADDR_A)
        res1["contract_names"].append("Evil")
        res1["verified"] = False

        res2 = await resolver.fetch_verified_source(8453, ADDR_A)

        assert res2["verified"] is True
        assert "Evil" not in res2["contract_names"]
        assert res2["contract_names"] == ["SafeContract"]
        assert mock_get.await_count == 1

    @pytest.mark.asyncio
    async def test_ttl_expiration_triggers_fresh_fetch(self, monkeypatch):
        now = [100.0]
        monkeypatch.setattr("src.source_resolver.time.monotonic", lambda: now[0])

        resolver = ContractSourceResolver(source_cache_ttl_seconds=60.0)
        mock_get = AsyncMock(return_value=_make_sourcify_response("TtlContract"))
        resolver._get_request = mock_get  # type: ignore[method-assign]

        await resolver.fetch_verified_source(8453, ADDR_A)
        assert mock_get.await_count == 1

        # Still valid just before TTL expires
        now[0] = 159.0
        await resolver.fetch_verified_source(8453, ADDR_A)
        assert mock_get.await_count == 1

        # Past TTL -> expired, must refetch
        now[0] = 160.5
        await resolver.fetch_verified_source(8453, ADDR_A)
        assert mock_get.await_count == 2

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "ttl,max_entries",
        [
            (0.0, 512),
            (3600.0, 0),
        ],
    )
    async def test_disabled_cache_does_not_store_entries(self, ttl: float, max_entries: int):
        resolver = ContractSourceResolver(
            source_cache_ttl_seconds=ttl,
            source_cache_max_entries=max_entries,
        )
        mock_get = AsyncMock(return_value=_make_sourcify_response("UncachedContract"))
        resolver._get_request = mock_get  # type: ignore[method-assign]

        await resolver.fetch_verified_source(8453, ADDR_A)
        await resolver.fetch_verified_source(8453, ADDR_A)

        assert mock_get.await_count == 2
        assert len(resolver._source_cache) == 0

    @pytest.mark.asyncio
    async def test_bounded_fifo_eviction(self):
        resolver = ContractSourceResolver(source_cache_max_entries=2)
        mock_get = AsyncMock(return_value=_make_sourcify_response("BoundedContract"))
        resolver._get_request = mock_get  # type: ignore[method-assign]

        await resolver.fetch_verified_source(8453, ADDR_A)
        await resolver.fetch_verified_source(8453, ADDR_B)
        await resolver.fetch_verified_source(8453, ADDR_C)

        assert mock_get.await_count == 3
        assert len(resolver._source_cache) == 2

        # 2nd and 3rd entries remain cached
        await resolver.fetch_verified_source(8453, ADDR_B)
        await resolver.fetch_verified_source(8453, ADDR_C)
        assert mock_get.await_count == 3

        # 1st entry was evicted, so fetching it triggers HTTP
        await resolver.fetch_verified_source(8453, ADDR_A)
        assert mock_get.await_count == 4

    @pytest.mark.asyncio
    async def test_unverified_and_transient_errors_not_cached(self, monkeypatch):
        # Ensure no Etherscan API keys interfere with fallback
        for key in ("ETHERSCAN_API_KEY", "ETHERSCAN_API_KEY_8453", "BASESCAN_API_KEY"):
            monkeypatch.delenv(key, raising=False)

        resolver = ContractSourceResolver()
        mock_get = AsyncMock(
            side_effect=[
                httpx.Response(status_code=404),
                None,
                _make_sourcify_response("RecoveredContract"),
            ]
        )
        resolver._get_request = mock_get  # type: ignore[method-assign]

        res_404 = await resolver.fetch_verified_source(8453, ADDR_A)
        assert res_404["verified"] is False
        assert len(resolver._source_cache) == 0

        res_err = await resolver.fetch_verified_source(8453, ADDR_A)
        assert res_err["verified"] is False
        assert len(resolver._source_cache) == 0

        res_ok = await resolver.fetch_verified_source(8453, ADDR_A)
        assert res_ok["verified"] is True
        assert res_ok["contract_names"] == ["RecoveredContract"]
        assert mock_get.await_count == 3
        assert len(resolver._source_cache) == 1


# =====================================================================
# 2. Structured 1-Line Telemetry Logging Tests
# =====================================================================


@pytest.fixture
def telemetry_app_client(tmp_path):
    """Build a TestClient with x402 enabled (mock facilitator) and background scanner off."""
    db_file = str(tmp_path / "telemetry_test.db")
    storage = AgentStorage(db_path=db_file)
    engine = ConditionAgentEngine(
        semantic_evaluator=MockSemanticEvaluator(),
        storage=storage,
    )
    x402_cfg = X402Config(
        enabled=True,
        use_live_facilitator=False,
        price_per_eval_usdc=0.05,
        price_per_preflight_usdc=0.01,
        price_per_deep_audit_usdc=0.25,
        network="eip155:8453",
    )
    app = create_app(
        engine=engine,
        storage=storage,
        x402_config=x402_cfg,
        facilitator=MockX402Facilitator(),
        public_evaluate_only=True,
        enable_background_scanner=False,
    )
    return TestClient(app)


class TestStructuredTelemetryLogging:
    """Tests for 1-line TELEMETRY structured logs in x402_payment.py and api.py."""

    def test_build_402_response_logs_x402_probe(self, caplog):
        cfg = X402Config(enabled=True, network="eip155:8453")
        with caplog.at_level(logging.INFO):
            resp = build_402_response(cfg, "/audit", 0.015, reason="Payment Required")

        assert resp.status_code == 402
        probe_lines = [
            rec.getMessage()
            for rec in caplog.records
            if "TELEMETRY | event=x402_probe" in rec.getMessage()
        ]
        assert len(probe_lines) == 1
        line = probe_lines[0]
        assert "\n" not in line
        assert (
            line
            == "TELEMETRY | event=x402_probe endpoint=/audit amount_usdc=0.015 network=eip155:8453 reason='Payment Required'"
        )

    def test_mcp_tools_call_logs_mcp_tool_call(self, telemetry_app_client, caplog):
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "scan_contract_selectors",
                "arguments": {
                    "target_address": ADDR_A,
                    "chain_id": 8453,
                    "bytecode_override": "0x63a9059cbb14",
                },
            },
        }
        with caplog.at_level(logging.INFO):
            resp = telemetry_app_client.post("/mcp", json=rpc_payload)

        assert resp.status_code == 200
        assert (
            "TELEMETRY | event=mcp_tool_call method=tools/call tool=scan_contract_selectors"
            in caplog.text
        )

    def test_mcp_rpc_initialize_and_tools_list_logs(self, telemetry_app_client, caplog):
        with caplog.at_level(logging.INFO):
            r1 = telemetry_app_client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            )
            r2 = telemetry_app_client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert "TELEMETRY | event=mcp_rpc method=initialize" in caplog.text
        assert "TELEMETRY | event=mcp_rpc method=tools/list" in caplog.text

    def test_mcp_batch_jsonrpc_logs_each_item(self, telemetry_app_client, caplog):
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "scan_contract_selectors",
                    "arguments": {
                        "target_address": ADDR_A,
                        "chain_id": 8453,
                        "bytecode_override": "0x63a9059cbb14",
                    },
                },
            },
        ]
        with caplog.at_level(logging.INFO):
            resp = telemetry_app_client.post("/mcp", json=batch)

        assert resp.status_code == 200
        assert "TELEMETRY | event=mcp_rpc method=initialize" in caplog.text
        assert "TELEMETRY | event=mcp_rpc method=tools/list" in caplog.text
        assert (
            "TELEMETRY | event=mcp_tool_call method=tools/call tool=scan_contract_selectors"
            in caplog.text
        )

    def test_log_mcp_telemetry_handles_non_dict_and_missing_params(self, caplog):
        with caplog.at_level(logging.INFO):
            # Non-dict inputs must be ignored without raising
            _log_mcp_telemetry(None)
            _log_mcp_telemetry("tools/list")
            _log_mcp_telemetry(42)
            _log_mcp_telemetry(["initialize"])

            # Missing or non-dict params on tools/call must safely default to unknown
            _log_mcp_telemetry({"method": "tools/call"})
            _log_mcp_telemetry({"method": "tools/call", "params": "invalid"})
            _log_mcp_telemetry({})

        assert "TELEMETRY | event=mcp_tool_call method=tools/call tool=unknown" in caplog.text
        assert "TELEMETRY | event=mcp_rpc method=unknown" in caplog.text

    def test_settled_x402_preflight_logs_telemetry_without_leaking_secrets(
        self, telemetry_app_client, caplog
    ):
        payer_acc = Account.create()
        secret_sig = "0xsuper_secret_eip3009_signature_do_not_log_987654321"
        secret_priv_marker = "0xPRIVATE_KEY_NEVER_LOGGED_12345"
        payment_header = json.dumps(
            {
                "payment_id": "test-telemetry-preflight-001",
                "payer_address": payer_acc.address,
                "amount_atomic": usdc_to_atomic(0.01),
                "network": "eip155:8453",
                "signature": secret_sig,
                "private_note": secret_priv_marker,
            }
        )
        body = {
            "target_address": ADDR_A,
            "calldata": "0xa9059cbb000000000000000000000000111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000f4240",
            "chain_id": 8453,
            "run_simulation": False,
        }

        with caplog.at_level(logging.INFO):
            resp = telemetry_app_client.post(
                "/preflight",
                json=body,
                headers={"X-PAYMENT": payment_header},
            )

        assert resp.status_code == 200
        settled_lines = [
            rec.getMessage()
            for rec in caplog.records
            if "TELEMETRY | event=x402_settled" in rec.getMessage()
        ]
        assert len(settled_lines) == 1
        line = settled_lines[0]
        assert "\n" not in line
        assert "TELEMETRY | event=x402_settled endpoint=/preflight amount_usdc=0.01 network=eip155:8453 tx_hash=" in line
        assert "tx_hash=none" not in line

        # Sensitive payment header / private key strings must never appear in logs
        assert payment_header not in caplog.text
        assert secret_sig not in caplog.text
        assert secret_priv_marker not in caplog.text
