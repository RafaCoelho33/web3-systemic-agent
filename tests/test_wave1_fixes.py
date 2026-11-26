"""
Wave 1 Fixes Verification Suite (tests/test_wave1_fixes.py)

Covers all 6 critical Wave 1 bugfixes and enhancements:
1. EVM bytecode SELFDESTRUCT scanner (PUSH immediate skipping & Solidity CBOR stripping).
2. OpenZeppelin v5 upgradeToAndCall(address,bytes) selector 0x4f1ef286 recognition.
3. EIP-712 token_name resolution per network ("USD Coin" on Mainnets vs "USDC" on Sepolia).
4. Bounded semantic cache hygiene (SEMANTIC_CACHE_MAX = 512, FIFO) & SQLite WAL + feed query.
5. Middleware ordering (CORS + security headers on 402/403/429), /.well-known/owners.json,
   404 without error logging on unknown /.well-known/*, and HEAD support on discovery routes.
6. MCP Remote Proxy Mode, protocolVersion negotiation, server/discover, and tiered pricing ($0.015 vs $0.25).
"""

import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from eth_account import Account
from fastapi.testclient import TestClient

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SCRIPTS_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scripts.block_contract_scanner import (
    extract_selectors_from_bytecode as scanner_extract_selectors,
    is_high_risk_signature,
)
from scripts.dex_pool_monitor import (
    analyze_bytecode_honeypot,
    has_selfdestruct_opcode,
)
from src.api import create_app
from src.mcp_server import Web3SystemicMCPServer
from src.schemas import (
    ChainId,
    ConditionRulePayload,
    DeterministicCondition,
    DeterministicResult,
    FinalAgentResponse,
    SemanticAuditResult,
    SemanticCondition,
)
from src.semantic_evaluator import (
    SEMANTIC_CACHE_MAX,
    MockSemanticEvaluator,
    _store_bounded_cache,
)
from src.source_resolver import (
    extract_selectors_from_bytecode as resolver_extract_selectors,
)
from src.storage import AgentStorage
from src.x402_payment import (
    DEFAULT_PAY_TO_ADDRESS,
    X402Config,
    build_402_response,
)


# =========================================================================
# 1. Bytecode SELFDESTRUCT Scanner & Honeypot Analyzer
# =========================================================================

class TestBytecodeSelfdestructScanner:
    """Validates accurate 0xff opcode detection skipping PUSH immediates and CBOR metadata."""

    def test_erc20_push32_and_push20_all_ff_not_flagged(self):
        """PUSH32 0xff..ff (7f + 64 f) and PUSH20 0xff..ff (73 + 40 f) must not trigger 0xff."""
        # Standard prologue + PUSH32 0xff*32 + POP + PUSH20 0xff*20 + POP + STOP
        bytecode = (
            "0x6080604052"
            + "7f" + ("ff" * 32) + "50"
            + "73" + ("ff" * 20) + "50"
            + "00"
        )
        assert has_selfdestruct_opcode(bytecode) is False

        analysis = analyze_bytecode_honeypot(bytecode)
        assert analysis["is_honeypot"] is False
        assert analysis["severity"] == "CLEAN"
        assert analysis["categories"]["destruct_drain"] == []

    def test_solidity_cbor_metadata_containing_ff_not_flagged(self):
        """Solidity CBOR suffix with 0xff inside IPFS hash must be stripped before opcode scan."""
        # CBOR map: a2 64 'ipfs' 58 22 <34-byte multihash with ff bytes> 64 'solc' 43 000814
        # Length = 8 + 34 + 9 = 51 bytes = 0x0033
        cbor_body = (
            "a264697066735822"
            + "1220" + ("ff" * 32)
            + "64736f6c6343000814"
        )
        assert len(bytes.fromhex(cbor_body)) == 0x0033
        bytecode = "0x608060405200" + cbor_body + "0033"

        assert has_selfdestruct_opcode(bytecode) is False
        assert has_selfdestruct_opcode(bytes.fromhex(bytecode[2:])) is False

    def test_real_selfdestruct_opcode_outside_push_is_critical(self):
        """Actual 0xff opcode outside PUSH operands triggers CRITICAL honeypot finding."""
        bytecode = "0x6080604052ff"
        assert has_selfdestruct_opcode(bytecode) is True

        analysis = analyze_bytecode_honeypot(bytecode)
        assert analysis["is_honeypot"] is True
        assert analysis["severity"] == "CRITICAL"
        assert any("SELFDESTRUCT" in item for item in analysis["categories"]["destruct_drain"])


# =========================================================================
# 2. OpenZeppelin v5 upgradeToAndCall (0x4f1ef286) Selector Recognition
# =========================================================================

class TestUpgradeToAndCallSelector:
    """Validates 0x4f1ef286 recognition in both source_resolver and block_contract_scanner."""

    def test_extract_selectors_recognizes_upgrade_to_and_call(self):
        # PUSH4 0x4f1ef286 EQ
        dispatcher_bytecode = "0x6080604052634f1ef28614"

        resolver_found = resolver_extract_selectors(dispatcher_bytecode)
        scanner_found = scanner_extract_selectors(dispatcher_bytecode)

        for found_list in (resolver_found, scanner_found):
            match = [s for s in found_list if s["selector"] == "0x4f1ef286"]
            assert len(match) == 1
            assert match[0]["signature"] == "upgradeToAndCall(address,bytes)"
            assert match[0]["known"] is True

        assert is_high_risk_signature("upgradeToAndCall(address,bytes)") is True


# =========================================================================
# 3. EIP-712 token_name per Network
# =========================================================================

class TestX402TokenNamePerNetwork:
    """Validates EIP-712 domain token name for Arbitrum, Base Mainnet, and Base Sepolia."""

    @pytest.mark.parametrize(
        "network,expected_name",
        [
            ("eip155:42161", "USD Coin"),
            ("eip155:8453", "USD Coin"),
            ("eip155:84532", "USDC"),
        ],
    )
    def test_build_402_response_token_name_by_network(self, network: str, expected_name: str):
        cfg = X402Config(
            enabled=True,
            network=network,
            pay_to_address="0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63",
        )
        resp = build_402_response(cfg, "/evaluate", 0.015)
        assert resp.status_code == 402
        body = json.loads(resp.body.decode("utf-8"))
        assert body["accepts"][0]["network"] == network
        assert body["accepts"][0]["extra"]["name"] == expected_name


# =========================================================================
# 4. Bounded Semantic Cache & SQLite WAL + Feed Query
# =========================================================================

class TestCacheAndStorageHygiene:
    """Validates FIFO bounded semantic cache (512) and SQLite WAL + recent feed evaluations."""

    def test_store_bounded_cache_enforces_512_fifo_limit(self):
        assert SEMANTIC_CACHE_MAX == 512
        cache: Dict[str, int] = {}

        for i in range(520):
            _store_bounded_cache(cache, f"key-{i}", i)

        assert len(cache) == 512
        # First 8 keys evicted in FIFO order
        for i in range(8):
            assert f"key-{i}" not in cache
        for i in range(8, 520):
            assert cache[f"key-{i}"] == i

        # Updating an existing key preserves size 512 without evicting oldest remaining key
        _store_bounded_cache(cache, "key-8", 9999)
        assert len(cache) == 512
        assert cache["key-8"] == 9999
        assert "key-9" in cache

    @pytest.mark.asyncio
    async def test_storage_wal_mode_and_recent_feed_evaluations_descending(self, tmp_path: Path):
        db_file = str(tmp_path / "wave1_wal_test.db")
        storage = AgentStorage(db_path=db_file)
        await storage.initialize()

        with sqlite3.connect(db_file) as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert str(mode).lower() == "wal"

        # Insert 3 evaluations sequentially
        inserted_rule_ids: List[str] = []
        for idx in range(3):
            rid = f"wave1-feed-rule-{idx}"
            inserted_rule_ids.append(rid)
            payload = ConditionRulePayload(
                rule_id=rid,
                chain_id=ChainId.BASE_MAINNET,
                deterministic=DeterministicCondition(
                    target_address="0x4200000000000000000000000000000000000006",
                ),
                semantic=SemanticCondition(
                    enabled=True,
                    policy_prompt=f"Feed evaluation #{idx}",
                ),
            )
            resp = FinalAgentResponse(
                rule_id=rid,
                chain_id=ChainId.BASE_MAINNET,
                deterministic_check=DeterministicResult(passed=True, reason="ok"),
                llm_invoked=True,
                semantic_Evaluation=SemanticAuditResult(
                    conditions_met=False,
                    risk_score=0.1 * (idx + 1),
                    summary=f"Summary {idx}",
                    recommended_action="APPROVE",
                    flagged_issues=[],
                ),
            )
            await storage.record_evaluation(payload, resp, source="api")

        feed = await storage.get_recent_feed_evaluations(limit=2)
        assert len(feed) == 2
        # Descending order by id (newest first)
        assert feed[0]["rule_id"] == "wave1-feed-rule-2"
        assert feed[1]["rule_id"] == "wave1-feed-rule-1"
        assert feed[0]["id"] > feed[1]["id"]


# =========================================================================
# 5. Middleware Ordering (CORS on 402/403/429), owners.json, 404 & HEAD
# =========================================================================

class TestApiMiddlewareAndDiscoveryHardening:
    """Validates CORS/security headers on error responses, owners.json, well-known 404, and HEAD."""

    @pytest.fixture
    def lockdown_client(self, tmp_path: Path):
        storage = AgentStorage(db_path=str(tmp_path / "wave1_api.db"))
        cfg = X402Config(
            enabled=True,
            network="eip155:8453",
            pay_to_address="0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63",
        )
        app = create_app(
            storage=storage,
            x402_config=cfg,
            public_evaluate_only=True,
            enable_background_scanner=False,
        )
        return TestClient(app), storage

    def test_cors_and_security_headers_on_402_and_403(self, lockdown_client):
        client, _ = lockdown_client
        headers = {"Origin": "https://app.example.com"}

        # 402 Payment Required on POST /evaluate without payment
        resp_402 = client.post("/evaluate", json={}, headers=headers)
        assert resp_402.status_code == 402
        assert resp_402.headers.get("access-control-allow-origin") == "*"
        assert resp_402.headers.get("x-content-type-options") == "nosniff"

        # 403 Forbidden on blocked admin/log endpoint in public_evaluate_only mode
        resp_403 = client.get("/logs/errors", headers=headers)
        assert resp_403.status_code == 403
        assert resp_403.headers.get("access-control-allow-origin") == "*"
        assert resp_403.headers.get("x-content-type-options") == "nosniff"

    def test_cors_and_security_headers_on_429(self, tmp_path: Path):
        storage = AgentStorage(db_path=str(tmp_path / "wave1_rl.db"))
        cfg = X402Config(enabled=False)
        app = create_app(
            storage=storage,
            x402_config=cfg,
            public_evaluate_only=True,
            rate_limit_per_minute=1,
            enable_background_scanner=False,
        )
        client = TestClient(app)
        headers = {"Origin": "https://app.example.com"}

        first = client.get("/health", headers=headers)
        assert first.status_code == 200

        second = client.get("/health", headers=headers)
        assert second.status_code == 429
        assert second.headers.get("access-control-allow-origin") == "*"
        assert second.headers.get("x-content-type-options") == "nosniff"

    def test_well_known_owners_json_and_no_email_exposure(self, lockdown_client):
        client, _ = lockdown_client
        for path in ("/.well-known/owners.json", "/mcp/.well-known/owners.json"):
            resp = client.get(path)
            assert resp.status_code == 200
            data = resp.json()
            assert "owners" in data and len(data["owners"]) >= 1
            owner = data["owners"][0]
            assert owner["handle"] == "RafaCoelho33"
            assert "wallet" in owner and owner["wallet"] != DEFAULT_PAY_TO_ADDRESS
            assert "email" not in owner
            assert "email" not in json.dumps(data).lower()

    @pytest.mark.asyncio
    async def test_unknown_well_known_returns_404_without_logging_error(self, lockdown_client):
        client, storage = lockdown_client
        resp = client.get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 404

        errors = await storage.get_errors()
        assert errors == []

    def test_head_requests_on_discovery_and_health_routes_return_200(self, lockdown_client):
        client, _ = lockdown_client
        for path in (
            "/",
            "/health",
            "/mcp",
            "/.well-known/x402",
            "/.well-known/owners.json",
        ):
            resp = client.head(path)
            assert resp.status_code == 200, f"HEAD {path} returned {resp.status_code}"


# =========================================================================
# 6. MCP Remote Proxy Mode, Protocol Negotiation, server/discover & Pricing
# =========================================================================

class TestMCPRemoteProxyAndProtocolNegotiation:
    """Validates MCP 2025-03-26 negotiation, server/discover, tier pricing, and remote proxy mode."""

    @pytest.mark.asyncio
    async def test_initialize_negotiates_2025_03_26_and_server_discover(self):
        server = Web3SystemicMCPServer()

        init_res = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        })
        assert init_res is not None
        assert init_res["result"]["protocolVersion"] == "2025-03-26"

        disc_res = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "server/discover",
        })
        assert disc_res is not None
        tools = disc_res["result"]["tools"]
        assert isinstance(tools, list)
        assert len(tools) >= 4
        assert any(t["name"] == "deep_semantic_audit" for t in tools)

    @pytest.mark.asyncio
    async def test_deep_semantic_audit_tier_pricing_standard_vs_deep(self, monkeypatch):
        monkeypatch.delenv("X402_PRICE_EVALUATE", raising=False)
        monkeypatch.delenv("X402_PRICE_DEEP_AUDIT", raising=False)

        server = Web3SystemicMCPServer(
            buyer_private_key=None,
            require_x402_for_deep_audit=True,
            agent_url="https://agent.example.com",
        )
        target = "0x4200000000000000000000000000000000000006"

        std_res = await server.deep_semantic_audit(
            target_address=target,
            proposal_description="Standard audit pricing check",
        )
        assert std_res["status_code"] == 402
        assert std_res["price_usdc"] == 0.015
        assert std_res["evaluate_endpoint"] == "https://agent.example.com/evaluate"

        deep_proxy_res = await server.deep_semantic_audit(
            target_address=target,
            proposal_description="Deep proxy audit pricing check",
            resolve_proxy=True,
        )
        assert deep_proxy_res["status_code"] == 402
        assert deep_proxy_res["price_usdc"] == 0.25
        assert deep_proxy_res["evaluate_endpoint"] == "https://agent.example.com/audit/deep"

        deep_source_res = await server.deep_semantic_audit(
            target_address=target,
            proposal_description="Deep verified source audit pricing check",
            fetch_verified_source=True,
        )
        assert deep_source_res["status_code"] == 402
        assert deep_source_res["price_usdc"] == 0.25
        assert deep_source_res["evaluate_endpoint"] == "https://agent.example.com/audit/deep"

    @pytest.mark.asyncio
    async def test_remote_proxy_mode_discovers_402_signs_and_posts_payment_signature(self):
        buyer_acc = Account.create()
        pay_to = "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"

        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 402
        mock_get_resp.json.return_value = {
            "x402Version": 2,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "amount": "15000",
                    "maxAmountRequired": "15000",
                    "amount_usdc": 0.015,
                    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "payTo": pay_to,
                }
            ],
        }

        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {
            "rule_id": "remote-rule-1",
            "chain_id": 8453,
            "llm_invoked": True,
            "deterministic_check": {"passed": True, "reason": "ok"},
            "semantic_Evaluation": {
                "risk_score": 0.12,
                "confidence": 0.94,
                "summary": "Verified safe transfer.",
                "recommended_action": "APPROVE",
                "flagged_issues": [],
            },
        }

        mock_http_client = MagicMock()
        mock_http_client.get = AsyncMock(return_value=mock_get_resp)
        mock_http_client.post = AsyncMock(return_value=mock_post_resp)

        server = Web3SystemicMCPServer(
            agent_url="https://agent.example.com",
            buyer_private_key=buyer_acc.key.hex(),
            remote_mode=True,
            http_client=mock_http_client,
        )

        res = await server.deep_semantic_audit(
            target_address="0x4200000000000000000000000000000000000006",
            proposal_description="Remote proxy audit execution test",
        )

        assert res["status"] == "completed"
        assert res["status_code"] == 200
        assert res["decision"] == "APPROVE"
        assert res["remote_endpoint"] == "https://agent.example.com/audit"

        mock_http_client.get.assert_awaited_once_with("https://agent.example.com/audit")
        mock_http_client.post.assert_awaited_once()
        post_kwargs = mock_http_client.post.call_args.kwargs
        assert "PAYMENT-SIGNATURE" in post_kwargs["headers"]
        assert len(post_kwargs["headers"]["PAYMENT-SIGNATURE"]) > 20
