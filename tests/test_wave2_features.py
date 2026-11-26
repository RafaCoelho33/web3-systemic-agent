"""
Wave 2 Features Verification Suite (tests/test_wave2_features.py)

Covers all Wave 2 enhancements:
1. MCP 6th tool `inspect_proxy_and_source` (offline_mode, mocked ContractSourceResolver, invalid address)
   & `preflight_tx_firewall` (default tools/list exposure & reasons synced with flagged_issues).
2. MCP `resources/list` + `resources/read` (4 URIs + -32602 on unknown URI)
   and `prompts/list` + `prompts/get` (3 prompts + -32602 on missing required arg / unknown prompt).
3. Micro-route GET and POST `/token/check` ($0.005 USDC / 5000 atomic):
   - 402 without X-PAYMENT (amount="5000", amount_usdc=0.005, bazaar extension)
   - 422 on invalid address without settling payment
   - 503 on total RPC failure with payment_settled=False without settling payment
   - EOA (b"") -> verdict="EOA", risk_score=0.0, settles payment + X-PAYMENT-RESPONSE
   - Honeypot bytecode -> verdict="DANGEROUS", is_honeypot_suspect=True
   - Replay protection -> 402
   - GET `/token/check?address=0x...` with X-PAYMENT
4. Real execution via paid GET on `/audit` ($0.015 / 15000 atomic) and `/preflight` ($0.01 / 10000 atomic).
5. Distribution packages `.cursorrules` and `integrations/openclaw/SKILL.md` (existence, valid YAML frontmatter,
   documentation of all 6 MCP tools and x402 routes).
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from eth_account import Account
from fastapi.testclient import TestClient
from web3 import Web3

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
for _p in (_ROOT_DIR, _SRC_DIR, _SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from src.api import create_app
from src.chain_inspector import ChainInspector
from src.engine import ConditionAgentEngine
from src.mcp_server import Web3SystemicMCPServer
from src.schemas import ChainId, ConditionRulePayload, DeterministicCondition, DeterministicResult, FinalAgentResponse, SemanticAuditResult, SemanticCondition
from src.semantic_evaluator import MockSemanticEvaluator
from src.storage import AgentStorage
from src.x402_payment import MockX402Facilitator, X402Config, usdc_to_atomic


def _make_mock_payment_header(
    payment_id: str,
    amount_atomic: int,
    network: str = "eip155:8453",
    payer_address: Optional[str] = None,
) -> str:
    payer = payer_address or Account.create().address
    return json.dumps({
        "payment_id": payment_id,
        "payer_address": payer,
        "amount_atomic": amount_atomic,
        "network": network,
        "signature": "0xvalidmocksignature1234567890",
    })


@pytest.fixture
def clean_chain_cache():
    ChainInspector._bytecode_cache.clear()
    yield
    ChainInspector._bytecode_cache.clear()


# =========================================================================
# 1. MCP 6th Tool `inspect_proxy_and_source` & `preflight_tx_firewall`
# =========================================================================

class TestWave2MCPTools:
    """Validates Wave 2 MCP tools: inspect_proxy_and_source and preflight_tx_firewall."""

    @pytest.mark.asyncio
    async def test_inspect_proxy_and_source_offline_mode(self):
        server = Web3SystemicMCPServer(require_x402_for_deep_audit=True)
        target = "0x4200000000000000000000000000000000000006"

        res = await server.inspect_proxy_and_source(
            target_address=target,
            chain_id=8453,
            offline_mode=True,
        )

        assert res["tool"] == "inspect_proxy_and_source"
        assert res["stage"] == 1
        assert res["cost_usd"] == 0.0
        assert res["llm_invoked"] is False
        assert res["target_address"] == Web3.to_checksum_address(target)
        assert res["effective_audit_address"] == Web3.to_checksum_address(target)
        assert res["is_proxy"] is False
        assert res["source_verified"] is False
        assert res["upsell_recommendation"] is None

    @pytest.mark.asyncio
    async def test_inspect_proxy_and_source_with_mocked_resolver_eip1967_sourcify(self):
        proxy_addr = "0x1111111111111111111111111111111111111111"
        impl_addr = "0x2222222222222222222222222222222222222222"
        admin_addr = "0x3333333333333333333333333333333333333333"
        owner_addr = "0x4444444444444444444444444444444444444444"

        mock_resolver = MagicMock()
        mock_resolver.resolve_full_audit_context = AsyncMock(return_value={
            "effective_audit_address": impl_addr,
            "proxy_info": {
                "is_proxy": True,
                "implementation_address": impl_addr,
                "admin_address": admin_addr,
                "beacon_address": None,
                "owner_address": owner_addr,
                "is_paused": False,
                "effective_audit_address": impl_addr,
            },
            "source_info": {
                "verified": True,
                "provider": "sourcify",
                "contract_names": ["UpgradeableVaultV2"],
            },
            "security_warnings": ["EIP-1967 upgradeable proxy detected"],
        })

        server = Web3SystemicMCPServer(require_x402_for_deep_audit=True)
        server.source_resolver = mock_resolver

        res = await server.inspect_proxy_and_source(
            target_address=proxy_addr,
            chain_id=8453,
            fetch_verified_source=True,
            offline_mode=False,
        )

        mock_resolver.resolve_full_audit_context.assert_awaited_once_with(
            chain_id=8453,
            target_address=Web3.to_checksum_address(proxy_addr),
            resolve_proxy=True,
            fetch_source=True,
        )
        assert res["tool"] == "inspect_proxy_and_source"
        assert res["stage"] == 1
        assert res["cost_usd"] == 0.0
        assert res["llm_invoked"] is False
        assert res["is_proxy"] is True
        assert res["implementation_address"] == impl_addr
        assert res["admin_address"] == admin_addr
        assert res["owner_address"] == owner_addr
        assert res["is_paused"] is False
        assert res["source_verified"] is True
        assert res["source_provider"] == "sourcify"
        assert res["contract_names"] == ["UpgradeableVaultV2"]
        assert res["upsell_recommendation"] is not None
        assert "deep_semantic_audit" in res["upsell_recommendation"]

    @pytest.mark.asyncio
    async def test_inspect_proxy_and_source_invalid_address_raises_and_jsonrpc_is_error(self):
        server = Web3SystemicMCPServer()

        with pytest.raises(ValueError, match="Invalid Ethereum address"):
            await server.inspect_proxy_and_source(target_address="0xbad_addr")

        rpc_res = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": "proxy-err-1",
            "method": "tools/call",
            "params": {
                "name": "inspect_proxy_and_source",
                "arguments": {"target_address": "0xbad_addr"},
            },
        })
        assert rpc_res is not None
        assert rpc_res["id"] == "proxy-err-1"
        assert rpc_res["result"]["isError"] is True
        assert "Invalid Ethereum address" in rpc_res["result"]["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_preflight_tx_firewall_in_tools_list_and_syncs_reasons_with_flagged_issues(self):
        server = Web3SystemicMCPServer()

        tools_list_res = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": "pf-list",
            "method": "tools/list",
        })
        assert tools_list_res is not None
        tool_names = [t["name"] for t in tools_list_res["result"]["tools"]]
        assert "preflight_tx_firewall" in tool_names
        assert "inspect_proxy_and_source" in tool_names

        # Unlimited ERC-20 approve calldata
        unlimited_approve_calldata = (
            "0x095ea7b3"
            "0000000000000000000000001111111111111111111111111111111111111111"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        res = await server.preflight_tx_firewall(
            to_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            calldata=unlimited_approve_calldata,
            chain_id=8453,
            run_simulation=False,
        )

        assert res["tool"] == "preflight_tx_firewall"
        assert res["stage"] == 1
        assert res["cost_usd"] == 0.0
        assert res["llm_invoked"] is False
        assert res["verdict"] in ("BLOCK", "MANUAL_REVIEW")
        assert len(res["flagged_issues"]) > 0
        assert res["reasons"] == res["flagged_issues"]

        # Also validate JSON-RPC tools/call wrapper
        rpc_call = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": "pf-call",
            "method": "tools/call",
            "params": {
                "name": "preflight_tx_firewall",
                "arguments": {
                    "to_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "calldata": unlimited_approve_calldata,
                    "run_simulation": False,
                },
            },
        })
        assert rpc_call is not None
        assert rpc_call["result"]["isError"] is False
        sc = rpc_call["result"]["structuredContent"]
        assert sc["reasons"] == sc["flagged_issues"]


# =========================================================================
# 2. MCP Resources & Prompts Tests
# =========================================================================

class TestWave2MCPResourcesAndPrompts:
    """Validates MCP resources/list, resources/read, prompts/list, and prompts/get."""

    @pytest.mark.asyncio
    async def test_resources_list_and_read_all_4_uris_and_unknown_32602(self, tmp_path: Path):
        db_file = str(tmp_path / "wave2_resources.db")
        storage = AgentStorage(db_path=db_file)
        await storage.initialize()

        payload = ConditionRulePayload(
            rule_id="wave2-res-rule-1",
            chain_id=ChainId.BASE_MAINNET,
            deterministic=DeterministicCondition(
                target_address="0x4200000000000000000000000000000000000006",
            ),
            semantic=SemanticCondition(enabled=True, policy_prompt="Check safety"),
        )
        eval_resp = FinalAgentResponse(
            rule_id="wave2-res-rule-1",
            chain_id=ChainId.BASE_MAINNET,
            deterministic_check=DeterministicResult(passed=True, reason="ok"),
            llm_invoked=True,
            semantic_Evaluation=SemanticAuditResult(
                conditions_met=False,
                risk_score=1.5,
                summary="Clean contract",
                recommended_action="APPROVE",
                flagged_issues=[],
            ),
        )
        await storage.record_evaluation(payload, eval_resp, source="mcp_server")

        server = Web3SystemicMCPServer(storage=storage)

        list_res = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": "res-list",
            "method": "resources/list",
        })
        assert list_res is not None
        resources = list_res["result"]["resources"]
        expected_uris = [
            "web3://x402/pricing",
            "web3://security/selectors-catalog",
            "web3://feed/dao-curated-proposals",
            "web3://feed/recent-audits",
        ]
        assert [r["uri"] for r in resources] == expected_uris

        for uri in expected_uris:
            read_res = await server.handle_jsonrpc({
                "jsonrpc": "2.0",
                "id": f"read-{uri}",
                "method": "resources/read",
                "params": {"uri": uri},
            })
            assert read_res is not None
            assert "result" in read_res
            contents = read_res["result"]["contents"]
            assert len(contents) == 1
            assert contents[0]["uri"] == uri
            assert contents[0]["mimeType"] == "application/json"
            parsed = json.loads(contents[0]["text"])
            assert isinstance(parsed, dict)

            if uri == "web3://x402/pricing":
                assert parsed["protocol"] == "x402"
                assert "token_check" in parsed["tiers"]
                assert "preflight" in parsed["tiers"]
                assert "standard_audit" in parsed["tiers"]
                assert "deep_audit" in parsed["tiers"]
            elif uri == "web3://security/selectors-catalog":
                assert "known_selectors" in parsed
                assert "high_risk_keywords" in parsed
                assert "honeypot_selectors" in parsed
            elif uri == "web3://feed/dao-curated-proposals":
                assert parsed["count"] >= 1
                assert len(parsed["proposals"]) >= 1
            elif uri == "web3://feed/recent-audits":
                assert parsed["count"] == 1
                assert parsed["evaluations"][0]["rule_id"] == "wave2-res-rule-1"

        # Unknown URI -> JSON-RPC -32602
        bad_uri_res = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": "read-missing",
            "method": "resources/read",
            "params": {"uri": "web3://unknown/resource"},
        })
        assert bad_uri_res is not None
        assert bad_uri_res["error"]["code"] == -32602

    @pytest.mark.asyncio
    async def test_prompts_list_and_get_all_3_prompts_and_errors_32602(self):
        server = Web3SystemicMCPServer()

        list_res = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": "prm-list",
            "method": "prompts/list",
        })
        assert list_res is not None
        prompts = list_res["result"]["prompts"]
        expected_names = [
            "audit-token-before-swap",
            "pre-sign-transaction-firewall",
            "audit-dao-governance-space",
        ]
        assert [p["name"] for p in prompts] == expected_names

        valid_args = {
            "audit-token-before-swap": {
                "token_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "chain_id": 8453,
            },
            "pre-sign-transaction-firewall": {
                "to_address": "0x4200000000000000000000000000000000000006",
                "calldata": "0xa9059cbb",
            },
            "audit-dao-governance-space": {
                "space_id": "aavedao.eth",
            },
        }
        for name in expected_names:
            get_res = await server.handle_jsonrpc({
                "jsonrpc": "2.0",
                "id": f"get-{name}",
                "method": "prompts/get",
                "params": {"name": name, "arguments": valid_args[name]},
            })
            assert get_res is not None
            assert "result" in get_res
            messages = get_res["result"]["messages"]
            assert isinstance(messages, list) and len(messages) == 1
            assert messages[0]["role"] == "user"
            assert messages[0]["content"]["type"] == "text"
            assert len(messages[0]["content"]["text"]) > 20

        # Missing required arg for audit-token-before-swap -> -32602
        missing_token_arg = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": "prm-err-1",
            "method": "prompts/get",
            "params": {"name": "audit-token-before-swap", "arguments": {}},
        })
        assert missing_token_arg is not None
        assert missing_token_arg["error"]["code"] == -32602

        # Missing required arg for pre-sign-transaction-firewall -> -32602
        missing_to_arg = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": "prm-err-2",
            "method": "prompts/get",
            "params": {"name": "pre-sign-transaction-firewall", "arguments": {}},
        })
        assert missing_to_arg is not None
        assert missing_to_arg["error"]["code"] == -32602

        # Unknown prompt name -> -32602
        unknown_prompt = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": "prm-err-3",
            "method": "prompts/get",
            "params": {"name": "nonexistent-prompt", "arguments": {}},
        })
        assert unknown_prompt is not None
        assert unknown_prompt["error"]["code"] == -32602


# =========================================================================
# 3. Micro-Route GET and POST `/token/check` ($0.005 USDC / 5000 atomic)
# =========================================================================

class TestWave2TokenCheckRoute:
    """Validates GET and POST /token/check x402 billing, validation, RPC errors, and verdicts."""

    @pytest.fixture
    def token_client(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("X402_PRICE_TOKEN_CHECK", raising=False)
        monkeypatch.delenv("X402_PRICE_EVALUATE", raising=False)
        monkeypatch.delenv("X402_PRICE_PREFLIGHT", raising=False)

        db_file = str(tmp_path / "wave2_token_check.db")
        storage = AgentStorage(db_path=db_file)
        evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(semantic_evaluator=evaluator, storage=storage)
        cfg = X402Config(
            enabled=True,
            price_per_token_check_usdc=0.005,
            price_per_preflight_usdc=0.01,
            price_per_eval_usdc=0.015,
            network="eip155:8453",
            pay_to_address="0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63",
        )
        facilitator = MockX402Facilitator()
        app = create_app(
            engine=engine,
            storage=storage,
            x402_config=cfg,
            facilitator=facilitator,
            public_evaluate_only=True,
            enable_background_scanner=False,
        )
        # Default safe mock source resolver so no outbound HTTP calls occur
        mock_resolver = MagicMock()
        mock_resolver.resolve_full_audit_context = AsyncMock(return_value={
            "proxy_info": {"is_proxy": False, "implementation_address": None},
            "source_info": {"verified": True, "provider": "sourcify"},
            "security_warnings": [],
        })
        app.state.source_resolver = mock_resolver
        return TestClient(app), facilitator, app

    def test_get_and_post_token_check_without_payment_return_402(self, token_client):
        client, facilitator, _ = token_client

        for method in ("GET", "POST"):
            if method == "GET":
                resp = client.get("/token/check")
            else:
                resp = client.post(
                    "/token/check",
                    json={"address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
                )

            assert resp.status_code == 402
            body = resp.json()
            assert body["error"] == "PaymentRequired"
            assert body["accepts"][0]["amount"] == "5000"
            assert body["accepts"][0]["amount_usdc"] == 0.005
            assert "bazaar" in body["extensions"]

        assert facilitator.settle_calls == 0

    def test_token_check_invalid_address_returns_422_without_settling(self, token_client):
        client, facilitator, _ = token_client

        hdr_post = _make_mock_payment_header("tc-invalid-post-01", 5000)
        resp_post = client.post(
            "/token/check",
            json={"address": "0xinvalid_token_addr"},
            headers={"X-PAYMENT": hdr_post},
        )
        assert resp_post.status_code == 422
        assert facilitator.settle_calls == 0

        hdr_get = _make_mock_payment_header("tc-invalid-get-01", 5000)
        resp_get = client.get(
            "/token/check?address=0xinvalid_token_addr",
            headers={"X-PAYMENT": hdr_get},
        )
        assert resp_get.status_code == 422
        assert facilitator.settle_calls == 0

    def test_token_check_total_rpc_failure_returns_503_no_charge(self, token_client, clean_chain_cache):
        client, facilitator, _ = token_client
        target = "0x9999999999999999999999999999999999999999"

        failing_w3 = MagicMock()
        failing_w3.eth.get_code = AsyncMock(side_effect=ConnectionError("All RPC endpoints unreachable"))

        hdr = _make_mock_payment_header("tc-rpc-fail-01", 5000)
        with patch.object(ChainInspector, "_get_or_create_w3", return_value=failing_w3):
            resp = client.post(
                "/token/check",
                json={"address": target, "chain_id": 8453},
                headers={"X-PAYMENT": hdr},
            )

        assert resp.status_code == 503
        body = resp.json()
        assert body["payment_settled"] is False
        assert facilitator.verify_calls == 1
        assert facilitator.settle_calls == 0

    def test_token_check_eoa_settles_payment_and_replay_returns_402(self, token_client, clean_chain_cache):
        client, facilitator, _ = token_client
        eoa_addr = "0x5555555555555555555555555555555555555555"
        ChainInspector._set_bytecode_cache(f"8453:{eoa_addr}", b"")

        hdr = _make_mock_payment_header("tc-eoa-01", 5000)
        resp = client.post(
            "/token/check",
            json={"address": eoa_addr, "chain_id": 8453},
            headers={"X-PAYMENT": hdr},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] == "EOA"
        assert body["risk_score"] == 0.0
        assert body["is_contract"] is False
        assert body["llm_invoked"] is False
        assert body["payment"] is not None
        assert body["payment"]["payment_id"] == "tc-eoa-01"
        assert body["payment"]["amount_atomic"] == 5000
        assert "X-PAYMENT-RESPONSE" in resp.headers
        assert facilitator.settle_calls == 1

        # Replay with identical payment_id must return 402
        replay_resp = client.post(
            "/token/check",
            json={"address": eoa_addr, "chain_id": 8453},
            headers={"X-PAYMENT": hdr},
        )
        assert replay_resp.status_code == 402
        assert "replay" in replay_resp.json()["message"].lower()
        assert facilitator.settle_calls == 1

    def test_token_check_honeypot_contract_returns_dangerous(self, token_client, clean_chain_cache):
        client, facilitator, _ = token_client
        honeypot_addr = "0x6666666666666666666666666666666666666666"
        honeypot_code = bytes.fromhex("6080604052806341c0e1b51461002057ff")
        ChainInspector._set_bytecode_cache(f"8453:{honeypot_addr}", honeypot_code)

        hdr = _make_mock_payment_header("tc-honeypot-01", 5000)
        resp = client.post(
            "/token/check",
            json={"address": honeypot_addr, "chain_id": 8453},
            headers={"X-PAYMENT": hdr},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] == "DANGEROUS"
        assert body["is_honeypot_suspect"] is True
        assert body["is_contract"] is True
        assert body["llm_invoked"] is False
        assert body["payment"]["payment_id"] == "tc-honeypot-01"
        assert facilitator.settle_calls == 1

    def test_get_token_check_with_query_address_and_payment_succeeds(self, token_client, clean_chain_cache):
        client, facilitator, _ = token_client
        benign_addr = "0x7777777777777777777777777777777777777777"
        ChainInspector._set_bytecode_cache(
            f"8453:{benign_addr}",
            bytes.fromhex("60806040528063a9059cbb14"),
        )

        hdr = _make_mock_payment_header("tc-get-ok-01", 5000)
        resp = client.get(
            f"/token/check?address={benign_addr}&chain_id=8453",
            headers={"X-PAYMENT": hdr},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["address"] == benign_addr
        assert body["is_contract"] is True
        assert body["is_honeypot_suspect"] is False
        assert body["verdict"] == "SAFE"
        assert body["payment"]["payment_id"] == "tc-get-ok-01"
        assert "X-PAYMENT-RESPONSE" in resp.headers
        assert facilitator.settle_calls == 1


# =========================================================================
# 4. Paid GET Execution on `/audit` and `/preflight`
# =========================================================================

class TestWave2PaidGetAuditAndPreflight:
    """Validates real execution via paid GET on /audit and /preflight."""

    @pytest.fixture
    def paid_get_client(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("X402_PRICE_EVALUATE", raising=False)
        monkeypatch.delenv("X402_PRICE_PREFLIGHT", raising=False)

        db_file = str(tmp_path / "wave2_paid_get.db")
        storage = AgentStorage(db_path=db_file)
        evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(semantic_evaluator=evaluator, storage=storage)
        cfg = X402Config(
            enabled=True,
            price_per_eval_usdc=0.015,
            price_per_preflight_usdc=0.01,
            network="eip155:8453",
            pay_to_address="0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63",
        )
        facilitator = MockX402Facilitator()
        app = create_app(
            engine=engine,
            storage=storage,
            x402_config=cfg,
            facilitator=facilitator,
            public_evaluate_only=True,
            enable_background_scanner=False,
        )
        return TestClient(app), facilitator

    def test_get_audit_requires_payment_then_executes_when_paid(self, paid_get_client, clean_chain_cache):
        client, facilitator = paid_get_client
        target = "0x4200000000000000000000000000000000000006"
        ChainInspector._set_bytecode_cache(
            f"8453:{target}",
            bytes.fromhex("60806040528063a9059cbb14"),
        )

        # Unpaid GET returns 402
        unpaid = client.get(f"/audit?address={target}")
        assert unpaid.status_code == 402
        assert facilitator.settle_calls == 0

        # Paid GET with 15000 atomic ($0.015 USDC) executes FinalAgentResponse
        hdr = _make_mock_payment_header("get-audit-paid-01", 15000)
        paid = client.get(
            f"/audit?address={target}",
            headers={"X-PAYMENT": hdr},
        )
        assert paid.status_code == 200
        body = paid.json()
        assert body["rule_id"].startswith("quick-audit-")
        assert body["deterministic_check"]["passed"] is True
        assert body["llm_invoked"] is True
        assert body["semantic_Evaluation"] is not None
        assert body["payment"]["payment_id"] == "get-audit-paid-01"
        assert body["payment"]["amount_atomic"] == 15000
        assert "X-PAYMENT-RESPONSE" in paid.headers
        assert facilitator.settle_calls == 1

    def test_get_preflight_requires_payment_then_executes_when_paid(self, paid_get_client):
        client, facilitator = paid_get_client
        to_addr = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        calldata = (
            "0x095ea7b30000000000000000000000001111111111111111111111111111111111111111"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        url = f"/preflight?to_address={to_addr}&calldata={calldata}&run_simulation=false"

        # Unpaid GET returns 402
        unpaid = client.get(url)
        assert unpaid.status_code == 402
        assert facilitator.settle_calls == 0

        # Paid GET with 10000 atomic ($0.01 USDC) executes PreflightVerdict
        hdr = _make_mock_payment_header("get-preflight-paid-01", 10000)
        paid = client.get(url, headers={"X-PAYMENT": hdr})
        assert paid.status_code == 200
        body = paid.json()
        assert body["verdict"] in ("MANUAL_REVIEW", "BLOCK")
        assert body["risk_score"] >= 7.0
        assert body["llm_invoked"] is False
        assert body["payment"]["payment_id"] == "get-preflight-paid-01"
        assert body["payment"]["amount_atomic"] == 10000
        assert "X-PAYMENT-RESPONSE" in paid.headers
        assert facilitator.settle_calls == 1


# =========================================================================
# 5. Distribution Packages `.cursorrules` and `integrations/openclaw/SKILL.md`
# =========================================================================

class TestWave2DistributionPackages:
    """Validates .cursorrules and integrations/openclaw/SKILL.md manifests."""

    EXPECTED_MCP_TOOLS = (
        "scan_contract_selectors",
        "check_token_honeypot",
        "scan_dao_proposals",
        "preflight_tx_firewall",
        "inspect_proxy_and_source",
        "deep_semantic_audit",
    )
    EXPECTED_X402_ROUTES = (
        "/token/check",
        "/preflight",
        "/audit",
        "/audit/deep",
    )

    def test_cursorrules_exists_and_documents_all_6_tools(self):
        cursorrules_path = Path(_ROOT_DIR) / ".cursorrules"
        assert cursorrules_path.exists(), ".cursorrules must exist in repository root"

        content = cursorrules_path.read_text(encoding="utf-8")
        for tool in self.EXPECTED_MCP_TOOLS:
            assert tool in content, f".cursorrules missing MCP tool '{tool}'"

        assert "x402" in content.lower()
        assert "web3://x402/pricing" in content
        assert "web3://security/selectors-catalog" in content

    def test_openclaw_skill_md_exists_valid_yaml_frontmatter_and_routes(self):
        skill_path = Path(_ROOT_DIR) / "integrations" / "openclaw" / "SKILL.md"
        assert skill_path.exists(), "integrations/openclaw/SKILL.md must exist"

        raw = skill_path.read_text(encoding="utf-8")
        assert raw.startswith("---"), "SKILL.md must start with YAML frontmatter '---'"
        parts = raw.split("---", 2)
        assert len(parts) >= 3, "SKILL.md must have closing '---' for YAML frontmatter"

        frontmatter = yaml.safe_load(parts[1])
        assert isinstance(frontmatter, dict)
        assert frontmatter.get("name") == "web3-systemic-agent"
        assert isinstance(frontmatter.get("description"), str) and len(frontmatter["description"]) > 10

        body = parts[2]
        for tool in self.EXPECTED_MCP_TOOLS:
            assert tool in body, f"SKILL.md missing MCP tool '{tool}'"

        for route in self.EXPECTED_X402_ROUTES:
            assert route in body, f"SKILL.md missing x402 route '{route}'"
