"""
Comprehensive test suite for:
1. QuickAuditRequest schema and build_bazaar_discovery_extension('/audit')
2. Enriched resource_obj (serviceName, tags) in build_402_response
3. HTTPX402Facilitator resource and extensions preservation
4. Web3SystemicMCPServer outputSchema and return dictionary alignment across all 4 tools
5. deep_semantic_audit x402 verification, replay defense, and settlement
6. FastAPI /.well-known/x402, GET /audit, and POST /audit endpoints in both lockdown and normal modes
"""

import asyncio
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from web3 import Web3
from eth_account import Account

# Setup paths
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(ROOT_DIR) in ("src", "tests"):
    ROOT_DIR = os.path.abspath(os.path.join(ROOT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
SCRIPTS_DIR = os.path.join(ROOT_DIR, "scripts")

for p in (ROOT_DIR, SRC_DIR, SCRIPTS_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from src.schemas import (
    ChainId,
    ConditionRulePayload,
    DeterministicCondition,
    DeterministicResult,
    FinalAgentResponse,
    SemanticCondition,
    PaymentReceipt,
)
from src.x402_payment import (
    QuickAuditRequest,
    build_bazaar_discovery_extension,
    build_402_response,
    HTTPX402Facilitator,
    MockX402Facilitator,
    SettlementResult,
    VerificationResult,
    X402Config,
    create_eip3009_payment_header,
    parse_x402_header,
    usdc_to_atomic,
)
from src.mcp_server import Web3SystemicMCPServer
from src.engine import ConditionAgentEngine
from src.semantic_evaluator import MockSemanticEvaluator
from src.chain_inspector import ChainInspector
from src.storage import AgentStorage
from src.api import create_app

try:
    from tests.test_x402_bazaar_cdp import simulate_cdp_validator
except ImportError:
    from test_x402_bazaar_cdp import simulate_cdp_validator


# =========================================================================
# 1. QuickAuditRequest Schema & Bazaar Auto-Discovery Tests
# =========================================================================

def test_quick_audit_request_schema():
    """Validates QuickAuditRequest schema, field defaults, and aliases."""
    req = QuickAuditRequest(
        target_address="0x4200000000000000000000000000000000000006",
        chain_id=8453,
    )
    assert req.target_address == "0x4200000000000000000000000000000000000006"
    assert req.chain_id == 8453
    assert req.risk_threshold == 7.0
    assert "administrative backdoors" in req.proposal_description
    assert "calldata" in req.model_dump()

    schema = QuickAuditRequest.model_json_schema()
    assert "properties" in schema
    assert "target_address" in schema["properties"]
    assert "address" in schema["properties"]
    assert "contract_address" in schema["properties"]
    assert "policy_prompt" in schema["properties"]


def test_build_bazaar_discovery_extension_for_audit():
    """Validates build_bazaar_discovery_extension for /audit uses QuickAuditRequest schema."""
    ext = build_bazaar_discovery_extension("/audit")
    assert "bazaar" in ext
    bazaar_info = ext["bazaar"]["info"]
    assert bazaar_info["input"]["method"] == "POST"
    assert "target_address" in bazaar_info["input"]["body"]

    # For default /evaluate, it should declare rule_id in sample input
    eval_ext = build_bazaar_discovery_extension("/evaluate")
    assert "rule_id" in eval_ext["bazaar"]["info"]["input"]["body"]


# =========================================================================
# 2. Enriched resource_obj in build_402_response
# =========================================================================

def test_build_402_response_enrichment():
    """Validates resource_obj in build_402_response includes serviceName and tags."""
    cfg = X402Config(enabled=True, price_per_eval_usdc=0.05, network="eip155:8453")
    resp = build_402_response(cfg, "/audit", 0.05)
    assert resp.status_code == 402

    body = json.loads(resp.body.decode("utf-8"))
    res_obj = body["resource"]
    assert res_obj["serviceName"] == "Web3 Systemic Agent"
    assert "web3-security" in res_obj["tags"]
    assert "smart-contract-audit" in res_obj["tags"]
    assert "base" in res_obj["tags"]
    assert "mimeType" in res_obj
    assert "url" in res_obj
    assert "description" in res_obj

    # accepts[0] must also have enriched resource
    accepts_res = body["accepts"][0]["resource"]
    assert accepts_res["serviceName"] == "Web3 Systemic Agent"


# =========================================================================
# 3. HTTPX402Facilitator resource and extensions preservation
# =========================================================================

def test_httpx402_facilitator_resource_and_extensions_builder():
    """Validates _build_resource_and_extensions handles default and custom data."""
    fac = HTTPX402Facilitator()
    payment_data = {"endpoint": "/audit"}
    res_obj, ext = fac._build_resource_and_extensions(payment_data)

    assert res_obj["serviceName"] == "Web3 Systemic Agent"
    assert "audit" in res_obj["url"]
    assert "bazaar" in ext
    assert "target_address" in ext["bazaar"]["info"]["input"]["body"]

    # Custom resource and extensions should be preserved
    custom_payment_data = {
        "endpoint": "/audit",
        "resource": {"url": "https://custom.service/test", "serviceName": "Custom"},
        "extensions": {"bazaar": {"custom": True}},
    }
    c_res, c_ext = fac._build_resource_and_extensions(custom_payment_data)
    assert c_res["url"] == "https://custom.service/test"
    assert c_ext["bazaar"]["custom"] is True


@pytest.mark.asyncio
async def test_httpx402_facilitator_settle_passes_resource_and_declared_extensions():
    """
    Validates that HTTPX402Facilitator.settle() and verify() preserve resource
    (including serviceName and tags) and extensions.bazaar in the payload
    sent to the HTTP client and _settle_eip3009_sync (declared_extensions).
    """
    mock_client = AsyncMock()
    verify_resp = MagicMock()
    verify_resp.status_code = 200
    verify_resp.json.return_value = {"isValid": True}

    settle_resp = MagicMock()
    settle_resp.status_code = 200
    settle_resp.json.return_value = {"success": True, "transaction": "0xabc123"}

    mock_client.post.side_effect = [verify_resp, settle_resp]

    cfg = X402Config(enabled=True, price_per_eval_usdc=0.05, network="eip155:8453")
    fac = HTTPX402Facilitator(client=mock_client)

    payment_data = {
        "payment_id": "test-pid-resource-check",
        "payer_address": "0x1111111111111111111111111111111111111111",
        "amount_atomic": 50000,
        "endpoint": "/audit",
    }

    # 1. verify() preserves resource (with serviceName and tags) and extensions.bazaar
    v_res = await fac.verify(payment_data, 50000, cfg)
    assert v_res.valid is True
    assert mock_client.post.call_count == 1
    _, call1_kwargs = mock_client.post.call_args
    verify_payload = call1_kwargs["json"]
    v_resource = verify_payload["paymentPayload"]["resource"]
    v_extensions = verify_payload["paymentPayload"]["extensions"]
    assert v_resource["serviceName"] == "Web3 Systemic Agent"
    assert "web3-security" in v_resource["tags"]
    assert "bazaar" in v_extensions

    # 2. settle() preserves resource (with serviceName and tags) and extensions.bazaar via HTTP client
    s_res = await fac.settle(payment_data, 50000, cfg)
    assert s_res.settled is True
    assert mock_client.post.call_count == 2
    _, call2_kwargs = mock_client.post.call_args
    settle_payload = call2_kwargs["json"]
    s_resource = settle_payload["paymentPayload"]["resource"]
    s_extensions = settle_payload["paymentPayload"]["extensions"]
    assert s_resource["serviceName"] == "Web3 Systemic Agent"
    assert "smart-contract-audit" in s_resource["tags"]
    assert "bazaar" in s_extensions

    # 3. settle() preserves resource and declared_extensions when delegating to _settle_eip3009_sync
    with patch.object(HTTPX402Facilitator, "_settle_eip3009_sync", return_value=SettlementResult(settled=True, tx_hash="0xsync123")) as mock_sync:
        eip_fac = HTTPX402Facilitator(client=None)
        with patch("src.x402_payment.HAS_X402_SDK", True):
            eip_payment_data = {
                "payment_id": "test-eip-sync",
                "payer_address": "0x1111111111111111111111111111111111111111",
                "amount_atomic": 50000,
                "endpoint": "/audit",
                "payload": {"authorization": {"nonce": "0x1"}},
            }
            res_eip = await eip_fac.settle(eip_payment_data, 50000, cfg)
            assert res_eip.settled is True
            mock_sync.assert_called_once()
            _, sync_kwargs = mock_sync.call_args
            assert "declared_extensions" in sync_kwargs
            assert "bazaar" in sync_kwargs["declared_extensions"]
            payload_obj = sync_kwargs.get("payload_obj")
            assert payload_obj is not None
            p_res = getattr(payload_obj, "resource", None)
            if hasattr(p_res, "service_name"):
                assert getattr(p_res, "service_name") == "Web3 Systemic Agent"
            elif isinstance(p_res, dict):
                assert p_res.get("serviceName") == "Web3 Systemic Agent"


# =========================================================================
# 4. Web3SystemicMCPServer Tool Schemas & Dict Alignment
# =========================================================================

@pytest.mark.asyncio
async def test_mcp_tools_manifest_output_schemas():
    """Validates all 4 tool outputSchemas in Web3SystemicMCPServer manifest."""
    server = Web3SystemicMCPServer()
    manifest = server.get_tools_manifest()
    tools_by_name = {t["name"]: t for t in manifest}

    # 1. scan_contract_selectors
    s1 = tools_by_name["scan_contract_selectors"]["outputSchema"]["properties"]
    assert s1["selectors_found"]["type"] == "array"
    assert s1["selectors_found"]["items"]["type"] == "object"
    assert s1["high_risk_selectors"]["type"] == "array"
    assert s1["high_risk_signatures"]["type"] == "array"
    assert "upsell_recommendation" in s1
    assert "llm_invoked" in s1

    # 2. check_token_honeypot
    s2 = tools_by_name["check_token_honeypot"]["outputSchema"]["properties"]
    assert "categories_detected" in s2
    assert "upsell_recommendation" in s2
    assert "llm_invoked" in s2
    assert "threat_categories" in s2

    # 3. scan_dao_proposals
    s3 = tools_by_name["scan_dao_proposals"]["outputSchema"]["properties"]
    assert "recommendation" in s3
    assert "upsell_recommendation" in s3
    assert "llm_invoked" in s3

    # 4. deep_semantic_audit
    s4 = tools_by_name["deep_semantic_audit"]["outputSchema"]["properties"]
    assert "status" in s4
    assert "status_code" in s4
    assert "decision" in s4
    assert "risk_score" in s4
    assert "reasoning" in s4
    assert "flagged_issues" in s4


@pytest.mark.asyncio
async def test_mcp_tool_return_dict_alignment():
    """Validates return dictionaries for scan_contract_selectors, check_token_honeypot, and scan_dao_proposals."""
    server = Web3SystemicMCPServer()

    # Tool 1: scan_contract_selectors
    benign_bytecode = "0x608060405234801561001057600080fd5b508063a9059cbb14"
    r1 = await server.scan_contract_selectors(
        target_address="0x3333333333333333333333333333333333333333",
        bytecode_override=benign_bytecode,
    )
    assert r1["tool"] == "scan_contract_selectors"
    assert r1["stage"] == 1
    assert isinstance(r1["high_risk_selectors"], list)
    assert "recommendation" in r1
    assert r1["is_contract"] is True
    assert r1["bytecode_size_bytes"] > 0
    assert "selectors_found" in r1
    assert "high_risk_signatures" in r1
    assert "upsell_recommendation" in r1
    assert r1["cost_usd"] == 0.0

    # Tool 2: check_token_honeypot
    r2_empty = await server.check_token_honeypot(
        token_address="0x5555555555555555555555555555555555555555",
        bytecode_override="0x",
    )
    assert r2_empty["tool"] == "check_token_honeypot"
    assert r2_empty["stage"] == 1
    assert r2_empty["is_contract"] is False
    assert r2_empty["bytecode_size_bytes"] == 0
    assert r2_empty["threat_categories"] == []
    assert "recommendation" in r2_empty

    honeypot_bytecode = "0x608060405263f9f02b011461002057634b7890ec1461004057"
    r2_honey = await server.check_token_honeypot(
        token_address="0x4444444444444444444444444444444444444444",
        bytecode_override=honeypot_bytecode,
    )
    assert r2_honey["tool"] == "check_token_honeypot"
    assert r2_honey["stage"] == 1
    assert r2_honey["is_contract"] is True
    assert r2_honey["bytecode_size_bytes"] > 0
    assert r2_honey["is_honeypot_suspect"] is True
    assert len(r2_honey["threat_categories"]) > 0
    assert "recommendation" in r2_honey

    # Tool 3: scan_dao_proposals
    r3 = await server.scan_dao_proposals(use_curated_offline=True, limit=2)
    assert r3["tool"] == "scan_dao_proposals"
    assert r3["stage"] == 1
    assert "deep_semantic_audit" in r3["recommendation"]
    assert "proposals" in r3
    assert r3["proposals_count"] >= 1


# =========================================================================
# 5. MCP deep_semantic_audit Verification & Settlement
# =========================================================================

@pytest.mark.asyncio
async def test_mcp_deep_semantic_audit_with_valid_payment(tmp_path: Path):
    """
    Validates deep_semantic_audit when require_x402_for_deep_audit=True and valid payment header is passed.
    Verifies facilitator.verify and facilitator.settle are invoked and PaymentReceipt is attached.
    """
    db_file = str(tmp_path / "mcp_paid_test.db")
    storage = AgentStorage(db_path=db_file)
    evaluator = MockSemanticEvaluator()
    engine = ConditionAgentEngine(semantic_evaluator=evaluator, storage=storage)

    cfg = X402Config(enabled=True, price_per_eval_usdc=0.05, network="eip155:8453")
    facilitator = MockX402Facilitator()

    target = "0x4200000000000000000000000000000000000006"
    ChainInspector._set_bytecode_cache(f"8453:{target}", bytes.fromhex("60806040528063a9059cbb14"))

    server = Web3SystemicMCPServer(
        engine=engine,
        x402_config=cfg,
        facilitator=facilitator,
        storage=storage,
        require_x402_for_deep_audit=True,
    )

    # Valid payment header using mock format
    payer_acc = Account.create()
    payment_header = json.dumps({
        "payment_id": "test-mcp-nonce-001",
        "payer_address": payer_acc.address,
        "amount_atomic": usdc_to_atomic(0.05),
        "network": "eip155:8453",
        "signature": "0xvalidmocksignature1234567890",
    })

    res = await server.deep_semantic_audit(
        target_address=target,
        proposal_description="Approve multisig treasury parameter update",
        x402_payment_header=payment_header,
    )

    assert res.get("status") == "completed"
    assert res.get("status_code") == 200
    assert res.get("tool") == "deep_semantic_audit"
    assert res.get("stage") == 2
    assert "decision" in res
    assert "risk_score" in res
    assert "reasoning" in res
    assert facilitator.verify_calls == 1
    assert facilitator.settle_calls == 1
    assert "payment" in res
    assert res["payment"]["payment_id"] == "test-mcp-nonce-001"

    # Replay attack attempt should return 402 replay detected
    replay_res = await server.deep_semantic_audit(
        target_address=target,
        proposal_description="Replay attempt",
        x402_payment_header=payment_header,
    )
    assert replay_res.get("status") == "payment_required"
    assert replay_res.get("status_code") == 402
    assert "replay detected" in replay_res.get("message", "").lower()


@pytest.mark.asyncio
async def test_mcp_deep_semantic_audit_rejects_fake_or_malformed_payment_header_without_llm_call(tmp_path: Path):
    """
    Validates that deep_semantic_audit rejects fake/malformed payment headers immediately
    without calling engine.process_rule, preventing unauthenticated LLM credit drain.
    Checks both direct server method invocation and JSON-RPC via POST /mcp.
    """
    db_file = str(tmp_path / "fake_header_test.db")
    storage = AgentStorage(db_path=db_file)
    engine = AsyncMock(spec=ConditionAgentEngine)
    cfg = X402Config(enabled=True, price_per_eval_usdc=0.05, network="eip155:8453")
    facilitator = MockX402Facilitator()

    target = "0x4200000000000000000000000000000000000006"
    server = Web3SystemicMCPServer(
        engine=engine,
        x402_config=cfg,
        facilitator=facilitator,
        storage=storage,
        require_x402_for_deep_audit=True,
    )

    # 1. Direct method invocation
    res = await server.deep_semantic_audit(
        target_address=target,
        proposal_description="Audit with fake header",
        x402_payment_header="fake",
    )
    assert res.get("status") == "payment_required"
    assert res.get("status_code") == 402
    assert "malformed" in res.get("message", "").lower() or "malformed" in res.get("reason", "").lower()
    engine.process_rule.assert_not_called()

    # 2. POST /mcp JSON-RPC execution
    app = create_app(
        engine=engine,
        storage=storage,
        x402_config=cfg,
        facilitator=facilitator,
        public_evaluate_only=True,
        enable_background_scanner=False,
    )
    app.state.mcp_server = server

    client = TestClient(app)
    rpc_payload = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "deep_semantic_audit",
            "arguments": {
                "target_address": target,
                "proposal_description": "Audit with fake header via JSON-RPC",
                "x402_payment_header": "fake",
            },
        },
    }
    rpc_resp = client.post("/mcp", json=rpc_payload)
    assert rpc_resp.status_code == 200
    rpc_data = rpc_resp.json()
    structured = rpc_data.get("result", {}).get("structuredContent", {})
    assert structured.get("status") == "payment_required"
    assert structured.get("status_code") == 402
    engine.process_rule.assert_not_called()


@pytest.mark.asyncio
async def test_mcp_deep_semantic_audit_no_charge_on_rpc_error(tmp_path: Path):
    """
    Validates that when engine.process_rule returns a deterministic error (e.g. RPC timeout),
    deep_semantic_audit returns status="error", status_code=503, payment_settled=False,
    and facilitator.settle is NOT called (facilitator.settle_calls == 0).
    """
    db_file = str(tmp_path / "mcp_rpc_error_test.db")
    storage = AgentStorage(db_path=db_file)
    cfg = X402Config(enabled=True, price_per_eval_usdc=0.05, network="eip155:8453")
    facilitator = MockX402Facilitator()

    target = "0x4200000000000000000000000000000000000006"
    engine = AsyncMock(spec=ConditionAgentEngine)
    engine.process_rule.return_value = FinalAgentResponse(
        rule_id="test-mcp-rpc-err",
        chain_id=ChainId.BASE_MAINNET,
        deterministic_check=DeterministicResult(
            passed=False,
            reason="RPC timeout",
            error="RPC timeout",
            target_address=target,
            chain_id=8453,
        ),
        semantic_evaluation=None,
        execution_timestamp=1700000000.0,
        llm_invoked=False,
    )

    server = Web3SystemicMCPServer(
        engine=engine,
        x402_config=cfg,
        facilitator=facilitator,
        storage=storage,
        require_x402_for_deep_audit=True,
    )

    payer_acc = Account.create()
    payment_header = json.dumps({
        "payment_id": "test-mcp-rpc-timeout-nonce-001",
        "payer_address": payer_acc.address,
        "amount_atomic": usdc_to_atomic(0.05),
        "network": "eip155:8453",
        "signature": "0xvalidmocksignature1234567890",
    })

    res = await server.deep_semantic_audit(
        target_address=target,
        proposal_description="Audit during RPC failure",
        x402_payment_header=payment_header,
    )

    assert res.get("status") == "error"
    assert res.get("status_code") == 503
    assert res.get("payment_settled") is False
    assert res.get("error") == "RPC timeout"
    assert facilitator.verify_calls == 1
    assert facilitator.settle_calls == 0


# =========================================================================
# 6. FastAPI /.well-known/x402, GET /audit, and POST /audit Tests
# =========================================================================

class TestFastAPIAuditAndWellKnownX402:
    @pytest.fixture
    def app_client(self, tmp_path: Path) -> TestClient:
        db_file = str(tmp_path / "api_audit_test.db")
        storage = AgentStorage(db_path=db_file)
        evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(semantic_evaluator=evaluator, storage=storage)
        cfg = X402Config(enabled=True, price_per_eval_usdc=0.05, network="eip155:8453")
        facilitator = MockX402Facilitator()

        app = create_app(
            engine=engine,
            storage=storage,
            x402_config=cfg,
            facilitator=facilitator,
            public_evaluate_only=True,
            enable_background_scanner=False,
        )
        return TestClient(app)

    def test_well_known_x402_endpoint(self, app_client: TestClient):
        """Validates GET /.well-known/x402 returns compliant metadata and resources."""
        resp = app_client.get("/.well-known/x402")
        assert resp.status_code == 200

        data = resp.json()
        assert data["x402Version"] == 2
        assert data["service"] == "Web3 Systemic Agent"
        assert data["network"] == "eip155:8453"
        assert len(data["resources"]) == 2

        endpoints = [r["endpoint"] for r in data["resources"]]
        assert "/evaluate" in endpoints
        assert "/audit" in endpoints

    def test_get_audit_returns_402(self, app_client: TestClient):
        """Validates GET /audit returns HTTP 402 with Bazaar discovery metadata."""
        resp = app_client.get("/audit")
        assert resp.status_code == 402
        assert "Payment-Required" in resp.headers

        data = resp.json()
        assert data["error"] == "PaymentRequired"
        assert "extensions" in data
        assert "bazaar" in data["extensions"]
        assert "target_address" in data["extensions"]["bazaar"]["info"]["input"]["body"]

    def test_post_audit_unpaid_probe_returns_402(self, app_client: TestClient):
        """Validates POST /audit without payment header returns HTTP 402 (payment required)."""
        body = {
            "target_address": "0x4200000000000000000000000000000000000006",
            "chain_id": 8453,
            "proposal_description": "Probe audit",
        }
        resp = app_client.post("/audit", json=body)
        assert resp.status_code == 402

    def test_post_audit_invalid_address_returns_422(self, app_client: TestClient):
        """Validates POST /audit with payment header but invalid address returns HTTP 422."""
        payer_acc = Account.create()
        payment_header = json.dumps({
            "payment_id": "test-api-invalid-addr",
            "payer_address": payer_acc.address,
            "amount_atomic": usdc_to_atomic(0.05),
            "network": "eip155:8453",
            "signature": "0xvalidmocksignature1234567890",
        })
        headers = {"X-PAYMENT": payment_header}
        body = {
            "target_address": "0xnot_an_evm_address",
            "chain_id": 8453,
            "proposal_description": "Probe audit",
        }
        resp = app_client.post("/audit", json=body, headers=headers)
        assert resp.status_code == 422

    def test_post_audit_success_with_payment(self, app_client: TestClient):
        """Validates POST /audit with valid payment header executes audit, settles, and returns receipt."""
        target = "0x4200000000000000000000000000000000000006"
        ChainInspector._set_bytecode_cache(f"8453:{target}", bytes.fromhex("60806040528063a9059cbb14"))

        payer_acc = Account.create()
        payment_header = json.dumps({
            "payment_id": "test-api-audit-success-01",
            "payer_address": payer_acc.address,
            "amount_atomic": usdc_to_atomic(0.05),
            "network": "eip155:8453",
            "signature": "0xvalidmocksignature1234567890",
        })
        headers = {"X-PAYMENT": payment_header}
        body = {
            "target_address": target,
            "chain_id": 8453,
            "proposal_description": "Audit sequencer oracle parameter feed update",
            "calldata": "0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111",
        }

        resp = app_client.post("/audit", json=body, headers=headers)
        assert resp.status_code == 200

        data = resp.json()
        assert data["rule_id"].startswith("quick-audit-")
        assert data["deterministic_check"]["passed"] is True
        assert data["llm_invoked"] is True
        assert "payment" in data
        assert data["payment"]["payment_id"] == "test-api-audit-success-01"
        assert "X-PAYMENT-RESPONSE" in resp.headers

    def test_cdp_validator_24_checks_on_get_and_post_audit(self, app_client: TestClient):
        """
        Validates that both GET /audit and POST /audit (empty probe {}) pass all 24/24
        Coinbase Developer Platform (CDP) Validator checks with valid is True and required_failed == 0.
        """
        # 1. GET /audit preflight simulation
        get_resp = app_client.get("/audit")
        assert get_resp.status_code == 402
        cdp_get_report = simulate_cdp_validator(get_resp, url="/audit")
        assert cdp_get_report["valid"] is True
        assert cdp_get_report["required_failed"] == 0
        assert cdp_get_report["total_checks"] == 24

        # 2. POST /audit empty probe ({}) simulation
        post_resp = app_client.post("/audit", json={})
        assert post_resp.status_code == 402
        cdp_post_report = simulate_cdp_validator(post_resp, url="/audit")
        assert cdp_post_report["valid"] is True
        assert cdp_post_report["required_failed"] == 0
        assert cdp_post_report["total_checks"] == 24

    def test_post_audit_address_aliases_and_503_no_charge_on_rpc_error(self, tmp_path: Path):
        """
        Validates:
        1. POST /audit accepts 'address' and 'contract_address' aliases instead of 'target_address'.
        2. When deterministic check fails with an upstream RPC error (deterministic_check.error is not None),
           the endpoint returns HTTP 503 Service Unavailable, payment_settled is False, and facilitator.settle is NOT called.
        """
        db_file = str(tmp_path / "alias_rpc_error.db")
        storage = AgentStorage(db_path=db_file)
        target = "0x4200000000000000000000000000000000000006"

        engine = AsyncMock(spec=ConditionAgentEngine)
        engine.process_rule.return_value = FinalAgentResponse(
            rule_id="test-alias-rpc-err",
            chain_id=ChainId.BASE_MAINNET,
            deterministic_check=DeterministicResult(
                passed=False,
                reason="RPC timeout connecting to archive node",
                error="RPC timeout connecting to archive node",
                target_address=target,
                chain_id=8453,
            ),
            semantic_evaluation=None,
            execution_timestamp=1700000000.0,
            llm_invoked=False,
        )

        cfg = X402Config(enabled=True, price_per_eval_usdc=0.05, network="eip155:8453")
        facilitator = MockX402Facilitator()

        app = create_app(
            engine=engine,
            storage=storage,
            x402_config=cfg,
            facilitator=facilitator,
            public_evaluate_only=True,
            enable_background_scanner=False,
        )
        client = TestClient(app)
        payer_acc = Account.create()

        # 1. Test 'address' alias with RPC error -> 503, payment_settled: False, settle_calls: 0
        payment_header_1 = json.dumps({
            "payment_id": "test-alias-addr-nonce-1",
            "payer_address": payer_acc.address,
            "amount_atomic": usdc_to_atomic(0.05),
            "network": "eip155:8453",
            "signature": "0xvalidmocksignature1234567890",
        })
        resp1 = client.post(
            "/audit",
            json={"address": target, "proposal_description": "Audit via address alias"},
            headers={"X-PAYMENT": payment_header_1},
        )
        assert resp1.status_code == 503
        body1 = resp1.json()
        assert body1.get("error") == "ServiceUnavailable"
        assert body1.get("payment_settled") is False
        assert facilitator.settle_calls == 0

        # 2. Test 'contract_address' alias with normal response -> 200, payment receipt attached, settle called
        engine.process_rule.return_value = FinalAgentResponse(
            rule_id="test-alias-success",
            chain_id=ChainId.BASE_MAINNET,
            deterministic_check=DeterministicResult(
                passed=True,
                reason="All deterministic checks passed",
                error=None,
                target_address=target,
                chain_id=8453,
            ),
            semantic_evaluation=None,
            execution_timestamp=1700000000.0,
            llm_invoked=False,
        )

        payment_header_2 = json.dumps({
            "payment_id": "test-alias-contract-addr-nonce-2",
            "payer_address": payer_acc.address,
            "amount_atomic": usdc_to_atomic(0.05),
            "network": "eip155:8453",
            "signature": "0xvalidmocksignature1234567890",
        })
        resp2 = client.post(
            "/audit",
            json={"contract_address": target, "proposal_description": "Audit via contract_address alias"},
            headers={"X-PAYMENT": payment_header_2},
        )
        assert resp2.status_code == 200
        body2 = resp2.json()
        assert body2.get("deterministic_check", {}).get("passed") is True
        assert "payment" in body2
        assert body2["payment"]["payment_id"] == "test-alias-contract-addr-nonce-2"
        assert facilitator.settle_calls == 1


# Top-level standalone aliases for direct import compatibility
def test_cdp_validator_24_checks_on_get_and_post_audit(tmp_path: Path):
    """Standalone wrapper executing CDP validator 24-check preflight on GET and POST /audit."""
    db_file = str(tmp_path / "cdp_standalone.db")
    storage = AgentStorage(db_path=db_file)
    evaluator = MockSemanticEvaluator()
    engine = ConditionAgentEngine(semantic_evaluator=evaluator, storage=storage)
    cfg = X402Config(enabled=True, price_per_eval_usdc=0.05, network="eip155:8453")
    facilitator = MockX402Facilitator()

    app = create_app(
        engine=engine,
        storage=storage,
        x402_config=cfg,
        facilitator=facilitator,
        public_evaluate_only=True,
        enable_background_scanner=False,
    )
    client = TestClient(app)
    t = TestFastAPIAuditAndWellKnownX402()
    t.test_cdp_validator_24_checks_on_get_and_post_audit(client)


def test_post_audit_address_aliases_and_503_no_charge_on_rpc_error(tmp_path: Path):
    """Standalone wrapper executing address aliases and 503 no charge verification."""
    t = TestFastAPIAuditAndWellKnownX402()
    t.test_post_audit_address_aliases_and_503_no_charge_on_rpc_error(tmp_path)

