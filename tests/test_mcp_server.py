"""
Comprehensive automated test suite for Model Context Protocol (MCP) Server (src/mcp_server.py),
FastAPI /mcp endpoints in Public Evaluate-Only mode (src/api.py),
and directory manifests (smithery.yaml, glama.json, README.md).
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
import yaml
from fastapi.testclient import TestClient
from web3 import Web3

# Setup module search paths so tests can run from root, tests/, or src/
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(ROOT_DIR) in ("src", "tests"):
    ROOT_DIR = os.path.abspath(os.path.join(ROOT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
SCRIPTS_DIR = os.path.join(ROOT_DIR, "scripts")

for p in (ROOT_DIR, SRC_DIR, SCRIPTS_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from src.mcp_server import (
    Web3SystemicMCPServer,
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_NAME,
    MCP_SERVER_VERSION,
    run_dry_run,
)
from src.engine import ConditionAgentEngine
from src.semantic_evaluator import MockSemanticEvaluator
from src.chain_inspector import ChainInspector
from src.storage import AgentStorage
from src.api import create_app


# =========================================================================
# 1. MCP Protocol Handshake, Discovery & JSON-RPC Core Tests
# =========================================================================

class TestMCPProtocolHandshakeAndDiscovery:
    """Validates MCP JSON-RPC 2.0 handshake, ping, notifications, tool listings, and error handling."""

    @pytest.fixture
    def server(self) -> Web3SystemicMCPServer:
        return Web3SystemicMCPServer(require_x402_for_deep_audit=True)

    @pytest.mark.asyncio
    async def test_mcp_initialize(self, server: Web3SystemicMCPServer):
        """Validates 'initialize' returns protocolVersion '2024-11-05', capabilities, and serverInfo."""
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }
        res = await server.handle_jsonrpc(req)

        assert res is not None
        assert res["jsonrpc"] == "2.0"
        assert res["id"] == 1
        result = res["result"]
        assert result["protocolVersion"] == "2024-11-05"
        assert "capabilities" in result
        assert "tools" in result["capabilities"]
        assert "resources" in result["capabilities"]
        assert "prompts" in result["capabilities"]
        assert result["serverInfo"]["name"] == "web3-systemic-agent"
        assert result["serverInfo"]["version"] == "1.0.0"

    @pytest.mark.asyncio
    async def test_mcp_notifications_initialized(self, server: Web3SystemicMCPServer):
        """Validates 'notifications/initialized' returns None (JSON-RPC notification has no response)."""
        req = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
        res = await server.handle_jsonrpc(req)
        assert res is None

    @pytest.mark.asyncio
    async def test_mcp_ping(self, server: Web3SystemicMCPServer):
        """Validates 'ping' returns empty dict result."""
        req = {
            "jsonrpc": "2.0",
            "id": "ping-42",
            "method": "ping",
        }
        res = await server.handle_jsonrpc(req)
        assert res is not None
        assert res["jsonrpc"] == "2.0"
        assert res["id"] == "ping-42"
        assert res["result"] == {}

    @pytest.mark.asyncio
    async def test_mcp_tools_list_schema(self, server: Web3SystemicMCPServer):
        """Validates 'tools/list' returns all 4 required tools with valid JSON Schemas."""
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        }
        res = await server.handle_jsonrpc(req)
        assert res is not None
        assert res["id"] == 2
        tools = res["result"]["tools"]
        assert len(tools) == 4

        tool_map = {t["name"]: t for t in tools}
        expected_tools = {
            "scan_contract_selectors",
            "check_token_honeypot",
            "scan_dao_proposals",
            "deep_semantic_audit",
        }
        assert set(tool_map.keys()) == expected_tools

        for name, t in tool_map.items():
            assert "description" in t
            assert len(t["description"]) > 10
            schema = t["inputSchema"]
            assert schema["type"] == "object"
            assert "properties" in schema
            assert isinstance(schema["properties"], dict)

    @pytest.mark.asyncio
    async def test_mcp_resources_and_prompts_list(self, server: Web3SystemicMCPServer):
        """Validates 'resources/list' and 'prompts/list' return valid structures."""
        res_resources = await server.handle_jsonrpc({"jsonrpc": "2.0", "id": 10, "method": "resources/list"})
        assert res_resources is not None
        assert res_resources["result"] == {"resources": []}

        res_prompts = await server.handle_jsonrpc({"jsonrpc": "2.0", "id": 11, "method": "prompts/list"})
        assert res_prompts is not None
        assert res_prompts["result"] == {"prompts": []}

    @pytest.mark.asyncio
    async def test_mcp_unknown_method_returns_32601(self, server: Web3SystemicMCPServer):
        """Validates unknown method returns JSON-RPC error code -32601."""
        req = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "unsupported/method",
        }
        res = await server.handle_jsonrpc(req)
        assert res is not None
        assert res["id"] == 99
        assert "error" in res
        assert res["error"]["code"] == -32601
        assert "not found" in res["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_mcp_unknown_tool_call_returns_32601(self, server: Web3SystemicMCPServer):
        """Validates tools/call with unregistered tool name returns error code -32601."""
        req = {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {"name": "ghost_tool", "arguments": {}},
        }
        res = await server.handle_jsonrpc(req)
        assert res is not None
        assert res["id"] == 100
        assert "error" in res
        assert res["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_mcp_invalid_jsonrpc_request_format(self, server: Web3SystemicMCPServer):
        """Validates non-dict input returns JSON-RPC error code -32600."""
        res = await server.handle_jsonrpc("not a json object")  # type: ignore
        assert res is not None
        assert res["error"]["code"] == -32600


# =========================================================================
# 2. Stage 1 Free Tools (Zero LLM Cost) Tests
# =========================================================================

class TestMCPStage1FreeTools:
    """Validates Stage 1 deterministic free tools operate at $0.00 cost with zero LLM consumption."""

    @pytest.fixture
    def server(self) -> Web3SystemicMCPServer:
        return Web3SystemicMCPServer(require_x402_for_deep_audit=True)

    @pytest.mark.asyncio
    async def test_scan_contract_selectors_benign_erc20(self, server: Web3SystemicMCPServer):
        """
        Validates scan_contract_selectors with benign ERC-20 bytecode (transfer selector 0xa9059cbb):
        returns is_contract=True, risk_level='LOW', llm_invoked=False, cost_usd=0.0, upsell_recommendation=None.
        """
        benign_bytecode = "0x60806040528063a9059cbb1461002057"
        addr = "0x1111111111111111111111111111111111111111"

        res = await server.scan_contract_selectors(
            target_address=addr,
            chain_id=8453,
            bytecode_override=benign_bytecode,
        )

        assert res["target_address"] == Web3.to_checksum_address(addr)
        assert res["is_contract"] is True
        assert res["risk_level"] == "LOW"
        assert res["llm_invoked"] is False
        assert res["cost_usd"] == 0.0
        assert res["upsell_recommendation"] is None
        assert any(s["selector"] == "0xa9059cbb" for s in res["selectors_found"])
        assert len(res["high_risk_signatures"]) == 0

    @pytest.mark.asyncio
    async def test_scan_contract_selectors_high_risk_backdoor(self, server: Web3SystemicMCPServer):
        """
        Validates scan_contract_selectors with privileged bytecode (transferOwnership 0xf2fde38b, destroy 0x00f714ce):
        returns risk_level='HIGH', non-empty high_risk_signatures, llm_invoked=False, cost_usd=0.0,
        and upsell_recommendation mentioning 'deep_semantic_audit'.
        """
        high_risk_bytecode = "0x608060405263f2fde38b14610020576300f714ce1461004057"
        addr = "0x2222222222222222222222222222222222222222"

        res = await server.scan_contract_selectors(
            target_address=addr,
            chain_id=8453,
            bytecode_override=high_risk_bytecode,
        )

        assert res["is_contract"] is True
        assert res["risk_level"] == "HIGH"
        assert len(res["high_risk_signatures"]) > 0
        assert res["llm_invoked"] is False
        assert res["cost_usd"] == 0.0
        assert res["upsell_recommendation"] is not None
        assert "deep_semantic_audit" in res["upsell_recommendation"]

    @pytest.mark.asyncio
    async def test_scan_contract_selectors_invalid_address(self, server: Web3SystemicMCPServer):
        """Validates invalid EVM address via tools/call returns isError=True."""
        req = {
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {
                "name": "scan_contract_selectors",
                "arguments": {
                    "target_address": "0xinvalid_evm_address_1234",
                },
            },
        }
        res = await server.handle_jsonrpc(req)
        assert res is not None
        assert res["id"] == 50
        assert res["result"]["isError"] is True
        assert "Invalid Ethereum address" in res["result"]["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_check_token_honeypot_benign(self, server: Web3SystemicMCPServer):
        """Validates check_token_honeypot on benign token: is_honeypot_suspect=False, llm_invoked=False, cost_usd=0.0."""
        benign_token_bytecode = "0x608060405234801561001057600080fd5b508063a9059cbb14"
        addr = "0x3333333333333333333333333333333333333333"

        res = await server.check_token_honeypot(
            token_address=addr,
            chain_id=8453,
            bytecode_override=benign_token_bytecode,
        )

        assert res["token_address"] == Web3.to_checksum_address(addr)
        assert res["is_honeypot_suspect"] is False
        assert res["llm_invoked"] is False
        assert res["cost_usd"] == 0.0
        assert res["upsell_recommendation"] is None

    @pytest.mark.asyncio
    async def test_check_token_honeypot_blacklist_and_sell_fee(self, server: Web3SystemicMCPServer):
        """
        Validates check_token_honeypot on bytecode with blacklist (0xf9f02b01 isBlacklisted)
        and sell tax (0x4b7890ec setSellFee): is_honeypot_suspect=True, risk_score >= 7.0,
        and upsell_recommendation mentions 'deep_semantic_audit'.
        """
        honeypot_bytecode = "0x608060405263f9f02b011461002057634b7890ec1461004057"
        addr = "0x4444444444444444444444444444444444444444"

        res = await server.check_token_honeypot(
            token_address=addr,
            chain_id=8453,
            bytecode_override=honeypot_bytecode,
        )

        assert res["is_honeypot_suspect"] is True
        assert res["risk_score"] >= 7.0
        assert res["llm_invoked"] is False
        assert res["cost_usd"] == 0.0
        assert res["upsell_recommendation"] is not None
        assert "deep_semantic_audit" in res["upsell_recommendation"]

    @pytest.mark.asyncio
    async def test_check_token_honeypot_empty_bytecode_eoa(self, server: Web3SystemicMCPServer):
        """Validates check_token_honeypot on empty bytecode / EOA returns clean status."""
        res = await server.check_token_honeypot(
            token_address="0x5555555555555555555555555555555555555555",
            bytecode_override="0x",
        )
        assert res["is_honeypot_suspect"] is False
        assert res["risk_score"] == 0.0
        assert res["cost_usd"] == 0.0

    @pytest.mark.asyncio
    async def test_scan_dao_proposals_offline_curated(self, server: Web3SystemicMCPServer):
        """Validates scan_dao_proposals with use_curated_offline=True returns curated proposals without network calls."""
        res = await server.scan_dao_proposals(
            space_id="arbitrumfoundation.eth",
            limit=2,
            use_curated_offline=True,
        )

        assert res["space_id"] == "arbitrumfoundation.eth"
        assert res["proposals_count"] >= 1
        assert len(res["proposals"]) <= 2
        assert res["llm_invoked"] is False
        assert res["cost_usd"] == 0.0

        p = res["proposals"][0]
        assert "proposal_id" in p
        assert "title" in p
        assert "target_address" in p
        assert "calldata" in p

    @pytest.mark.asyncio
    async def test_tools_call_jsonrpc_wrapper_success(self, server: Web3SystemicMCPServer):
        """Validates tools/call execution via handle_jsonrpc returns structured JSON-RPC result."""
        req = {
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "scan_contract_selectors",
                "arguments": {
                    "target_address": "0x1111111111111111111111111111111111111111",
                    "bytecode_override": "0x60806040528063a9059cbb1461002057",
                },
            },
        }
        res = await server.handle_jsonrpc(req)
        assert res is not None
        assert res["id"] == "call-1"
        assert res["result"]["isError"] is False
        assert "structuredContent" in res["result"]
        assert res["result"]["structuredContent"]["is_contract"] is True


# =========================================================================
# 3. Stage 2 Paid Tool (deep_semantic_audit) Tests
# =========================================================================

class TestMCPStage2PaidTool:
    """Validates Stage 2 paid tool monetization gatekeeping, x402 402 responses, and audit completion."""

    @pytest.mark.asyncio
    async def test_deep_semantic_audit_without_payment_returns_402(self):
        """
        Validates deep_semantic_audit without x402_payment_header and without buyer_private_key
        (require_x402_for_deep_audit=True): returns status='payment_required', status_code=402,
        price_usdc=0.05, network='eip155:8453', and pre-validated rule_payload.
        """
        server = Web3SystemicMCPServer(
            buyer_private_key=None,
            require_x402_for_deep_audit=True,
        )
        target = "0x4200000000000000000000000000000000000006"
        desc = "Routine parameter update for L2 sequencer feed."

        res = await server.deep_semantic_audit(
            target_address=target,
            proposal_description=desc,
        )

        assert res.get("status") == "payment_required"
        assert res.get("status_code") == 402
        assert res.get("protocol") == "x402"
        assert res.get("network") == "eip155:8453"
        assert res.get("price_usdc") == 0.05
        assert "rule_payload" in res

        payload = res["rule_payload"]
        assert payload["deterministic"]["target_address"] == Web3.to_checksum_address(target)
        assert payload["semantic"]["enabled"] is True

    @pytest.mark.asyncio
    async def test_deep_semantic_audit_execution_with_mock_engine(self, tmp_path: Path):
        """
        Validates deep_semantic_audit when require_x402_for_deep_audit=False and injected ConditionAgentEngine
        with MockSemanticEvaluator executes two-stage audit: returns status='completed' and llm_invoked=True.
        """
        db_file = str(tmp_path / "mcp_audit_test.db")
        storage = AgentStorage(db_path=db_file)
        evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(
            semantic_evaluator=evaluator,
            storage=storage,
        )

        target = "0x4200000000000000000000000000000000000006"
        # Seed bytecode cache in ChainInspector to guarantee zero network RPC overhead
        ChainInspector._set_bytecode_cache(f"8453:{target}", bytes.fromhex("60806040528063a9059cbb14"))

        server = Web3SystemicMCPServer(
            engine=engine,
            require_x402_for_deep_audit=False,
        )

        res = await server.deep_semantic_audit(
            target_address=target,
            proposal_description="Transfer approved grant funds",
            calldata="0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111",
        )

        assert res.get("status") == "completed"
        assert res.get("llm_invoked") is True
        assert res.get("deterministic_check", {}).get("passed") is True
        assert "semantic_Evaluation" in res
        assert res["semantic_Evaluation"]["recommended_action"] in ("APPROVE", "MANUAL_REVIEW", "REJECT")


# =========================================================================
# 4. FastAPI /mcp Endpoints & Lockdown Whitelist Tests
# =========================================================================

class TestFastAPIMCPEndpoints:
    """Validates FastAPI /mcp endpoints under Public Evaluate-Only lockdown mode."""

    @pytest.fixture
    def test_client(self, tmp_path: Path) -> TestClient:
        db_file = str(tmp_path / "api_mcp_test.db")
        storage = AgentStorage(db_path=db_file)
        evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(semantic_evaluator=evaluator, storage=storage)

        # Create app explicitly in public_evaluate_only mode
        app = create_app(
            engine=engine,
            public_evaluate_only=True,
            enable_background_scanner=False,
        )
        return TestClient(app)

    def test_get_mcp_discovery_in_lockdown(self, test_client: TestClient):
        """Validates GET /mcp is whitelisted and returns 4 tools manifest when PUBLIC_EVALUATE_ONLY=true."""
        response = test_client.get("/mcp")
        assert response.status_code == 200

        data = response.json()
        assert data["name"] == "web3-systemic-agent"
        assert data["version"] == "1.0.0"
        assert data["protocolVersion"] == "2024-11-05"
        assert data["transport"] == "streamable-http"
        assert "tools" in data
        assert len(data["tools"]) == 4

        tool_names = [t["name"] for t in data["tools"]]
        assert "scan_contract_selectors" in tool_names
        assert "check_token_honeypot" in tool_names
        assert "scan_dao_proposals" in tool_names
        assert "deep_semantic_audit" in tool_names

    def test_post_mcp_initialize_in_lockdown(self, test_client: TestClient):
        """Validates POST /mcp with 'initialize' succeeds over HTTP in lockdown mode."""
        req = {
            "jsonrpc": "2.0",
            "id": "http-init-1",
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        response = test_client.post("/mcp", json=req)
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == "http-init-1"
        assert data["result"]["protocolVersion"] == "2024-11-05"
        assert data["result"]["serverInfo"]["name"] == "web3-systemic-agent"

    def test_post_mcp_tools_list_in_lockdown(self, test_client: TestClient):
        """Validates POST /mcp with 'tools/list' succeeds over HTTP in lockdown mode."""
        req = {
            "jsonrpc": "2.0",
            "id": "http-tools-1",
            "method": "tools/list",
        }
        response = test_client.post("/mcp", json=req)
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == "http-tools-1"
        assert len(data["result"]["tools"]) == 4

    def test_post_mcp_tools_call_in_lockdown(self, test_client: TestClient):
        """Validates POST /mcp with 'tools/call' executes tools over HTTP in lockdown mode."""
        req = {
            "jsonrpc": "2.0",
            "id": "http-call-1",
            "method": "tools/call",
            "params": {
                "name": "scan_contract_selectors",
                "arguments": {
                    "target_address": "0x1111111111111111111111111111111111111111",
                    "bytecode_override": "0x60806040528063a9059cbb1461002057",
                },
            },
        }
        response = test_client.post("/mcp", json=req)
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == "http-call-1"
        assert data["result"]["isError"] is False
        assert "structuredContent" in data["result"]
        assert data["result"]["structuredContent"]["is_contract"] is True

    def test_post_mcp_batch_requests(self, test_client: TestClient):
        """Validates POST /mcp accepts batch JSON-RPC request and returns batch responses."""
        batch = [
            {"jsonrpc": "2.0", "id": "batch-1", "method": "ping"},
            {"jsonrpc": "2.0", "id": "batch-2", "method": "prompts/list"},
        ]
        response = test_client.post("/mcp", json=batch)
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["id"] == "batch-1"
        assert data[1]["id"] == "batch-2"

    def test_post_mcp_invalid_json(self, test_client: TestClient):
        """Validates POST /mcp with non-JSON payload returns 400 Bad Request with -32700."""
        response = test_client.post(
            "/mcp",
            content=b"invalid raw json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == -32700


# =========================================================================
# 5. Manifests & Dry-Run CLI Verification Tests
# =========================================================================

class TestMCPManifestsAndDryRunCLI:
    """Validates configuration files smithery.yaml, glama.json, README.md, and dry-run CLI execution."""

    def test_smithery_manifest_exists_and_valid(self):
        """Verifies smithery.yaml exists in the repository root and has valid schema configuration."""
        smithery_path = Path(ROOT_DIR) / "smithery.yaml"
        assert smithery_path.exists(), "smithery.yaml must exist in repo root"

        with open(smithery_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        assert isinstance(data, dict)
        assert "startCommand" in data
        assert data["startCommand"]["type"] == "stdio"
        assert "commandFunction" in data["startCommand"]
        assert "python -m src.mcp_server" in data["startCommand"]["commandFunction"]["python"]

    def test_glama_manifest_exists_and_valid(self):
        """Verifies glama.json exists in the repository root and contains valid MCP directory metadata."""
        glama_path = Path(ROOT_DIR) / "glama.json"
        assert glama_path.exists(), "glama.json must exist in repo root"

        with open(glama_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert isinstance(data, dict)
        assert data["name"] == "web3-systemic-agent"
        assert "description" in data
        assert data.get("capabilities", {}).get("tools") is True

    def test_readme_mentions_mcp_server_and_tools(self):
        """Verifies README.md documents the MCP server, transport modes, and tool signatures."""
        readme_path = Path(ROOT_DIR) / "README.md"
        assert readme_path.exists(), "README.md must exist in repo root"

        with open(readme_path, "r", encoding="utf-8") as f:
            content = f.read().lower()

        assert "mcp" in content
        assert "scan_contract_selectors" in content
        assert "check_token_honeypot" in content
        assert "scan_dao_proposals" in content
        assert "deep_semantic_audit" in content
        assert "--dry-run" in content

    @pytest.mark.asyncio
    async def test_run_dry_run_function_succeeds(self):
        """Verifies calling run_dry_run() directly succeeds and returns exit code 0."""
        code = await run_dry_run()
        assert code == 0

    def test_cli_dry_run_subprocess_succeeds(self):
        """Verifies executing 'python src/mcp_server.py --dry-run' via subprocess terminates cleanly with code 0."""
        proc = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "mcp_server.py"), "--dry-run"],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0, f"CLI dry-run failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
        assert "Registered 4 MCP tools" in proc.stdout
        assert "All MCP self-tests PASSED successfully" in proc.stdout


# =========================================================================
# 6. Crawler Discovery, Agent-Teaching & Security Hardening Tests
# =========================================================================

class TestAgentDiscoveryTeachingAndSecurityHardening:
    """
    Validates crawler discovery manifests (robots.txt), agent-teaching files (llms.txt, llms-full.txt),
    standard well-known agent and MCP cards, and strict lockdown blocking unauthorized / crawler noise paths.
    """

    @pytest.fixture
    def test_client(self, tmp_path: Path) -> TestClient:
        db_file = str(tmp_path / "api_discovery_test.db")
        storage = AgentStorage(db_path=db_file)
        evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(semantic_evaluator=evaluator, storage=storage)

        app = create_app(
            engine=engine,
            public_evaluate_only=True,
            enable_background_scanner=False,
        )
        return TestClient(app)

    def test_robots_txt_public_and_valid(self, test_client: TestClient):
        """
        Validates that GET /robots.txt returns 200 OK, text/plain, and correctly
        specifies crawl allowances for agent endpoints (/mcp, /llms.txt) while
        disallowing sensitive/internal endpoints (/metrics/, /logs/).
        """
        response = test_client.get("/robots.txt")
        assert response.status_code == 200
        assert "text/plain" in response.headers.get("content-type", "").lower()

        text = response.text
        assert "User-agent: *" in text
        assert "Allow: /mcp" in text
        assert "Allow: /llms.txt" in text
        assert "Disallow: /metrics/" in text
        assert "Disallow: /logs/" in text

    def test_llms_txt_and_llms_full_txt_teach_agent_usage(self, test_client: TestClient):
        """
        Validates that GET /llms.txt and GET /llms-full.txt return 200 OK, text/plain,
        and thoroughly teach external LLM agents how to invoke all 4 MCP tools,
        the FastAPI endpoints (/mcp, /evaluate, /rules/validate), and x402 payment details.
        """
        for path in ("/llms.txt", "/llms-full.txt"):
            response = test_client.get(path)
            assert response.status_code == 200, f"{path} did not return 200 OK"
            assert "text/plain" in response.headers.get("content-type", "").lower()

            content = response.text
            # All 4 MCP tools must be documented
            assert "scan_contract_selectors" in content, f"{path} missing scan_contract_selectors"
            assert "check_token_honeypot" in content, f"{path} missing check_token_honeypot"
            assert "scan_dao_proposals" in content, f"{path} missing scan_dao_proposals"
            assert "deep_semantic_audit" in content, f"{path} missing deep_semantic_audit"

            # Key endpoints and protocols
            assert "/mcp" in content, f"{path} missing /mcp"
            assert "/evaluate" in content, f"{path} missing /evaluate"
            assert "/rules/validate" in content, f"{path} missing /rules/validate"
            assert "x402" in content.lower(), f"{path} missing x402 documentation"

    def test_well_known_mcp_server_card_and_agent_card(self, test_client: TestClient):
        """
        Validates discovery server-cards and agent-cards under /.well-known:
        - GET /.well-known/mcp/server-card.json and /.well-known/mcp.json return 200 OK JSON
          with serverInfo.name == 'io.github.RafaCoelho33/web3-systemic-agent',
          protocolVersion == '2024-11-05', and the 4 tools.
        - GET /.well-known/agent.json returns 200 OK JSON with capabilities.mcp is True,
          capabilities.x402 is True, payment, endpoints, and skills.
        """
        for card_path in ("/.well-known/mcp/server-card.json", "/.well-known/mcp.json"):
            res = test_client.get(card_path)
            assert res.status_code == 200, f"{card_path} did not return 200 OK"
            data = res.json()
            assert data.get("serverInfo", {}).get("name") == "io.github.RafaCoelho33/web3-systemic-agent"
            assert data.get("protocolVersion") == "2024-11-05"
            assert "tools" in data
            assert len(data["tools"]) == 4

            tool_names = {t["name"] for t in data["tools"]}
            assert tool_names == {
                "scan_contract_selectors",
                "check_token_honeypot",
                "scan_dao_proposals",
                "deep_semantic_audit",
            }

        # Agent card
        agent_res = test_client.get("/.well-known/agent.json")
        assert agent_res.status_code == 200, "/.well-known/agent.json did not return 200 OK"
        agent_data = agent_res.json()
        assert agent_data.get("capabilities", {}).get("mcp") is True
        assert agent_data.get("capabilities", {}).get("x402") is True
        assert "payment" in agent_data
        assert "endpoints" in agent_data
        assert "skills" in agent_data

    def test_security_txt_endpoints(self, test_client: TestClient):
        """
        Validates security.txt standard endpoints:
        - GET /.well-known/security.txt and GET /security.txt return 200 OK, text/plain,
          containing 'Contact:' and 'Expires:'.
        """
        for sec_path in ("/.well-known/security.txt", "/security.txt"):
            res = test_client.get(sec_path)
            assert res.status_code == 200, f"{sec_path} did not return 200 OK"
            assert "text/plain" in res.headers.get("content-type", "").lower()
            text = res.text
            assert "Contact:" in text
            assert "Expires:" in text

    def test_strict_lockdown_blocks_unauthorized_and_crawler_noise_paths(self, test_client: TestClient):
        """
        Verifies that in public_evaluate_only=True mode, probing unauthorized paths and
        common web crawler / vulnerability scanning paths returns 403 Forbidden, and
        the responses strictly enforce security headers:
        - x-content-type-options: nosniff
        - x-frame-options: DENY
        """
        forbidden_paths = [
            "/contact",
            "/about",
            "/privacy",
            "/terms",
            "/legal",
            "/imprint",
            "/impressum",
            "/team",
            "/.env",
            "/.git/config",
            "/metrics/summary",
            "/logs/errors",
            "/payments",
        ]

        for path in forbidden_paths:
            res = test_client.get(path)
            assert res.status_code == 403, f"Path {path} was not blocked by lockdown (status: {res.status_code})"

            # Verify mandatory security hardening headers
            headers_lower = {k.lower(): v for k, v in res.headers.items()}
            assert headers_lower.get("x-content-type-options") == "nosniff", (
                f"Path {path} missing 'X-Content-Type-Options: nosniff' header"
            )
            assert headers_lower.get("x-frame-options") == "DENY", (
                f"Path {path} missing 'X-Frame-Options: DENY' header"
            )

