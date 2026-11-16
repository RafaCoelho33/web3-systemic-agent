"""
Unit and Integration Tests for Deep Source & Proxy Audit.
Covers:
1. Address extraction from storage words (_extract_address_from_word)
2. Proxy and state resolution (ContractSourceResolver.resolve_proxy_and_state):
   - Non-proxy contracts (all EIP-1967 slots zero)
   - EIP-1967 proxy contracts with implementation, admin, owner, and paused status
   - Beacon proxy contracts with implementation() probe
   - Upstream RPC network failure handling
3. Verified source code fetching (ContractSourceResolver.fetch_verified_source):
   - Sourcify API parsing, file prioritization, and character truncation
   - Etherscan v2 API fallback (single-file and multi-file standard JSON {{...}})
   - Unverified fallback and security warnings
4. FastAPI GET /audit/deep & POST /audit/deep:
   - 402 Payment Required discovery ($0.25 USDC) passing 24 CDP Validator checks
   - Paid audit execution with enriched context_metadata & payment settlement
   - 503 No-Charge-on-Error on upstream RPC failure
5. MCP deep_semantic_audit with proxy and verified source resolution
"""

import asyncio
import json
import os
import sys
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

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
    PaymentReceipt,
    SemanticCondition,
)
from src.source_resolver import (
    ContractSourceResolver,
    _extract_address_from_word,
    _sol_sort_key,
    _format_and_truncate_sol_files,
    extract_selectors_from_bytecode,
    MAX_SOURCE_CHARS,
    EIP1967_IMPLEMENTATION_SLOT,
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    SELECTOR_OWNER,
    SELECTOR_PAUSED,
    SELECTOR_IMPLEMENTATION,
)
from src.chain_inspector import ChainInspector
from src.x402_payment import (
    X402Config,
    MockX402Facilitator,
    usdc_to_atomic,
    DEFAULT_X402_PRICE_DEEP_AUDIT_USDC,
)
from src.mcp_server import Web3SystemicMCPServer
from src.engine import ConditionAgentEngine
from src.semantic_evaluator import MockSemanticEvaluator
from src.storage import AgentStorage
from src.api import create_app

try:
    from tests.test_x402_bazaar_cdp import simulate_cdp_validator
except ImportError:
    from test_x402_bazaar_cdp import simulate_cdp_validator


TARGET_CONTRACT = "0x4200000000000000000000000000000000000006"
IMPL_CONTRACT = "0x1111111111111111111111111111111111111111"
ADMIN_ADDR = "0x2222222222222222222222222222222222222222"
BEACON_ADDR = "0x4444444444444444444444444444444444444444"
OWNER_ADDR = "0x3333333333333333333333333333333333333333"

ZERO_BYTES_32 = b"\x00" * 32
ZERO_HEX_32 = "0x" + "0" * 64


def pad_address_to_word(addr: str) -> bytes:
    clean = addr[2:] if addr.startswith(("0x", "0X")) else addr
    return bytes.fromhex(clean.zfill(64))


# =========================================================================
# 1. Address Extraction From Storage Words
# =========================================================================

class TestExtractAddressFromWord:
    def test_extract_zero_words_return_none(self):
        """Zero words (bytes or hex) return None."""
        assert _extract_address_from_word(ZERO_BYTES_32) is None
        assert _extract_address_from_word(ZERO_HEX_32) is None
        assert _extract_address_from_word("0x" + "0" * 40) is None
        assert _extract_address_from_word(None) is None
        assert _extract_address_from_word("") is None
        assert _extract_address_from_word("0x1234") is None

    def test_extract_valid_address_word(self):
        """Valid 32-byte word with address in lower 20 bytes returns EIP-55 checksum address."""
        word_bytes = pad_address_to_word(TARGET_CONTRACT)
        extracted = _extract_address_from_word(word_bytes)
        assert extracted == Web3.to_checksum_address(TARGET_CONTRACT)

        # Hex string format
        word_hex = "0x" + word_bytes.hex()
        extracted_hex = _extract_address_from_word(word_hex)
        assert extracted_hex == Web3.to_checksum_address(TARGET_CONTRACT)


# =========================================================================
# 2. Proxy & State Resolution (resolve_proxy_and_state)
# =========================================================================

class TestContractSourceResolverProxyAndState:
    @pytest.mark.asyncio
    async def test_non_proxy_contract(self):
        """Non-proxy contract: all EIP-1967 storage slots zero -> is_proxy is False."""
        resolver = ContractSourceResolver()

        mock_w3 = MagicMock()
        mock_w3.eth = MagicMock()
        # Storage slots return 0x0
        mock_w3.eth.get_storage_at = AsyncMock(return_value=ZERO_BYTES_32)
        # owner() and paused() return 0x0
        mock_w3.eth.call = AsyncMock(return_value=ZERO_BYTES_32)

        with patch("src.chain_inspector.ChainInspector._get_or_create_w3", return_value=mock_w3):
            res = await resolver.resolve_proxy_and_state(8453, TARGET_CONTRACT)

        assert res["is_proxy"] is False
        assert res["implementation_address"] is None
        assert res["admin_address"] is None
        assert res["beacon_address"] is None
        assert res["effective_audit_address"] == Web3.to_checksum_address(TARGET_CONTRACT)
        assert res["rpc_error"] is None

    @pytest.mark.asyncio
    async def test_eip1967_proxy_contract(self):
        """EIP-1967 Proxy contract: implementation & admin slots populated, probes owner() and paused()."""
        resolver = ContractSourceResolver()

        impl_word = pad_address_to_word(IMPL_CONTRACT)
        admin_word = pad_address_to_word(ADMIN_ADDR)
        owner_word = pad_address_to_word(OWNER_ADDR)
        paused_word = bytes.fromhex("1".zfill(64))  # paused = True
        mock_bytecode = bytes.fromhex("60806040528063a9059cbb14")  # contains transfer selector

        mock_w3 = MagicMock()
        mock_w3.eth = MagicMock()

        async def mock_get_storage_at(addr, slot):
            if slot == EIP1967_IMPLEMENTATION_SLOT:
                return impl_word
            elif slot == EIP1967_ADMIN_SLOT:
                return admin_word
            return ZERO_BYTES_32

        async def mock_call(tx):
            data = tx.get("data", "")
            if data == SELECTOR_OWNER:
                return owner_word
            elif data == SELECTOR_PAUSED:
                return paused_word
            return ZERO_BYTES_32

        mock_w3.eth.get_storage_at = AsyncMock(side_effect=mock_get_storage_at)
        mock_w3.eth.call = AsyncMock(side_effect=mock_call)
        mock_w3.eth.get_code = AsyncMock(return_value=mock_bytecode)

        with patch("src.chain_inspector.ChainInspector._get_or_create_w3", return_value=mock_w3):
            res = await resolver.resolve_proxy_and_state(8453, TARGET_CONTRACT)

        assert res["is_proxy"] is True
        assert res["implementation_address"] == Web3.to_checksum_address(IMPL_CONTRACT)
        assert res["admin_address"] == Web3.to_checksum_address(ADMIN_ADDR)
        assert res["owner_address"] == Web3.to_checksum_address(OWNER_ADDR)
        assert res["is_paused"] is True
        assert res["effective_audit_address"] == Web3.to_checksum_address(IMPL_CONTRACT)
        assert res["implementation_bytecode_size"] == len(mock_bytecode)
        assert res["rpc_error"] is None

        # Implementation bytecode must be cached in ChainInspector._bytecode_cache
        cache_key = f"8453:{Web3.to_checksum_address(IMPL_CONTRACT)}"
        assert ChainInspector._bytecode_cache.get(cache_key) == mock_bytecode

    @pytest.mark.asyncio
    async def test_beacon_proxy_contract(self):
        """Beacon proxy: beacon slot non-zero -> probes implementation() on beacon address."""
        resolver = ContractSourceResolver()

        beacon_word = pad_address_to_word(BEACON_ADDR)
        impl_word = pad_address_to_word(IMPL_CONTRACT)

        mock_w3 = MagicMock()
        mock_w3.eth = MagicMock()

        async def mock_get_storage_at(addr, slot):
            if slot == EIP1967_BEACON_SLOT:
                return beacon_word
            return ZERO_BYTES_32

        async def mock_call(tx):
            to = tx.get("to")
            data = tx.get("data")
            if to == Web3.to_checksum_address(BEACON_ADDR) and data == SELECTOR_IMPLEMENTATION:
                return impl_word
            return ZERO_BYTES_32

        mock_w3.eth.get_storage_at = AsyncMock(side_effect=mock_get_storage_at)
        mock_w3.eth.call = AsyncMock(side_effect=mock_call)
        mock_w3.eth.get_code = AsyncMock(return_value=b"")

        with patch("src.chain_inspector.ChainInspector._get_or_create_w3", return_value=mock_w3):
            res = await resolver.resolve_proxy_and_state(8453, TARGET_CONTRACT)

        assert res["is_proxy"] is True
        assert res["beacon_address"] == Web3.to_checksum_address(BEACON_ADDR)
        assert res["implementation_address"] == Web3.to_checksum_address(IMPL_CONTRACT)
        assert res["effective_audit_address"] == Web3.to_checksum_address(IMPL_CONTRACT)

    @pytest.mark.asyncio
    async def test_rpc_failure_sets_rpc_error(self):
        """When all RPC nodes fail during storage slot queries, sets rpc_error."""
        resolver = ContractSourceResolver()

        mock_w3 = MagicMock()
        mock_w3.eth = MagicMock()
        mock_w3.eth.get_storage_at = AsyncMock(side_effect=Exception("HTTP 502 Bad Gateway: connection refused"))

        with patch("src.chain_inspector.ChainInspector._get_or_create_w3", return_value=mock_w3):
            res = await resolver.resolve_proxy_and_state(8453, TARGET_CONTRACT)

        assert res["is_proxy"] is False
        assert res["rpc_error"] is not None
        assert "502 Bad Gateway" in res["rpc_error"]


# =========================================================================
# 3. Verified Source Retrieval (fetch_verified_source)
# =========================================================================

class TestContractSourceResolverFetchVerifiedSource:
    @pytest.mark.asyncio
    async def test_sourcify_success_with_file_prioritization_and_truncation(self):
        """Sourcify API returns multiple .sol files, prioritizes main contract, and truncates if oversized."""
        resolver = ContractSourceResolver()

        mock_files = [
            {"name": "contracts/interfaces/IERC20.sol", "content": "interface IERC20 { function totalSupply() external view returns (uint256); }"},
            {"name": "contracts/MyToken.sol", "content": "contract MyToken is IERC20 { function mint() external {} }"},
            {"name": "contracts/libraries/SafeMath.sol", "content": "library SafeMath { function add(uint a, uint b) internal pure returns (uint) {} }"},
        ]
        mock_resp = httpx.Response(
            status_code=200,
            json={"files": mock_files, "status": "full"},
            request=httpx.Request("GET", "https://sourcify.dev"),
        )

        with patch.object(resolver, "_get_request", AsyncMock(return_value=mock_resp)):
            res = await resolver.fetch_verified_source(8453, TARGET_CONTRACT)

        assert res["verified"] is True
        assert res["provider"] == "sourcify"
        assert res["files_count"] == 3
        assert "MyToken" in res["contract_names"]
        assert "IERC20" in res["contract_names"]
        assert "SafeMath" in res["contract_names"]

        # Primary contract MyToken must appear first before interfaces/libraries
        idx_mytoken = res["source_code"].find("// File: contracts/MyToken.sol")
        idx_ierc20 = res["source_code"].find("// File: contracts/interfaces/IERC20.sol")
        assert idx_mytoken != -1 and idx_ierc20 != -1
        assert idx_mytoken < idx_ierc20

    @pytest.mark.asyncio
    async def test_sourcify_oversized_truncation(self):
        """Sourcify oversized source code is truncated cleanly at MAX_SOURCE_CHARS (24000)."""
        resolver = ContractSourceResolver()

        large_content = "contract HugeContract {\n" + ("    // filler comment line\n" * 1500) + "}\n"
        mock_files = [{"name": "contracts/HugeContract.sol", "content": large_content}]
        mock_resp = httpx.Response(
            status_code=200,
            json={"files": mock_files},
            request=httpx.Request("GET", "https://sourcify.dev"),
        )

        with patch.object(resolver, "_get_request", AsyncMock(return_value=mock_resp)):
            res = await resolver.fetch_verified_source(8453, TARGET_CONTRACT)

        assert res["verified"] is True
        assert res["truncated"] is True
        assert len(res["source_code"]) <= MAX_SOURCE_CHARS
        assert "[TRUNCATED]" in res["source_code"]

    @pytest.mark.asyncio
    async def test_etherscan_fallback_single_file(self, monkeypatch):
        """When Sourcify returns 404, falls back to Etherscan v2 API single-file source."""
        monkeypatch.setenv("ETHERSCAN_API_KEY", "MOCK_KEY_123")
        resolver = ContractSourceResolver()

        sourcify_404 = httpx.Response(status_code=404, request=httpx.Request("GET", "https://sourcify.dev"))
        etherscan_200 = httpx.Response(
            status_code=200,
            json={
                "status": "1",
                "message": "OK",
                "result": [
                    {
                        "SourceCode": "contract SequencerOracle { function updateFeed() external {} }",
                        "ContractName": "SequencerOracle",
                    }
                ],
            },
            request=httpx.Request("GET", "https://api.etherscan.io"),
        )

        async def mock_get(url, params=None):
            if "sourcify" in url:
                return sourcify_404
            return etherscan_200

        with patch.object(resolver, "_get_request", side_effect=mock_get):
            res = await resolver.fetch_verified_source(8453, TARGET_CONTRACT)

        assert res["verified"] is True
        assert res["provider"] == "etherscan_v2"
        assert res["files_count"] == 1
        assert "SequencerOracle" in res["contract_names"]
        assert "SequencerOracle" in res["source_code"]

    @pytest.mark.asyncio
    async def test_etherscan_fallback_multifile_standard_json(self, monkeypatch):
        """When Sourcify returns 404, falls back to Etherscan {{...}} standard JSON multi-file source."""
        monkeypatch.setenv("ETHERSCAN_API_KEY", "MOCK_KEY_123")
        resolver = ContractSourceResolver()

        raw_standard_json = json.dumps({
            "sources": {
                "contracts/Vault.sol": {"content": "contract Vault { function deposit() external {} }"},
                "contracts/interfaces/IVault.sol": {"content": "interface IVault {}"},
            }
        })
        # Etherscan wraps standard JSON in double braces {{ ... }}
        etherscan_source_code = f"{{{raw_standard_json}}}"

        sourcify_404 = httpx.Response(status_code=404, request=httpx.Request("GET", "https://sourcify.dev"))
        etherscan_200 = httpx.Response(
            status_code=200,
            json={
                "status": "1",
                "message": "OK",
                "result": [
                    {
                        "SourceCode": etherscan_source_code,
                        "ContractName": "Vault",
                    }
                ],
            },
            request=httpx.Request("GET", "https://api.etherscan.io"),
        )

        async def mock_get(url, params=None):
            if "sourcify" in url:
                return sourcify_404
            return etherscan_200

        with patch.object(resolver, "_get_request", side_effect=mock_get):
            res = await resolver.fetch_verified_source(8453, TARGET_CONTRACT)

        assert res["verified"] is True
        assert res["provider"] == "etherscan_v2"
        assert res["files_count"] == 2
        assert "Vault" in res["contract_names"]
        assert "// File: contracts/Vault.sol" in res["source_code"]

    @pytest.mark.asyncio
    async def test_unverified_fallback_when_both_fail(self):
        """When Sourcify returns 404 and no Etherscan key or Etherscan 404 -> verified is False."""
        resolver = ContractSourceResolver()
        mock_404 = httpx.Response(status_code=404, request=httpx.Request("GET", "https://sourcify.dev"))

        with patch.object(resolver, "_get_request", AsyncMock(return_value=mock_404)):
            res = await resolver.fetch_verified_source(8453, TARGET_CONTRACT)

        assert res["verified"] is False
        assert res["provider"] is None
        assert res["source_code"] == ""
        assert res["files_count"] == 0

    @pytest.mark.asyncio
    async def test_resolve_full_audit_context_generates_security_warnings(self):
        """resolve_full_audit_context generates security warnings for unverified source, proxy, paused, etc."""
        resolver = ContractSourceResolver()

        proxy_info = {
            "target_address": TARGET_CONTRACT,
            "chain_id": 8453,
            "is_proxy": True,
            "implementation_address": IMPL_CONTRACT,
            "admin_address": ADMIN_ADDR,
            "beacon_address": None,
            "owner_address": OWNER_ADDR,
            "is_paused": True,
            "effective_audit_address": IMPL_CONTRACT,
            "implementation_bytecode_size": 100,
            "rpc_error": None,
        }
        source_info = {
            "verified": False,
            "provider": None,
            "source_code": "",
            "contract_names": [],
            "files_count": 0,
            "truncated": False,
        }

        with patch.object(resolver, "resolve_proxy_and_state", AsyncMock(return_value=proxy_info)), \
             patch.object(resolver, "fetch_verified_source", AsyncMock(return_value=source_info)):
            ctx = await resolver.resolve_full_audit_context(8453, TARGET_CONTRACT)

        warnings = ctx["security_warnings"]
        assert "Unverified contract source code" in warnings
        assert "Upgradeable EIP-1967 proxy detected" in warnings
        assert "Contract is currently in paused state" in warnings
        assert any(ADMIN_ADDR in w for w in warnings)


# =========================================================================
# 4. FastAPI /audit/deep & MCP deep_semantic_audit
# =========================================================================

class TestFastAPIDeepAuditAndMCP:
    @pytest.fixture
    def deep_audit_client(self, tmp_path):
        db_file = str(tmp_path / "deep_audit_test.db")
        storage = AgentStorage(db_path=db_file)
        evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(semantic_evaluator=evaluator, storage=storage)
        cfg = X402Config(
            enabled=True,
            price_per_eval_usdc=0.05,
            price_per_preflight_usdc=0.01,
            price_per_deep_audit_usdc=0.25,
            network="eip155:8453",
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
        return {
            "client": TestClient(app),
            "storage": storage,
            "engine": engine,
            "cfg": cfg,
            "facilitator": facilitator,
        }

    def test_get_and_post_audit_deep_return_402_and_pass_cdp(self, deep_audit_client):
        """GET /audit/deep and unpaid POST /audit/deep return HTTP 402 ($0.25 USDC) and pass all 24 CDP checks."""
        client = deep_audit_client["client"]

        # 1. GET /audit/deep
        get_resp = client.get("/audit/deep")
        assert get_resp.status_code == 402
        get_cdp = simulate_cdp_validator(get_resp, url="/audit/deep")
        assert get_cdp["valid"] is True
        assert get_cdp["required_failed"] == 0
        assert get_cdp["total_checks"] == 24

        # 2. Unpaid POST /audit/deep probe
        post_resp = client.post("/audit/deep", json={})
        assert post_resp.status_code == 402
        post_cdp = simulate_cdp_validator(post_resp, url="/audit/deep")
        assert post_cdp["valid"] is True
        assert post_cdp["required_failed"] == 0
        assert post_cdp["total_checks"] == 24

    def test_paid_post_audit_deep_success(self, deep_audit_client):
        """Paid POST /audit/deep settles $0.25 USDC, enriches context_metadata, and returns HTTP 200 with PaymentReceipt."""
        client = deep_audit_client["client"]
        facilitator = deep_audit_client["facilitator"]
        engine = deep_audit_client["engine"]

        # Cache bytecode for deterministic check
        ChainInspector._set_bytecode_cache(f"8453:{TARGET_CONTRACT}", bytes.fromhex("60806040528063a9059cbb14"))
        ChainInspector._set_bytecode_cache(f"8453:{IMPL_CONTRACT}", bytes.fromhex("60806040528063a9059cbb14"))

        payer_acc = Account.create()
        payment_header = json.dumps({
            "payment_id": "test-deep-audit-success-001",
            "payer_address": payer_acc.address,
            "amount_atomic": usdc_to_atomic(0.25),
            "network": "eip155:8453",
            "signature": "0xvalidmocksignature1234567890",
        })

        mock_audit_ctx = {
            "target_address": TARGET_CONTRACT,
            "chain_id": 8453,
            "effective_audit_address": IMPL_CONTRACT,
            "proxy_info": {
                "is_proxy": True,
                "implementation_address": IMPL_CONTRACT,
                "admin_address": ADMIN_ADDR,
                "is_paused": False,
                "effective_audit_address": IMPL_CONTRACT,
                "rpc_error": None,
            },
            "source_info": {
                "verified": True,
                "provider": "sourcify",
                "contract_names": ["MyToken"],
                "files_count": 1,
                "truncated": False,
                "source_code": "contract MyToken { function mint() external {} }",
            },
            "effective_selectors": [{"selector": "0xa9059cbb", "signature": "transfer(address,uint256)"}],
            "security_warnings": ["Upgradeable EIP-1967 proxy detected"],
        }

        body = {
            "target_address": TARGET_CONTRACT,
            "chain_id": 8453,
            "proposal_description": "Audit token upgrade implementation",
            "resolve_proxy": True,
            "fetch_verified_source": True,
        }

        with patch("src.source_resolver.ContractSourceResolver.resolve_full_audit_context", AsyncMock(return_value=mock_audit_ctx)):
            resp = client.post("/audit/deep", json=body, headers={"X-PAYMENT": payment_header})

        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"].startswith("deep-audit-")
        assert data["deterministic_check"]["passed"] is True
        assert data["llm_invoked"] is True
        assert "payment" in data and data["payment"] is not None

        receipt = data["payment"]
        assert receipt["payment_id"] == "test-deep-audit-success-001"
        assert receipt["amount_usdc"] == 0.25
        assert receipt["amount_atomic"] == 250000
        assert facilitator.verify_calls == 1
        assert facilitator.settle_calls == 1

    def test_paid_post_audit_deep_rpc_error_returns_503_no_charge(self, deep_audit_client):
        """Paid POST /audit/deep when proxy resolution encounters RPC error returns 503 and does NOT settle."""
        client = deep_audit_client["client"]
        facilitator = deep_audit_client["facilitator"]

        payer_acc = Account.create()
        payment_header = json.dumps({
            "payment_id": "test-deep-audit-rpc-err-001",
            "payer_address": payer_acc.address,
            "amount_atomic": usdc_to_atomic(0.25),
            "network": "eip155:8453",
            "signature": "0xvalidmocksignature1234567890",
        })

        mock_audit_ctx_rpc_err = {
            "target_address": TARGET_CONTRACT,
            "chain_id": 8453,
            "effective_audit_address": TARGET_CONTRACT,
            "proxy_info": {
                "is_proxy": False,
                "implementation_address": None,
                "effective_audit_address": TARGET_CONTRACT,
                "rpc_error": "All RPC endpoints failed: Connection timeout",
            },
            "source_info": {"verified": False},
            "effective_selectors": [],
            "security_warnings": ["RPC error during proxy/state resolution: Connection timeout"],
        }

        body = {
            "target_address": TARGET_CONTRACT,
            "chain_id": 8453,
            "proposal_description": "Audit during RPC failure",
        }

        with patch("src.source_resolver.ContractSourceResolver.resolve_full_audit_context", AsyncMock(return_value=mock_audit_ctx_rpc_err)):
            resp = client.post("/audit/deep", json=body, headers={"X-PAYMENT": payment_header})

        assert resp.status_code == 503
        data = resp.json()
        assert data["payment_settled"] is False
        assert "upstream RPC error" in data["message"]
        assert facilitator.verify_calls == 1
        assert facilitator.settle_calls == 0  # No charge on error!

    @pytest.mark.asyncio
    async def test_mcp_deep_semantic_audit_with_source_and_proxy(self, deep_audit_client):
        """Calling MCP deep_semantic_audit with resolve_proxy=True and fetch_verified_source=True enriches context."""
        server = Web3SystemicMCPServer(
            engine=deep_audit_client["engine"],
            x402_config=deep_audit_client["cfg"],
            facilitator=deep_audit_client["facilitator"],
            storage=deep_audit_client["storage"],
            require_x402_for_deep_audit=False,  # Unpaid direct MCP test
        )

        ChainInspector._set_bytecode_cache(f"8453:{TARGET_CONTRACT}", bytes.fromhex("60806040528063a9059cbb14"))

        mock_audit_ctx = {
            "target_address": TARGET_CONTRACT,
            "chain_id": 8453,
            "effective_audit_address": IMPL_CONTRACT,
            "proxy_info": {"is_proxy": True, "implementation_address": IMPL_CONTRACT},
            "source_info": {"verified": True, "provider": "sourcify"},
            "effective_selectors": [{"selector": "0xa9059cbb", "signature": "transfer(address,uint256)"}],
            "security_warnings": ["Upgradeable EIP-1967 proxy detected"],
        }

        with patch("src.source_resolver.ContractSourceResolver.resolve_full_audit_context", AsyncMock(return_value=mock_audit_ctx)):
            res = await server.deep_semantic_audit(
                target_address=TARGET_CONTRACT,
                proposal_description="Test proxy audit via MCP",
                resolve_proxy=True,
                fetch_verified_source=True,
            )

        assert res.get("tool") == "deep_semantic_audit"
        assert res.get("status") == "completed"
        assert res.get("status_code") == 200
        assert res.get("deterministic_check", {}).get("passed") is True
