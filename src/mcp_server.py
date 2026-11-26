"""
Model Context Protocol (MCP) Server for Web3 Condition-Action Trigger Agent.

Provides 5 Free Stage 1 Deterministic Inspection Tools:
  1. scan_contract_selectors: Discovers 4-byte EVM function selectors and flags administrative backdoors.
  2. check_token_honeypot: Static bytecode analysis for DEX honeypots, transfer taxes, and blacklist traps.
  3. scan_dao_proposals: Ingests and summarizes recent Snapshot DAO governance proposals with on-chain execution payloads.
  4. preflight_tx_firewall: Pre-sign security firewall for calldata, approvals, Permit2, EIP-712, prompt injection, and eth_call simulation.
  5. inspect_proxy_and_source: Resolves EIP-1967/Beacon proxy implementations, admin/owner/paused state, and verified Solidity source.

Provides 1 Paid Stage 2 Deep Semantic LLM Audit Tool:
  6. deep_semantic_audit: Two-stage on-chain gatekeeping + structured Google Gemini LLM security evaluation ($0.015 USDC standard / $0.25 USDC deep proxy + verified source x402 micropayment on Base Mainnet).

Usage:
  # 1. Run MCP Server in stdio mode (Claude Desktop / Cursor / Smithery / Glama):
  python -m src.mcp_server

  # 2. Offline verification and self-test:
  python src/mcp_server.py --dry-run
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union

import httpx
from eth_account import Account
from web3 import Web3

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
for _p in (_ROOT_DIR, _SRC_DIR, _SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.schemas import (
        ChainId,
        ConditionRulePayload,
        DeterministicCondition,
        SemanticCondition,
        FinalAgentResponse,
        PaymentReceipt,
        PreflightRequest,
        PreflightVerdict,
    )
    from src.preflight_firewall import PreflightFirewall
    from src.source_resolver import ContractSourceResolver
    from src.engine import ConditionAgentEngine
    from src.chain_inspector import ChainInspector
    from src.governance_connector import (
        SnapshotGovernanceConnector,
        get_curated_dao_proposals,
    )
    from src.x402_payment import (
        X402Config,
        parse_x402_header,
        create_eip3009_payment_header,
        get_x402_facilitator,
        usdc_to_atomic,
        DEFAULT_PAY_TO_ADDRESS,
    )
    from scripts.block_contract_scanner import (
        extract_selectors_from_bytecode,
        is_high_risk_signature,
        KNOWN_SELECTORS as SCANNER_KNOWN_SELECTORS,
        HIGH_RISK_KEYWORDS,
    )
    from scripts.dex_pool_monitor import (
        analyze_bytecode_honeypot,
        HONEYPOT_SELECTORS,
    )
except ImportError:
    from schemas import (
        ChainId,
        ConditionRulePayload,
        DeterministicCondition,
        SemanticCondition,
        FinalAgentResponse,
        PaymentReceipt,
        PreflightRequest,
        PreflightVerdict,
    )
    from preflight_firewall import PreflightFirewall
    from source_resolver import ContractSourceResolver
    from engine import ConditionAgentEngine
    from chain_inspector import ChainInspector
    from governance_connector import (
        SnapshotGovernanceConnector,
        get_curated_dao_proposals,
    )
    from x402_payment import (
        X402Config,
        parse_x402_header,
        create_eip3009_payment_header,
        get_x402_facilitator,
        usdc_to_atomic,
        DEFAULT_PAY_TO_ADDRESS,
    )
    from block_contract_scanner import (
        extract_selectors_from_bytecode,
        is_high_risk_signature,
        KNOWN_SELECTORS as SCANNER_KNOWN_SELECTORS,
        HIGH_RISK_KEYWORDS,
    )
    from dex_pool_monitor import (
        analyze_bytecode_honeypot,
        HONEYPOT_SELECTORS,
    )

logger = logging.getLogger("mcp_server")

MCP_PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_MCP_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
MCP_SERVER_NAME = "web3-systemic-agent"
MCP_SERVER_VERSION = "1.0.2"


def _validate_checksum_address(address: str) -> str:
    """Validates an EVM hex address and returns its canonical EIP-55 checksum string."""
    if not address or not isinstance(address, str) or not Web3.is_address(address):
        raise ValueError(f"Invalid Ethereum address: {address}")
    return Web3.to_checksum_address(address)


async def _resolve_contract_bytecode(
    checksum_addr: str,
    chain_id: int,
    bytecode_override: Optional[str] = None,
) -> bytes:
    """
    Resolves contract runtime bytecode with priority:
    1. Explicit bytecode_override (offline analysis / test fixture)
    2. ChainInspector FIFO memory cache
    3. On-chain EVM RPC query via ChainInspector
    """
    if bytecode_override is not None:
        raw = bytecode_override.strip()
        if raw.startswith("0x") or raw.startswith("0X"):
            raw = raw[2:]
        if not raw:
            return b""
        try:
            return bytes.fromhex(raw)
        except ValueError as exc:
            raise ValueError(f"Invalid bytecode_override hex string: {exc}")

    cache_key = f"{chain_id}:{checksum_addr}"
    cached = getattr(ChainInspector, "_bytecode_cache", {}).get(cache_key)
    if cached is not None:
        return cached

    try:
        inspector = ChainInspector(chain_id=chain_id)
        code = await inspector.w3.eth.get_code(checksum_addr)
        if isinstance(code, str):
            code_hex = code[2:] if code.startswith("0x") else code
            code_bytes = bytes.fromhex(code_hex) if code_hex else b""
        else:
            code_bytes = bytes(code) if code else b""
        ChainInspector._set_bytecode_cache(cache_key, code_bytes)
        return code_bytes
    except Exception as exc:
        logger.warning(f"Failed to fetch bytecode for {checksum_addr} on chain {chain_id}: {exc}")
        return b""


class Web3SystemicMCPServer:
    """
    Model Context Protocol (MCP) Server exposing Web3 Condition-Action Trigger Agent capabilities.
    Serves 5 Free Stage 1 Deterministic Inspection Tools and 1 Paid Stage 2 Semantic Audit Tool,
    plus MCP Resources and Prompts.
    """

    def __init__(
        self,
        engine: Optional[ConditionAgentEngine] = None,
        agent_url: Optional[str] = None,
        buyer_private_key: Optional[str] = None,
        require_x402_for_deep_audit: bool = True,
        x402_config: Optional[Any] = None,
        facilitator: Optional[Any] = None,
        storage: Optional[Any] = None,
        remote_mode: Optional[bool] = None,
        http_client: Optional[Any] = None,
    ):
        self.engine = engine
        self.agent_url = (
            agent_url
            or os.getenv("WEB3_AGENT_URL")
            or os.getenv("PUBLIC_API_URL")
            or "https://web3-systemic-agent.onrender.com"
        ).rstrip("/")
        self.buyer_private_key = buyer_private_key or os.getenv("X402_BUYER_PRIVATE_KEY")
        self.require_x402_for_deep_audit = require_x402_for_deep_audit
        self.x402_config = x402_config
        self.facilitator = facilitator
        self.storage = storage
        self.remote_mode = remote_mode
        self.http_client = http_client

    def _should_use_remote_api(self) -> bool:
        """Determines whether paid deep_semantic_audit calls should proxy to the remote HTTP API."""
        if self.remote_mode is not None:
            return bool(self.remote_mode)
        mode_env = os.getenv("MCP_EXECUTION_MODE", "").strip().lower()
        if mode_env == "remote":
            return True
        if mode_env == "local":
            return False
        if self.engine is not None or self.facilitator is not None or "pytest" in sys.modules:
            return False
        has_llm_key = bool(
            os.getenv("GEMINI_API_KEY")
            or os.getenv("GOOGLE_API_KEY")
            or os.getenv("OPENAI_API_KEY")
        )
        return not has_llm_key

    def get_tools_manifest(self, include_extended: bool = True) -> List[Dict[str, Any]]:
        """Returns the canonical MCP tools manifest defining all available tools and their schemas."""
        tools = [
            {
                "name": "scan_contract_selectors",
                "description": (
                    "Stage 1 Free ($0.00) deterministic EVM bytecode inspector that extracts 4-byte function "
                    "selectors and flags privileged backdoors (transferOwnership, upgradeTo, mint, selfdestruct). "
                    "Queries live RPC for chain_id (8453 Base, 84532 Base Sepolia, 42161 Arbitrum) unless "
                    "bytecode_override (0x hex) is supplied for offline analysis; falls back to empty bytecode on RPC error. "
                    "Returns JSON with is_contract, bytecode_size_bytes, selectors_found, high_risk_selectors, "
                    "risk_level (HIGH, LOW, EOA), and recommendation."
                ),
                "annotations": {
                    "title": "Scan Smart Contract Bytecode & Selectors",
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": True,
                },
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_address": {
                            "type": "string",
                            "description": "Hex EVM address of smart contract to inspect (e.g. '0x4200000000000000000000000000000000000006')",
                        },
                        "chain_id": {
                            "type": "integer",
                            "default": 8453,
                            "description": "EVM Chain ID (8453 for Base Mainnet, 84532 for Base Sepolia, 42161 for Arbitrum One)",
                        },
                        "bytecode_override": {
                            "type": "string",
                            "description": "Optional raw contract runtime bytecode hex string (0x...) for offline analysis without RPC calls",
                        },
                    },
                    "required": ["target_address"],
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "stage": {"type": "integer"},
                        "cost_usd": {"type": "number"},
                        "target_address": {"type": "string"},
                        "chain_id": {"type": "integer"},
                        "is_contract": {"type": "boolean"},
                        "bytecode_size_bytes": {"type": "integer"},
                        "selectors_found": {"type": "array", "items": {"type": "object"}},
                        "high_risk_selectors": {"type": "array", "items": {"type": "string"}},
                        "high_risk_signatures": {"type": "array", "items": {"type": "string"}},
                        "risk_level": {"type": "string", "enum": ["HIGH", "LOW", "EOA"]},
                        "recommendation": {"type": "string"},
                        "upsell_recommendation": {"type": ["string", "null"]},
                        "llm_invoked": {"type": "boolean"},
                    },
                    "required": ["target_address", "is_contract", "selectors_found", "high_risk_selectors", "risk_level"],
                },
            },
            {
                "name": "check_token_honeypot",
                "description": (
                    "Stage 1 Free ($0.00) static DEX token bytecode scanner that detects blacklist traps "
                    "(isBlacklisted, setBlacklist), 100% sell-tax modifiers (setTax, setFee), trading freezes (pause), "
                    "and SELFDESTRUCT opcodes. Fetches live token_address bytecode on chain_id unless bytecode_override "
                    "(0x hex) is provided for offline execution; returns safe EOA status if bytecode is empty. "
                    "Returns JSON with is_contract, is_honeypot_suspect (bool), risk_score (0.0-10.0), "
                    "threat_categories, risk_flags, and recommendation."
                ),
                "annotations": {
                    "title": "Check Token Honeypot & Tax Traps",
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": True,
                },
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "token_address": {
                            "type": "string",
                            "description": "Hex EVM address of token contract to inspect for honeypot traps",
                        },
                        "chain_id": {
                            "type": "integer",
                            "default": 8453,
                            "description": "EVM Chain ID (8453 for Base Mainnet)",
                        },
                        "bytecode_override": {
                            "type": "string",
                            "description": "Optional raw token runtime bytecode hex string (0x...) for offline analysis",
                        },
                    },
                    "required": ["token_address"],
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "stage": {"type": "integer"},
                        "cost_usd": {"type": "number"},
                        "token_address": {"type": "string"},
                        "chain_id": {"type": "integer"},
                        "is_contract": {"type": "boolean"},
                        "bytecode_size_bytes": {"type": "integer"},
                        "is_honeypot_suspect": {"type": "boolean"},
                        "risk_score": {"type": "number"},
                        "threat_categories": {"type": "array", "items": {"type": "string"}},
                        "categories_detected": {"type": "array", "items": {"type": "string"}},
                        "risk_flags": {"type": "array", "items": {"type": "string"}},
                        "recommendation": {"type": "string"},
                        "upsell_recommendation": {"type": ["string", "null"]},
                        "llm_invoked": {"type": "boolean"},
                    },
                    "required": ["token_address", "is_honeypot_suspect", "risk_score", "threat_categories", "risk_flags"],
                },
            },
            {
                "name": "scan_dao_proposals",
                "description": (
                    "Stage 1 Free ($0.00) governance scanner that fetches up to limit (1-20) recent Snapshot DAO "
                    "proposals for space_id (e.g. arbitrumfoundation.eth, aavedao.eth, ens.eth) and extracts on-chain "
                    "target addresses and calldata to spot hostile takeover payloads. Queries Snapshot GraphQL API "
                    "by default, or falls back to deterministic offline fixtures when use_curated_offline=true or "
                    "network fails. Returns JSON with space_id, proposals_count, proposals (id, title, target_address, "
                    "calldata, value_wei, state), and recommendation."
                ),
                "annotations": {
                    "title": "Scan Snapshot DAO Governance Proposals",
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": True,
                },
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "space_id": {
                            "type": "string",
                            "default": "arbitrumfoundation.eth",
                            "description": "Snapshot DAO space ENS identifier (e.g., 'arbitrumfoundation.eth', 'aavedao.eth', 'ens.eth')",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 3,
                            "description": "Maximum number of proposals to fetch (default: 3)",
                        },
                        "use_curated_offline": {
                            "type": "boolean",
                            "default": False,
                            "description": "If true, returns verified realistic offline curated proposals without outbound network calls",
                        },
                    },
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "stage": {"type": "integer"},
                        "cost_usd": {"type": "number"},
                        "space_id": {"type": "string"},
                        "proposals_count": {"type": "integer"},
                        "proposals": {"type": "array", "items": {"type": "object"}},
                        "recommendation": {"type": "string"},
                        "upsell_recommendation": {"type": ["string", "null"]},
                        "llm_invoked": {"type": "boolean"},
                    },
                    "required": ["space_id", "proposals_count", "proposals"],
                },
            },
            {
                "name": "deep_semantic_audit",
                "description": (
                    "Stage 2 Paid ($0.015 USDC standard / $0.25 USDC deep proxy + verified source via x402 on Base Mainnet) "
                    "hybrid audit combining Stage 1 on-chain gatekeeping with Stage 2 Gemini LLM evaluation to verify "
                    "proposal_description claims against target_address bytecode and calldata under policy_prompt. "
                    "Non-idempotent due to LLM evaluation and single-use EIP-3009 x402_payment_header nonce; omitting "
                    "x402_payment_header safely returns an HTTP 402 payment challenge without charging. Breaching "
                    "risk_threshold (0.0-10.0) escalates decision to REJECT. Returns JSON with status, decision "
                    "(APPROVE, MANUAL_REVIEW, REJECT), risk_score, reasoning, and flagged_issues."
                ),
                "annotations": {
                    "title": "Deep Semantic LLM Governance & Contract Audit (x402)",
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": False,
                    "openWorldHint": True,
                },
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_address": {
                            "type": "string",
                            "description": "Hex EVM address of smart contract under evaluation",
                        },
                        "proposal_description": {
                            "type": "string",
                            "description": "Natural language claim or governance proposal description explaining the intent of the transaction",
                        },
                        "policy_prompt": {
                            "type": "string",
                            "default": (
                                "Audit contract and proposal for unauthorized privilege escalation, "
                                "proxy upgrades, honeypot traps, or treasury drainage."
                            ),
                            "description": "Security policy or governance criteria to audit against",
                        },
                        "calldata": {
                            "type": "string",
                            "default": "0x",
                            "description": "Transaction hex calldata or function selector being executed",
                        },
                        "chain_id": {
                            "type": "integer",
                            "default": 8453,
                            "description": "EVM Chain ID (default: 8453 for Base Mainnet)",
                        },
                        "risk_threshold": {
                            "type": "number",
                            "default": 7.0,
                            "description": "Risk score threshold (0.0 to 10.0) above which the audit triggers rejection or alert",
                        },
                        "x402_payment_header": {
                            "type": "string",
                            "description": "Optional Base64-encoded EIP-3009 transferWithAuthorization payment header satisfying $0.015 USDC (standard) or $0.25 USDC (deep proxy + verified source) requirement",
                        },
                        "resolve_proxy": {
                            "type": "boolean",
                            "default": False,
                            "description": "If true, resolves EIP-1967/1822 proxy implementation contract and inspects implementation state",
                        },
                        "fetch_verified_source": {
                            "type": "boolean",
                            "default": False,
                            "description": "If true, fetches verified Solidity source code from block explorers (Etherscan, Basescan, Sourcify)",
                        },
                    },
                    "required": ["target_address", "proposal_description"],
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "stage": {"type": "integer"},
                        "status": {"type": "string", "enum": ["completed", "payment_required"]},
                        "status_code": {"type": "integer"},
                        "decision": {"type": "string"},
                        "risk_score": {"type": "number"},
                        "reasoning": {"type": "string"},
                        "flagged_issues": {"type": "array", "items": {"type": "string"}},
                        "llm_invoked": {"type": "boolean"},
                    },
                    "required": ["tool", "stage", "status"],
                },
            },
        ]

        if include_extended:
            tools.append({
                "name": "preflight_tx_firewall",
                "description": (
                    "Stage 1 Free ($0.00) pre-sign security firewall evaluating EVM transaction risks, "
                    "calldata decoding, unlimited token approvals, Permit2 signatures, EIP-712 typed data phishing, "
                    "Indirect Prompt Injections in untrusted calldata/descriptions, and simulated state changes via eth_call. "
                    "Returns JSON with verdict (ALLOW, BLOCK, MANUAL_REVIEW), risk_score (0.0-10.0), reasons, and simulation details."
                ),
                "annotations": {
                    "title": "Preflight Transaction Security Firewall",
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": True,
                },
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "to_address": {
                            "type": "string",
                            "description": "Target contract or recipient EVM address",
                        },
                        "target_address": {
                            "type": "string",
                            "description": "Alias for to_address",
                        },
                        "from_address": {
                            "type": "string",
                            "description": "Optional sender EVM address",
                        },
                        "calldata": {
                            "type": "string",
                            "default": "0x",
                            "description": "Hex transaction calldata",
                        },
                        "value_wei": {
                            "type": "integer",
                            "default": 0,
                            "description": "Transaction value in Wei",
                        },
                        "chain_id": {
                            "type": "integer",
                            "default": 8453,
                            "description": "EVM Chain ID (default: 8453 for Base Mainnet)",
                        },
                        "eip712_typed_data": {
                            "type": "object",
                            "description": "Optional EIP-712 typed data dictionary to inspect before signing",
                        },
                        "untrusted_text": {
                            "type": "string",
                            "description": "Optional untrusted text or proposal description to scan for prompt injection",
                        },
                        "run_simulation": {
                            "type": "boolean",
                            "default": True,
                            "description": "Whether to run eth_call simulation on chain",
                        },
                    },
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "stage": {"type": "integer"},
                        "cost_usd": {"type": "number"},
                        "verdict": {"type": "string", "enum": ["ALLOW", "BLOCK", "MANUAL_REVIEW"]},
                        "risk_score": {"type": "number"},
                        "flagged_issues": {"type": "array", "items": {"type": "string"}},
                        "approval_risks": {"type": "array", "items": {"type": "string"}},
                        "eip712_findings": {"type": "array", "items": {"type": "string"}},
                        "prompt_injection_detected": {"type": "boolean"},
                        "reasons": {"type": "array", "items": {"type": "string"}},
                        "summary": {"type": "string"},
                        "llm_invoked": {"type": "boolean"},
                    },
                    "required": ["tool", "stage", "verdict", "risk_score", "flagged_issues", "reasons"],
                },
            })
            tools.append({
                "name": "inspect_proxy_and_source",
                "description": (
                    "Stage 1 Free ($0.00) EIP-1967/Beacon proxy slot inspector and verified Solidity source resolver. "
                    "Probes on-chain implementation, admin, beacon, owner(), and paused() states via AsyncWeb3 and "
                    "retrieves verified source metadata from Sourcify/Etherscan v2 without invoking any LLM. "
                    "Supports offline_mode=True for deterministic dry-run or network-free verification."
                ),
                "annotations": {
                    "title": "Inspect EIP-1967 Proxy & Verified Source",
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": True,
                },
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_address": {
                            "type": "string",
                            "description": "Hex EVM address of smart contract or proxy to inspect",
                        },
                        "chain_id": {
                            "type": "integer",
                            "default": 8453,
                            "description": "EVM Chain ID (8453 for Base Mainnet, 84532 for Base Sepolia, 42161 for Arbitrum One)",
                        },
                        "fetch_verified_source": {
                            "type": "boolean",
                            "default": True,
                            "description": "Whether to query Sourcify/Etherscan v2 for verified Solidity source metadata",
                        },
                        "offline_mode": {
                            "type": "boolean",
                            "default": False,
                            "description": "If true, returns a deterministic clean offline structure without making RPC or HTTP calls",
                        },
                    },
                    "required": ["target_address"],
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "stage": {"type": "integer"},
                        "cost_usd": {"type": "number"},
                        "llm_invoked": {"type": "boolean"},
                        "target_address": {"type": "string"},
                        "chain_id": {"type": "integer"},
                        "effective_audit_address": {"type": "string"},
                        "is_proxy": {"type": "boolean"},
                        "implementation_address": {"type": ["string", "null"]},
                        "admin_address": {"type": ["string", "null"]},
                        "beacon_address": {"type": ["string", "null"]},
                        "owner_address": {"type": ["string", "null"]},
                        "is_paused": {"type": ["boolean", "null"]},
                        "source_verified": {"type": "boolean"},
                        "source_provider": {"type": ["string", "null"]},
                        "contract_names": {"type": "array", "items": {"type": "string"}},
                        "security_warnings": {"type": "array", "items": {"type": "string"}},
                        "recommendation": {"type": "string"},
                        "upsell_recommendation": {"type": ["string", "null"]},
                    },
                    "required": [
                        "tool",
                        "stage",
                        "cost_usd",
                        "llm_invoked",
                        "target_address",
                        "is_proxy",
                        "source_verified",
                    ],
                },
            })

        return tools

    async def scan_contract_selectors(
        self,
        target_address: str,
        chain_id: int = 8453,
        bytecode_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Tool 1: Discovers 4-byte EVM function selectors and flags high-risk administrative capabilities."""
        checksum_addr = _validate_checksum_address(target_address)
        code_bytes = await _resolve_contract_bytecode(checksum_addr, chain_id, bytecode_override)

        is_contract = bool(code_bytes and code_bytes not in (b"", b"\x00"))
        bytecode_size = len(code_bytes) if is_contract else 0

        if is_contract:
            selectors = extract_selectors_from_bytecode(code_bytes)
            high_risk = [
                s["signature"]
                for s in selectors
                if is_high_risk_signature(s.get("signature", ""))
            ]
            risk_level = "HIGH" if high_risk else "LOW"
            upsell = (
                "High-risk administrative capabilities detected. "
                "Run 'deep_semantic_audit' for comprehensive Gemini LLM security evaluation."
                if high_risk
                else None
            )
        else:
            selectors = []
            high_risk = []
            risk_level = "EOA"
            upsell = None

        return {
            "tool": "scan_contract_selectors",
            "stage": 1,
            "target_address": checksum_addr,
            "chain_id": chain_id,
            "is_contract": is_contract,
            "bytecode_size_bytes": bytecode_size,
            "selectors_found": selectors,
            "high_risk_selectors": high_risk,
            "high_risk_signatures": high_risk,
            "risk_level": risk_level,
            "recommendation": upsell or "No high-risk administrative selectors detected.",
            "llm_invoked": False,
            "cost_usd": 0.0,
            "upsell_recommendation": upsell,
        }

    async def check_token_honeypot(
        self,
        token_address: str,
        chain_id: int = 8453,
        bytecode_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Tool 2: Static bytecode analysis for DEX honeypots, transfer taxes, and blacklist traps."""
        checksum_addr = _validate_checksum_address(token_address)
        code_bytes = await _resolve_contract_bytecode(checksum_addr, chain_id, bytecode_override)

        if not code_bytes or code_bytes in (b"", b"\x00"):
            return {
                "tool": "check_token_honeypot",
                "stage": 1,
                "token_address": checksum_addr,
                "chain_id": chain_id,
                "is_contract": False,
                "bytecode_size_bytes": 0,
                "is_honeypot_suspect": False,
                "risk_score": 0.0,
                "threat_categories": [],
                "risk_flags": [],
                "categories_detected": [],
                "recommendation": "No static honeypot indicators detected.",
                "llm_invoked": False,
                "cost_usd": 0.0,
                "upsell_recommendation": None,
            }

        analysis = analyze_bytecode_honeypot(code_bytes)
        is_honeypot = bool(analysis.get("is_honeypot", False))
        categories = analysis.get("categories", {})
        active_cats = [k for k, v in categories.items() if v]
        severity = analysis.get("severity", "CLEAN")

        risk_score = (
            9.5
            if severity == "CRITICAL"
            else (7.5 if severity == "HIGH" else (5.0 if severity == "MEDIUM" else 1.0))
        )
        upsell = (
            "Critical honeypot indicators detected! Recommend executing 'deep_semantic_audit' before interacting."
            if is_honeypot
            else None
        )

        return {
            "tool": "check_token_honeypot",
            "stage": 1,
            "token_address": checksum_addr,
            "chain_id": chain_id,
            "is_contract": bool(code_bytes and code_bytes not in (b"", b"\x00")),
            "bytecode_size_bytes": len(code_bytes) if code_bytes and code_bytes not in (b"", b"\x00") else 0,
            "is_honeypot_suspect": is_honeypot,
            "risk_score": risk_score,
            "threat_categories": active_cats,
            "risk_flags": analysis.get("honeypot_flags", []),
            "categories_detected": active_cats,
            "recommendation": upsell or "No static honeypot indicators detected.",
            "llm_invoked": False,
            "cost_usd": 0.0,
            "upsell_recommendation": upsell,
        }

    async def scan_dao_proposals(
        self,
        space_id: str = "arbitrumfoundation.eth",
        limit: int = 3,
        use_curated_offline: bool = False,
    ) -> Dict[str, Any]:
        """Tool 3: Ingests and summarizes recent Snapshot DAO governance proposals with on-chain execution payloads."""
        proposals = []
        if use_curated_offline:
            all_curated = get_curated_dao_proposals(limit=10)
            matched = [p for p in all_curated if p.space_id == space_id]
            proposals = (matched if matched else all_curated)[:limit]
        else:
            try:
                connector = SnapshotGovernanceConnector()
                proposals = await connector.fetch_proposals(spaces=[space_id], limit=limit)
            except Exception as exc:
                logger.warning(f"Snapshot query failed ({exc}), falling back to curated proposals.")
                all_curated = get_curated_dao_proposals(limit=10)
                matched = [p for p in all_curated if p.space_id == space_id]
                proposals = (matched if matched else all_curated)[:limit]

        formatted = [
            {
                "proposal_id": p.proposal_id,
                "title": p.title,
                "state": p.state,
                "target_address": p.target_address,
                "calldata": p.calldata,
                "onchain_hints": {
                    "tx_value_wei": p.tx_value_wei,
                    "chain_id": int(p.chain_id),
                },
            }
            for p in proposals
        ]

        return {
            "tool": "scan_dao_proposals",
            "stage": 1,
            "space_id": space_id,
            "proposals_count": len(formatted),
            "proposals": formatted,
            "recommendation": "Use 'deep_semantic_audit' on any proposal with suspicious calldata or target contract.",
            "llm_invoked": False,
            "cost_usd": 0.0,
            "upsell_recommendation": "Use 'deep_semantic_audit' on any proposal with suspicious calldata or target contract.",
        }

    def _build_mcp_402_dict(
        self,
        payload: ConditionRulePayload,
        reason: Optional[str] = None,
        cfg: Optional[Any] = None,
        is_deep_tier: bool = False,
    ) -> Dict[str, Any]:
        net = cfg.network if cfg and getattr(cfg, "network", None) else "eip155:8453"
        if is_deep_tier:
            raw_price = getattr(cfg, "price_per_deep_audit_usdc", None) if cfg else None
            price = float(
                raw_price
                if raw_price is not None
                else os.getenv("X402_PRICE_DEEP_AUDIT", "0.25")
            )
            evaluate_endpoint = f"{self.agent_url}/audit/deep"
        else:
            raw_price = getattr(cfg, "price_per_eval_usdc", None) if cfg else None
            price = float(
                raw_price
                if raw_price is not None
                else os.getenv("X402_PRICE_EVALUATE", "0.015")
            )
            evaluate_endpoint = f"{self.agent_url}/evaluate"

        pay_to = (
            cfg.pay_to_address
            if cfg and getattr(cfg, "pay_to_address", None) and cfg.pay_to_address != DEFAULT_PAY_TO_ADDRESS
            else os.getenv("PAY_TO_ADDRESS", "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63")
        )
        price_label = f"${price:.3f}".rstrip("0").rstrip(".")
        return {
            "tool": "deep_semantic_audit",
            "stage": 2,
            "status": "payment_required",
            "status_code": 402,
            "protocol": "x402",
            "network": net,
            "price_usdc": price,
            "pay_to_address": pay_to,
            "evaluate_endpoint": evaluate_endpoint,
            "message": reason or f"Stage 2 Deep Semantic LLM Audit requires a {price_label} USDC x402 micropayment on Base Mainnet.",
            "reason": reason or "Payment Required",
            "instructions": "Provide 'x402_payment_header' (Base64 EIP-3009 authorization) or configure X402_BUYER_PRIVATE_KEY in the MCP environment.",
            "rule_payload": payload.model_dump(mode="json"),
        }

    async def preflight_tx_firewall(
        self,
        to_address: Optional[str] = None,
        target_address: Optional[str] = None,
        from_address: Optional[str] = None,
        calldata: str = "0x",
        value_wei: int = 0,
        chain_id: int = 8453,
        eip712_typed_data: Optional[Dict[str, Any]] = None,
        untrusted_text: Optional[str] = None,
        run_simulation: bool = True,
    ) -> Dict[str, Any]:
        """Tool 5: Stage 1 Free pre-sign security firewall evaluating EVM tx risks, calldata, Permit2, EIP-712, prompt injection, and simulations."""
        try:
            cid = ChainId(chain_id)
        except ValueError:
            cid = ChainId.BASE_MAINNET

        req = PreflightRequest(
            chain_id=cid,
            to_address=to_address,
            target_address=target_address,
            from_address=from_address,
            calldata=calldata,
            value_wei=value_wei,
            eip712_typed_data=eip712_typed_data,
            untrusted_text=untrusted_text,
            run_simulation=run_simulation,
        )
        firewall = getattr(self, "preflight_firewall", None) or PreflightFirewall()
        verdict = await firewall.evaluate(req)
        dumped = verdict.model_dump(mode="json")
        dumped["tool"] = "preflight_tx_firewall"
        dumped["stage"] = 1
        dumped["cost_usd"] = 0.0
        dumped["reasons"] = list(dumped.get("flagged_issues", []))
        return dumped

    async def inspect_proxy_and_source(
        self,
        target_address: str,
        chain_id: int = 8453,
        fetch_verified_source: bool = True,
        offline_mode: bool = False,
    ) -> Dict[str, Any]:
        """Tool 6: Stage 1 Free EIP-1967/Beacon proxy slot inspector and verified Solidity source resolver."""
        checksum_addr = _validate_checksum_address(target_address)

        if offline_mode:
            return {
                "tool": "inspect_proxy_and_source",
                "stage": 1,
                "cost_usd": 0.0,
                "llm_invoked": False,
                "target_address": checksum_addr,
                "chain_id": chain_id,
                "effective_audit_address": checksum_addr,
                "is_proxy": False,
                "implementation_address": None,
                "admin_address": None,
                "beacon_address": None,
                "owner_address": None,
                "is_paused": None,
                "source_verified": False,
                "source_provider": None,
                "contract_names": [],
                "security_warnings": [],
                "recommendation": "Offline mode: skipped on-chain proxy and block explorer source resolution.",
                "upsell_recommendation": None,
            }

        resolver = getattr(self, "source_resolver", None) or ContractSourceResolver()
        audit_ctx = await resolver.resolve_full_audit_context(
            chain_id=chain_id,
            target_address=checksum_addr,
            resolve_proxy=True,
            fetch_source=fetch_verified_source,
        )
        proxy_info = audit_ctx.get("proxy_info", {}) or {}
        source_info = audit_ctx.get("source_info", {}) or {}
        effective_audit_address = (
            audit_ctx.get("effective_audit_address")
            or proxy_info.get("effective_audit_address")
            or checksum_addr
        )
        is_proxy = bool(proxy_info.get("is_proxy", False))
        source_verified = bool(source_info.get("verified"))
        security_warnings = list(audit_ctx.get("security_warnings", []))

        if is_proxy or security_warnings or source_verified:
            upsell: Optional[str] = (
                "Proxy, verified source, or security warnings detected. Run 'deep_semantic_audit' "
                "with resolve_proxy=True and fetch_verified_source=True ($0.25 USDC via x402) for "
                "full implementation and Solidity LLM evaluation."
            )
            recommendation = upsell
        else:
            upsell = None
            recommendation = (
                "No EIP-1967 proxy slots or verified source detected. Run 'scan_contract_selectors' "
                "for static bytecode inspection."
            )

        return {
            "tool": "inspect_proxy_and_source",
            "stage": 1,
            "cost_usd": 0.0,
            "llm_invoked": False,
            "target_address": checksum_addr,
            "chain_id": chain_id,
            "effective_audit_address": effective_audit_address,
            "is_proxy": is_proxy,
            "implementation_address": proxy_info.get("implementation_address"),
            "admin_address": proxy_info.get("admin_address"),
            "beacon_address": proxy_info.get("beacon_address"),
            "owner_address": proxy_info.get("owner_address"),
            "is_paused": proxy_info.get("is_paused"),
            "source_verified": source_verified,
            "source_provider": source_info.get("provider"),
            "contract_names": list(source_info.get("contract_names", [])),
            "security_warnings": security_warnings,
            "recommendation": recommendation,
            "upsell_recommendation": upsell,
        }

    async def _execute_remote_deep_audit(
        self,
        payload: ConditionRulePayload,
        checksum_addr: str,
        cid: ChainId,
        proposal_description: str,
        policy_prompt: str,
        calldata: str,
        risk_threshold: float,
        x402_payment_header: Optional[str],
        resolve_proxy: bool,
        fetch_verified_source: bool,
        is_deep: bool,
    ) -> Dict[str, Any]:
        """Delegates deep_semantic_audit execution to the remote HTTP API using x402."""
        cid_int = int(cid.value if hasattr(cid, "value") else cid)
        endpoint_path = "/audit/deep" if is_deep else "/audit"
        target_url = f"{self.agent_url}{endpoint_path}"

        if self.require_x402_for_deep_audit and not x402_payment_header and not self.buyer_private_key:
            return self._build_mcp_402_dict(payload, cfg=self.x402_config, is_deep_tier=is_deep)

        body: Dict[str, Any] = {
            "target_address": checksum_addr,
            "chain_id": cid_int,
            "proposal_description": proposal_description,
            "policy_prompt": policy_prompt,
            "calldata": calldata,
            "risk_threshold": risk_threshold,
        }
        if is_deep:
            body["resolve_proxy"] = resolve_proxy
            body["fetch_verified_source"] = fetch_verified_source

        cfg = self.x402_config or X402Config(
            enabled=True,
            network=os.getenv("X402_NETWORK", "eip155:8453"),
            price_per_eval_usdc=float(os.getenv("X402_PRICE_EVALUATE", "0.015")),
            price_per_deep_audit_usdc=float(os.getenv("X402_PRICE_DEEP_AUDIT", "0.25")),
            pay_to_address=os.getenv("PAY_TO_ADDRESS", "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"),
        )

        async def _run_with_client(client: Any) -> Dict[str, Any]:
            payment_hdr = x402_payment_header
            if not payment_hdr and self.buyer_private_key:
                fallback_price = (
                    float(getattr(cfg, "price_per_deep_audit_usdc", 0.25))
                    if is_deep
                    else float(getattr(cfg, "price_per_eval_usdc", 0.015))
                )
                pay_to = (
                    cfg.pay_to_address
                    if getattr(cfg, "pay_to_address", None) and cfg.pay_to_address != DEFAULT_PAY_TO_ADDRESS
                    else os.getenv("PAY_TO_ADDRESS", "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63")
                )
                amount_atomic = usdc_to_atomic(fallback_price)
                network = getattr(cfg, "network", None) or "eip155:8453"
                usdc_address: Optional[str] = None

                try:
                    probe_resp = await client.get(target_url)
                    if probe_resp.status_code == 402:
                        probe_json = probe_resp.json()
                        accepts = probe_json.get("accepts", [])
                        if isinstance(accepts, list) and accepts:
                            acc = accepts[0]
                            pay_to = acc.get("payTo") or pay_to
                            raw_amt = acc.get("amount") or acc.get("maxAmountRequired")
                            if raw_amt is not None:
                                amount_atomic = int(raw_amt)
                            network = acc.get("network") or network
                            usdc_address = acc.get("asset") or acc.get("usdcAddress") or usdc_address
                except Exception as exc:
                    logger.debug("Remote 402 challenge probe failed, using X402Config fallback: %s", exc)

                try:
                    account = Account.from_key(self.buyer_private_key)
                    payment_hdr = create_eip3009_payment_header(
                        account=account,
                        pay_to_address=pay_to,
                        amount_atomic=amount_atomic,
                        network=network,
                        usdc_address=usdc_address,
                        as_base64=True,
                    )
                except Exception as exc:
                    return self._build_mcp_402_dict(
                        payload,
                        reason=f"Invalid buyer private key or signing failure: {exc}",
                        cfg=cfg,
                        is_deep_tier=is_deep,
                    )

            req_headers = {"PAYMENT-SIGNATURE": payment_hdr} if payment_hdr else {}
            try:
                post_resp = await client.post(target_url, json=body, headers=req_headers)
            except Exception as exc:
                return {
                    "tool": "deep_semantic_audit",
                    "stage": 2,
                    "status": "error",
                    "status_code": 503,
                    "payment_settled": False,
                    "error": f"Remote API request failed: {exc}",
                    "remote_endpoint": target_url,
                }

            if post_resp.status_code == 200:
                remote_data = post_resp.json()
                sem = remote_data.get("semantic_Evaluation") or remote_data.get("semantic_evaluation") or {}
                det = remote_data.get("deterministic_check") or {}
                decision = (
                    sem.get("recommended_action")
                    if sem
                    else ("APPROVE" if det.get("passed") else "REJECT")
                )
                risk_score = sem.get("risk_score", 0.0) if sem else 0.0
                reasoning = sem.get("summary") if sem else det.get("reason", "")
                flagged_issues = sem.get("flagged_issues", []) if sem else []

                result = dict(remote_data)
                result["tool"] = "deep_semantic_audit"
                result["stage"] = 2
                result["status"] = "completed"
                result["status_code"] = 200
                result["decision"] = decision
                result["risk_score"] = risk_score
                result["reasoning"] = reasoning
                result["flagged_issues"] = flagged_issues
                result["remote_endpoint"] = target_url
                return result

            if post_resp.status_code == 402:
                reason = "Payment Required"
                remote_402: Dict[str, Any] = {}
                try:
                    remote_402 = post_resp.json()
                    reason = remote_402.get("message") or remote_402.get("error") or reason
                except Exception:
                    pass
                out_402 = self._build_mcp_402_dict(payload, reason=reason, cfg=cfg, is_deep_tier=is_deep)
                accepts = remote_402.get("accepts", [])
                if isinstance(accepts, list) and accepts:
                    acc = accepts[0]
                    if acc.get("payTo"):
                        out_402["pay_to_address"] = acc["payTo"]
                    if acc.get("network"):
                        out_402["network"] = acc["network"]
                    if acc.get("amount_usdc") is not None:
                        out_402["price_usdc"] = acc["amount_usdc"]
                return out_402

            err_detail = post_resp.text
            try:
                err_json = post_resp.json()
                err_detail = err_json.get("message") or err_json.get("error") or err_json.get("detail") or err_detail
            except Exception:
                pass
            return {
                "tool": "deep_semantic_audit",
                "stage": 2,
                "status": "error",
                "status_code": post_resp.status_code,
                "payment_settled": False,
                "error": str(err_detail),
                "remote_endpoint": target_url,
            }

        if self.http_client is not None:
            return await _run_with_client(self.http_client)
        async with httpx.AsyncClient(timeout=45.0) as client:
            return await _run_with_client(client)

    async def deep_semantic_audit(
        self,
        target_address: str,
        proposal_description: str,
        policy_prompt: str = (
            "Audit contract and proposal for unauthorized privilege escalation, "
            "proxy upgrades, honeypot traps, or treasury drainage."
        ),
        calldata: str = "0x",
        chain_id: int = 8453,
        risk_threshold: float = 7.0,
        x402_payment_header: Optional[str] = None,
        resolve_proxy: bool = False,
        fetch_verified_source: bool = False,
    ) -> Dict[str, Any]:
        """Tool 4: Two-stage on-chain gatekeeping + structured Gemini LLM security audit ($0.015 USDC standard / $0.25 USDC deep proxy + verified source x402 payment)."""
        checksum_addr = _validate_checksum_address(target_address)
        try:
            cid = ChainId(chain_id)
        except ValueError:
            cid = ChainId.BASE_MAINNET

        is_deep = bool(resolve_proxy or fetch_verified_source)
        selector = (
            calldata[:10].lower()
            if calldata and calldata != "0x" and len(calldata) >= 10
            else "0x"
        )
        payload = ConditionRulePayload(
            rule_id=f"mcp-audit-{checksum_addr.lower()[:8]}-{int(time.time())}",
            chain_id=cid,
            deterministic=DeterministicCondition(
                target_address=checksum_addr,
                min_value_wei=0,
                required_function_selectors=None,
                check_native_balance=False,
            ),
            semantic=SemanticCondition(
                enabled=True,
                policy_prompt=policy_prompt,
                risk_threshold=risk_threshold,
            ),
            context_metadata={
                "contract_address": checksum_addr,
                "proposal_description": proposal_description,
                "calldata": calldata,
                "calldata_analysis": {
                    "selector": selector,
                    "signature": ChainInspector.KNOWN_SELECTORS.get(
                        selector, "unknown_selector"
                    ),
                },
                "source": "mcp_server",
            },
        )

        if self._should_use_remote_api():
            return await self._execute_remote_deep_audit(
                payload=payload,
                checksum_addr=checksum_addr,
                cid=cid,
                proposal_description=proposal_description,
                policy_prompt=policy_prompt,
                calldata=calldata,
                risk_threshold=risk_threshold,
                x402_payment_header=x402_payment_header,
                resolve_proxy=resolve_proxy,
                fetch_verified_source=fetch_verified_source,
                is_deep=is_deep,
            )

        async def _enrich_audit_context():
            if resolve_proxy or fetch_verified_source:
                resolver = getattr(self, "source_resolver", None) or ContractSourceResolver()
                cid_int = int(cid.value if hasattr(cid, "value") else cid)
                audit_ctx = await resolver.resolve_full_audit_context(
                    chain_id=cid_int,
                    target_address=checksum_addr,
                    resolve_proxy=resolve_proxy,
                    fetch_source=fetch_verified_source,
                )
                effective_addr = (
                    audit_ctx.get("effective_audit_address")
                    or audit_ctx.get("proxy_info", {}).get("effective_audit_address")
                )
                if effective_addr:
                    payload.deterministic.target_address = effective_addr
                payload.context_metadata["effective_audit_address"] = effective_addr or checksum_addr
                payload.context_metadata["proxy_info"] = audit_ctx.get("proxy_info", {})
                payload.context_metadata["source_info"] = audit_ctx.get("source_info", {})
                payload.context_metadata["effective_selectors"] = audit_ctx.get("effective_selectors", [])
                payload.context_metadata["security_warnings"] = audit_ctx.get("security_warnings", [])

        if self.require_x402_for_deep_audit:
            if not x402_payment_header and not self.buyer_private_key:
                return self._build_mcp_402_dict(payload, cfg=self.x402_config, is_deep_tier=is_deep)

            cfg = self.x402_config or X402Config(
                enabled=True,
                network=os.getenv("X402_NETWORK", "eip155:8453"),
                price_per_eval_usdc=float(os.getenv("X402_PRICE_EVALUATE", "0.015")),
                price_per_deep_audit_usdc=float(os.getenv("X402_PRICE_DEEP_AUDIT", "0.25")),
                pay_to_address=os.getenv("PAY_TO_ADDRESS", "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"),
            )

            required_usdc = (
                float(getattr(cfg, "price_per_deep_audit_usdc", 0.25))
                if is_deep
                else float(getattr(cfg, "price_per_eval_usdc", 0.015))
            )
            endpoint_path = "/audit/deep" if is_deep else "/evaluate"

            if not x402_payment_header and self.buyer_private_key:
                try:
                    account = Account.from_key(self.buyer_private_key)
                    req_atomic = usdc_to_atomic(required_usdc)
                    x402_payment_header = create_eip3009_payment_header(
                        account=account,
                        pay_to_address=cfg.pay_to_address,
                        amount_atomic=req_atomic,
                        network=cfg.network,
                        as_base64=True,
                    )
                except Exception as exc:
                    return self._build_mcp_402_dict(
                        payload,
                        reason=f"Invalid buyer private key or signing failure: {exc}",
                        cfg=cfg,
                        is_deep_tier=is_deep,
                    )

            try:
                payment_data = parse_x402_header(x402_payment_header, default_network=cfg.network)
            except ValueError as exc:
                return self._build_mcp_402_dict(
                    payload,
                    reason=f"Malformed payment header: {exc}",
                    cfg=cfg,
                    is_deep_tier=is_deep,
                )

            payment_data["endpoint"] = endpoint_path

            if self.storage is not None and await self.storage.is_payment_settled(payment_data["payment_id"]):
                return self._build_mcp_402_dict(
                    payload,
                    reason="Payment already settled (replay detected)",
                    cfg=cfg,
                    is_deep_tier=is_deep,
                )

            facilitator = self.facilitator or get_x402_facilitator(cfg)
            required_atomic = usdc_to_atomic(required_usdc)

            ver = await facilitator.verify(payment_data, required_atomic, cfg)
            if not ver.valid:
                return self._build_mcp_402_dict(
                    payload,
                    reason=ver.reason or "Payment verification failed",
                    cfg=cfg,
                    is_deep_tier=is_deep,
                )

            if self.engine is None:
                self.engine = ConditionAgentEngine()

            if resolve_proxy or fetch_verified_source:
                await _enrich_audit_context()

            res = await self.engine.process_rule(payload, source="mcp_server")

            if res.deterministic_check.error is not None:
                return {
                    "tool": "deep_semantic_audit",
                    "stage": 2,
                    "status": "error",
                    "status_code": 503,
                    "payment_settled": False,
                    "error": res.deterministic_check.error,
                }

            settlement = await facilitator.settle(payment_data, required_atomic, cfg)
            if not settlement.settled:
                return self._build_mcp_402_dict(
                    payload,
                    reason=settlement.error or "Payment settlement failed",
                    cfg=cfg,
                    is_deep_tier=is_deep,
                )

            receipt = PaymentReceipt(
                payment_id=payment_data["payment_id"],
                payer_address=payment_data["payer_address"],
                pay_to_address=cfg.pay_to_address,
                amount_usdc=round(required_usdc, 6),
                amount_atomic=required_atomic,
                network=payment_data.get("network") or cfg.network,
                asset=cfg.asset,
                tx_hash=settlement.tx_hash or "",
                endpoint=endpoint_path,
                settled_at=datetime.now(timezone.utc).isoformat(),
            )
            res.payment = receipt
            if self.storage is not None:
                await self.storage.record_payment(receipt, rule_id=payload.rule_id)
        else:
            if self.engine is None:
                self.engine = ConditionAgentEngine()

            if resolve_proxy or fetch_verified_source:
                await _enrich_audit_context()

            res = await self.engine.process_rule(payload, source="mcp_server")

        sem = getattr(res, "semantic_Evaluation", None) or getattr(res, "semantic_evaluation", None)
        dumped = res.model_dump(mode="json")
        dumped["tool"] = "deep_semantic_audit"
        dumped["stage"] = 2
        dumped["status"] = "completed"
        dumped["status_code"] = 200
        dumped["decision"] = sem.recommended_action if sem else ("APPROVE" if res.deterministic_check.passed else "REJECT")
        dumped["risk_score"] = sem.risk_score if sem else 0.0
        dumped["reasoning"] = sem.summary if sem else res.deterministic_check.reason
        dumped["flagged_issues"] = sem.flagged_issues if sem else []
        return dumped

    def get_resources_manifest(self) -> List[Dict[str, Any]]:
        """Returns the canonical MCP resources manifest defining all readable agent resources."""
        return [
            {
                "uri": "web3://x402/pricing",
                "name": "x402 Micropayment Pricing & Tiers",
                "mimeType": "application/json",
                "description": (
                    "Current x402 USDC micropayment pricing tiers, supported EVM network profiles "
                    "(Base Mainnet, Base Sepolia, Arbitrum One), and free vs paid tool mapping."
                ),
            },
            {
                "uri": "web3://security/selectors-catalog",
                "name": "Known EVM Selectors & Honeypot Traps",
                "mimeType": "application/json",
                "description": (
                    "Static catalog of known 4-byte EVM administrative selectors, high-risk keywords, "
                    "and DEX honeypot/rugpull signatures."
                ),
            },
            {
                "uri": "web3://feed/dao-curated-proposals",
                "name": "Curated Snapshot DAO Governance Proposals",
                "mimeType": "application/json",
                "description": (
                    "Deterministic curated dataset of Snapshot DAO governance proposals with extracted "
                    "on-chain target contracts and execution calldata."
                ),
            },
            {
                "uri": "web3://feed/recent-audits",
                "name": "Recent Autonomous Security Audits Feed",
                "mimeType": "application/json",
                "description": (
                    "Most recent autonomous contract and governance security evaluations recorded in "
                    "AgentStorage."
                ),
            },
        ]

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Reads and returns the JSON payload for a known MCP resource URI."""
        if uri == "web3://x402/pricing":
            cfg = self.x402_config or X402Config(
                enabled=True,
                network=os.getenv("X402_NETWORK", "eip155:8453"),
                price_per_token_check_usdc=float(os.getenv("X402_PRICE_TOKEN_CHECK", "0.005")),
                price_per_preflight_usdc=float(os.getenv("X402_PRICE_PREFLIGHT", "0.01")),
                price_per_eval_usdc=float(os.getenv("X402_PRICE_EVALUATE", "0.015")),
                price_per_deep_audit_usdc=float(os.getenv("X402_PRICE_DEEP_AUDIT", "0.25")),
                pay_to_address=os.getenv("PAY_TO_ADDRESS", "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"),
            )
            pay_to = (
                cfg.pay_to_address
                if getattr(cfg, "pay_to_address", None) and cfg.pay_to_address != DEFAULT_PAY_TO_ADDRESS
                else os.getenv("PAY_TO_ADDRESS", "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63")
            )
            return {
                "protocol": "x402",
                "asset": getattr(cfg, "asset", "USDC"),
                "network": getattr(cfg, "network", "eip155:8453"),
                "pay_to_address": pay_to,
                "stage_1_free_mcp_tools": [
                    "scan_contract_selectors",
                    "check_token_honeypot",
                    "scan_dao_proposals",
                    "preflight_tx_firewall",
                    "inspect_proxy_and_source",
                ],
                "tiers": {
                    "token_check": {
                        "endpoint": "/token/check",
                        "price_usdc": float(getattr(cfg, "price_per_token_check_usdc", 0.005)),
                    },
                    "preflight": {
                        "endpoint": "/preflight",
                        "price_usdc": float(getattr(cfg, "price_per_preflight_usdc", 0.01)),
                    },
                    "standard_audit": {
                        "endpoint": "/audit",
                        "mcp_tool": "deep_semantic_audit",
                        "price_usdc": float(getattr(cfg, "price_per_eval_usdc", 0.015)),
                    },
                    "deep_audit": {
                        "endpoint": "/audit/deep",
                        "mcp_tool": "deep_semantic_audit (resolve_proxy=True or fetch_verified_source=True)",
                        "price_usdc": float(getattr(cfg, "price_per_deep_audit_usdc", 0.25)),
                    },
                },
            }

        if uri == "web3://security/selectors-catalog":
            return {
                "known_selectors": dict(SCANNER_KNOWN_SELECTORS),
                "high_risk_keywords": list(HIGH_RISK_KEYWORDS),
                "honeypot_selectors": dict(HONEYPOT_SELECTORS),
            }

        if uri == "web3://feed/dao-curated-proposals":
            proposals = get_curated_dao_proposals(limit=10)
            return {
                "count": len(proposals),
                "proposals": [p.model_dump(mode="json") for p in proposals],
            }

        if uri == "web3://feed/recent-audits":
            evaluations: List[Dict[str, Any]] = []
            if self.storage is not None and hasattr(self.storage, "get_recent_feed_evaluations"):
                rows = await self.storage.get_recent_feed_evaluations(limit=10)
                if isinstance(rows, list):
                    evaluations = rows
            return {
                "count": len(evaluations),
                "evaluations": evaluations,
            }

        raise ValueError(f"Resource not found: {uri}")

    def get_prompts_manifest(self) -> List[Dict[str, Any]]:
        """Returns the canonical MCP prompts manifest defining all reusable security audit workflows."""
        return [
            {
                "name": "audit-token-before-swap",
                "description": (
                    "Guided pre-swap security workflow for evaluating an ERC-20 token for honeypot traps, "
                    "privileged selectors, proxy upgradability, and optional deep LLM source audit."
                ),
                "arguments": [
                    {
                        "name": "token_address",
                        "description": "Hex EVM address of the token contract to audit before swapping",
                        "required": True,
                    },
                    {
                        "name": "chain_id",
                        "description": "EVM Chain ID (default: 8453 for Base Mainnet)",
                        "required": False,
                    },
                ],
            },
            {
                "name": "pre-sign-transaction-firewall",
                "description": (
                    "Pre-sign transaction security firewall workflow inspecting calldata, unlimited approvals, "
                    "Permit2, EIP-712 typed data phishing, prompt injections, and eth_call simulation."
                ),
                "arguments": [
                    {
                        "name": "to_address",
                        "description": "Target contract or recipient EVM hex address",
                        "required": True,
                    },
                    {
                        "name": "calldata",
                        "description": "Hex transaction calldata (default: 0x)",
                        "required": False,
                    },
                ],
            },
            {
                "name": "audit-dao-governance-space",
                "description": (
                    "Governance security workflow scanning recent Snapshot DAO proposals for hostile takeover "
                    "payloads and escalating suspicious execution calldata."
                ),
                "arguments": [
                    {
                        "name": "space_id",
                        "description": "Snapshot DAO space ENS identifier (default: arbitrumfoundation.eth)",
                        "required": False,
                    },
                ],
            },
        ]

    def get_prompt(
        self, name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Renders a named MCP prompt template with validated arguments."""
        args = arguments if isinstance(arguments, dict) else {}

        if name == "audit-token-before-swap":
            token_address = str(args.get("token_address") or "").strip()
            if not token_address:
                raise ValueError("Missing required prompt argument: 'token_address'")
            chain_id = args.get("chain_id", 8453)
            prompt_text = (
                f"Perform a pre-swap security audit for token `{token_address}` on chain_id={chain_id}:\n"
                f"1. Call `check_token_honeypot(token_address='{token_address}', chain_id={chain_id})` (Free Stage 1).\n"
                f"2. Call `scan_contract_selectors(target_address='{token_address}', chain_id={chain_id})` (Free Stage 1).\n"
                f"3. Call `inspect_proxy_and_source(target_address='{token_address}', chain_id={chain_id})` (Free Stage 1).\n"
                "4. If honeypot traps, privileged backdoors (mint/setTax/upgradeTo), or unverified proxy risks are flagged, "
                "escalate to `deep_semantic_audit` with `resolve_proxy=True` and `fetch_verified_source=True` before swapping."
            )
            return {
                "description": "Pre-swap ERC-20 token security audit workflow",
                "messages": [
                    {
                        "role": "user",
                        "content": {"type": "text", "text": prompt_text},
                    }
                ],
            }

        if name == "pre-sign-transaction-firewall":
            to_address = str(args.get("to_address") or "").strip()
            if not to_address:
                raise ValueError("Missing required prompt argument: 'to_address'")
            calldata = str(args.get("calldata") or "0x").strip()
            prompt_text = (
                f"Run a pre-sign firewall check before signing a transaction to `{to_address}` with calldata `{calldata}`:\n"
                f"1. Call `preflight_tx_firewall(to_address='{to_address}', calldata='{calldata}', run_simulation=True)` (Free Stage 1).\n"
                f"2. Call `inspect_proxy_and_source(target_address='{to_address}')` to verify whether the destination is an upgradeable proxy.\n"
                "3. Block execution immediately if `verdict == 'BLOCK'`, unlimited approval risks, EIP-712 phishing, or prompt injection are detected."
            )
            return {
                "description": "Pre-sign transaction security firewall inspection",
                "messages": [
                    {
                        "role": "user",
                        "content": {"type": "text", "text": prompt_text},
                    }
                ],
            }

        if name == "audit-dao-governance-space":
            space_id = str(args.get("space_id") or "arbitrumfoundation.eth").strip()
            prompt_text = (
                f"Audit recent governance proposals for Snapshot DAO space `{space_id}`:\n"
                f"1. Call `scan_dao_proposals(space_id='{space_id}', limit=5)` (Free Stage 1).\n"
                "2. For any proposal containing an on-chain `target_address` and non-empty `calldata`, run "
                "`preflight_tx_firewall` and `inspect_proxy_and_source`.\n"
                "3. Escalate suspicious or high-impact treasury/upgrade payloads to `deep_semantic_audit`."
            )
            return {
                "description": "Snapshot DAO governance security audit workflow",
                "messages": [
                    {
                        "role": "user",
                        "content": {"type": "text", "text": prompt_text},
                    }
                ],
            }

        raise ValueError(f"Prompt not found: {name}")

    async def handle_jsonrpc(
        self, request_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Handles a single JSON-RPC 2.0 request or notification according to MCP specifications."""
        if not isinstance(request_data, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: expected JSON object",
                },
            }

        req_id = request_data.get("id")
        method = request_data.get("method")

        # 1. initialize
        if method == "initialize":
            params = request_data.get("params")
            if not isinstance(params, dict):
                params = {}
            requested_ver = params.get("protocolVersion")
            negotiated_ver = (
                requested_ver
                if requested_ver in SUPPORTED_MCP_VERSIONS
                else MCP_PROTOCOL_VERSION
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated_ver,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": MCP_SERVER_NAME,
                        "version": MCP_SERVER_VERSION,
                    },
                    "instructions": (
                        "Use the five free Stage 1 tools (scan_contract_selectors, check_token_honeypot, "
                        "scan_dao_proposals, preflight_tx_firewall, inspect_proxy_and_source) first for "
                        "zero-cost deterministic screening. Escalate to the paid Stage 2 tool "
                        "(deep_semantic_audit, $0.015 USDC standard / $0.25 USDC deep proxy + verified source "
                        "via x402 on Base) only when high-risk selectors, honeypot traps, upgradeable proxies, "
                        "or suspicious governance calldata are detected."
                    ),
                },
            }

        # 2. notifications/initialized (notification - no response)
        if method == "notifications/initialized":
            return None

        # 3. ping
        if method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {},
            }

        # 3b. server/discover & rpc.discover
        if method in ("server/discover", "rpc.discover"):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "name": MCP_SERVER_NAME,
                    "version": MCP_SERVER_VERSION,
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "tools": self.get_tools_manifest(),
                },
            }

        # 3c. logging/setLevel
        if method == "logging/setLevel":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {},
            }

        # 4. tools/list
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.get_tools_manifest(),
                },
            }

        # 5. resources/list
        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resources": self.get_resources_manifest(),
                },
            }

        # 5b. resources/read
        if method == "resources/read":
            params = request_data.get("params")
            uri = params.get("uri") if isinstance(params, dict) else None
            if not uri or not isinstance(uri, str):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: 'uri' string is required",
                    },
                }
            try:
                data = await self.read_resource(uri)
            except ValueError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": str(exc),
                    },
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(data, indent=2, default=str),
                        }
                    ]
                },
            }

        # 6. prompts/list
        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "prompts": self.get_prompts_manifest(),
                },
            }

        # 6b. prompts/get
        if method == "prompts/get":
            params = request_data.get("params")
            name = params.get("name") if isinstance(params, dict) else None
            arguments = params.get("arguments") if isinstance(params, dict) else None
            if not name or not isinstance(name, str):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: 'name' string is required",
                    },
                }
            try:
                prompt_result = self.get_prompt(name, arguments)
            except ValueError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": str(exc),
                    },
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": prompt_result,
            }

        # 7. tools/call
        if method == "tools/call":
            params = request_data.get("params", {})
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            known_tools = {
                "scan_contract_selectors": self.scan_contract_selectors,
                "check_token_honeypot": self.check_token_honeypot,
                "scan_dao_proposals": self.scan_dao_proposals,
                "deep_semantic_audit": self.deep_semantic_audit,
                "preflight_tx_firewall": self.preflight_tx_firewall,
                "inspect_proxy_and_source": self.inspect_proxy_and_source,
            }

            if tool_name not in known_tools:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Tool '{tool_name}' not found",
                    },
                }

            try:
                fn = known_tools[tool_name]
                out = await fn(**arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(out, indent=2, default=str),
                            }
                        ],
                        "structuredContent": out,
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps({"error": str(exc)}),
                            }
                        ],
                        "isError": True,
                    },
                }

        # Unrecognized method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not found",
            },
        }


async def run_stdio_server(server: Web3SystemicMCPServer) -> None:
    """Runs the MCP server over standard I/O (JSON-RPC 2.0)."""
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        raw_text = line.strip()
        if not raw_text:
            continue
        try:
            req_data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
            continue

        resp = await server.handle_jsonrpc(req_data)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


async def run_dry_run() -> int:
    """Executes an offline self-test verifying all 6 MCP tools, resources, prompts, and protocol conformance."""
    print("=== Web3 Systemic Agent MCP Server Self-Test ===")
    server = Web3SystemicMCPServer(require_x402_for_deep_audit=True)
    manifest = server.get_tools_manifest()
    tool_names = [t["name"] for t in manifest]
    print(f"[1/9] Registered {len(manifest)} MCP tools: {', '.join(tool_names)}")
    assert len(manifest) == 6, f"Expected 6 tools, got {len(manifest)}"

    # 1. scan_contract_selectors
    benign_bytecode = "0x608060405234801561001057600080fd5b508063a9059cbb14"
    r1 = await server.scan_contract_selectors(
        target_address="0x3333333333333333333333333333333333333333",
        bytecode_override=benign_bytecode,
    )
    print(
        f"[2/9] Tool 'scan_contract_selectors' OK: risk_level={r1['risk_level']}, "
        f"selectors={len(r1['selectors_found'])}, cost=${r1['cost_usd']:.2f}"
    )
    assert r1["is_contract"] is True
    assert r1["cost_usd"] == 0.0

    # 2. check_token_honeypot
    honeypot_bytecode = "0x6080604052631e3dd19f14"  # setTax(uint256)
    r2 = await server.check_token_honeypot(
        token_address="0x4444444444444444444444444444444444444444",
        bytecode_override=honeypot_bytecode,
    )
    print(
        f"[3/9] Tool 'check_token_honeypot' OK: is_honeypot={r2['is_honeypot_suspect']}, "
        f"score={r2['risk_score']}, cost=${r2['cost_usd']:.2f}"
    )
    assert r2["cost_usd"] == 0.0

    # 3. scan_dao_proposals
    r3 = await server.scan_dao_proposals(use_curated_offline=True, limit=2)
    print(
        f"[4/9] Tool 'scan_dao_proposals' OK: count={r3['proposals_count']}, "
        f"cost=${r3['cost_usd']:.2f}"
    )
    assert r3["proposals_count"] >= 1
    assert r3["cost_usd"] == 0.0

    # 4. preflight_tx_firewall (offline without eth_call)
    r4_pf = await server.preflight_tx_firewall(
        to_address="0x4200000000000000000000000000000000000006",
        calldata="0x095ea7b30000000000000000000000001111111111111111111111111111111111111111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        run_simulation=False,
    )
    print(
        f"[5/9] Tool 'preflight_tx_firewall' OK: verdict={r4_pf['verdict']}, "
        f"risk_score={r4_pf['risk_score']}, cost=${r4_pf['cost_usd']:.2f}"
    )
    assert r4_pf["verdict"] in ("BLOCK", "MANUAL_REVIEW")
    assert r4_pf["risk_score"] >= 7.0
    assert r4_pf["reasons"] == r4_pf["flagged_issues"]
    assert r4_pf["cost_usd"] == 0.0

    # 5. inspect_proxy_and_source (offline_mode=True)
    r5_proxy = await server.inspect_proxy_and_source(
        target_address="0x4200000000000000000000000000000000000006",
        offline_mode=True,
    )
    print(
        f"[6/9] Tool 'inspect_proxy_and_source' OK: is_proxy={r5_proxy['is_proxy']}, "
        f"source_verified={r5_proxy['source_verified']}, cost=${r5_proxy['cost_usd']:.2f}"
    )
    assert r5_proxy["tool"] == "inspect_proxy_and_source"
    assert r5_proxy["is_proxy"] is False
    assert r5_proxy["source_verified"] is False
    assert r5_proxy["cost_usd"] == 0.0
    assert r5_proxy["llm_invoked"] is False

    # 6. deep_semantic_audit (expecting 402 payment required)
    r6 = await server.deep_semantic_audit(
        target_address="0x4200000000000000000000000000000000000006",
        proposal_description="Test proposal",
    )
    print(
        f"[7/9] Tool 'deep_semantic_audit' OK: status={r6.get('status')}, "
        f"status_code={r6.get('status_code')}, price_usdc={r6.get('price_usdc')}"
    )
    assert r6.get("status") == "payment_required"
    assert r6.get("status_code") == 402

    # 7. MCP resources/list & resources/read
    res_list = await server.handle_jsonrpc({"jsonrpc": "2.0", "id": "res-list", "method": "resources/list"})
    resources = res_list["result"]["resources"]
    assert len(resources) == 4, f"Expected 4 resources, got {len(resources)}"
    for res_item in resources:
        res_read = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": f"read-{res_item['uri']}",
            "method": "resources/read",
            "params": {"uri": res_item["uri"]},
        })
        assert "result" in res_read and len(res_read["result"]["contents"]) == 1
        parsed = json.loads(res_read["result"]["contents"][0]["text"])
        assert isinstance(parsed, dict)
    print(f"[8/9] MCP resources/list & resources/read OK: {len(resources)} resources verified")

    # 8. MCP prompts/list & prompts/get
    prm_list = await server.handle_jsonrpc({"jsonrpc": "2.0", "id": "prm-list", "method": "prompts/list"})
    prompts = prm_list["result"]["prompts"]
    assert len(prompts) == 3, f"Expected 3 prompts, got {len(prompts)}"
    sample_args = {
        "audit-token-before-swap": {"token_address": "0x4200000000000000000000000000000000000006"},
        "pre-sign-transaction-firewall": {"to_address": "0x4200000000000000000000000000000000000006", "calldata": "0x"},
        "audit-dao-governance-space": {"space_id": "arbitrumfoundation.eth"},
    }
    for prm_item in prompts:
        prm_get = await server.handle_jsonrpc({
            "jsonrpc": "2.0",
            "id": f"get-{prm_item['name']}",
            "method": "prompts/get",
            "params": {"name": prm_item["name"], "arguments": sample_args[prm_item["name"]]},
        })
        assert "result" in prm_get and len(prm_get["result"]["messages"]) >= 1
    print(f"[9/9] MCP prompts/list & prompts/get OK: {len(prompts)} prompts verified")

    print("=== All MCP self-tests PASSED successfully ===")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Web3 Systemic Agent MCP Server")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run offline self-test verification without starting stdio loop",
    )
    args = parser.parse_args()

    if args.dry_run:
        exit_code = asyncio.run(run_dry_run())
        sys.exit(exit_code)
    else:
        server = Web3SystemicMCPServer()
        asyncio.run(run_stdio_server(server))


if __name__ == "__main__":
    main()
