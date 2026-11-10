"""
Model Context Protocol (MCP) Server for Web3 Condition-Action Trigger Agent.

Provides 3 Free Stage 1 Deterministic Inspection Tools:
  1. scan_contract_selectors: Discovers 4-byte EVM function selectors and flags administrative backdoors.
  2. check_token_honeypot: Static bytecode analysis for DEX honeypots, transfer taxes, and blacklist traps.
  3. scan_dao_proposals: Ingests and summarizes recent Snapshot DAO governance proposals with on-chain execution payloads.

Provides 1 Paid Stage 2 Deep Semantic LLM Audit Tool:
  4. deep_semantic_audit: Two-stage on-chain gatekeeping + structured Google Gemini LLM security evaluation ($0.05 USDC x402 micropayment on Base Mainnet).

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
from typing import Dict, Any, Optional, List, Union

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
    )
    from src.engine import ConditionAgentEngine
    from src.chain_inspector import ChainInspector
    from src.governance_connector import (
        SnapshotGovernanceConnector,
        get_curated_dao_proposals,
    )
    from scripts.block_contract_scanner import (
        extract_selectors_from_bytecode,
        is_high_risk_signature,
    )
    from scripts.dex_pool_monitor import analyze_bytecode_honeypot
except ImportError:
    from schemas import (
        ChainId,
        ConditionRulePayload,
        DeterministicCondition,
        SemanticCondition,
        FinalAgentResponse,
    )
    from engine import ConditionAgentEngine
    from chain_inspector import ChainInspector
    from governance_connector import (
        SnapshotGovernanceConnector,
        get_curated_dao_proposals,
    )
    from block_contract_scanner import (
        extract_selectors_from_bytecode,
        is_high_risk_signature,
    )
    from dex_pool_monitor import analyze_bytecode_honeypot

logger = logging.getLogger("mcp_server")

MCP_PROTOCOL_VERSION = "2024-11-05"
MCP_SERVER_NAME = "web3-systemic-agent"
MCP_SERVER_VERSION = "1.0.0"


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
    Serves 3 Free Stage 1 Deterministic Inspection Tools and 1 Paid Stage 2 Semantic Audit Tool.
    """

    def __init__(
        self,
        engine: Optional[ConditionAgentEngine] = None,
        agent_url: Optional[str] = None,
        buyer_private_key: Optional[str] = None,
        require_x402_for_deep_audit: bool = True,
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

    def get_tools_manifest(self) -> List[Dict[str, Any]]:
        """Returns the canonical MCP tools manifest defining all available tools and their schemas."""
        return [
            {
                "name": "scan_contract_selectors",
                "description": (
                    "Stage 1 Free deterministic inspection of smart contract bytecode on Base or EVM chains. "
                    "Discovers 4-byte function selectors and flags high-risk administrative capabilities "
                    "(ownership transfer, proxy upgrade, unconstrained minting, selfdestruct)."
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
            },
            {
                "name": "check_token_honeypot",
                "description": (
                    "Stage 1 Free static bytecode scanner for honeypot indicators on DEX tokens: "
                    "blacklist manipulation (isBlacklisted, setBlacklist), arbitrary transfer taxes / 100% sell fee traps, "
                    "trading freeze backdoors, and selfdestruct opcodes."
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
            },
            {
                "name": "scan_dao_proposals",
                "description": (
                    "Stage 1 Free scanner for recent Snapshot DAO governance proposals (Arbitrum, Aave, ENS). "
                    "Extracts on-chain target addresses and calldata execution payloads to detect governance takeover attempts and discrepancies."
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
            },
            {
                "name": "deep_semantic_audit",
                "description": (
                    "Stage 2 Deep Semantic LLM Security and Governance Audit. "
                    "Performs deterministic on-chain gatekeeping followed by structured Gemini LLM evaluation "
                    "over natural language proposal claims vs bytecode and calldata reality. "
                    "Requires $0.05 USDC x402 micropayment on Base Mainnet."
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
                            "description": "Optional Base64-encoded EIP-3009 transferWithAuthorization payment header satisfying $0.05 USDC requirement",
                        },
                    },
                    "required": ["target_address", "proposal_description"],
                },
            },
        ]

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
            "target_address": checksum_addr,
            "chain_id": chain_id,
            "is_contract": is_contract,
            "bytecode_size_bytes": bytecode_size,
            "selectors_found": selectors,
            "high_risk_signatures": high_risk,
            "risk_level": risk_level,
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
                "token_address": checksum_addr,
                "chain_id": chain_id,
                "is_honeypot_suspect": False,
                "risk_score": 0.0,
                "risk_flags": [],
                "categories_detected": [],
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
            "token_address": checksum_addr,
            "chain_id": chain_id,
            "is_honeypot_suspect": is_honeypot,
            "risk_score": risk_score,
            "risk_flags": analysis.get("honeypot_flags", []),
            "categories_detected": active_cats,
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
            "space_id": space_id,
            "proposals_count": len(formatted),
            "proposals": formatted,
            "llm_invoked": False,
            "cost_usd": 0.0,
            "upsell_recommendation": "Use 'deep_semantic_audit' on any proposal with suspicious calldata or target contract.",
        }

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
    ) -> Dict[str, Any]:
        """Tool 4: Two-stage on-chain gatekeeping + structured Gemini LLM security audit ($0.05 USDC x402 payment)."""
        checksum_addr = _validate_checksum_address(target_address)
        try:
            cid = ChainId(chain_id)
        except ValueError:
            cid = ChainId.BASE_MAINNET

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

        # Payment check: if x402 is required and neither header nor buyer key is present
        if (
            self.require_x402_for_deep_audit
            and not x402_payment_header
            and not self.buyer_private_key
        ):
            return {
                "status": "payment_required",
                "status_code": 402,
                "protocol": "x402",
                "network": "eip155:8453",
                "price_usdc": 0.05,
                "pay_to_address": os.getenv(
                    "PAY_TO_ADDRESS", "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"
                ),
                "evaluate_endpoint": f"{self.agent_url}/evaluate",
                "message": "Stage 2 Deep Semantic LLM Audit requires a $0.05 USDC x402 micropayment on Base Mainnet.",
                "instructions": "Provide 'x402_payment_header' (Base64 EIP-3009 authorization) or configure X402_BUYER_PRIVATE_KEY in the MCP environment.",
                "rule_payload": payload.model_dump(mode="json"),
            }

        if self.engine is None:
            self.engine = ConditionAgentEngine()

        res = await self.engine.process_rule(payload, source="mcp_server")
        dumped = res.model_dump(mode="json")
        dumped["status"] = "completed"
        return dumped

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
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": MCP_SERVER_NAME,
                        "version": MCP_SERVER_VERSION,
                    },
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
                    "resources": [],
                },
            }

        # 6. prompts/list
        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "prompts": [],
                },
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
    """Executes an offline self-test verifying all 4 MCP tools and protocol conformance."""
    print("=== Web3 Systemic Agent MCP Server Self-Test ===")
    server = Web3SystemicMCPServer(require_x402_for_deep_audit=True)
    manifest = server.get_tools_manifest()
    tool_names = [t["name"] for t in manifest]
    print(f"[1/5] Registered {len(manifest)} MCP tools: {', '.join(tool_names)}")
    assert len(manifest) == 4, f"Expected 4 tools, got {len(manifest)}"

    # 1. scan_contract_selectors
    benign_bytecode = "0x608060405234801561001057600080fd5b508063a9059cbb14"
    r1 = await server.scan_contract_selectors(
        target_address="0x3333333333333333333333333333333333333333",
        bytecode_override=benign_bytecode,
    )
    print(
        f"[2/5] Tool 'scan_contract_selectors' OK: risk_level={r1['risk_level']}, "
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
        f"[3/5] Tool 'check_token_honeypot' OK: is_honeypot={r2['is_honeypot_suspect']}, "
        f"score={r2['risk_score']}, cost=${r2['cost_usd']:.2f}"
    )
    assert r2["cost_usd"] == 0.0

    # 3. scan_dao_proposals
    r3 = await server.scan_dao_proposals(use_curated_offline=True, limit=2)
    print(
        f"[4/5] Tool 'scan_dao_proposals' OK: count={r3['proposals_count']}, "
        f"cost=${r3['cost_usd']:.2f}"
    )
    assert r3["proposals_count"] >= 1
    assert r3["cost_usd"] == 0.0

    # 4. deep_semantic_audit (expecting 402 payment required)
    r4 = await server.deep_semantic_audit(
        target_address="0x4200000000000000000000000000000000000006",
        proposal_description="Test proposal",
    )
    print(
        f"[5/5] Tool 'deep_semantic_audit' OK: status={r4.get('status')}, "
        f"status_code={r4.get('status_code')}, price_usdc={r4.get('price_usdc')}"
    )
    assert r4.get("status") == "payment_required"
    assert r4.get("status_code") == 402

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
