"""
HTTP API Service Layer for Web3 Condition-Action Trigger Agent.
Built on FastAPI providing asynchronous endpoints for health monitoring,
syntactic rule pre-validation, and two-stage pipeline execution.
"""

import asyncio
from contextlib import asynccontextmanager
import html
import json
import logging
import os
import sys
import re
import time
import traceback
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
for _p in (_ROOT_DIR, _SRC_DIR, _SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field, ValidationError
from web3 import Web3, AsyncWeb3, AsyncHTTPProvider

try:
    from scripts.block_contract_scanner import (
        get_latest_block_number,
        scan_recent_blocks,
        audit_discovered_contracts,
        extract_selectors_from_bytecode,
        is_high_risk_signature,
    )
except ImportError:
    try:
        from block_contract_scanner import (
            get_latest_block_number,
            scan_recent_blocks,
            audit_discovered_contracts,
            extract_selectors_from_bytecode,
            is_high_risk_signature,
        )
    except ImportError:
        get_latest_block_number = None
        scan_recent_blocks = None
        audit_discovered_contracts = None
        extract_selectors_from_bytecode = None
        is_high_risk_signature = None

try:
    from scripts.dex_pool_monitor import analyze_bytecode_honeypot
except ImportError:
    try:
        from dex_pool_monitor import analyze_bytecode_honeypot
    except ImportError:
        analyze_bytecode_honeypot = None

try:
    from src.schemas import (
        ConditionRulePayload,
        FinalAgentResponse,
        ChainId,
        PaymentReceipt,
        DeterministicCondition,
        SemanticCondition,
        PreflightRequest,
        PreflightVerdict,
        DeepAuditRequest,
        TokenCheckResponse,
    )
    from src.preflight_firewall import PreflightFirewall
    from src.source_resolver import ContractSourceResolver
    from src.engine import ConditionAgentEngine
    from src.chain_inspector import ChainInspector
    from src.semantic_evaluator import (
        MockSemanticEvaluator,
        OpenAISemanticEvaluator,
        GeminiSemanticEvaluator,
        get_semantic_evaluator,
    )
    from src.task_worker import AgentWorkerPool, JobStore, JobStatus, JobRecord
    from src.storage import AgentStorage
    from src.x402_payment import (
        X402Config,
        MockX402Facilitator,
        HTTPX402Facilitator,
        get_x402_facilitator,
        NETWORK_PROFILES,
        get_network_profile,
        parse_x402_header,
        build_402_response,
        build_bazaar_discovery_extension,
        QuickAuditRequest,
        TokenCheckRequest,
        usdc_to_atomic,
    )
    from src.governance_connector import (
        SnapshotGovernanceConnector,
        GovernanceProposal,
        GovernanceAuditReport,
        GovernanceScanRequest,
        get_curated_dao_proposals,
    )
    from src.mcp_server import (
        Web3SystemicMCPServer,
        MCP_PROTOCOL_VERSION,
        MCP_SERVER_NAME,
        MCP_SERVER_VERSION,
        _resolve_contract_bytecode,
    )
except ImportError:
    from schemas import (
        ConditionRulePayload,
        FinalAgentResponse,
        ChainId,
        PaymentReceipt,
        DeterministicCondition,
        SemanticCondition,
        PreflightRequest,
        PreflightVerdict,
        DeepAuditRequest,
        TokenCheckResponse,
    )
    from preflight_firewall import PreflightFirewall
    from source_resolver import ContractSourceResolver
    from engine import ConditionAgentEngine
    from chain_inspector import ChainInspector
    from semantic_evaluator import (
        MockSemanticEvaluator,
        OpenAISemanticEvaluator,
        GeminiSemanticEvaluator,
        get_semantic_evaluator,
    )
    from task_worker import AgentWorkerPool, JobStore, JobStatus, JobRecord
    from storage import AgentStorage
    from x402_payment import (
        X402Config,
        MockX402Facilitator,
        HTTPX402Facilitator,
        get_x402_facilitator,
        NETWORK_PROFILES,
        get_network_profile,
        parse_x402_header,
        build_402_response,
        build_bazaar_discovery_extension,
        QuickAuditRequest,
        TokenCheckRequest,
        usdc_to_atomic,
    )
    from governance_connector import (
        SnapshotGovernanceConnector,
        GovernanceProposal,
        GovernanceAuditReport,
        GovernanceScanRequest,
        get_curated_dao_proposals,
    )
    from mcp_server import (
        Web3SystemicMCPServer,
        MCP_PROTOCOL_VERSION,
        MCP_SERVER_NAME,
        MCP_SERVER_VERSION,
        _resolve_contract_bytecode,
    )

if not hasattr(X402Config, "price_atomic"):
    setattr(
        X402Config,
        "price_atomic",
        property(lambda self: usdc_to_atomic(self.price_per_eval_usdc)),
    )

logger = logging.getLogger(__name__)


def configure_runtime_logging(force: bool = False) -> bool:
    """Configure INFO logging on the ``src`` namespace without altering root or third-party loggers."""
    if not force and "pytest" in sys.modules:
        return False

    app_logger = logging.getLogger("src")
    has_runtime_handler = any(
        getattr(handler, "_web3_agent_runtime", False)
        for handler in app_logger.handlers
    )
    if not has_runtime_handler:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(levelname)s:     %(name)s - %(message)s"))
        handler._web3_agent_runtime = True  # type: ignore[attr-defined]
        app_logger.addHandler(handler)

    app_logger.setLevel(logging.INFO)
    app_logger.propagate = False
    return True


def _log_mcp_telemetry(msg: Any) -> None:
    """Emit a 1-line structured telemetry log for incoming MCP JSON-RPC requests."""
    if not isinstance(msg, dict):
        return
    method = msg.get("method", "unknown")
    if method == "tools/call":
        params = msg.get("params")
        tool_name = params.get("name", "unknown") if isinstance(params, dict) else "unknown"
        logger.info("TELEMETRY | event=mcp_tool_call method=tools/call tool=%s", tool_name)
    else:
        logger.info("TELEMETRY | event=mcp_rpc method=%s", method)


def _log_x402_settled(endpoint: str, amount_usdc: float, tx_hash: Optional[str], network: str) -> None:
    """Emit a 1-line structured telemetry log when an x402 payment settles."""
    logger.info(
        "TELEMETRY | event=x402_settled endpoint=%s amount_usdc=%s network=%s tx_hash=%s",
        endpoint,
        round(amount_usdc, 6),
        network,
        tx_hash or "none",
    )


def _extract_payment_header(request: Request) -> Optional[str]:
    """Extract x402 payment header across supported header aliases."""
    header_val = (
        request.headers.get("x-payment")
        or request.headers.get("payment-signature")
        or request.headers.get("x-payment-signature")
        or request.headers.get("X-PAYMENT")
        or request.headers.get("PAYMENT-SIGNATURE")
    )
    if header_val and header_val.strip():
        return header_val
    return None


def _get_public_url() -> str:
    """Resolve the canonical public API base URL."""
    return (
        os.getenv("PUBLIC_API_URL")
        or os.getenv("WEB3_AGENT_URL")
        or "https://web3-systemic-agent.onrender.com"
    ).rstrip("/")


DEFAULT_BATCH_MAX_ITEMS = 50


def get_batch_max_items() -> int:
    """
    Returns maximum allowed items in a batch evaluation request.
    Reads BATCH_MAX_ITEMS from environment, defaulting to 50.
    """
    val = os.getenv("BATCH_MAX_ITEMS")
    if val is not None:
        try:
            return int(val)
        except (ValueError, TypeError):
            pass
    return DEFAULT_BATCH_MAX_ITEMS


# -------------------------------------------------------------------------
# API Response Schemas
# -------------------------------------------------------------------------

class ServiceDiscoveryResponse(BaseModel):
    service: str = Field(default="Web3 Condition-Action Trigger Agent", description="Service identifier")
    version: str = Field(default="1.0.2", description="Application semantic version")
    status: str = Field(default="online", description="Operational status of the service")
    x402_enabled: bool = Field(default=False, description="Whether x402 payment gate is enabled")
    x402_network: Optional[str] = Field(default=None, description="Active x402 CAIP-2 network")
    price_per_eval_usdc: float = Field(default=0.015, description="Base price in USDC per evaluation")
    pay_to_address: Optional[str] = Field(default=None, description="Recipient EVM address for x402 micropayments")
    endpoints: Dict[str, str] = Field(..., description="Canonical API endpoint route registry")


class SimpleHealthResponse(BaseModel):
    status: str = Field(default="ok", description="Basic health status")


class HealthCheckResponse(BaseModel):
    status: str = Field(..., description="Overall health status: 'ok', 'degraded', or 'error'")
    version: str = Field(default="1.0.2", description="Application version")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of inspection")
    rpc_status: Dict[int, bool] = Field(..., description="RPC connectivity per chain ID")
    semantic_provider: str = Field(..., description="Active semantic provider ('gemini', 'openai', or 'mock')")
    provider: str = Field(default="mock", description="Normalized provider identifier ('gemini', 'openai', or 'mock')")
    is_mock: bool = Field(..., description="Whether running a simulation/mock LLM")
    model: Optional[str] = Field(default=None, description="Active model name if using Gemini or OpenAI")
    x402_enabled: bool = Field(default=False, description="Whether x402 payment gate is enabled")
    x402_network: Optional[str] = Field(default=None, description="Active x402 CAIP-2 network")
    price_per_eval_usdc: float = Field(default=0.015, description="Base price in USDC per evaluation")


class ValidationDetail(BaseModel):
    rule_id: str
    chain_id: int
    target_address: str
    required_selectors: Optional[List[str]] = None
    calldata_selector: Optional[str] = None
    semantic_enabled: bool
    risk_threshold: float
    min_value_wei: int


class RuleValidationResponse(BaseModel):
    valid: bool = Field(..., description="True if payload is structurally and logically sound")
    message: str = Field(..., description="High-level validation summary")
    details: ValidationDetail = Field(..., description="Parsed rule attributes")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings or short-circuit hints")


# -------------------------------------------------------------------------
# Application Factory & Background Workers
# -------------------------------------------------------------------------

async def _background_scanner_worker(app_instance: FastAPI):
    """
    Background worker that continuously scans newly produced blocks on Base Mainnet
    for smart contract deployments and executes deterministic and semantic security audits.
    """
    rpc_url = os.getenv("RPC_URL_8453", "https://mainnet.base.org")
    w3 = getattr(app_instance.state, "scanner_w3", None) or AsyncWeb3(AsyncHTTPProvider(rpc_url))
    last_scanned_block: Optional[int] = None
    try:
        poll_interval = float(os.getenv("SCANNER_POLL_INTERVAL_SECONDS", "60.0"))
    except (ValueError, TypeError):
        poll_interval = 60.0

    try:
        limit = int(os.getenv("SCANNER_CONTRACT_LIMIT", "2"))
    except (ValueError, TypeError):
        limit = 2

    require_high_risk_str = os.getenv("SCANNER_REQUIRE_HIGH_RISK_FOR_LLM", "true").strip().lower()
    require_high_risk = require_high_risk_str in ("true", "1", "yes")

    raw_channels = os.getenv(
        "HUNTER_CHANNELS",
        "dex_pools,geckoterminal_base,dexscreener_base,snapshot_daos",
    )
    hunter_channels = [c.strip() for c in raw_channels.split(",") if c.strip()] or [
        "dex_pools",
        "geckoterminal_base",
        "dexscreener_base",
        "snapshot_daos",
    ]
    hunter_channel_idx = 0

    logger.info("Background block contract scanner worker started on Base Mainnet (%s)", rpc_url)
    try:
        while True:
            try:
                if get_latest_block_number is None or scan_recent_blocks is None or audit_discovered_contracts is None:
                    logger.warning("Block contract scanner functions unavailable. Sleeping...")
                    await asyncio.sleep(poll_interval)
                    continue

                current_block = await get_latest_block_number(w3)
                if last_scanned_block is None:
                    blocks_to_check = 1
                    start_b = current_block
                elif current_block > last_scanned_block:
                    blocks_to_check = min(current_block - last_scanned_block, 10)
                    start_b = current_block
                else:
                    await asyncio.sleep(poll_interval)
                    continue

                discovered = await scan_recent_blocks(
                    w3=w3,
                    num_blocks=blocks_to_check,
                    limit=limit,
                    start_block=start_b,
                )

                if discovered:
                    active_eng = getattr(app_instance.state, "engine", None)
                    if active_eng is not None:
                        try:
                            await audit_discovered_contracts(
                                discovered,
                                active_eng,
                                rpc_url=rpc_url,
                                require_high_risk_for_llm=require_high_risk,
                            )
                        except TypeError:
                            await audit_discovered_contracts(discovered, active_eng, rpc_url=rpc_url)

                last_scanned_block = current_block

                # Optional multi-channel autonomous discovery hunter (1 rotating channel per cycle)
                enable_hunter = (
                    os.getenv("ENABLE_MULTI_CHANNEL_HUNTER", "true").strip().lower()
                    in ("true", "1", "yes")
                )
                if getattr(app_instance.state, "scanner_w3", None) is None and enable_hunter:
                    try:
                        from src.discovery_hunter import ActiveContractHunter  # lazy import

                        channel = hunter_channels[hunter_channel_idx % len(hunter_channels)]
                        hunter_channel_idx += 1
                        active_eng = getattr(app_instance.state, "engine", None)
                        active_storage = getattr(app_instance.state, "storage", None)
                        hunter = getattr(app_instance.state, "discovery_hunter", None)
                        if hunter is None:
                            try:
                                hunter = ActiveContractHunter(
                                    engine=active_eng,
                                    storage=active_storage,
                                    rpc_url=rpc_url,
                                    require_high_risk_for_llm=require_high_risk,
                                )
                            except TypeError:
                                hunter = ActiveContractHunter(engine=active_eng, rpc_url=rpc_url)
                            app_instance.state.discovery_hunter = hunter
                        if hasattr(hunter, "run_hunt_cycle"):
                            await hunter.run_hunt_cycle(
                                channels=[channel],
                                limit_per_channel=limit,
                            )
                        elif hasattr(hunter, "run_channel"):
                            await hunter.run_channel(channel, limit_per_channel=limit)
                    except asyncio.CancelledError:
                        raise
                    except Exception as hunter_exc:
                        logger.debug("Multi-channel hunter cycle skipped: %s", hunter_exc)

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Transient error in background block scanner worker: %s", exc)

            await asyncio.sleep(poll_interval)

    except asyncio.CancelledError:
        logger.info("Background block scanner worker received cancellation. Shutting down gracefully.")
    finally:
        if hasattr(w3, "provider") and hasattr(w3.provider, "disconnect"):
            try:
                await w3.provider.disconnect()
            except Exception:
                pass
        app_instance.state.scanner_active = False


# -------------------------------------------------------------------------
# Static Discovery & Agent-Teaching Content
# -------------------------------------------------------------------------

ROBOTS_TXT_CONTENT = """User-agent: *
Allow: /
Allow: /openapi.json
Allow: /mcp
Allow: /evaluate
Allow: /audit
Allow: /preflight
Allow: /audit/deep
Allow: /token/check
Allow: /feed/recent
Allow: /report/
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Allow: /.well-known/x402
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/

User-agent: GPTBot
Allow: /
Allow: /openapi.json
Allow: /mcp
Allow: /evaluate
Allow: /audit
Allow: /preflight
Allow: /audit/deep
Allow: /token/check
Allow: /feed/recent
Allow: /report/
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Allow: /.well-known/x402
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/

User-agent: ClaudeBot
Allow: /
Allow: /openapi.json
Allow: /mcp
Allow: /evaluate
Allow: /audit
Allow: /preflight
Allow: /audit/deep
Allow: /token/check
Allow: /feed/recent
Allow: /report/
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Allow: /.well-known/x402
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/

User-agent: PerplexityBot
Allow: /
Allow: /openapi.json
Allow: /mcp
Allow: /evaluate
Allow: /audit
Allow: /preflight
Allow: /audit/deep
Allow: /token/check
Allow: /feed/recent
Allow: /report/
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Allow: /.well-known/x402
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/

User-agent: Google-Extended
Allow: /
Allow: /openapi.json
Allow: /mcp
Allow: /evaluate
Allow: /audit
Allow: /preflight
Allow: /audit/deep
Allow: /token/check
Allow: /feed/recent
Allow: /report/
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Allow: /.well-known/x402
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/
"""

SECURITY_TXT_CONTENT = """Contact: https://github.com/RafaCoelho33/web3-systemic-agent/issues
Expires: 2027-12-31T23:59:59.000Z
Preferred-Languages: en, pt
Canonical: https://web3-systemic-agent.onrender.com/.well-known/security.txt
Policy: https://github.com/RafaCoelho33/web3-systemic-agent/blob/main/README.md
"""

ICON_SVG_CONTENT = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0052FF" />
      <stop offset="100%" stop-color="#1652F0" />
    </linearGradient>
    <linearGradient id="glowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00D2FF" />
      <stop offset="100%" stop-color="#0052FF" />
    </linearGradient>
  </defs>
  <rect width="128" height="128" rx="28" fill="#0A0B0D"/>
  <path d="M64 16 L104 32 C104 76 74 104 64 112 C54 104 24 76 24 32 Z" fill="url(#shieldGrad)" stroke="#1E2025" stroke-width="2"/>
  <path d="M64 24 L96 38 C96 72 72 96 64 103 C56 96 32 72 32 38 Z" fill="none" stroke="url(#glowGrad)" stroke-width="2.5" opacity="0.8"/>
  <circle cx="64" cy="64" r="16" fill="#00D2FF" opacity="0.9"/>
  <path d="M58 64 L62 68 L70 58" fill="none" stroke="#FFFFFF" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

LLMS_TXT_CONTENT = """# Web3 Systemic Agent (io.github.RafaCoelho33/web3-systemic-agent)
> Autonomous Web3 Security & Governance Auditor with Two-Stage Hybrid LLM Pipeline & x402 Bazaar Micropayments.

- **Version:** `1.0.2`
- **Public API URL:** `https://web3-systemic-agent.onrender.com`
- **Supported Chains:** Base Mainnet (`eip155:8453`), Base Sepolia (`eip155:84532`), Arbitrum One (`eip155:42161`)
- **Full Documentation:** `/llms-full.txt`

## MCP Streamable-HTTP (`POST /mcp`)
- `scan_contract_selectors` (Free): Extracts 4-byte EVM selectors and flags admin backdoors.
- `check_token_honeypot` (Free): Static bytecode scanner for honeypots, sell-tax modifiers, and blacklists.
- `scan_dao_proposals` (Free): Ingests Snapshot DAO proposals and extracts on-chain execution payloads.
- `deep_semantic_audit` (Paid via x402: `$0.015` USDC standard / `$0.25` USDC deep proxy + verified source): Two-stage deterministic gatekeeping + Gemini LLM semantic audit.

## REST API & x402 Pricing (Base Mainnet USDC)
- `POST /rules/validate` (Free): Static payload pre-validation.
- `GET` / `POST /token/check` (`$0.005` USDC via x402): Fast deterministic token safety & honeypot check (bytecode honeypot, proxy & Sourcify verification).
- `POST /preflight` (`$0.01` USDC via x402): Pre-sign EVM transaction firewall, simulation & prompt injection defense.
- `POST /evaluate` (`$0.015` USDC via x402): Full rule evaluation with Stage 1 gatekeeping + Stage 2 Gemini LLM.
- `POST /audit` (`$0.015` USDC via x402): Quick contract & calldata audit.
- `POST /audit/deep` (`$0.25` USDC via x402): Deep EIP-1967/1822 proxy resolution & verified Solidity source audit.

## Discovery & Ownership
- `GET /.well-known/x402` | `GET /.well-known/mcp/server-card.json` | `GET /.well-known/agent.json` | `GET /.well-known/owners.json` | `GET /.well-known/security.txt`
- **Contact:** https://github.com/RafaCoelho33/web3-systemic-agent/issues
"""

LLMS_FULL_TXT_CONTENT = """# Web3 Systemic Agent (io.github.RafaCoelho33/web3-systemic-agent)
> Autonomous Web3 Security & Governance Auditor with Two-Stage Hybrid LLM Pipeline & x402 Bazaar Micropayments.

## System Overview
- **System Identifier:** `io.github.RafaCoelho33/web3-systemic-agent`
- **Name:** Web3 Systemic Agent
- **Version:** `1.0.2`
- **Public API URL:** `https://web3-systemic-agent.onrender.com`
- **Supported Chains:** Base Mainnet (`eip155:8453`), Base Sepolia (`eip155:84532`), Arbitrum One (`eip155:42161`)

## Two-Stage Hybrid Architecture
1. **Stage 1: Deterministic On-Chain Gatekeeping (Zero LLM Token Cost / Free)**
   - High-throughput EVM bytecode and calldata analysis using `ChainInspector` with local FIFO caching.
   - Extracts 4-byte function selectors, inspects target contract bytecode existence, verifies native balances, and evaluates DEX honeypot signatures.
   - Short-circuits non-matching or benign conditions with `llm_invoked=False` ($0.00 LLM token cost).
2. **Stage 2: Deep Semantic LLM Governance & Security Audit ($0.015 USDC standard / $0.25 USDC deep proxy + verified source via x402)**
   - Triggered only when Stage 1 deterministic conditions pass or high-risk administrative capabilities are detected.
   - Leverages Google Gemini (`gemini-3.5-flash-lite` with automatic cooldown failover to `gemini-3.1-flash-lite`, `gemini-2.5-flash-lite`, and `gemini-2.0-flash`).
   - Evaluates natural language claims against actual on-chain bytecode, native balance, and execution calldata.
   - Enforces deterministic policy escalation (`APPROVE`, `MANUAL_REVIEW`, `REJECT`) via `enforce_decision_policy`.

## Model Context Protocol (MCP) Streamable-HTTP (`POST /mcp`)
Connect using MCP specification (`2024-11-05`, `2025-03-26`, `2025-06-18`) via HTTP POST:
- **Endpoint:** `POST https://web3-systemic-agent.onrender.com/mcp`
- **Headers:** `Content-Type: application/json`

### JSON-RPC 2.0 Examples

#### 1. Initialize Request
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "autonomous-client", "version": "1.0.2"}
  }
}
```

#### 2. Tools List Request
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list"
}
```

#### 3. Tools Call Request (scan_contract_selectors)
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "scan_contract_selectors",
    "arguments": {
      "target_address": "0x4200000000000000000000000000000000000006",
      "chain_id": 8453
    }
  }
}
```

## Available MCP Tools

### 1. `scan_contract_selectors` (Stage 1 Free)
- **Description:** Deterministic inspection of smart contract bytecode to discover 4-byte EVM selectors and detect high-risk administrative backdoors (`transferOwnership`, `upgradeTo`, `mint`, `selfdestruct`).
- **Arguments:**
  - `target_address` (string, required): Hex EVM address of smart contract.
  - `chain_id` (integer, default 8453): EVM Chain ID (8453 for Base Mainnet, 84532 for Base Sepolia, 42161 for Arbitrum One).
  - `bytecode_override` (string, optional): Raw contract runtime hex bytecode for offline analysis.

### 2. `check_token_honeypot` (Stage 1 Free)
- **Description:** Static bytecode analysis for DEX honeypots, rugpull traps, and malicious token contracts: blacklist manipulation (`isBlacklisted`, `setBlacklist`), arbitrary transfer taxes (`setTax`, `setFee`), pause backdoors (`pause`, `setTrading`), and `selfdestruct` (opcode `0xff`).
- **Arguments:**
  - `token_address` (string, required): Hex EVM address of token contract.
  - `chain_id` (integer, default 8453): EVM Chain ID.
  - `bytecode_override` (string, optional): Raw token runtime hex bytecode for offline analysis.

### 3. `scan_dao_proposals` (Stage 1 Free)
- **Description:** Ingests recent Snapshot DAO governance proposals (Arbitrum, Aave, ENS). Extracts on-chain target addresses, Wei transfers, and calldata execution payloads to flag governance discrepancies.
- **Arguments:**
  - `space_id` (string, default "arbitrumfoundation.eth"): Snapshot space ENS domain.
  - `limit` (integer, default 3): Number of proposals to fetch.
  - `use_curated_offline` (boolean, default false): If true, returns verified offline curated proposals.

### 4. `deep_semantic_audit` (Stage 2 Paid - $0.015 USDC standard / $0.25 USDC deep proxy + verified source via x402)
- **Description:** Two-stage security audit crossing natural language proposal text with on-chain bytecode and calldata. Returns risk scores (0.0 to 10.0), flagged issues, and deterministic policy action (`APPROVE`, `MANUAL_REVIEW`, `REJECT`).
- **Arguments:**
  - `target_address` (string, required): Smart contract address under evaluation.
  - `proposal_description` (string, required): Claim or governance proposal intent.
  - `policy_prompt` (string, optional): Custom policy prompt.
  - `calldata` (string, default "0x"): Hex calldata being executed.
  - `chain_id` (integer, default 8453): EVM Chain ID.
  - `risk_threshold` (number, default 7.0): Risk threshold.
  - `resolve_proxy` (boolean, default false): Resolve EIP-1967/1822 proxy implementation ($0.25 tier).
  - `fetch_verified_source` (boolean, default false): Fetch verified Solidity source code ($0.25 tier).
  - `x402_payment_header` (string, optional): Base64 EIP-3009 transfer authorization (or pass `X-PAYMENT` / `PAYMENT-SIGNATURE` HTTP header).
- **Payment Requirement:** If called without `x402_payment_header` or configured buyer key, returns HTTP 402 with recipient address `0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63` on Base Mainnet (`eip155:8453`).

## REST API Integration

### Static Rule Validation (Free)
- **Endpoint:** `POST https://web3-systemic-agent.onrender.com/rules/validate`
- Validates payload structure and parameters before submission.

### Token Safety Check ($0.005 USDC via x402)
- **Endpoint:** `GET` or `POST https://web3-systemic-agent.onrender.com/token/check`
- **Headers:** `X-PAYMENT: <base64_eip3009_auth>`
- **Request Body / Query Params:** `TokenCheckRequest` (`address` / `token` / `token_address`, `chain_id`, `include_source_status`) -> returns `TokenCheckResponse` (`verdict`, `risk_score`, `is_honeypot_suspect`, `honeypot_flags`, `selectors_found`, `high_risk_selectors`, `is_proxy`, `source_verified`) with zero LLM cost (`llm_invoked: false`).

### Preflight Transaction Security Firewall ($0.01 USDC via x402)
- **Endpoint:** `POST https://web3-systemic-agent.onrender.com/preflight`
- **Headers:** `X-PAYMENT: <base64_eip3009_auth>`
- **Request Body:** `PreflightRequest` (`to_address`, `calldata`, `value_wei`, `chain_id`, `eip712_typed_data`, `untrusted_text`, `run_simulation`)

### Deep Evaluation Execution ($0.015 USDC via x402)
- **Endpoint:** `POST https://web3-systemic-agent.onrender.com/evaluate`
- **Headers:** `X-PAYMENT: <base64_eip3009_auth>`

#### Example Request Payload:
```json
{
  "rule_id": "rule-audit-001",
  "chain_id": 8453,
  "deterministic": {
    "target_address": "0x4200000000000000000000000000000000000006",
    "min_value_wei": 0,
    "required_function_selectors": null,
    "check_native_balance": false
  },
  "semantic": {
    "enabled": true,
    "policy_prompt": "Audit contract for unauthorized ownership transfer or backdoor drainage.",
    "risk_threshold": 7.0
  },
  "context_metadata": {
    "proposal_description": "Routine parameter update without audit",
    "calldata": "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  }
}
```

### Simplified Quick Contract Audit ($0.015 USDC via x402)
- **Endpoint:** `POST https://web3-systemic-agent.onrender.com/audit`
- **Headers:** `X-PAYMENT: <base64_eip3009_auth>`
- **Request Body:** `QuickAuditRequest` (`target_address`, `chain_id`, `proposal_description`, `calldata`, `policy_prompt`, `risk_threshold`)

#### Example Quick Audit Payload:
```json
{
  "target_address": "0x4200000000000000000000000000000000000006",
  "chain_id": 8453,
  "proposal_description": "Audit smart contract for administrative backdoors, honeypot traps, or unauthorized privilege escalation.",
  "calldata": "0x"
}
```

### Deep Source & Proxy Smart Contract Audit ($0.25 USDC via x402)
- **Endpoint:** `POST https://web3-systemic-agent.onrender.com/audit/deep`
- **Headers:** `X-PAYMENT: <base64_eip3009_auth>`
- **Request Body:** `DeepAuditRequest` (`target_address`, `chain_id`, `proposal_description`, `resolve_proxy`, `fetch_verified_source`)

### x402 Bazaar Protocol Discovery
- **Endpoint:** `GET https://web3-systemic-agent.onrender.com/.well-known/x402`
- Returns official x402 v2 service discovery metadata and resource specifications for `/evaluate`, `/audit`, `/preflight`, `/audit/deep`, and `/token/check`.

## Security & Transparency
- **Security Policy:** `/.well-known/security.txt`
- **MCP Server Card:** `/.well-known/mcp/server-card.json`
- **Agent Card:** `/.well-known/agent.json`
- **Owners Manifest:** `/.well-known/owners.json`
- **Contact:** https://github.com/RafaCoelho33/web3-systemic-agent/issues
"""


# -------------------------------------------------------------------------
# Wave 3B: HTML Landing Page, Public Feed & Shareable Reports Helpers
# -------------------------------------------------------------------------

_CHAIN_NAMES: Dict[int, str] = {
    1: "Ethereum Mainnet",
    8453: "Base Mainnet",
    84532: "Base Sepolia",
    42161: "Arbitrum One",
    10: "Optimism",
    137: "Polygon",
}


def _chain_display_name(chain_id: int) -> str:
    """Return human-readable EVM network name for a numeric chain ID."""
    return _CHAIN_NAMES.get(chain_id, f"EVM Chain {chain_id}")


def _short_address(address: str) -> str:
    """Shorten a 42-char EVM address to 0x1234...abcd format."""
    if len(address) >= 12:
        return f"{address[:6]}...{address[-4:]}"
    return address


def _wants_html_response(request: Request, format_param: Optional[str] = None) -> bool:
    """
    Determine whether to serve HTML via explicit ?format=html override or Accept header negotiation.
    Programmatic clients sending */* or application/json always receive JSON.
    """
    if format_param is not None:
        fmt = format_param.strip().lower()
        if fmt == "html":
            return True
        if fmt == "json":
            return False
    accept = request.headers.get("accept", "").lower()
    return ("text/html" in accept) and ("application/json" not in accept)


def _extract_target_address_from_row(row: Dict[str, Any]) -> Optional[str]:
    """Extract target EVM address from a stored evaluation row's request_json."""
    raw_req = row.get("request_json")
    if not raw_req:
        return None
    if isinstance(raw_req, str):
        try:
            req_data = json.loads(raw_req)
        except (ValueError, TypeError):
            return None
    elif isinstance(raw_req, dict):
        req_data = raw_req
    else:
        return None

    if not isinstance(req_data, dict):
        return None

    deterministic = req_data.get("deterministic")
    if isinstance(deterministic, dict) and deterministic.get("target_address"):
        return str(deterministic["target_address"])

    ctx_meta = req_data.get("context_metadata")
    if isinstance(ctx_meta, dict) and ctx_meta.get("contract_address"):
        return str(ctx_meta["contract_address"])

    for fallback_key in ("target_address", "contract_address", "token_address"):
        if req_data.get(fallback_key):
            return str(req_data[fallback_key])
    return None


def _build_feed_item(row: Dict[str, Any], public_url: str) -> Dict[str, Any]:
    """Normalize a storage evaluation row into a public /feed/recent item."""
    chain_id = row.get("chain_id")
    target_address = _extract_target_address_from_row(row)
    report_url = (
        f"{public_url}/report/{chain_id}/{target_address}"
        if (chain_id is not None and target_address)
        else None
    )
    token_check_url = (
        f"{public_url}/token/check?address={target_address}&chain_id={chain_id}"
        if (chain_id is not None and target_address)
        else None
    )
    stage1_val = row.get("stage1_passed")
    llm_val = row.get("llm_invoked")
    return {
        "rule_id": row.get("rule_id"),
        "chain_id": chain_id,
        "target_address": target_address,
        "source": row.get("source"),
        "stage1_passed": bool(stage1_val) if stage1_val is not None else None,
        "llm_invoked": bool(llm_val) if llm_val is not None else None,
        "decision": row.get("decision"),
        "risk_score": row.get("risk_score"),
        "created_at": row.get("created_at"),
        "report_url": report_url,
        "token_check_x402_url": token_check_url,
        "deep_audit_x402_url": f"{public_url}/audit/deep",
    }


def _resolve_report_badge(
    evaluated: bool,
    latest_decision: Optional[str],
    risk_score: Optional[float],
    honeypot_analysis: Optional[Dict[str, Any]],
) -> tuple:
    """Resolve verdict badge label, accent hex color, and tint background."""
    dec_upper = (latest_decision or "").strip().upper()
    is_hp = bool(honeypot_analysis and honeypot_analysis.get("is_honeypot"))
    if dec_upper == "REJECT" or (risk_score is not None and float(risk_score) >= 7.0) or is_hp:
        return ("HIGH RISK / REJECT", "#FF4D4F", "rgba(255,77,79,0.16)")
    if dec_upper in ("MANUAL_REVIEW", "CAUTION") or (risk_score is not None and float(risk_score) >= 4.0):
        return ("CAUTION / MANUAL_REVIEW", "#FAAD14", "rgba(250,173,20,0.16)")
    if evaluated or (risk_score is not None and float(risk_score) < 4.0):
        return ("VERIFIED / SAFE", "#00D26A", "rgba(0,210,106,0.16)")
    return ("UNSCANNED — READY FOR AUDIT", "#00D2FF", "rgba(0,210,255,0.16)")


async def _build_contract_report_context(
    app_instance: FastAPI,
    chain_id: int,
    checksum_addr: str,
) -> Dict[str, Any]:
    """Assemble contract security report context from storage feed history and ChainInspector cache."""
    public_url = _get_public_url()
    storage_inst: Optional[AgentStorage] = getattr(app_instance.state, "storage", None)

    latest_row: Optional[Dict[str, Any]] = None
    if storage_inst is not None and hasattr(storage_inst, "get_recent_feed_evaluations"):
        rows = await storage_inst.get_recent_feed_evaluations(limit=50)
        target_lower = checksum_addr.lower()
        for row in rows:
            row_chain = row.get("chain_id")
            if row_chain is None or int(row_chain) != chain_id:
                continue
            row_addr = _extract_target_address_from_row(row)
            if row_addr and row_addr.lower() == target_lower:
                latest_row = row
                break

    cache_key = f"{chain_id}:{checksum_addr}"
    code_bytes = ChainInspector._bytecode_cache.get(cache_key)
    if code_bytes is None:
        code_bytes = ChainInspector._bytecode_cache.get(f"{chain_id}:{checksum_addr.lower()}")

    bytecode_cached = bool(code_bytes and code_bytes not in (b"", b"\x00"))
    bytecode_size_bytes = len(code_bytes) if bytecode_cached and code_bytes is not None else 0
    honeypot_analysis: Optional[Dict[str, Any]] = None
    selectors_count = 0
    high_risk_signatures: List[str] = []

    if bytecode_cached and code_bytes is not None:
        if analyze_bytecode_honeypot is not None:
            honeypot_analysis = analyze_bytecode_honeypot(code_bytes)
        if extract_selectors_from_bytecode is not None:
            extracted = extract_selectors_from_bytecode(code_bytes)
            selectors_count = len(extracted)
            if is_high_risk_signature is not None:
                high_risk_signatures = [
                    str(s.get("signature", ""))
                    for s in extracted
                    if is_high_risk_signature(str(s.get("signature", "")))
                ]

    evaluated = latest_row is not None
    latest_decision = latest_row.get("decision") if latest_row else None
    risk_score = latest_row.get("risk_score") if latest_row else None
    rule_id = latest_row.get("rule_id") if latest_row else None
    source = latest_row.get("source") if latest_row else None
    created_at = latest_row.get("created_at") if latest_row else None
    stage1_passed = (
        bool(latest_row["stage1_passed"])
        if latest_row and latest_row.get("stage1_passed") is not None
        else None
    )
    llm_invoked = (
        bool(latest_row["llm_invoked"])
        if latest_row and latest_row.get("llm_invoked") is not None
        else None
    )

    badge_label, badge_color, badge_bg = _resolve_report_badge(
        evaluated=evaluated,
        latest_decision=latest_decision,
        risk_score=risk_score,
        honeypot_analysis=honeypot_analysis,
    )

    return {
        "address": checksum_addr,
        "short_address": _short_address(checksum_addr),
        "chain_id": chain_id,
        "chain_name": _chain_display_name(chain_id),
        "evaluated": evaluated,
        "latest_decision": latest_decision,
        "risk_score": risk_score,
        "rule_id": rule_id,
        "source": source,
        "stage1_passed": stage1_passed,
        "llm_invoked": llm_invoked,
        "created_at": created_at,
        "bytecode_cached": bytecode_cached,
        "bytecode_size_bytes": bytecode_size_bytes,
        "selectors_count": selectors_count,
        "high_risk_signatures": high_risk_signatures,
        "honeypot_analysis": honeypot_analysis,
        "verdict_badge": badge_label,
        "badge_color": badge_color,
        "badge_bg": badge_bg,
        "report_url": f"{public_url}/report/{chain_id}/{checksum_addr}",
        "card_svg_url": f"{public_url}/report/{chain_id}/{checksum_addr}/card.svg",
        "token_check_x402_url": f"{public_url}/token/check?address={checksum_addr}&chain_id={chain_id}",
        "audit_x402_url": f"{public_url}/audit",
        "deep_audit_x402_url": f"{public_url}/audit/deep",
    }


def _build_report_svg(report_ctx: Dict[str, Any]) -> str:
    """Render a 1200x630 OpenGraph SVG security card for a contract report."""
    short_addr = html.escape(str(report_ctx["short_address"]), quote=True)
    full_addr = html.escape(str(report_ctx["address"]), quote=True)
    chain_id = int(report_ctx["chain_id"])
    chain_name = html.escape(str(report_ctx["chain_name"]), quote=True)
    badge_label = html.escape(str(report_ctx["verdict_badge"]), quote=True)
    badge_color = html.escape(str(report_ctx["badge_color"]), quote=True)
    badge_bg = html.escape(str(report_ctx["badge_bg"]), quote=True)

    risk_score = report_ctx.get("risk_score")
    score_text = f"{float(risk_score):.1f} / 10" if risk_score is not None else "Pending"
    decision_text = html.escape(str(report_ctx.get("latest_decision") or "UNSCANNED"), quote=True)
    cache_text = (
        f"Cached ({report_ctx.get('bytecode_size_bytes', 0)} bytes)"
        if report_ctx.get("bytecode_cached")
        else "On-Demand RPC"
    )
    cache_text_esc = html.escape(cache_text, quote=True)

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630" width="1200" height="630">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#07090E" />
      <stop offset="100%" stop-color="#0E1422" />
    </linearGradient>
    <linearGradient id="brandGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0052FF" />
      <stop offset="100%" stop-color="#00D2FF" />
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bgGrad)" />
  <rect x="36" y="36" width="1128" height="558" rx="24" fill="#0D111A" stroke="#1E293B" stroke-width="2" />
  <rect x="36" y="36" width="1128" height="6" rx="3" fill="url(#brandGrad)" />

  <g transform="translate(80, 82)">
    <path d="M24 0 L48 10 C48 34 30 50 24 55 C18 50 0 34 0 10 Z" fill="#0052FF" />
    <path d="M16 27 L22 33 L33 20" fill="none" stroke="#FFFFFF" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" />
    <text x="66" y="25" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="26" font-weight="700" fill="#F8FAFC">Web3 Systemic Agent</text>
    <text x="66" y="50" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="16" fill="#94A3B8">Autonomous EVM Security Firewall • MCP Server • x402 Auditor</text>
  </g>

  <rect x="740" y="84" width="380" height="52" rx="26" fill="{badge_bg}" stroke="{badge_color}" stroke-width="2" />
  <text x="930" y="117" text-anchor="middle" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="19" font-weight="700" fill="{badge_color}">{badge_label}</text>

  <text x="80" y="210" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="18" font-weight="600" fill="#64748B">TARGET CONTRACT REPORT</text>
  <text x="80" y="268" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="48" font-weight="700" fill="#FFFFFF">{short_addr}</text>
  <text x="80" y="312" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="22" fill="#94A3B8">{full_addr}</text>

  <rect x="80" y="360" width="320" height="118" rx="14" fill="#131926" stroke="#1E293B" stroke-width="1.5" />
  <text x="104" y="396" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="15" fill="#64748B">NETWORK / CHAIN ID</text>
  <text x="104" y="432" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="24" font-weight="700" fill="#F8FAFC">{chain_name}</text>
  <text x="104" y="458" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="16" fill="#38BDF8">eip155:{chain_id}</text>

  <rect x="440" y="360" width="320" height="118" rx="14" fill="#131926" stroke="#1E293B" stroke-width="1.5" />
  <text x="464" y="396" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="15" fill="#64748B">VERDICT &amp; RISK SCORE</text>
  <text x="464" y="432" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="24" font-weight="700" fill="{badge_color}">{decision_text}</text>
  <text x="464" y="458" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="16" fill="#CBD5E1">Risk Score: {html.escape(score_text, quote=True)}</text>

  <rect x="800" y="360" width="320" height="118" rx="14" fill="#131926" stroke="#1E293B" stroke-width="1.5" />
  <text x="824" y="396" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="15" fill="#64748B">STATIC BYTECODE CACHE</text>
  <text x="824" y="432" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="22" font-weight="700" fill="#F8FAFC">{cache_text_esc}</text>
  <text x="824" y="458" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="16" fill="#94A3B8">Selectors: {int(report_ctx.get("selectors_count", 0))}</text>

  <line x1="80" y1="518" x2="1120" y2="518" stroke="#1E293B" stroke-width="1.5" />
  <text x="80" y="556" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="18" font-weight="600" fill="#38BDF8">$0.005 Quick Check  •  $0.015 AI Audit  •  $0.25 Deep Source</text>
  <text x="1120" y="556" text-anchor="end" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="16" fill="#64748B">x402 Micropayments on Base</text>
</svg>"""


def _build_report_html(report_ctx: Dict[str, Any], public_url: str) -> str:
    """Render shareable HTML contract report with OpenGraph/Twitter tags and live Stage-1 runner."""
    addr = html.escape(str(report_ctx["address"]), quote=True)
    short_addr = html.escape(str(report_ctx["short_address"]), quote=True)
    chain_id = int(report_ctx["chain_id"])
    chain_name = html.escape(str(report_ctx["chain_name"]), quote=True)
    badge_label = html.escape(str(report_ctx["verdict_badge"]), quote=True)
    badge_color = html.escape(str(report_ctx["badge_color"]), quote=True)
    badge_bg = html.escape(str(report_ctx["badge_bg"]), quote=True)
    card_svg_url = html.escape(str(report_ctx["card_svg_url"]), quote=True)
    report_url = html.escape(str(report_ctx["report_url"]), quote=True)

    decision_str = html.escape(str(report_ctx.get("latest_decision") or "UNSCANNED"), quote=True)
    risk_val = report_ctx.get("risk_score")
    risk_str = f"{float(risk_val):.2f} / 10" if risk_val is not None else "Not yet scored"
    source_str = html.escape(str(report_ctx.get("source") or "on-demand"), quote=True)
    created_str = html.escape(str(report_ctx.get("created_at") or "—"), quote=True)
    og_desc = html.escape(
        f"Security status for {report_ctx['short_address']} on {report_ctx['chain_name']}: "
        f"{report_ctx['verdict_badge']}. Inspect selectors, honeypot traps, or run a paid x402 deep audit.",
        quote=True,
    )

    hp_flags = []
    if isinstance(report_ctx.get("honeypot_analysis"), dict):
        hp_flags = report_ctx["honeypot_analysis"].get("honeypot_flags") or []
    flags_items = "".join(
        f"<li>{html.escape(str(flag), quote=True)}</li>" for flag in hp_flags
    ) or "<li>No static honeypot flags cached yet. Run Live Stage-1 Scan below.</li>"

    high_risk_sigs = report_ctx.get("high_risk_signatures") or []
    sig_items = "".join(
        f"<li><code>{html.escape(str(sig), quote=True)}</code></li>" for sig in high_risk_sigs
    ) or "<li>No cached high-risk administrative selectors.</li>"

    curl_token_check = html.escape(
        f'curl -X POST "{public_url}/token/check" -H "Content-Type: application/json" '
        f'-d \'{{"token_address": "{report_ctx["address"]}", "chain_id": {chain_id}}}\'',
        quote=True,
    )
    curl_deep_audit = html.escape(
        f'curl -X POST "{public_url}/audit/deep" -H "Content-Type: application/json" '
        f'-d \'{{"target_address": "{report_ctx["address"]}", "chain_id": {chain_id}, '
        f'"resolve_proxy": true, "fetch_verified_source": true}}\'',
        quote=True,
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Security Report {short_addr} ({chain_name}) — Web3 Systemic Agent</title>
  <meta property="og:title" content="Web3 Systemic Agent — {short_addr} ({chain_name})" />
  <meta property="og:description" content="{og_desc}" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="{report_url}" />
  <meta property="og:image" content="{card_svg_url}" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Web3 Systemic Agent — {short_addr} ({chain_name})" />
  <meta name="twitter:description" content="{og_desc}" />
  <meta name="twitter:image" content="{card_svg_url}" />
  <style>
    :root {{ --bg:#0A0B0D; --panel:#111318; --border:#1E2430; --text:#F8FAFC; --muted:#94A3B8; --blue:#0052FF; --cyan:#00D2FF; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; }}
    .wrap {{ max-width:980px; margin:0 auto; padding:28px 20px 64px; }}
    .nav {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; gap:12px; flex-wrap:wrap; }}
    .nav a {{ color:var(--cyan); text-decoration:none; font-weight:600; }}
    .badge {{ display:inline-block; padding:6px 14px; border-radius:999px; font-weight:700; font-size:13px; color:{badge_color}; background:{badge_bg}; border:1px solid {badge_color}; }}
    .card-img {{ width:100%; border-radius:16px; border:1px solid var(--border); display:block; margin:16px 0 24px; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; margin-bottom:24px; }}
    .box {{ background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:18px; }}
    .lbl {{ font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin-bottom:6px; }}
    .val {{ font-size:18px; font-weight:700; word-break:break-all; }}
    .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:13px; }}
    .btn {{ background:var(--blue); color:#fff; border:none; border-radius:10px; padding:11px 18px; font-weight:700; cursor:pointer; font-size:14px; }}
    .btn:hover {{ background:#1652F0; }}
    pre {{ background:#07090D; border:1px solid var(--border); padding:12px; border-radius:10px; overflow-x:auto; font-size:12px; color:#E2E8F0; }}
    ul {{ margin:8px 0 0 18px; color:var(--muted); }}
    #live-out {{ margin-top:16px; display:none; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="nav">
      <a href="/?format=html">← Web3 Systemic Agent Playground</a>
      <span class="badge">{badge_label}</span>
    </div>
    <h1 style="margin:0 0 6px;">Contract Security Report</h1>
    <div class="mono" style="color:var(--muted);">{addr} • {chain_name} (eip155:{chain_id})</div>

    <img class="card-img" src="/report/{chain_id}/{addr}/card.svg" alt="Contract Security Card for {short_addr}" />

    <div class="grid">
      <div class="box"><div class="lbl">Latest Verdict</div><div class="val">{decision_str}</div></div>
      <div class="box"><div class="lbl">Risk Score</div><div class="val">{html.escape(risk_str, quote=True)}</div></div>
      <div class="box"><div class="lbl">Discovery Source</div><div class="val">{source_str}</div></div>
      <div class="box"><div class="lbl">Last Evaluated</div><div class="val mono">{created_str}</div></div>
    </div>

    <div class="box" style="margin-bottom:20px;">
      <div class="lbl">Static Bytecode &amp; Selector Signals (Cached: {str(report_ctx.get("bytecode_cached")).lower()})</div>
      <ul>{flags_items}</ul>
      <div class="lbl" style="margin-top:14px;">High-Risk Admin Selectors</div>
      <ul>{sig_items}</ul>
    </div>

    <div class="box" style="margin-bottom:20px;">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
        <div>
          <div class="lbl">Free On-Demand Verification</div>
          <div style="font-weight:700;">Run Live Stage-1 MCP Scan (Honeypot + Selectors)</div>
        </div>
        <button id="run-scan-btn" class="btn" type="button">Run Live Stage-1 Scan ($0.00)</button>
      </div>
      <div id="live-out" class="box" style="margin-top:14px; background:#07090D;"></div>
    </div>

    <div class="box">
      <div class="lbl">Upgrade to Paid x402 Verification (Base USDC)</div>
      <p style="margin:4px 0 8px; color:var(--muted); font-size:14px;">Quick Token Check (<strong>$0.005</strong>):</p>
      <pre>{curl_token_check}</pre>
      <p style="margin:12px 0 8px; color:var(--muted); font-size:14px;">Deep Source &amp; Proxy Audit (<strong>$0.25</strong>):</p>
      <pre>{curl_deep_audit}</pre>
    </div>
  </div>
  <script>
    (function () {{
      var btn = document.getElementById("run-scan-btn");
      var out = document.getElementById("live-out");
      var targetAddr = {json.dumps(str(report_ctx["address"]))};
      var chainId = {chain_id};

      btn.addEventListener("click", async function () {{
        btn.disabled = true;
        btn.textContent = "Scanning on-chain bytecode...";
        out.style.display = "block";
        out.textContent = "Calling /mcp check_token_honeypot & scan_contract_selectors...";
        try {{
          var res = await fetch("/mcp", {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify([
              {{
                jsonrpc: "2.0", id: 1, method: "tools/call",
                params: {{ name: "check_token_honeypot", arguments: {{ token_address: targetAddr, chain_id: chainId }} }}
              }},
              {{
                jsonrpc: "2.0", id: 2, method: "tools/call",
                params: {{ name: "scan_contract_selectors", arguments: {{ target_address: targetAddr, chain_id: chainId }} }}
              }}
            ])
          }});
          var data = await res.json();
          out.textContent = JSON.stringify(data, null, 2);
        }} catch (err) {{
          out.textContent = "Scan error: " + (err && err.message ? err.message : String(err));
        }} finally {{
          btn.disabled = false;
          btn.textContent = "Run Live Stage-1 Scan ($0.00)";
        }}
      }});
    }})();
  </script>
</body>
</html>"""


def _build_landing_html(public_url: str, x402_cfg: X402Config) -> str:
    """Render self-contained dark-mode Landing Page + Live Stage-1 Playground + Threat Feed."""
    safe_url = html.escape(public_url, quote=True)
    price_token = f"{x402_cfg.price_per_token_check_usdc:.3f}".rstrip("0").rstrip(".")
    price_audit = f"{x402_cfg.price_per_eval_usdc:.3f}".rstrip("0").rstrip(".")
    price_deep = f"{x402_cfg.price_per_deep_audit_usdc:.2f}"

    cursor_snippet = html.escape(
        json.dumps(
            {
                "mcpServers": {
                    "web3-systemic-agent": {
                        "url": f"{public_url}/mcp",
                    }
                }
            },
            indent=2,
        ),
        quote=True,
    )
    claude_snippet = html.escape(
        json.dumps(
            {
                "mcpServers": {
                    "web3-systemic-agent": {
                        "command": "uvx",
                        "args": [
                            "--from",
                            "git+https://github.com/RafaCoelho33/web3-systemic-agent",
                            "web3-systemic-agent",
                        ],
                    }
                }
            },
            indent=2,
        ),
        quote=True,
    )
    uvx_snippet = html.escape(
        "uvx --from git+https://github.com/RafaCoelho33/web3-systemic-agent web3-systemic-agent",
        quote=True,
    )
    x402_snippet = html.escape(
        f"# 1. Quick Token Check (${price_token} USDC)\n"
        f'curl -X POST "{public_url}/token/check" -H "Content-Type: application/json" \\\n'
        f'  -d \'{{"token_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "chain_id": 8453}}\'\n\n'
        f"# 2. Quick AI Contract Audit (${price_audit} USDC)\n"
        f'curl -X POST "{public_url}/audit" -H "Content-Type: application/json" \\\n'
        f'  -d \'{{"target_address": "0x4200000000000000000000000000000000000006", "chain_id": 8453}}\'\n\n'
        f"# 3. Deep Source & Proxy Audit (${price_deep} USDC)\n"
        f'curl -X POST "{public_url}/audit/deep" -H "Content-Type: application/json" \\\n'
        f'  -d \'{{"target_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "chain_id": 8453, "resolve_proxy": true, "fetch_verified_source": true}}\'',
        quote=True,
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Web3 Systemic Agent v1.0.2 — Autonomous EVM Security Firewall</title>
  <style>
    :root {{
      --bg:#07090D; --panel:#10141D; --panel-alt:#0B0E15; --border:#1E293B;
      --text:#F8FAFC; --muted:#94A3B8; --blue:#0052FF; --cyan:#00D2FF;
      --green:#00D26A; --amber:#FAAD14; --red:#FF4D4F;
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
      background:radial-gradient(circle at top right, rgba(0,82,255,0.14), transparent 42%), var(--bg);
      color:var(--text); line-height:1.5;
    }}
    .container {{ max-width:1120px; margin:0 auto; padding:32px 20px 72px; }}
    .hero {{ display:flex; justify-content:space-between; align-items:flex-start; gap:20px; flex-wrap:wrap; margin-bottom:28px; }}
    .brand {{ display:flex; align-items:center; gap:14px; }}
    .pill {{ display:inline-block; padding:4px 12px; border-radius:999px; font-size:12px; font-weight:700; background:rgba(0,210,255,0.12); color:var(--cyan); border:1px solid rgba(0,210,255,0.35); }}
    h1 {{ margin:6px 0 6px; font-size:30px; letter-spacing:-0.02em; }}
    .subtitle {{ color:var(--muted); margin:0; font-size:15px; }}
    .links {{ display:flex; gap:10px; flex-wrap:wrap; }}
    .link-btn {{ padding:8px 14px; border-radius:10px; border:1px solid var(--border); background:var(--panel); color:var(--text); text-decoration:none; font-size:13px; font-weight:600; }}
    .link-btn:hover {{ border-color:var(--cyan); }}
    .card {{ background:var(--panel); border:1px solid var(--border); border-radius:16px; padding:22px; margin-bottom:22px; }}
    .card-title {{ margin:0 0 14px; font-size:18px; display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; }}
    .form-row {{ display:grid; grid-template-columns:1fr 220px auto; gap:10px; }}
    @media (max-width: 760px) {{ .form-row {{ grid-template-columns:1fr; }} }}
    input, select {{
      background:var(--panel-alt); border:1px solid var(--border); color:var(--text);
      padding:11px 14px; border-radius:10px; font-size:14px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    }}
    .btn {{ background:var(--blue); color:#fff; border:none; padding:11px 18px; border-radius:10px; font-weight:700; cursor:pointer; font-size:14px; }}
    .btn:hover {{ background:#1652F0; }}
    .btn-ghost {{ background:var(--panel-alt); color:var(--cyan); border:1px solid var(--border); padding:7px 12px; border-radius:8px; font-size:12px; font-weight:600; cursor:pointer; }}
    .btn-ghost:hover {{ border-color:var(--cyan); }}
    .chips {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; align-items:center; }}
    .verdict-box {{ margin-top:18px; padding:16px; border-radius:12px; background:var(--panel-alt); border:1px solid var(--border); display:none; }}
    .verdict-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin-top:12px; }}
    .stat {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:12px; }}
    .stat-lbl {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }}
    .stat-val {{ font-size:16px; font-weight:700; margin-top:4px; }}
    table {{ width:100%; border-collapse:collapse; font-size:13px; }}
    th, td {{ text-align:left; padding:10px 8px; border-bottom:1px solid var(--border); }}
    th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.06em; }}
    .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
    .tabs {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px; }}
    .tab {{ background:var(--panel-alt); color:var(--muted); border:1px solid var(--border); padding:8px 14px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer; }}
    .tab.active {{ color:#fff; border-color:var(--blue); background:rgba(0,82,255,0.22); }}
    pre {{ margin:0; background:#06080C; border:1px solid var(--border); border-radius:10px; padding:14px; overflow-x:auto; font-size:12px; color:#E2E8F0; }}
    a.addr-link {{ color:var(--cyan); text-decoration:none; }}
    a.addr-link:hover {{ text-decoration:underline; }}
  </style>
</head>
<body>
  <div class="container">
    <header class="hero">
      <div class="brand">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="56" height="56">
          <rect width="128" height="128" rx="28" fill="#0D111A" stroke="#1E293B" stroke-width="3"/>
          <path d="M64 16 L104 32 C104 76 74 104 64 112 C54 104 24 76 24 32 Z" fill="#0052FF"/>
          <circle cx="64" cy="64" r="16" fill="#00D2FF"/>
          <path d="M58 64 L62 68 L70 58" fill="none" stroke="#FFFFFF" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <div>
          <span class="pill">v1.0.2 • Base Mainnet &amp; x402 Bazaar</span>
          <h1>Web3 Systemic Agent</h1>
          <p class="subtitle">Autonomous EVM Security Firewall, MCP Server &amp; x402 Auditor on Base</p>
        </div>
      </div>
      <div class="links">
        <a class="link-btn" href="/?format=json">Discovery JSON</a>
        <a class="link-btn" href="/feed/recent">Feed JSON</a>
        <a class="link-btn" href="/llms.txt">llms.txt</a>
        <a class="link-btn" href="/.well-known/x402">x402 Manifest</a>
      </div>
    </header>

    <section class="card">
      <h2 class="card-title">
        <span>Interactive Free Stage-1 Scanner Playground</span>
        <span class="pill">Free via POST /mcp</span>
      </h2>
      <div class="form-row">
        <input id="scan-addr" type="text" value="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" placeholder="0x... EVM Contract or Token Address" aria-label="Contract Address" />
        <select id="scan-chain" aria-label="EVM Chain">
          <option value="8453" selected>8453 — Base Mainnet</option>
          <option value="84532">84532 — Base Sepolia</option>
          <option value="42161">42161 — Arbitrum One</option>
        </select>
        <button id="scan-btn" class="btn" type="button">Scan Free (Stage 1)</button>
      </div>
      <div class="chips">
        <span style="font-size:12px;color:var(--muted);">Quick examples:</span>
        <button class="btn-ghost example-btn" type="button" data-addr="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" data-chain="8453">Base USDC</button>
        <button class="btn-ghost example-btn" type="button" data-addr="0x4200000000000000000000000000000000000006" data-chain="8453">Base WETH</button>
      </div>
      <div id="verdict-box" class="verdict-box">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
          <strong id="verdict-title">Stage-1 Scan Result</strong>
          <a id="verdict-report-link" class="addr-link mono" href="#">Open Shareable Report →</a>
        </div>
        <div id="verdict-grid" class="verdict-grid"></div>
        <div style="margin-top:14px;">
          <div class="stat-lbl" style="margin-bottom:6px;">Upgrade with x402 Micropayments (USDC on Base)</div>
          <pre id="verdict-upgrade"></pre>
        </div>
      </div>
    </section>

    <section class="card">
      <h2 class="card-title">
        <span>Live Threat Intelligence Feed</span>
        <button id="feed-refresh" class="btn-ghost" type="button">Refresh Feed</button>
      </h2>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Contract</th>
              <th>Chain</th>
              <th>Source</th>
              <th>Decision</th>
              <th>Score</th>
              <th>LLM</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody id="feed-body">
            <tr><td colspan="7" style="color:var(--muted);">Loading live evaluations...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <h2 class="card-title">
        <span>Quick Install Snippets</span>
        <button id="copy-snippet" class="btn-ghost" type="button">Copy Snippet</button>
      </h2>
      <div class="tabs">
        <button class="tab active" type="button" data-tab="cursor">Cursor (.cursor/mcp.json)</button>
        <button class="tab" type="button" data-tab="claude">Claude Desktop</button>
        <button class="tab" type="button" data-tab="uvx">uvx CLI</button>
        <button class="tab" type="button" data-tab="x402">x402 HTTP</button>
      </div>
      <pre id="snippet-cursor">{cursor_snippet}</pre>
      <pre id="snippet-claude" style="display:none;">{claude_snippet}</pre>
      <pre id="snippet-uvx" style="display:none;">{uvx_snippet}</pre>
      <pre id="snippet-x402" style="display:none;">{x402_snippet}</pre>
    </section>
  </div>

  <script>
    (function () {{
      var PUBLIC_URL = {json.dumps(safe_url)};
      var addrInput = document.getElementById("scan-addr");
      var chainSelect = document.getElementById("scan-chain");
      var scanBtn = document.getElementById("scan-btn");
      var verdictBox = document.getElementById("verdict-box");
      var verdictTitle = document.getElementById("verdict-title");
      var verdictGrid = document.getElementById("verdict-grid");
      var verdictReport = document.getElementById("verdict-report-link");
      var verdictUpgrade = document.getElementById("verdict-upgrade");

      function addStat(label, value) {{
        var div = document.createElement("div");
        div.className = "stat";
        var l = document.createElement("div");
        l.className = "stat-lbl";
        l.textContent = label;
        var v = document.createElement("div");
        v.className = "stat-val";
        v.textContent = String(value);
        div.appendChild(l);
        div.appendChild(v);
        verdictGrid.appendChild(div);
      }}

      function parseMcpToolResult(rpcEntry) {{
        if (!rpcEntry || !rpcEntry.result) return null;
        if (rpcEntry.result.structuredContent) return rpcEntry.result.structuredContent;
        if (Array.isArray(rpcEntry.result.content) && rpcEntry.result.content[0] && rpcEntry.result.content[0].text) {{
          try {{ return JSON.parse(rpcEntry.result.content[0].text); }} catch (e) {{ return null; }}
        }}
        return rpcEntry.result;
      }}

      async function runScan() {{
        var addr = (addrInput.value || "").trim();
        var chainId = parseInt(chainSelect.value || "8453", 10);
        if (!addr) return;
        scanBtn.disabled = true;
        scanBtn.textContent = "Scanning...";
        verdictBox.style.display = "block";
        verdictTitle.textContent = "Running Stage-1 MCP tools...";
        verdictGrid.innerHTML = "";
        try {{
          var resp = await fetch("/mcp", {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify([
              {{
                jsonrpc: "2.0", id: 1, method: "tools/call",
                params: {{ name: "check_token_honeypot", arguments: {{ token_address: addr, chain_id: chainId }} }}
              }},
              {{
                jsonrpc: "2.0", id: 2, method: "tools/call",
                params: {{ name: "scan_contract_selectors", arguments: {{ target_address: addr, chain_id: chainId }} }}
              }}
            ])
          }});
          var data = await resp.json();
          var hp = parseMcpToolResult(Array.isArray(data) ? data[0] : data) || {{}};
          var sel = parseMcpToolResult(Array.isArray(data) ? data[1] : null) || {{}};

          var suspect = Boolean(hp.is_honeypot_suspect);
          verdictTitle.textContent = suspect ? "HIGH RISK — Honeypot Indicators Found" : ("Stage-1 Verdict: " + (sel.risk_level || "SCANNED"));
          verdictTitle.style.color = suspect ? "var(--red)" : (sel.risk_level === "HIGH" ? "var(--amber)" : "var(--green)");
          verdictReport.href = "/report/" + chainId + "/" + encodeURIComponent(addr) + "?format=html";

          addStat("Honeypot Suspect", suspect ? "YES" : "NO");
          addStat("Risk Score", hp.risk_score !== undefined ? hp.risk_score + " / 10" : "N/A");
          addStat("Selector Risk", sel.risk_level || "N/A");
          addStat("Bytecode Size", (sel.bytecode_size_bytes !== undefined ? sel.bytecode_size_bytes : 0) + " bytes");

          verdictUpgrade.textContent =
            "Quick Token Check ($0.005): " + PUBLIC_URL + "/token/check?address=" + addr + "&chain_id=" + chainId + "\\n" +
            "Quick AI Audit    ($0.015): POST " + PUBLIC_URL + "/audit\\n" +
            "Deep Source Audit ($0.25) : POST " + PUBLIC_URL + "/audit/deep";
        }} catch (err) {{
          verdictTitle.textContent = "Scan failed: " + (err && err.message ? err.message : String(err));
          verdictTitle.style.color = "var(--red)";
        }} finally {{
          scanBtn.disabled = false;
          scanBtn.textContent = "Scan Free (Stage 1)";
        }}
      }}

      scanBtn.addEventListener("click", runScan);
      document.querySelectorAll(".example-btn").forEach(function (btn) {{
        btn.addEventListener("click", function () {{
          addrInput.value = btn.getAttribute("data-addr") || "";
          chainSelect.value = btn.getAttribute("data-chain") || "8453";
          runScan();
        }});
      }});

      async function loadFeed() {{
        var tbody = document.getElementById("feed-body");
        try {{
          var resp = await fetch("/feed/recent?limit=10");
          var data = await resp.json();
          var items = Array.isArray(data.items) ? data.items : [];
          tbody.innerHTML = "";
          if (!items.length) {{
            var emptyRow = document.createElement("tr");
            var emptyCell = document.createElement("td");
            emptyCell.colSpan = 7;
            emptyCell.style.color = "var(--muted)";
            emptyCell.textContent = "No evaluations recorded yet. Run a scan above to populate the feed.";
            emptyRow.appendChild(emptyCell);
            tbody.appendChild(emptyRow);
            return;
          }}
          items.forEach(function (it) {{
            var tr = document.createElement("tr");
            var tdAddr = document.createElement("td");
            tdAddr.className = "mono";
            if (it.target_address && it.chain_id) {{
              var a = document.createElement("a");
              a.className = "addr-link";
              a.href = "/report/" + it.chain_id + "/" + encodeURIComponent(it.target_address) + "?format=html";
              a.textContent = it.target_address.length > 14 ? (it.target_address.slice(0, 8) + "..." + it.target_address.slice(-6)) : it.target_address;
              tdAddr.appendChild(a);
            }} else {{
              tdAddr.textContent = it.rule_id || "—";
            }}
            tr.appendChild(tdAddr);

            [it.chain_id || "—", it.source || "api", it.decision || "—", it.risk_score !== null && it.risk_score !== undefined ? it.risk_score : "—", it.llm_invoked ? "Yes" : "Stage-1", it.created_at || "—"].forEach(function (val) {{
              var td = document.createElement("td");
              td.textContent = String(val);
              tr.appendChild(td);
            }});
            tbody.appendChild(tr);
          }});
        }} catch (err) {{
          tbody.innerHTML = "";
          var errRow = document.createElement("tr");
          var errCell = document.createElement("td");
          errCell.colSpan = 7;
          errCell.style.color = "var(--red)";
          errCell.textContent = "Failed to load feed.";
          errRow.appendChild(errCell);
          tbody.appendChild(errRow);
        }}
      }}

      document.getElementById("feed-refresh").addEventListener("click", loadFeed);
      loadFeed();

      var activeTab = "cursor";
      document.querySelectorAll(".tab").forEach(function (tab) {{
        tab.addEventListener("click", function () {{
          activeTab = tab.getAttribute("data-tab") || "cursor";
          document.querySelectorAll(".tab").forEach(function (t) {{ t.classList.remove("active"); }});
          tab.classList.add("active");
          ["cursor", "claude", "uvx", "x402"].forEach(function (name) {{
            var pre = document.getElementById("snippet-" + name);
            if (pre) pre.style.display = name === activeTab ? "block" : "none";
          }});
        }});
      }});

      document.getElementById("copy-snippet").addEventListener("click", function () {{
        var pre = document.getElementById("snippet-" + activeTab);
        if (pre && navigator.clipboard) {{
          navigator.clipboard.writeText(pre.textContent || "");
        }}
      }});
    }})();
  </script>
</body>
</html>"""


def create_app(
    engine: Optional[ConditionAgentEngine] = None,
    storage: Optional[AgentStorage] = None,
    x402_config: Optional[X402Config] = None,
    facilitator: Optional[Any] = None,
    rate_limit_per_minute: Optional[int] = None,
    public_evaluate_only: Optional[bool] = None,
    enable_background_scanner: Optional[bool] = None,
) -> FastAPI:
    """
    Creates and configures the FastAPI application instance.
    Allows injecting custom ConditionAgentEngine, AgentStorage, X402Config, and facilitator instances.
    """
    configure_runtime_logging()

    if public_evaluate_only is not None:
        effective_public_evaluate_only = bool(public_evaluate_only)
    else:
        effective_public_evaluate_only = (
            os.getenv("PUBLIC_EVALUATE_ONLY", "false").strip().lower()
            in ("true", "1", "yes")
        )

    if enable_background_scanner is not None:
        effective_enable_scanner = bool(enable_background_scanner)
    else:
        env_scanner = os.getenv("ENABLE_BACKGROUND_SCANNER")
        if env_scanner is not None:
            effective_enable_scanner = env_scanner.strip().lower() in ("true", "1", "yes")
        else:
            effective_enable_scanner = bool(os.getenv("RENDER"))

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        configure_runtime_logging()
        if effective_enable_scanner:
            app_instance.state.scanner_active = True
            app_instance.state.scanner_task = asyncio.create_task(
                _background_scanner_worker(app_instance)
            )
        else:
            app_instance.state.scanner_active = False
            app_instance.state.scanner_task = None

        yield

        if hasattr(app_instance.state, "scanner_task") and app_instance.state.scanner_task:
            app_instance.state.scanner_task.cancel()
            try:
                await app_instance.state.scanner_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.warning(f"Error during scanner task cancellation: {exc}")
            app_instance.state.scanner_active = False

        if hasattr(app_instance.state, "worker_pool") and app_instance.state.worker_pool:
            await app_instance.state.worker_pool.shutdown()

    app = FastAPI(
        title="Web3 Condition-Action Trigger Agent",
        version="1.0.2",
        description=(
            "Autonomous Web3 Agent for deterministic on-chain gatekeeping "
            "and LLM-powered semantic governance/security auditing."
        ),
        lifespan=lifespan,
        docs_url=None if effective_public_evaluate_only else "/docs",
        redoc_url=None if effective_public_evaluate_only else "/redoc",
        openapi_url="/openapi.json",
    )

    # Associate engine, storage, worker pool, and x402 state with application
    active_engine = engine if engine is not None else ConditionAgentEngine()
    active_storage = storage or getattr(active_engine, "storage", None) or AgentStorage()
    active_x402_config = x402_config if x402_config is not None else X402Config()
    active_facilitator = facilitator if facilitator is not None else get_x402_facilitator(active_x402_config)

    app.state.engine = active_engine
    app.state.storage = active_storage
    app.state.worker_pool = AgentWorkerPool(
        engine=active_engine, num_workers=2, storage=active_storage
    )
    app.state.x402_config = active_x402_config
    app.state.facilitator = active_facilitator
    app.state.scanner_active = False
    app.state.scanner_task = None
    app.state.mcp_server = Web3SystemicMCPServer(
        engine=active_engine,
        x402_config=active_x402_config,
        facilitator=active_facilitator,
        storage=active_storage,
        remote_mode=False,
    )
    app.state.preflight_firewall = PreflightFirewall()
    app.state.source_resolver = ContractSourceResolver()

    # ---------------------------------------------------------------------
    # Middlewares (Registered innermost -> outermost due to Starlette LIFO)
    # ---------------------------------------------------------------------

    # 1. Innermost: Intercept paid endpoints for Coinbase CDP Crawler & x402 Bazaar compliance
    @app.middleware("http")
    async def x402_evaluate_interceptor(request: Request, call_next):
        clean_path = request.url.path.rstrip("/")
        if clean_path in ("/evaluate", "/audit", "/preflight", "/audit/deep", "/token/check") and request.method in ("GET", "POST"):
            x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
            if x402_cfg.enabled:
                payment_hdr = (
                    request.headers.get("x-payment")
                    or request.headers.get("payment-signature")
                    or request.headers.get("x-payment-signature")
                    or request.headers.get("X-PAYMENT")
                    or request.headers.get("PAYMENT-SIGNATURE")
                )
                has_payment = bool(payment_hdr and payment_hdr.strip())
                if not has_payment:
                    if clean_path == "/preflight":
                        req_price = x402_cfg.price_per_preflight_usdc
                    elif clean_path == "/audit/deep":
                        req_price = x402_cfg.price_per_deep_audit_usdc
                    elif clean_path == "/token/check":
                        req_price = x402_cfg.price_per_token_check_usdc
                    else:
                        req_price = x402_cfg.price_per_eval_usdc
                    return build_402_response(
                        x402_cfg,
                        request.url.path,
                        req_price,
                    )
        return await call_next(request)

    # 2. Public Evaluate-Only Lockdown Mode
    app.state.public_evaluate_only = effective_public_evaluate_only

    if effective_public_evaluate_only:
        @app.middleware("http")
        async def public_evaluate_only_middleware(request: Request, call_next):
            # Optional admin bypass if ADMIN_API_KEY is configured
            admin_key = os.getenv("ADMIN_API_KEY", "").strip()
            if admin_key and request.headers.get("x-admin-api-key") == admin_key:
                return await call_next(request)

            allowed_paths = {
                "/",
                "/openapi.json",
                "/favicon.ico",
                "/icon.svg",
                "/health",
                "/evaluate",
                "/audit",
                "/preflight",
                "/audit/deep",
                "/token/check",
                "/feed/recent",
                "/rules/evaluate-batch",
                "/rules/validate",
                "/rules/enqueue",
                "/mcp",
                "/robots.txt",
                "/llms.txt",
                "/llms-full.txt",
                "/mcp/server-card",
                "/mcp/server-card.json",
                "/security.txt",
            }
            clean_path = request.url.path.rstrip("/") or "/"
            if (
                clean_path in allowed_paths
                or clean_path.startswith("/jobs/")
                or clean_path.startswith("/report/")
                or clean_path.startswith("/.well-known/")
                or clean_path.startswith("/mcp/.well-known/")
            ):
                return await call_next(request)

            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden",
                    "message": "Public access is restricted to evaluation endpoints only.",
                },
                headers={
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                },
            )

    # 3. Per-IP Sliding-Window Rate Limiter
    try:
        default_rate_limit = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    except (ValueError, TypeError):
        default_rate_limit = 60
    effective_rate_limit = (
        rate_limit_per_minute
        if rate_limit_per_minute is not None
        else default_rate_limit
    )

    app.state.rate_limit_buckets = {}

    if effective_rate_limit > 0:
        @app.middleware("http")
        async def rate_limit_middleware(request: Request, call_next):
            client_ip = (
                request.headers.get("cf-connecting-ip")
                or (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
                or (request.client.host if request.client else "unknown")
            )
            if not client_ip:
                client_ip = request.client.host if request.client else "unknown"

            now = time.monotonic()
            buckets = app.state.rate_limit_buckets

            # Prune expired keys if dictionary grows large to bound memory
            if len(buckets) > 5000:
                cutoff = now - 60.0
                expired_keys = [k for k, v in buckets.items() if not v or v[-1] < cutoff]
                for k in expired_keys:
                    buckets.pop(k, None)

            # Prune timestamps older than 60.0 seconds for client_ip
            timestamps = [ts for ts in buckets.get(client_ip, []) if now - ts < 60.0]
            buckets[client_ip] = timestamps

            if len(timestamps) >= effective_rate_limit:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "TooManyRequests",
                        "message": f"Rate limit of {effective_rate_limit} requests per minute exceeded.",
                    },
                    headers={"Retry-After": "60"},
                )

            buckets[client_ip].append(now)
            return await call_next(request)

    # 4. Defensive HTTP Security Headers (applied to all responses, including 402/403/404/429)
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # 5. Outermost: Enable CORS for B2B/Micro-SaaS integration (covers 402/403/404/429 responses)
    raw_origins = os.getenv("CORS_ALLOW_ORIGINS", "*")
    origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
    if not origins:
        origins = ["*"]
    allow_credentials = "*" not in origins

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-PAYMENT-REQUIRED", "X-PAYMENT-RESPONSE", "PAYMENT-RESPONSE", "Payment-Required"],
    )

    # ---------------------------------------------------------------------
    # Standardized Exception Handlers
    # ---------------------------------------------------------------------

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger.warning(f"Request validation error on {request.url.path}: {exc.errors()}")
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
        if storage_inst is not None:
            try:
                await storage_inst.log_error(
                    stage="validation",
                    error_type="RequestValidationError",
                    message=str(exc.errors()),
                    context={"path": str(request.url.path), "method": str(request.method)},
                )
            except Exception:
                pass
        return JSONResponse(
            status_code=422,
            content=jsonable_encoder({
                "error": "RequestValidationError",
                "message": "The supplied request body failed schema validation.",
                "details": exc.errors(),
            }),
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        logger.warning(f"HTTPException on {request.url.path} [{exc.status_code}]: {exc.detail}")
        clean_path = request.url.path.rstrip("/") or "/"
        is_well_known_404 = (
            exc.status_code == 404
            and (clean_path.startswith("/.well-known/") or clean_path.startswith("/mcp/.well-known/"))
        )
        if exc.status_code >= 400 and not is_well_known_404:
            storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
            if storage_inst is not None:
                try:
                    await storage_inst.log_error(
                        stage="validation" if exc.status_code == 422 else "api",
                        error_type="HTTPException",
                        message=str(exc.detail),
                        context={
                            "path": str(request.url.path),
                            "method": str(request.method),
                            "status_code": exc.status_code,
                        },
                    )
                except Exception:
                    pass
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "HTTPException",
                "message": exc.detail,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception(f"Unhandled server error on {request.url.path}: {exc}")
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
        if storage_inst is not None:
            try:
                await storage_inst.log_error(
                    stage="api",
                    error_type=type(exc).__name__,
                    message=str(exc),
                    traceback_str=traceback.format_exc(),
                    context={"path": str(request.url.path), "method": str(request.method)},
                )
            except Exception:
                pass
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "InternalServerError",
                "message": "An unexpected server error occurred during request processing.",
                "detail": str(exc),
            },
        )

    # ---------------------------------------------------------------------
    # Endpoints
    # ---------------------------------------------------------------------

    @app.get(
        "/",
        response_model=ServiceDiscoveryResponse,
        tags=["Monitoring"],
        summary="Service Discovery and Root Status",
    )
    async def root(request: Request, format: Optional[str] = None):
        """
        Root discovery endpoint supporting content negotiation:
        serves interactive HTML landing page & playground for browsers (?format=html or Accept: text/html),
        and canonical JSON ServiceDiscoveryResponse for programmatic clients.
        """
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        if _wants_html_response(request, format):
            return HTMLResponse(
                content=_build_landing_html(_get_public_url(), x402_cfg),
                status_code=status.HTTP_200_OK,
            )

        if getattr(app.state, "public_evaluate_only", False):
            endpoints = {
                "openapi": "/openapi.json",
                "health": "/health",
                "validate_rule": "/rules/validate",
                "evaluate": "/evaluate",
                "audit": "/audit",
                "preflight": "/preflight",
                "deep_audit": "/audit/deep",
                "token_check": "/token/check",
                "feed_recent": "/feed/recent",
                "report_template": "/report/{chain_id}/{address}",
                "evaluate_batch": "/rules/evaluate-batch",
                "enqueue_job": "/rules/enqueue",
                "mcp": "/mcp",
                "llms_txt": "/llms.txt",
                "well_known_x402": "/.well-known/x402",
                "mcp_server_card": "/.well-known/mcp/server-card.json",
                "agent_card": "/.well-known/agent.json",
            }
        else:
            endpoints = {
                "swagger_docs": "/docs",
                "openapi": "/openapi.json",
                "health": "/health",
                "validate_rule": "/rules/validate",
                "evaluate": "/evaluate",
                "audit": "/audit",
                "preflight": "/preflight",
                "deep_audit": "/audit/deep",
                "token_check": "/token/check",
                "feed_recent": "/feed/recent",
                "report_template": "/report/{chain_id}/{address}",
                "evaluate_batch": "/rules/evaluate-batch",
                "enqueue_job": "/rules/enqueue",
                "governance_audit": "/governance/audit-proposals",
                "metrics_summary": "/metrics/summary",
                "payments_ledger": "/payments",
                "error_logs": "/logs/errors",
                "mcp": "/mcp",
                "llms_txt": "/llms.txt",
                "well_known_x402": "/.well-known/x402",
                "mcp_server_card": "/.well-known/mcp/server-card.json",
                "agent_card": "/.well-known/agent.json",
            }
        return {
            "service": "Web3 Condition-Action Trigger Agent",
            "version": "1.0.2",
            "status": "online",
            "x402_enabled": x402_cfg.enabled,
            "x402_network": x402_cfg.network,
            "price_per_eval_usdc": x402_cfg.price_per_eval_usdc,
            "pay_to_address": x402_cfg.pay_to_address,
            "endpoints": endpoints,
        }

    @app.head("/", include_in_schema=False)
    async def head_root():
        """HEAD probe handler for root discovery endpoint."""
        return Response(status_code=status.HTTP_200_OK, media_type="application/json")

    @app.get(
        "/feed/recent",
        tags=["Monitoring"],
        summary="Live Autonomous Contract & Pool Security Feed",
    )
    async def get_recent_feed(limit: int = 20, source: Optional[str] = None):
        """
        Public free feed of recently audited smart contracts, DEX pools, and tokens.
        """
        clamped_limit = max(1, min(int(limit), 50))
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
        rows: List[Dict[str, Any]] = []
        if storage_inst is not None and hasattr(storage_inst, "get_recent_feed_evaluations"):
            rows = await storage_inst.get_recent_feed_evaluations(
                limit=max(clamped_limit * 2, 20)
            )

        if source is not None and source.strip():
            source_filter = source.strip().lower()
            rows = [
                r for r in rows
                if str(r.get("source") or "").strip().lower() == source_filter
            ]

        public_url = _get_public_url()
        items = [_build_feed_item(row, public_url) for row in rows[:clamped_limit]]
        return {
            "service": "Web3 Systemic Agent",
            "count": len(items),
            "items": items,
        }

    @app.head("/feed/recent", include_in_schema=False)
    async def head_recent_feed():
        """HEAD probe handler for public security feed."""
        return Response(status_code=status.HTTP_200_OK, media_type="application/json")

    @app.get(
        "/report/{chain_id}/{address}/card.svg",
        tags=["Monitoring"],
        summary="Shareable OpenGraph SVG Security Card",
    )
    async def get_contract_report_card_svg(chain_id: int, address: str):
        """Render a 1200x630 SVG OpenGraph badge card for a target contract on a chain."""
        if not Web3.is_address(address):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid EVM address: {address}",
            )
        checksum_addr = Web3.to_checksum_address(address)
        report_ctx = await _build_contract_report_context(app, chain_id, checksum_addr)
        svg_str = _build_report_svg(report_ctx)
        return Response(
            content=svg_str,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.head("/report/{chain_id}/{address}/card.svg", include_in_schema=False)
    async def head_contract_report_card_svg(chain_id: int, address: str):
        """HEAD probe handler for shareable SVG security card."""
        if not Web3.is_address(address):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid EVM address: {address}",
            )
        return Response(
            status_code=status.HTTP_200_OK,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get(
        "/report/{chain_id}/{address}",
        tags=["Monitoring"],
        summary="Shareable Contract Security Report (HTML or JSON)",
    )
    async def get_contract_report(
        chain_id: int,
        address: str,
        request: Request,
        format: Optional[str] = None,
    ):
        """
        Returns a shareable contract security report combining evaluation history and
        cached static bytecode analysis (HTML with OpenGraph meta tags for browsers,
        structured JSON for programmatic callers).
        """
        if not Web3.is_address(address):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid EVM address: {address}",
            )
        checksum_addr = Web3.to_checksum_address(address)
        report_ctx = await _build_contract_report_context(app, chain_id, checksum_addr)

        if _wants_html_response(request, format):
            return HTMLResponse(
                content=_build_report_html(report_ctx, _get_public_url()),
                status_code=status.HTTP_200_OK,
            )

        return {
            "address": report_ctx["address"],
            "chain_id": report_ctx["chain_id"],
            "chain_name": report_ctx["chain_name"],
            "evaluated": report_ctx["evaluated"],
            "latest_decision": report_ctx["latest_decision"],
            "risk_score": report_ctx["risk_score"],
            "verdict_badge": report_ctx["verdict_badge"],
            "bytecode_cached": report_ctx["bytecode_cached"],
            "bytecode_size_bytes": report_ctx["bytecode_size_bytes"],
            "selectors_count": report_ctx["selectors_count"],
            "high_risk_signatures": report_ctx["high_risk_signatures"],
            "honeypot_analysis": report_ctx["honeypot_analysis"],
            "rule_id": report_ctx["rule_id"],
            "source": report_ctx["source"],
            "stage1_passed": report_ctx["stage1_passed"],
            "llm_invoked": report_ctx["llm_invoked"],
            "created_at": report_ctx["created_at"],
            "report_url": report_ctx["report_url"],
            "card_svg_url": report_ctx["card_svg_url"],
            "token_check_x402_url": report_ctx["token_check_x402_url"],
            "audit_x402_url": report_ctx["audit_x402_url"],
            "deep_audit_x402_url": report_ctx["deep_audit_x402_url"],
        }

    @app.head("/report/{chain_id}/{address}", include_in_schema=False)
    async def head_contract_report(chain_id: int, address: str):
        """HEAD probe handler for shareable contract security report."""
        if not Web3.is_address(address):
            raise HTTPException(
                status_code=422,
                detail=f"Invalid EVM address: {address}",
            )
        return Response(status_code=status.HTTP_200_OK, media_type="application/json")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        """
        Silent favicon handler returning 204 No Content to avoid browser 404 noise.
        """
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get(
        "/mcp",
        tags=["MCP Server"],
        summary="MCP Discovery and Tools Manifest",
    )
    async def get_mcp_discovery():
        """
        Model Context Protocol (MCP) streamable-http discovery endpoint.
        Returns server metadata, protocol version, and the full tools manifest.
        """
        mcp: Optional[Web3SystemicMCPServer] = getattr(app.state, "mcp_server", None)
        tools = mcp.get_tools_manifest() if mcp else []
        return {
            "name": MCP_SERVER_NAME,
            "version": MCP_SERVER_VERSION,
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "transport": "streamable-http",
            "tools": tools,
        }

    @app.head("/mcp", include_in_schema=False)
    async def head_mcp():
        """HEAD probe handler for MCP discovery endpoint."""
        return Response(status_code=status.HTTP_200_OK, media_type="application/json")

    @app.post(
        "/mcp",
        tags=["MCP Server"],
        summary="MCP JSON-RPC Execution Endpoint",
    )
    async def post_mcp_jsonrpc(request: Request):
        """
        Model Context Protocol (MCP) JSON-RPC 2.0 execution endpoint.
        Accepts standard MCP JSON-RPC requests (e.g. tools/list, tools/call, initialize, ping).
        """
        mcp: Optional[Web3SystemicMCPServer] = getattr(app.state, "mcp_server", None)
        if mcp is None:
            mcp = Web3SystemicMCPServer(
                engine=getattr(app.state, "engine", None),
                remote_mode=False,
            )
            app.state.mcp_server = mcp

        try:
            body = await request.json()
        except Exception as exc:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                },
            )

        http_payment_hdr = (
            request.headers.get("x-payment")
            or request.headers.get("payment-signature")
            or request.headers.get("x-payment-signature")
        )

        def _inject_http_payment(msg: Any) -> None:
            if not http_payment_hdr or not isinstance(msg, dict):
                return
            if msg.get("method") != "tools/call":
                return
            params = msg.get("params")
            if not isinstance(params, dict) or params.get("name") != "deep_semantic_audit":
                return
            args = params.get("arguments")
            if args is None:
                args = {}
                params["arguments"] = args
            if isinstance(args, dict) and not args.get("x402_payment_header"):
                args["x402_payment_header"] = http_payment_hdr

        if isinstance(body, list):
            responses = []
            for item in body:
                _inject_http_payment(item)
                _log_mcp_telemetry(item)
                resp = await mcp.handle_jsonrpc(item)
                if resp is not None:
                    responses.append(resp)
            return JSONResponse(status_code=status.HTTP_200_OK, content=responses)

        _inject_http_payment(body)
        _log_mcp_telemetry(body)
        rpc_resp = await mcp.handle_jsonrpc(body)
        if rpc_resp is None:
            return Response(status_code=status.HTTP_202_ACCEPTED)

        return JSONResponse(status_code=status.HTTP_200_OK, content=rpc_resp)

    # ---------------------------------------------------------------------
    # Crawler Discovery, Agent-Teaching & Security Endpoints
    # ---------------------------------------------------------------------

    @app.api_route("/robots.txt", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_robots_txt():
        """Returns robots.txt rules for search engine and AI crawlers."""
        return Response(content=ROBOTS_TXT_CONTENT, media_type="text/plain; charset=utf-8")

    @app.api_route("/llms.txt", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_llms_txt():
        """Returns concise Markdown guide teaching LLMs how to use the Web3 Systemic Agent."""
        return Response(content=LLMS_TXT_CONTENT, media_type="text/plain; charset=utf-8")

    @app.api_route("/llms-full.txt", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_llms_full_txt():
        """Returns comprehensive Markdown guide teaching LLMs how to use the Web3 Systemic Agent."""
        return Response(content=LLMS_FULL_TXT_CONTENT, media_type="text/plain; charset=utf-8")

    @app.api_route("/icon.svg", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_icon_svg():
        """Returns static server SVG icon."""
        return Response(content=ICON_SVG_CONTENT, media_type="image/svg+xml")

    @app.api_route("/.well-known/mcp/server-card.json", methods=["GET", "HEAD"], include_in_schema=False)
    @app.api_route("/.well-known/mcp.json", methods=["GET", "HEAD"], include_in_schema=False)
    @app.api_route("/mcp/server-card", methods=["GET", "HEAD"], include_in_schema=False)
    @app.api_route("/mcp/server-card.json", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_mcp_server_card():
        """Returns official MCP server card metadata."""
        public_url = (
            os.getenv("PUBLIC_API_URL")
            or os.getenv("WEB3_AGENT_URL")
            or "https://web3-systemic-agent.onrender.com"
        ).rstrip("/")
        mcp: Optional[Web3SystemicMCPServer] = getattr(app.state, "mcp_server", None)
        if mcp is None:
            mcp = Web3SystemicMCPServer(
                engine=getattr(app.state, "engine", None),
                remote_mode=False,
            )
            app.state.mcp_server = mcp

        card = {
            "serverInfo": {
                "name": "io.github.RafaCoelho33/web3-systemic-agent",
                "title": "Web3 Systemic Agent",
                "version": "1.0.2",
            },
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "websiteUrl": public_url,
            "icons": [
                {
                    "src": f"{public_url}/icon.svg",
                    "mimeType": "image/svg+xml",
                    "sizes": ["any"],
                }
            ],
            "transport": "streamable-http",
            "remotes": [
                {
                    "type": "streamable-http",
                    "url": f"{public_url}/mcp",
                }
            ],
            "authentication": {
                "required": False,
                "schemes": ["none", "x402"],
            },
            "tools": mcp.get_tools_manifest(),
            "resources": [],
            "prompts": [],
        }
        return JSONResponse(status_code=status.HTTP_200_OK, content=card)

    @app.api_route("/.well-known/agent.json", methods=["GET", "HEAD"], include_in_schema=False)
    @app.api_route("/.well-known/agent-card.json", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_agent_card():
        """Returns Agent-to-Agent (A2A) agent discovery card."""
        public_url = (
            os.getenv("PUBLIC_API_URL")
            or os.getenv("WEB3_AGENT_URL")
            or "https://web3-systemic-agent.onrender.com"
        ).rstrip("/")
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        mcp: Optional[Web3SystemicMCPServer] = getattr(app.state, "mcp_server", None)
        if mcp is None:
            mcp = Web3SystemicMCPServer(
                engine=getattr(app.state, "engine", None),
                remote_mode=False,
            )
            app.state.mcp_server = mcp

        agent_card = {
            "name": "Web3 Systemic Agent",
            "id": "io.github.RafaCoelho33/web3-systemic-agent",
            "version": "1.0.2",
            "description": (
                "Autonomous Web3 Security and Governance Auditor Agent with Two-Stage "
                "Hybrid Architecture (zero-cost on-chain gatekeeping + Gemini LLM semantic audits) "
                "and x402 Bazaar Micropayments."
            ),
            "url": public_url,
            "capabilities": {
                "mcp": True,
                "x402": True,
                "streaming": False,
            },
            "payment": {
                "protocol": "x402",
                "network": x402_cfg.network,
                "price_usdc": x402_cfg.price_per_eval_usdc,
                "pay_to_address": x402_cfg.pay_to_address,
            },
            "endpoints": {
                "mcp": "/mcp",
                "evaluate": "/evaluate",
                "audit": "/audit",
                "preflight": f"{public_url}/preflight",
                "deep_audit": f"{public_url}/audit/deep",
                "token_check": f"{public_url}/token/check",
                "validate_rule": "/rules/validate",
                "llms_txt": "/llms.txt",
                "well_known_x402": "/.well-known/x402",
                "server_card": "/.well-known/mcp/server-card.json",
            },
            "skills": mcp.get_tools_manifest(),
        }
        return JSONResponse(status_code=status.HTTP_200_OK, content=agent_card)

    @app.api_route("/.well-known/owners.json", methods=["GET", "HEAD"], include_in_schema=False)
    @app.api_route("/mcp/.well-known/owners.json", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_well_known_owners():
        """Returns verified project ownership metadata (GitHub + payout wallet)."""
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "owners": [
                    {
                        "handle": "RafaCoelho33",
                        "github": "https://github.com/RafaCoelho33",
                        "repository": "https://github.com/RafaCoelho33/web3-systemic-agent",
                        "wallet": x402_cfg.pay_to_address,
                        "network": x402_cfg.network,
                        "verified": True,
                    }
                ]
            },
        )

    @app.api_route("/.well-known/glama.json", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_well_known_glama():
        """Returns Glama MCP directory discovery manifest."""
        public_url = (
            os.getenv("PUBLIC_API_URL")
            or os.getenv("WEB3_AGENT_URL")
            or "https://web3-systemic-agent.onrender.com"
        ).rstrip("/")
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "$schema": "https://glama.ai/mcp/schemas/server.json",
                "name": "web3-systemic-agent",
                "description": (
                    "Autonomous Web3 Security and Governance Auditor MCP Server. Provides 3 free Stage 1 "
                    "on-chain analysis tools (contract selectors, honeypot detection, Snapshot DAO scanning) "
                    "and 1 paid Stage 2 Deep Semantic LLM Audit tool ($0.015 standard / $0.25 deep source audit "
                    "via x402 USDC on Base)."
                ),
                "maintainers": ["RafaCoelho33"],
                "homepage": public_url,
                "repository": "https://github.com/RafaCoelho33/web3-systemic-agent",
                "capabilities": {
                    "tools": True,
                    "resources": False,
                    "prompts": False,
                },
            },
        )

    @app.api_route("/.well-known/x402", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_well_known_x402():
        """Returns standard x402 Bazaar protocol auto-discovery specification."""
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        token_name = "USD Coin" if x402_cfg.network == "eip155:8453" else "USDC"
        public_url = (
            os.getenv("PUBLIC_API_URL")
            or os.getenv("WEB3_AGENT_URL")
            or "https://web3-systemic-agent.onrender.com"
        ).rstrip("/")

        resource_endpoints = [
            (
                "/evaluate",
                x402_cfg.price_per_eval_usdc,
                "Web3 Security & Governance Audit for /evaluate — EVM Pre-Transaction Security Firewall, Calldata Decoder & DAO Proposal Risk Auditor (Base, Ethereum, Arbitrum, Optimism)",
            ),
            (
                "/audit",
                x402_cfg.price_per_eval_usdc,
                "Web3 Security & Governance Audit for /audit — EVM Pre-Transaction Security Firewall, Calldata Decoder & DAO Proposal Risk Auditor (Base, Ethereum, Arbitrum, Optimism)",
            ),
            (
                "/preflight",
                x402_cfg.price_per_preflight_usdc,
                "Web3 Preflight Transaction Security Firewall for /preflight — Pre-sign Simulation, Approval Screening & Prompt Injection Defense",
            ),
            (
                "/audit/deep",
                x402_cfg.price_per_deep_audit_usdc,
                "Web3 Deep Source & Proxy Smart Contract Audit for /audit/deep — EIP-1967/1822 Proxy State Resolution & Verified Solidity Source Code Evaluation",
            ),
            (
                "/token/check",
                x402_cfg.price_per_token_check_usdc,
                "Web3 Fast Token & Honeypot Scanner for /token/check — Instant EVM Bytecode Honeypot, Tax Trap, Proxy & Sourcify Verification Check",
            ),
        ]

        resources = []
        for path, price_usdc, desc in resource_endpoints:
            full_url = f"{public_url}{path}"
            res_atomic = usdc_to_atomic(price_usdc)
            res_obj = {
                "url": full_url,
                "description": desc,
                "mimeType": "application/json",
                "serviceName": "Web3 Systemic Agent",
                "tags": ["web3-security", "smart-contract-audit", "honeypot-detector", "dao-governance", "base", "evm"],
            }
            resources.append({
                "url": full_url,
                "endpoint": path,
                "price_usdc": price_usdc,
                "amount_atomic": res_atomic,
                "description": res_obj["description"],
                "mimeType": "application/json",
                "serviceName": "Web3 Systemic Agent",
                "tags": res_obj["tags"],
                "accepts": [
                    {
                        "scheme": "exact",
                        "network": x402_cfg.network,
                        "amount": str(res_atomic),
                        "maxAmountRequired": str(res_atomic),
                        "amount_usdc": round(price_usdc, 6),
                        "asset": x402_cfg.usdc_contract_address,
                        "usdcAddress": x402_cfg.usdc_contract_address,
                        "payTo": x402_cfg.pay_to_address,
                        "maxTimeoutSeconds": 300,
                        "resource": res_obj,
                        "url": full_url,
                        "description": res_obj["description"],
                        "mimeType": "application/json",
                        "discoverable": True,
                        "extra": {"name": token_name, "version": "2"},
                    }
                ],
                "extensions": build_bazaar_discovery_extension(path),
            })

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "x402Version": 2,
                "service": "Web3 Systemic Agent",
                "network": x402_cfg.network,
                "asset": x402_cfg.asset,
                "pay_to_address": x402_cfg.pay_to_address,
                "price_per_eval_usdc": x402_cfg.price_per_eval_usdc,
                "resources": resources,
            },
        )

    @app.api_route("/.well-known/security.txt", methods=["GET", "HEAD"], include_in_schema=False)
    @app.api_route("/security.txt", methods=["GET", "HEAD"], include_in_schema=False)
    async def get_security_txt():
        """Returns RFC 9116 security vulnerability reporting policy."""
        return Response(content=SECURITY_TXT_CONTENT, media_type="text/plain; charset=utf-8")

    @app.head("/health", include_in_schema=False)
    async def head_health():
        """HEAD probe handler for health endpoint."""
        return Response(status_code=status.HTTP_200_OK, media_type="application/json")

    @app.get(
        "/health",
        response_model=Union[SimpleHealthResponse, HealthCheckResponse],
        tags=["Monitoring"],
    )
    async def health_check(full: bool = False):
        """
        Asynchronously checks service health.

        - If full=False (default): Returns an ultra-lightweight response {"status": "ok"}
          suitable for high-frequency cron jobs and external uptime monitors.
        - If full=True: Probes RPC connectivity across configured EVM networks
          and reports operational status of the semantic evaluation provider and x402 gate.
        """
        if not full:
            return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ok"})

        active_engine: ConditionAgentEngine = app.state.engine

        async def _check_rpc(chain_id: int, url: str) -> tuple[int, bool]:
            inspector = None
            try:
                inspector = ChainInspector(chain_id=chain_id, rpc_url=url, use_cache=False)
                is_conn = await asyncio.wait_for(inspector.verify_connection(), timeout=3.5)
                return chain_id, bool(is_conn)
            except Exception as exc:
                logger.warning(f"Health check RPC failure for chain {chain_id} ({url}): {exc}")
                return chain_id, False
            finally:
                if inspector and hasattr(inspector.w3, "provider") and hasattr(inspector.w3.provider, "disconnect"):
                    try:
                        await inspector.w3.provider.disconnect()
                    except Exception:
                        pass

        # Concurrently probe all default network RPCs
        rpc_tasks = [
            _check_rpc(cid, url)
            for cid, url in ChainInspector.DEFAULT_RPCS.items()
        ]
        rpc_results = await asyncio.gather(*rpc_tasks)
        rpc_status = {cid: conn for cid, conn in rpc_results}

        evaluator = active_engine.semantic_evaluator
        evaluator_cls = evaluator.__class__.__name__

        if isinstance(evaluator, GeminiSemanticEvaluator) or evaluator_cls == "GeminiSemanticEvaluator":
            provider_type = "gemini"
            is_mock = False
            model_name = getattr(evaluator, "model_name", getattr(evaluator, "model", "gemini-2.0-flash"))
        elif isinstance(evaluator, OpenAISemanticEvaluator) or evaluator_cls == "OpenAISemanticEvaluator":
            provider_type = "openai"
            is_mock = False
            model_name = getattr(evaluator, "model", "gpt-4o-mini")
        else:
            provider_type = "mock"
            is_mock = True
            model_name = getattr(evaluator, "model_name", getattr(evaluator, "model", None))

        if model_name is not None and not isinstance(model_name, str):
            model_name = None if hasattr(model_name, "_mock_name") else str(model_name)

        if all(rpc_status.values()):
            overall_status = "ok"
        elif any(rpc_status.values()):
            overall_status = "degraded"
        else:
            overall_status = "error"

        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        x402_enabled = bool(x402_cfg.enabled)
        x402_network = x402_cfg.network if x402_enabled else getattr(x402_cfg, "network", None)
        price_per_eval = float(x402_cfg.price_per_eval_usdc)

        return HealthCheckResponse(
            status=overall_status,
            version="1.0.2",
            timestamp=datetime.now(timezone.utc).isoformat(),
            rpc_status=rpc_status,
            semantic_provider=provider_type,
            provider=provider_type,
            is_mock=is_mock,
            model=model_name,
            x402_enabled=x402_enabled,
            x402_network=x402_network,
            price_per_eval_usdc=price_per_eval,
        )

    @app.post("/rules/validate", response_model=RuleValidationResponse, tags=["Rules"])
    async def validate_rule(payload: ConditionRulePayload):
        """
        Performs static, non-blocking pre-validation of a ConditionRulePayload
        without incurring heavy on-chain I/O or LLM costs.
        Flags formatting anomalies, selector mismatches, and semantic policy oversights.
        """
        warnings: List[str] = []

        # 1. Validate function selector syntax if provided (defensive check)
        hex_selector_regex = re.compile(r"^0x[0-9a-fA-F]{8}$")
        if payload.deterministic.required_function_selectors:
            for selector in payload.deterministic.required_function_selectors:
                if not hex_selector_regex.match(selector):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            f"Invalid function selector format '{selector}'. "
                            f"Must be a 10-character hex string starting with '0x' (e.g., '0xa9059cbb')."
                        ),
                    )

        # 2. Inspect calldata in context metadata if present
        calldata = str(payload.context_metadata.get("calldata", "")).strip()
        calldata_selector = None

        if calldata:
            if not calldata.startswith("0x"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Calldata must be a hexadecimal string prefixed with '0x'.",
                )
            # Inspect calldata selector using static method (no AsyncWeb3 creation)
            calldata_analysis = ChainInspector.inspect_calldata_selector(calldata)
            calldata_selector = calldata_analysis.get("selector")

            # Cross-reference with required selectors
            if payload.deterministic.required_function_selectors:
                normalized_required = [
                    s.lower() for s in payload.deterministic.required_function_selectors
                ]
                if calldata_selector and calldata_selector.lower() not in normalized_required:
                    warnings.append(
                        f"Calldata selector '{calldata_selector}' does not match required selectors "
                        f"{normalized_required}. The rule will short-circuit at Stage 1."
                    )

        # 3. Check value constraints
        if (
            payload.deterministic.min_value_wei > 0
            and not payload.deterministic.check_native_balance
        ):
            tx_val = int(payload.context_metadata.get("tx_value_wei", 0))
            if tx_val < payload.deterministic.min_value_wei:
                warnings.append(
                    f"tx_value_wei ({tx_val}) is below min_value_wei ({payload.deterministic.min_value_wei}). "
                    f"The rule will short-circuit at Stage 1 unless target balance check is enabled."
                )

        # 4. Check semantic policy prompt
        if payload.semantic.enabled and not payload.semantic.policy_prompt.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Semantic evaluation is enabled but policy_prompt is empty.",
            )

        details = ValidationDetail(
            rule_id=payload.rule_id,
            chain_id=payload.chain_id.value,
            target_address=payload.deterministic.target_address,
            required_selectors=payload.deterministic.required_function_selectors,
            calldata_selector=calldata_selector,
            semantic_enabled=payload.semantic.enabled,
            risk_threshold=payload.semantic.risk_threshold,
            min_value_wei=payload.deterministic.min_value_wei,
        )

        return RuleValidationResponse(
            valid=True,
            message="Rule payload passed pre-validation successfully.",
            details=details,
            warnings=warnings,
        )

    @app.get("/evaluate", tags=["Evaluation"], summary="x402 Payment & Bazaar Discovery Metadata")
    async def evaluate_discovery(request: Request):
        """
        Returns HTTP 402 Payment Required response containing x402 payment requirements
        and Bazaar auto-discovery extensions for crawlers and discovery agents.
        """
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        return build_402_response(
            x402_cfg,
            request.url.path,
            x402_cfg.price_per_eval_usdc,
        )

    @app.post("/evaluate", response_model=FinalAgentResponse, tags=["Evaluation"])
    async def evaluate_rule(
        payload: ConditionRulePayload,
        request: Request,
        response: Response,
    ):
        """
        Executes the two-stage autonomous agent pipeline for the given rule payload:
        Stage 1: Deterministic on-chain validation via AsyncWeb3.
        Stage 2: LLM semantic policy evaluation (if Stage 1 matches and semantic is enabled).
        Returns a strongly-typed FinalAgentResponse conforming to schemas.py.
        """
        active_engine: ConditionAgentEngine = app.state.engine
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)

        if not x402_cfg.enabled:
            try:
                agent_resp = await active_engine.process_rule(payload, source="evaluate")
                return agent_resp
            except Exception as exc:
                logger.exception(f"Error evaluating rule '{payload.rule_id}': {exc}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Execution error while processing rule '{payload.rule_id}': {str(exc)}",
                )

        # Paid mode: Payment Gate Flow
        required_usdc = x402_cfg.price_per_eval_usdc
        required_atomic = usdc_to_atomic(required_usdc)

        # 1. Extract payment header
        payment_header = _extract_payment_header(request)
        if not payment_header:
            return build_402_response(x402_cfg, request.url.path, required_usdc)

        # 2. Parse header
        try:
            payment_data = parse_x402_header(payment_header, default_network=x402_cfg.network)
        except ValueError as exc:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=f"Malformed payment header: {exc}",
            )

        payment_data["endpoint"] = request.url.path

        # 3. Check replay in SQLite
        payment_id = payment_data["payment_id"]
        if storage_inst and await storage_inst.is_payment_settled(payment_id):
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason="Payment already settled (replay detected)",
            )

        # 4. Verify payment with facilitator
        facilitator = getattr(app.state, "facilitator", None) or MockX402Facilitator()
        ver = await facilitator.verify(payment_data, required_atomic, x402_cfg)
        if not ver.valid:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=ver.reason or "Payment verification failed",
            )

        # 5. Core logic execution
        try:
            agent_resp = await active_engine.process_rule(payload, source="evaluate")
        except Exception as exc:
            logger.exception(f"Error evaluating rule '{payload.rule_id}': {exc}")
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Execution error while processing rule '{payload.rule_id}': {str(exc)}",
                    rule_id=payload.rule_id,
                    traceback_str=traceback.format_exc(),
                    context={"path": str(request.url.path)},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC or internal error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        # 6. No-Charge-on-Error check (RPC failure in deterministic check)
        if agent_resp.deterministic_check.error is not None:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Deterministic RPC error: {agent_resp.deterministic_check.error}",
                    rule_id=payload.rule_id,
                    context={"path": str(request.url.path)},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC or internal error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        # 7. Facilitator settlement
        settlement = await facilitator.settle(payment_data, required_atomic, x402_cfg)
        if not settlement.settled:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="payment",
                    error_type="SettlementError",
                    message=settlement.error or "Failed to settle",
                    rule_id=payload.rule_id,
                    context={"path": str(request.url.path)},
                )
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=settlement.error or "Payment settlement failed",
            )

        _log_x402_settled(
            request.url.path,
            required_usdc,
            settlement.tx_hash,
            payment_data.get("network") or x402_cfg.network,
        )

        receipt = PaymentReceipt(
            payment_id=payment_data["payment_id"],
            payer_address=payment_data["payer_address"],
            pay_to_address=x402_cfg.pay_to_address,
            amount_usdc=round(required_usdc, 6),
            amount_atomic=required_atomic,
            network=payment_data.get("network") or x402_cfg.network,
            asset=x402_cfg.asset,
            tx_hash=settlement.tx_hash or "",
            endpoint=request.url.path,
            settled_at=datetime.now(timezone.utc).isoformat(),
        )

        if storage_inst is not None:
            await storage_inst.record_payment(receipt, rule_id=payload.rule_id)

        receipt_summary = json.dumps({
            "tx_hash": receipt.tx_hash,
            "payment_id": receipt.payment_id,
            "amount_usdc": receipt.amount_usdc,
        })
        response.headers["X-PAYMENT-RESPONSE"] = receipt_summary
        response.headers["PAYMENT-RESPONSE"] = receipt_summary

        agent_resp.payment = receipt
        return agent_resp

    @app.get("/audit", tags=["Evaluation"], summary="x402 Quick Audit Discovery & Execution")
    async def audit_discovery(
        request: Request,
        response: Response,
        address: Optional[str] = None,
        target_address: Optional[str] = None,
        contract_address: Optional[str] = None,
        chain_id: int = 8453,
        proposal_description: Optional[str] = None,
        calldata: str = "0x",
    ):
        """
        Executes a Quick Contract Audit when target address is passed via query parameters
        (and x402 is disabled or payment header is present), or returns HTTP 402
        Bazaar auto-discovery metadata when called without parameters/payment.
        """
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        raw_addr = address or target_address or contract_address
        has_payment = bool(_extract_payment_header(request))
        if raw_addr and (not x402_cfg.enabled or has_payment):
            req_kwargs: Dict[str, Any] = {
                "target_address": raw_addr,
                "address": address,
                "contract_address": contract_address,
                "chain_id": chain_id,
                "calldata": calldata,
            }
            if proposal_description is not None:
                req_kwargs["proposal_description"] = proposal_description
            audit_payload = QuickAuditRequest(**req_kwargs)
            return await quick_audit(payload=audit_payload, request=request, response=response)
        return build_402_response(
            x402_cfg,
            "/audit",
            x402_cfg.price_per_eval_usdc,
        )

    @app.post("/audit", response_model=FinalAgentResponse, tags=["Evaluation"])
    async def quick_audit(
        payload: QuickAuditRequest,
        request: Request,
        response: Response,
    ):
        """
        Simplified Smart Contract Audit endpoint for autonomous AI agents.
        Accepts QuickAuditRequest with target_address (or alias address/contract_address),
        resolves bytecode & function selectors, and executes the two-stage security audit under x402 micropayments.
        """
        raw_addr = payload.target_address or payload.address or payload.contract_address
        if not raw_addr or not isinstance(raw_addr, str) or not Web3.is_address(raw_addr):
            return JSONResponse(
                status_code=422,
                content={
                    "error": "RequestValidationError",
                    "message": "Missing or invalid EVM target address in QuickAuditRequest.",
                    "details": [
                        {
                            "loc": ["body", "target_address"],
                            "msg": "Invalid or missing EVM hex address",
                            "type": "value_error",
                        }
                    ],
                },
            )
        checksum_addr = Web3.to_checksum_address(raw_addr)

        try:
            cid = ChainId(payload.chain_id)
        except ValueError:
            cid = ChainId.BASE_MAINNET

        calldata_str = payload.calldata if payload.calldata and payload.calldata.startswith("0x") else "0x"
        calldata_selector = (
            calldata_str[:10].lower()
            if len(calldata_str) >= 10
            else "0x"
        )

        selectors_found = []
        try:
            chain_id_int = int(cid.value if hasattr(cid, "value") else cid)
            if _resolve_contract_bytecode is not None:
                code_bytes = await _resolve_contract_bytecode(checksum_addr, chain_id_int)
                if code_bytes and code_bytes not in (b"", b"\x00") and extract_selectors_from_bytecode is not None:
                    selectors_found = extract_selectors_from_bytecode(code_bytes)
        except Exception as exc:
            logger.debug("Bytecode selector extraction in /audit skipped: %s", exc)

        rule_payload = ConditionRulePayload(
            rule_id=f"quick-audit-{checksum_addr.lower()[:8]}-{int(time.time())}",
            chain_id=cid,
            deterministic=DeterministicCondition(
                target_address=checksum_addr,
                min_value_wei=0,
                required_function_selectors=None,
                check_native_balance=False,
            ),
            semantic=SemanticCondition(
                enabled=True,
                policy_prompt=payload.policy_prompt,
                risk_threshold=payload.risk_threshold,
            ),
            context_metadata={
                "contract_address": checksum_addr,
                "proposal_description": payload.proposal_description,
                "calldata": calldata_str,
                "calldata_analysis": {
                    "selector": calldata_selector,
                    "signature": ChainInspector.KNOWN_SELECTORS.get(
                        calldata_selector, "unknown_selector"
                    ),
                },
                "selectors_discovered": selectors_found,
                "source": "quick_audit",
            },
        )

        active_engine: ConditionAgentEngine = app.state.engine
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)

        if not x402_cfg.enabled:
            try:
                agent_resp = await active_engine.process_rule(rule_payload, source="quick_audit")
                return agent_resp
            except Exception as exc:
                logger.exception(f"Error evaluating quick audit rule '{rule_payload.rule_id}': {exc}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Execution error while processing quick audit: {str(exc)}",
                )

        # Paid mode: Payment Gate Flow
        required_usdc = x402_cfg.price_per_eval_usdc
        required_atomic = usdc_to_atomic(required_usdc)

        # 1. Extract payment header
        payment_header = _extract_payment_header(request)
        if not payment_header:
            return build_402_response(x402_cfg, request.url.path, required_usdc)

        # 2. Parse header
        try:
            payment_data = parse_x402_header(payment_header, default_network=x402_cfg.network)
        except ValueError as exc:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=f"Malformed payment header: {exc}",
            )

        payment_data["endpoint"] = request.url.path

        # 3. Check replay in SQLite
        payment_id = payment_data["payment_id"]
        if storage_inst and await storage_inst.is_payment_settled(payment_id):
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason="Payment already settled (replay detected)",
            )

        # 4. Verify payment with facilitator
        facilitator = getattr(app.state, "facilitator", None) or MockX402Facilitator()
        ver = await facilitator.verify(payment_data, required_atomic, x402_cfg)
        if not ver.valid:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=ver.reason or "Payment verification failed",
            )

        # 5. Core logic execution
        try:
            agent_resp = await active_engine.process_rule(rule_payload, source="quick_audit")
        except Exception as exc:
            logger.exception(f"Error evaluating quick audit rule '{rule_payload.rule_id}': {exc}")
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Execution error while processing quick audit: {str(exc)}",
                    rule_id=rule_payload.rule_id,
                    traceback_str=traceback.format_exc(),
                    context={"path": str(request.url.path)},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC or internal error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        # 6. No-Charge-on-Error check (RPC failure in deterministic check)
        if agent_resp.deterministic_check.error is not None:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Deterministic RPC error: {agent_resp.deterministic_check.error}",
                    rule_id=rule_payload.rule_id,
                    context={"path": str(request.url.path)},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC or internal error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        # 7. Facilitator settlement
        settlement = await facilitator.settle(payment_data, required_atomic, x402_cfg)
        if not settlement.settled:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="payment",
                    error_type="SettlementError",
                    message=settlement.error or "Failed to settle",
                    rule_id=rule_payload.rule_id,
                    context={"path": str(request.url.path)},
                )
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=settlement.error or "Payment settlement failed",
            )

        _log_x402_settled(
            request.url.path,
            required_usdc,
            settlement.tx_hash,
            payment_data.get("network") or x402_cfg.network,
        )

        receipt = PaymentReceipt(
            payment_id=payment_data["payment_id"],
            payer_address=payment_data["payer_address"],
            pay_to_address=x402_cfg.pay_to_address,
            amount_usdc=round(required_usdc, 6),
            amount_atomic=required_atomic,
            network=payment_data.get("network") or x402_cfg.network,
            asset=x402_cfg.asset,
            tx_hash=settlement.tx_hash or "",
            endpoint=request.url.path,
            settled_at=datetime.now(timezone.utc).isoformat(),
        )

        if storage_inst is not None:
            await storage_inst.record_payment(receipt, rule_id=rule_payload.rule_id)

        receipt_summary = json.dumps({
            "tx_hash": receipt.tx_hash,
            "payment_id": receipt.payment_id,
            "amount_usdc": receipt.amount_usdc,
        })
        response.headers["X-PAYMENT-RESPONSE"] = receipt_summary
        response.headers["PAYMENT-RESPONSE"] = receipt_summary

        agent_resp.payment = receipt
        return agent_resp

    @app.get("/preflight", tags=["Evaluation"], summary="x402 Preflight Firewall Discovery & Execution")
    async def preflight_discovery(
        request: Request,
        response: Response,
        to_address: Optional[str] = None,
        target_address: Optional[str] = None,
        from_address: Optional[str] = None,
        calldata: str = "0x",
        value_wei: int = 0,
        chain_id: int = 8453,
        run_simulation: bool = True,
    ):
        """
        Executes Preflight EVM Transaction Firewall screening when target/calldata query parameters
        are supplied (and x402 is disabled or payment header is present), or returns HTTP 402
        Bazaar auto-discovery metadata when called without parameters/payment.
        """
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        has_payment = bool(_extract_payment_header(request))
        has_target_or_calldata = bool(
            to_address or target_address or (calldata and calldata != "0x")
        )
        if has_target_or_calldata and (not x402_cfg.enabled or has_payment):
            try:
                preflight_payload = PreflightRequest(
                    chain_id=chain_id,
                    from_address=from_address,
                    to_address=to_address,
                    target_address=target_address,
                    calldata=calldata,
                    value_wei=value_wei,
                    run_simulation=run_simulation,
                )
            except ValidationError as exc:
                return JSONResponse(
                    status_code=422,
                    content=jsonable_encoder({
                        "error": "RequestValidationError",
                        "message": "Invalid preflight query parameters.",
                        "details": exc.errors(),
                    }),
                )
            return await preflight_tx(payload=preflight_payload, request=request, response=response)
        return build_402_response(
            x402_cfg,
            "/preflight",
            x402_cfg.price_per_preflight_usdc,
        )

    @app.post("/preflight", response_model=PreflightVerdict, tags=["Evaluation"])
    async def preflight_tx(
        payload: PreflightRequest,
        request: Request,
        response: Response,
    ):
        """
        Preflight EVM Transaction Security Firewall endpoint for autonomous AI agents.
        Evaluates transaction risks, function selector decoding, unlimited approvals,
        EIP-712 typed data phishing, and Indirect Prompt Injection under x402 micropayments.
        """
        firewall = getattr(app.state, "preflight_firewall", None) or PreflightFirewall()
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)

        if not x402_cfg.enabled:
            try:
                verdict = await firewall.evaluate(payload)
                return verdict
            except Exception as exc:
                logger.exception(f"Error evaluating preflight firewall: {exc}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Execution error while processing preflight: {str(exc)}",
                )

        # Paid mode: Payment Gate Flow
        required_usdc = x402_cfg.price_per_preflight_usdc
        required_atomic = usdc_to_atomic(required_usdc)

        payment_header = (
            request.headers.get("x-payment")
            or request.headers.get("payment-signature")
            or request.headers.get("x-payment-signature")
            or request.headers.get("X-PAYMENT")
            or request.headers.get("PAYMENT-SIGNATURE")
        )
        if not payment_header:
            return build_402_response(x402_cfg, "/preflight", required_usdc)

        try:
            payment_data = parse_x402_header(payment_header, default_network=x402_cfg.network)
        except ValueError as exc:
            return build_402_response(
                x402_cfg,
                "/preflight",
                required_usdc,
                reason=f"Malformed payment header: {exc}",
            )

        payment_data["endpoint"] = "/preflight"
        payment_id = payment_data["payment_id"]
        if storage_inst and await storage_inst.is_payment_settled(payment_id):
            return build_402_response(
                x402_cfg,
                "/preflight",
                required_usdc,
                reason="Payment already settled (replay detected)",
            )

        facilitator = getattr(app.state, "facilitator", None) or MockX402Facilitator()
        ver = await facilitator.verify(payment_data, required_atomic, x402_cfg)
        if not ver.valid:
            return build_402_response(
                x402_cfg,
                "/preflight",
                required_usdc,
                reason=ver.reason or "Payment verification failed",
            )

        try:
            verdict = await firewall.evaluate(payload)
        except Exception as exc:
            logger.exception(f"Error evaluating preflight firewall: {exc}")
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Execution error while processing preflight: {str(exc)}",
                    traceback_str=traceback.format_exc(),
                    context={"path": "/preflight"},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        # No-Charge-on-Error check (upstream RPC failure in simulation)
        if verdict.simulation and verdict.simulation.rpc_error is not None:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Preflight simulation RPC error: {verdict.simulation.rpc_error}",
                    context={"path": "/preflight"},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        settlement = await facilitator.settle(payment_data, required_atomic, x402_cfg)
        if not settlement.settled:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="payment",
                    error_type="SettlementError",
                    message=settlement.error or "Failed to settle",
                    context={"path": "/preflight"},
                )
            return build_402_response(
                x402_cfg,
                "/preflight",
                required_usdc,
                reason=settlement.error or "Payment settlement failed",
            )

        _log_x402_settled(
            "/preflight",
            required_usdc,
            settlement.tx_hash,
            payment_data.get("network") or x402_cfg.network,
        )

        receipt = PaymentReceipt(
            payment_id=payment_data["payment_id"],
            payer_address=payment_data["payer_address"],
            pay_to_address=x402_cfg.pay_to_address,
            amount_usdc=round(required_usdc, 6),
            amount_atomic=required_atomic,
            network=payment_data.get("network") or x402_cfg.network,
            asset=x402_cfg.asset,
            tx_hash=settlement.tx_hash or "",
            endpoint="/preflight",
            settled_at=datetime.now(timezone.utc).isoformat(),
        )

        if storage_inst is not None:
            await storage_inst.record_payment(
                receipt, rule_id=f"preflight-{verdict.target_address or 'tx'}"
            )

        receipt_summary = json.dumps({
            "tx_hash": receipt.tx_hash,
            "payment_id": receipt.payment_id,
            "amount_usdc": receipt.amount_usdc,
        })
        response.headers["X-PAYMENT-RESPONSE"] = receipt_summary
        response.headers["PAYMENT-RESPONSE"] = receipt_summary

        verdict.payment = receipt
        return verdict

    @app.get("/audit/deep", tags=["Evaluation"], summary="x402 Deep Source & Proxy Audit Discovery Metadata")
    async def deep_audit_discovery(request: Request):
        """
        Returns HTTP 402 Payment Required response containing x402 payment requirements
        and Bazaar auto-discovery extensions for deep proxy & source code smart contract audits.
        """
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        return build_402_response(
            x402_cfg,
            "/audit/deep",
            x402_cfg.price_per_deep_audit_usdc,
        )

    @app.post("/audit/deep", response_model=FinalAgentResponse, tags=["Evaluation"])
    async def deep_audit_contract(
        payload: DeepAuditRequest,
        request: Request,
        response: Response,
    ):
        """
        Deep Smart Contract & Proxy Audit endpoint for autonomous AI agents.
        Resolves EIP-1967/1822 proxy storage slots on-chain, fetches verified Solidity source code
        from block explorers, and conducts deep two-stage LLM evaluation under x402 micropayments ($0.25 USDC).
        """
        raw_addr = payload.target_address or payload.address or payload.contract_address
        if not raw_addr or not isinstance(raw_addr, str) or not Web3.is_address(raw_addr):
            return JSONResponse(
                status_code=422,
                content={
                    "error": "RequestValidationError",
                    "message": "Missing or invalid EVM target address in DeepAuditRequest.",
                    "details": [
                        {
                            "loc": ["body", "target_address"],
                            "msg": "Invalid or missing EVM hex address",
                            "type": "value_error",
                        }
                    ],
                },
            )
        checksum_addr = Web3.to_checksum_address(raw_addr)

        try:
            cid = ChainId(payload.chain_id)
        except ValueError:
            cid = ChainId.BASE_MAINNET
        cid_int = int(cid.value if hasattr(cid, "value") else cid)

        active_engine: ConditionAgentEngine = app.state.engine
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
        resolver = getattr(app.state, "source_resolver", None) or ContractSourceResolver()

        required_usdc = x402_cfg.price_per_deep_audit_usdc
        required_atomic = usdc_to_atomic(required_usdc)

        # Payment gate (if enabled)
        payment_data: Optional[Dict[str, Any]] = None
        if x402_cfg.enabled:
            payment_header = (
                request.headers.get("x-payment")
                or request.headers.get("payment-signature")
                or request.headers.get("x-payment-signature")
                or request.headers.get("X-PAYMENT")
                or request.headers.get("PAYMENT-SIGNATURE")
            )
            if not payment_header:
                return build_402_response(x402_cfg, "/audit/deep", required_usdc)

            try:
                payment_data = parse_x402_header(payment_header, default_network=x402_cfg.network)
            except ValueError as exc:
                return build_402_response(
                    x402_cfg,
                    "/audit/deep",
                    required_usdc,
                    reason=f"Malformed payment header: {exc}",
                )

            payment_data["endpoint"] = "/audit/deep"
            payment_id = payment_data["payment_id"]
            if storage_inst and await storage_inst.is_payment_settled(payment_id):
                return build_402_response(
                    x402_cfg,
                    "/audit/deep",
                    required_usdc,
                    reason="Payment already settled (replay detected)",
                )

            facilitator = getattr(app.state, "facilitator", None) or MockX402Facilitator()
            ver = await facilitator.verify(payment_data, required_atomic, x402_cfg)
            if not ver.valid:
                return build_402_response(
                    x402_cfg,
                    "/audit/deep",
                    required_usdc,
                    reason=ver.reason or "Payment verification failed",
                )

        # Resolve full audit context: proxy status, storage state, verified source code
        try:
            audit_ctx = await resolver.resolve_full_audit_context(
                chain_id=cid_int,
                target_address=checksum_addr,
                resolve_proxy=payload.resolve_proxy,
                fetch_source=payload.fetch_verified_source,
            )
        except Exception as exc:
            logger.exception(f"Error during contract source/proxy resolution: {exc}")
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="source_resolver",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Contract resolution error: {str(exc)}",
                    traceback_str=traceback.format_exc(),
                    context={"path": "/audit/deep"},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        # No-Charge-on-Error check for proxy resolution RPC failure
        if x402_cfg.enabled and audit_ctx.get("proxy_info", {}).get("rpc_error") is not None:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Proxy resolution RPC error: {audit_ctx['proxy_info']['rpc_error']}",
                    context={"path": "/audit/deep"},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        effective_audit_addr = audit_ctx.get("proxy_info", {}).get("effective_audit_address") or checksum_addr
        source_info = audit_ctx.get("source_info", {})
        verified_source = {
            "verified": source_info.get("verified", False),
            "provider": source_info.get("provider"),
            "contract_names": source_info.get("contract_names", []),
            "files_count": source_info.get("files_count", 0),
            "truncated": source_info.get("truncated", False),
            "source_code": source_info.get("source_code", ""),
        }
        calldata_str = payload.calldata if payload.calldata and payload.calldata.startswith("0x") else "0x"
        rule_payload = ConditionRulePayload(
            rule_id=f"deep-audit-{checksum_addr.lower()[:8]}-{int(time.time())}",
            chain_id=cid,
            deterministic=DeterministicCondition(
                target_address=effective_audit_addr,
                min_value_wei=0,
                required_function_selectors=None,
                check_native_balance=False,
            ),
            semantic=SemanticCondition(
                enabled=True,
                policy_prompt=payload.policy_prompt,
                risk_threshold=payload.risk_threshold,
            ),
            context_metadata={
                "target_address": checksum_addr,
                "effective_audit_address": effective_audit_addr,
                "proxy_info": audit_ctx.get("proxy_info", {}),
                "verified_source": verified_source,
                "security_warnings": audit_ctx.get("security_warnings", []),
                "selectors_found": audit_ctx.get("effective_selectors", []),
                "proposal_description": payload.proposal_description,
                "calldata": calldata_str,
                "source": "deep_audit",
            },
        )

        try:
            agent_resp = await active_engine.process_rule(rule_payload, source="deep_audit")
        except Exception as exc:
            logger.exception(f"Error evaluating deep audit rule '{rule_payload.rule_id}': {exc}")
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Execution error while processing deep audit: {str(exc)}",
                    rule_id=rule_payload.rule_id,
                    traceback_str=traceback.format_exc(),
                    context={"path": "/audit/deep"},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC or internal error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        if not x402_cfg.enabled:
            return agent_resp

        # No-Charge-on-Error check for deterministic execution
        if agent_resp.deterministic_check.error is not None:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Deterministic RPC error: {agent_resp.deterministic_check.error}",
                    rule_id=rule_payload.rule_id,
                    context={"path": "/audit/deep"},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC or internal error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        facilitator = getattr(app.state, "facilitator", None) or MockX402Facilitator()
        settlement = await facilitator.settle(payment_data, required_atomic, x402_cfg)
        if not settlement.settled:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="payment",
                    error_type="SettlementError",
                    message=settlement.error or "Failed to settle",
                    rule_id=rule_payload.rule_id,
                    context={"path": "/audit/deep"},
                )
            return build_402_response(
                x402_cfg,
                "/audit/deep",
                required_usdc,
                reason=settlement.error or "Payment settlement failed",
            )

        _log_x402_settled(
            "/audit/deep",
            required_usdc,
            settlement.tx_hash,
            payment_data.get("network") or x402_cfg.network,
        )

        receipt = PaymentReceipt(
            payment_id=payment_data["payment_id"],
            payer_address=payment_data["payer_address"],
            pay_to_address=x402_cfg.pay_to_address,
            amount_usdc=round(required_usdc, 6),
            amount_atomic=required_atomic,
            network=payment_data.get("network") or x402_cfg.network,
            asset=x402_cfg.asset,
            tx_hash=settlement.tx_hash or "",
            endpoint="/audit/deep",
            settled_at=datetime.now(timezone.utc).isoformat(),
        )

        if storage_inst is not None:
            await storage_inst.record_payment(receipt, rule_id=rule_payload.rule_id)

        receipt_summary = json.dumps({
            "tx_hash": receipt.tx_hash,
            "payment_id": receipt.payment_id,
            "amount_usdc": receipt.amount_usdc,
        })
        response.headers["X-PAYMENT-RESPONSE"] = receipt_summary
        response.headers["PAYMENT-RESPONSE"] = receipt_summary

        agent_resp.payment = receipt
        return agent_resp

    async def _handle_token_check(
        raw_addr: Optional[str],
        chain_id: int,
        include_source_status: bool,
        request: Request,
        response: Response,
        is_get: bool = False,
    ):
        """
        Unified handler for GET and POST /token/check ($0.005 USDC micro-tier).
        Performs zero-LLM deterministic bytecode honeypot detection, selector scanning,
        and optional Sourcify/proxy verification resolution with x402 no-charge-on-error guarantees.
        """
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
        required_usdc = x402_cfg.price_per_token_check_usdc
        required_atomic = usdc_to_atomic(required_usdc)
        facilitator = getattr(app.state, "facilitator", None) or MockX402Facilitator()

        payment_data: Optional[Dict[str, Any]] = None
        if x402_cfg.enabled:
            payment_header = _extract_payment_header(request)
            if not payment_header:
                return build_402_response(x402_cfg, "/token/check", required_usdc)

            if not raw_addr or not isinstance(raw_addr, str) or not Web3.is_address(raw_addr):
                return JSONResponse(
                    status_code=422,
                    content={
                        "error": "RequestValidationError",
                        "message": "Missing or invalid EVM token address for /token/check.",
                        "details": [
                            {
                                "loc": ["query" if is_get else "body", "address"],
                                "msg": "Invalid or missing EVM hex address",
                                "type": "value_error",
                            }
                        ],
                    },
                )

            try:
                payment_data = parse_x402_header(payment_header, default_network=x402_cfg.network)
            except ValueError as exc:
                return build_402_response(
                    x402_cfg,
                    "/token/check",
                    required_usdc,
                    reason=f"Malformed payment header: {exc}",
                )

            payment_data["endpoint"] = "/token/check"
            payment_id = payment_data["payment_id"]
            if storage_inst and await storage_inst.is_payment_settled(payment_id):
                return build_402_response(
                    x402_cfg,
                    "/token/check",
                    required_usdc,
                    reason="Payment already settled (replay detected)",
                )

            ver = await facilitator.verify(payment_data, required_atomic, x402_cfg)
            if not ver.valid:
                return build_402_response(
                    x402_cfg,
                    "/token/check",
                    required_usdc,
                    reason=ver.reason or "Payment verification failed",
                )
        else:
            if is_get and (not raw_addr or not str(raw_addr).strip()):
                return build_402_response(x402_cfg, "/token/check", required_usdc)
            if not raw_addr or not isinstance(raw_addr, str) or not Web3.is_address(raw_addr):
                return JSONResponse(
                    status_code=422,
                    content={
                        "error": "RequestValidationError",
                        "message": "Missing or invalid EVM token address for /token/check.",
                        "details": [
                            {
                                "loc": ["query" if is_get else "body", "address"],
                                "msg": "Invalid or missing EVM hex address",
                                "type": "value_error",
                            }
                        ],
                    },
                )

        checksum_addr = Web3.to_checksum_address(raw_addr)
        try:
            cid = ChainId(chain_id)
            cid_int = int(cid.value)
        except ValueError:
            cid_int = (
                int(chain_id)
                if chain_id in ChainInspector.DEFAULT_RPCS
                else int(ChainId.BASE_MAINNET.value)
            )

        inspector = ChainInspector(chain_id=cid_int)
        cache_key = f"{cid_int}:{checksum_addr}"
        code_bytes: Optional[bytes] = None

        if cache_key in inspector._bytecode_cache:
            code_bytes = inspector._bytecode_cache[cache_key]
        else:
            last_exc: Optional[Exception] = None
            for idx, url in enumerate(inspector.rpc_urls):
                w3 = (
                    inspector.w3
                    if idx == 0
                    else inspector._get_or_create_w3(cid_int, url, use_cache=inspector.use_cache)
                )
                try:
                    raw_code = await w3.eth.get_code(checksum_addr)
                    if isinstance(raw_code, str):
                        clean_hex = raw_code[2:] if raw_code.startswith("0x") else raw_code
                        code_bytes = bytes.fromhex(clean_hex) if clean_hex else b""
                    else:
                        code_bytes = bytes(raw_code) if raw_code else b""
                    inspector._set_bytecode_cache(cache_key, code_bytes)
                    break
                except Exception as exc:
                    logger.warning(
                        "TokenCheck RPC get_code failed for URL %s (chain %s): %s",
                        url,
                        cid_int,
                        exc,
                    )
                    last_exc = exc

            if code_bytes is None:
                if storage_inst is not None:
                    await storage_inst.log_error(
                        stage="api",
                        error_type="ServiceUnavailableNoCharge",
                        message=f"All RPCs failed fetching bytecode for {checksum_addr}: {last_exc}",
                        context={"path": "/token/check"},
                    )
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "ServiceUnavailable",
                        "message": "Execution failed due to upstream RPC error. Payment was NOT settled.",
                        "payment_settled": False,
                    },
                )

        if len(code_bytes) == 0:
            is_contract = False
            bytecode_size_bytes = 0
            verdict = "EOA"
            risk_score = 0.0
            is_honeypot = False
            threat_categories: List[str] = []
            honeypot_flags: List[str] = []
            selectors_found: List[Dict[str, Any]] = []
            high_risk_selectors: List[str] = []
            is_proxy = False
            implementation_address: Optional[str] = None
            source_verified = False
            source_provider: Optional[str] = None
            security_warnings: List[str] = []
            summary = (
                f"Address {checksum_addr} on chain {cid_int} is an Externally Owned Account (EOA) "
                f"with 0 bytes of deployed bytecode."
            )
        else:
            is_contract = True
            bytecode_size_bytes = len(code_bytes)

            if analyze_bytecode_honeypot is not None:
                hp_analysis = analyze_bytecode_honeypot(code_bytes)
            else:
                hp_analysis = {
                    "selectors": [],
                    "honeypot_flags": [],
                    "categories": {},
                    "is_honeypot": False,
                    "severity": "CLEAN",
                    "summary_display": "CLEAN",
                }

            if extract_selectors_from_bytecode is not None:
                selectors_found = extract_selectors_from_bytecode(code_bytes)
            else:
                selectors_found = list(hp_analysis.get("selectors", []))

            seen_sel_hex = {str(s.get("selector", "")).lower() for s in selectors_found}
            for hp_sel in hp_analysis.get("selectors", []):
                sel_hex = str(hp_sel.get("selector", "")).lower()
                if sel_hex and sel_hex not in seen_sel_hex:
                    selectors_found.append(hp_sel)
                    seen_sel_hex.add(sel_hex)

            high_risk_selectors = []
            if is_high_risk_signature is not None:
                for sel_item in selectors_found:
                    sig = str(sel_item.get("signature", ""))
                    if sig and is_high_risk_signature(sig) and sig not in high_risk_selectors:
                        high_risk_selectors.append(sig)

            is_honeypot = bool(hp_analysis.get("is_honeypot", False))
            honeypot_flags = list(hp_analysis.get("honeypot_flags", []))
            categories_map = hp_analysis.get("categories", {})
            threat_categories = [
                cat for cat, items in categories_map.items() if items
            ]

            is_proxy = False
            implementation_address = None
            source_verified = False
            source_provider = None
            security_warnings = []

            if include_source_status:
                resolver = getattr(app.state, "source_resolver", None) or ContractSourceResolver()
                try:
                    audit_ctx = await resolver.resolve_full_audit_context(
                        chain_id=cid_int,
                        target_address=checksum_addr,
                        resolve_proxy=True,
                        fetch_source=True,
                    )
                    proxy_info = audit_ctx.get("proxy_info", {})
                    source_info = audit_ctx.get("source_info", {})
                    is_proxy = bool(proxy_info.get("is_proxy", False))
                    implementation_address = proxy_info.get("implementation_address")
                    source_verified = bool(source_info.get("verified", False))
                    source_provider = source_info.get("provider")
                    security_warnings = list(audit_ctx.get("security_warnings", []))
                except Exception as exc:
                    logger.warning(
                        "Source/proxy resolution failed in /token/check for %s: %s",
                        checksum_addr,
                        exc,
                    )
                    security_warnings.append(f"Source/proxy lookup unavailable: {exc}")

            severity = str(hp_analysis.get("severity", "CLEAN")).upper()
            if is_honeypot:
                base_score = 9.0 if severity == "CRITICAL" else 8.5
                risk_score = min(
                    10.0,
                    round(base_score + min(1.0, 0.25 * max(0, len(honeypot_flags) - 1)), 2),
                )
            else:
                score = 0.5
                if severity == "CRITICAL":
                    score = max(score, 8.5)
                elif severity == "HIGH":
                    score = max(score, 7.0)
                elif severity == "MEDIUM":
                    score = max(score, 5.0)
                if high_risk_selectors:
                    score = max(score, 4.5)
                    score = min(7.5, score + min(1.5, 0.5 * len(high_risk_selectors)))
                if is_proxy:
                    score = max(score, 4.0)
                    if high_risk_selectors:
                        score = min(7.5, score + 0.5)
                if include_source_status and not source_verified:
                    score = max(score, 4.0)
                    if high_risk_selectors or is_proxy:
                        score = min(7.5, score + 0.5)
                risk_score = round(min(10.0, score), 2)

            if is_honeypot or risk_score >= 8.0:
                verdict = "DANGEROUS"
            elif (
                high_risk_selectors
                or is_proxy
                or (include_source_status and not source_verified)
                or risk_score >= 4.0
            ):
                verdict = "CAUTION"
            else:
                verdict = "SAFE"

            summary_parts = [
                f"Token/contract {checksum_addr} on chain {cid_int} ({bytecode_size_bytes} bytes): "
                f"verdict={verdict}, risk_score={risk_score}/10.0."
            ]
            if honeypot_flags:
                summary_parts.append(f"Honeypot flags: {', '.join(honeypot_flags[:4])}.")
            if high_risk_selectors:
                summary_parts.append(f"Privileged selectors: {', '.join(high_risk_selectors[:4])}.")
            if is_proxy:
                summary_parts.append(
                    f"Upgradeable proxy -> implementation {implementation_address or 'unknown'}."
                )
            if include_source_status:
                summary_parts.append(
                    f"Source verified: {source_verified}"
                    + (f" ({source_provider})" if source_provider else "")
                    + "."
                )
            summary = " ".join(summary_parts)

        receipt: Optional[PaymentReceipt] = None
        if x402_cfg.enabled and payment_data is not None:
            settlement = await facilitator.settle(payment_data, required_atomic, x402_cfg)
            if not settlement.settled:
                if storage_inst is not None:
                    await storage_inst.log_error(
                        stage="payment",
                        error_type="SettlementError",
                        message=settlement.error or "Failed to settle",
                        context={"path": "/token/check"},
                    )
                return build_402_response(
                    x402_cfg,
                    "/token/check",
                    required_usdc,
                    reason=settlement.error or "Payment settlement failed",
                )

            _log_x402_settled(
                "/token/check",
                required_usdc,
                settlement.tx_hash,
                payment_data.get("network") or x402_cfg.network,
            )

            receipt = PaymentReceipt(
                payment_id=payment_data["payment_id"],
                payer_address=payment_data["payer_address"],
                pay_to_address=x402_cfg.pay_to_address,
                amount_usdc=round(required_usdc, 6),
                amount_atomic=required_atomic,
                network=payment_data.get("network") or x402_cfg.network,
                asset=x402_cfg.asset,
                tx_hash=settlement.tx_hash or "",
                endpoint="/token/check",
                settled_at=datetime.now(timezone.utc).isoformat(),
            )

            if storage_inst is not None:
                await storage_inst.record_payment(
                    receipt, rule_id=f"token-check-{checksum_addr.lower()[:10]}"
                )

            receipt_summary = json.dumps({
                "tx_hash": receipt.tx_hash,
                "payment_id": receipt.payment_id,
                "amount_usdc": receipt.amount_usdc,
            })
            response.headers["X-PAYMENT-RESPONSE"] = receipt_summary
            response.headers["PAYMENT-RESPONSE"] = receipt_summary

        public_url = _get_public_url()
        return TokenCheckResponse(
            address=checksum_addr,
            chain_id=cid_int,
            is_contract=is_contract,
            bytecode_size_bytes=bytecode_size_bytes,
            verdict=verdict,
            risk_score=risk_score,
            is_honeypot_suspect=is_honeypot,
            threat_categories=threat_categories,
            honeypot_flags=honeypot_flags,
            selectors_found=selectors_found,
            high_risk_selectors=high_risk_selectors,
            is_proxy=is_proxy,
            implementation_address=implementation_address,
            source_verified=source_verified,
            source_provider=source_provider,
            security_warnings=security_warnings,
            summary=summary,
            deep_audit_url=f"{public_url}/audit/deep",
            report_url=f"{public_url}/report/{cid_int}/{checksum_addr}",
            llm_invoked=False,
            payment=receipt,
        )

    @app.get("/token/check", tags=["Evaluation"], summary="Fast Micro-Tier Token & Honeypot Check (GET)")
    async def token_check_get(
        request: Request,
        response: Response,
        address: Optional[str] = None,
        token: Optional[str] = None,
        token_address: Optional[str] = None,
        chain_id: int = 8453,
        include_source_status: bool = True,
    ):
        """
        Micro-tier ($0.005 USDC) fast deterministic token safety & honeypot scanner via GET query params.
        Returns HTTP 402 discovery metadata when called without address/payment.
        """
        raw_addr = address or token or token_address
        return await _handle_token_check(
            raw_addr=raw_addr,
            chain_id=chain_id,
            include_source_status=include_source_status,
            request=request,
            response=response,
            is_get=True,
        )

    @app.post("/token/check", response_model=TokenCheckResponse, tags=["Evaluation"])
    async def token_check_post(
        payload: TokenCheckRequest,
        request: Request,
        response: Response,
    ):
        """
        Micro-tier ($0.005 USDC) fast deterministic token safety & honeypot scanner via POST JSON.
        Zero LLM token cost (llm_invoked=False).
        """
        raw_addr = payload.address or payload.token_address or payload.target_address
        return await _handle_token_check(
            raw_addr=raw_addr,
            chain_id=payload.chain_id,
            include_source_status=payload.include_source_status,
            request=request,
            response=response,
            is_get=False,
        )

    @app.post("/rules/evaluate-batch", response_model=List[FinalAgentResponse], tags=["Evaluation"])
    async def evaluate_rules_batch(
        payloads: List[ConditionRulePayload],
        request: Request,
        response: Response,
    ):
        """
        Concurrently evaluates a batch of ConditionRulePayload items
        respecting semaphore limits and isolating individual execution errors.
        """
        max_batch = get_batch_max_items()
        if len(payloads) > max_batch:
            storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
            if storage_inst is not None:
                try:
                    await storage_inst.log_error(
                        stage="validation",
                        error_type="BatchSizeLimitExceeded",
                        message=f"Batch size {len(payloads)} exceeds maximum allowed ({max_batch}).",
                    )
                except Exception:
                    pass
            return JSONResponse(
                status_code=422,
                content={
                    "error": "BatchSizeLimitExceeded",
                    "message": f"Batch size {len(payloads)} exceeds maximum allowed ({max_batch}).",
                },
            )

        if len(payloads) == 0:
            return []

        active_engine: ConditionAgentEngine = app.state.engine
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)

        if not x402_cfg.enabled:
            try:
                return await active_engine.process_rules_batch(payloads)
            except Exception as exc:
                logger.exception(f"Error evaluating batch of {len(payloads)} rules: {exc}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Execution error while processing rules batch: {str(exc)}",
                )

        # Paid mode: Payment Gate Flow for Batch
        required_usdc = round(x402_cfg.price_per_eval_usdc * len(payloads), 6)
        required_atomic = usdc_to_atomic(required_usdc)

        # 1. Extract payment header
        payment_header = _extract_payment_header(request)
        if not payment_header:
            return build_402_response(x402_cfg, request.url.path, required_usdc)

        # 2. Parse header
        try:
            payment_data = parse_x402_header(payment_header, default_network=x402_cfg.network)
        except ValueError as exc:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=f"Malformed payment header: {exc}",
            )

        payment_data["endpoint"] = request.url.path

        # 3. Check replay in SQLite
        payment_id = payment_data["payment_id"]
        if storage_inst and await storage_inst.is_payment_settled(payment_id):
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason="Payment already settled (replay detected)",
            )

        # 4. Verify payment with facilitator
        facilitator = getattr(app.state, "facilitator", None) or MockX402Facilitator()
        ver = await facilitator.verify(payment_data, required_atomic, x402_cfg)
        if not ver.valid:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=ver.reason or "Payment verification failed",
            )

        # 5. Core logic execution
        try:
            results = await active_engine.process_rules_batch(payloads)
        except Exception as exc:
            logger.exception(f"Error evaluating batch of {len(payloads)} rules: {exc}")
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Execution error while processing rules batch: {str(exc)}",
                    traceback_str=traceback.format_exc(),
                    context={"path": str(request.url.path)},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC or internal error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        # 6. No-Charge-on-Error check (RPC or execution error on any batch item)
        has_batch_error = any(
            (item.deterministic_check.error is not None)
            or (item.deterministic_check.reason and item.deterministic_check.reason.startswith("Execution error:"))
            for item in results
        )
        if has_batch_error:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message="One or more batch items encountered RPC or execution error without settling payment",
                    context={"path": str(request.url.path)},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC or internal error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        # 7. Facilitator settlement
        settlement = await facilitator.settle(payment_data, required_atomic, x402_cfg)
        if not settlement.settled:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="payment",
                    error_type="SettlementError",
                    message=settlement.error or "Failed to settle",
                    context={"path": str(request.url.path)},
                )
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=settlement.error or "Payment settlement failed",
            )

        _log_x402_settled(
            request.url.path,
            required_usdc,
            settlement.tx_hash,
            payment_data.get("network") or x402_cfg.network,
        )

        receipt = PaymentReceipt(
            payment_id=payment_data["payment_id"],
            payer_address=payment_data["payer_address"],
            pay_to_address=x402_cfg.pay_to_address,
            amount_usdc=round(required_usdc, 6),
            amount_atomic=required_atomic,
            network=payment_data.get("network") or x402_cfg.network,
            asset=x402_cfg.asset,
            tx_hash=settlement.tx_hash or "",
            endpoint=request.url.path,
            settled_at=datetime.now(timezone.utc).isoformat(),
        )

        if storage_inst is not None:
            await storage_inst.record_payment(receipt)

        receipt_summary = json.dumps({
            "tx_hash": receipt.tx_hash,
            "payment_id": receipt.payment_id,
            "amount_usdc": receipt.amount_usdc,
        })
        response.headers["X-PAYMENT-RESPONSE"] = receipt_summary
        response.headers["PAYMENT-RESPONSE"] = receipt_summary

        for item in results:
            item.payment = receipt

        return results

    @app.post("/rules/enqueue", status_code=status.HTTP_202_ACCEPTED, tags=["Asynchronous Tasks"])
    async def enqueue_rule(
        payload: ConditionRulePayload,
        request: Request,
        response: Response,
    ):
        """
        Enqueues a rule for background evaluation by the AgentWorkerPool.
        Returns HTTP 202 Accepted with tracking job_id and status.
        """
        pool: AgentWorkerPool = app.state.worker_pool
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)

        if not x402_cfg.enabled:
            job_id = pool.enqueue(payload)
            return {"job_id": job_id, "status": "QUEUED"}

        # Paid mode: Payment Gate Flow for Enqueue
        required_usdc = x402_cfg.price_per_eval_usdc
        required_atomic = usdc_to_atomic(required_usdc)

        # 1. Extract payment header
        payment_header = _extract_payment_header(request)
        if not payment_header:
            return build_402_response(x402_cfg, request.url.path, required_usdc)

        # 2. Parse header
        try:
            payment_data = parse_x402_header(payment_header, default_network=x402_cfg.network)
        except ValueError as exc:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=f"Malformed payment header: {exc}",
            )

        payment_data["endpoint"] = request.url.path

        # 3. Check replay in SQLite
        payment_id = payment_data["payment_id"]
        if storage_inst and await storage_inst.is_payment_settled(payment_id):
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason="Payment already settled (replay detected)",
            )

        # 4. Verify payment with facilitator
        facilitator = getattr(app.state, "facilitator", None) or MockX402Facilitator()
        ver = await facilitator.verify(payment_data, required_atomic, x402_cfg)
        if not ver.valid:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=ver.reason or "Payment verification failed",
            )

        # 5. Core logic execution
        try:
            job_id = pool.enqueue(payload)
        except Exception as exc:
            logger.exception(f"Error enqueuing rule '{payload.rule_id}': {exc}")
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Enqueue error without settling payment: {str(exc)}",
                    rule_id=payload.rule_id,
                    traceback_str=traceback.format_exc(),
                    context={"path": str(request.url.path)},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream RPC or internal error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        # 7. Facilitator settlement
        settlement = await facilitator.settle(payment_data, required_atomic, x402_cfg)
        if not settlement.settled:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="payment",
                    error_type="SettlementError",
                    message=settlement.error or "Failed to settle",
                    rule_id=payload.rule_id,
                    context={"path": str(request.url.path)},
                )
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=settlement.error or "Payment settlement failed",
            )

        _log_x402_settled(
            request.url.path,
            required_usdc,
            settlement.tx_hash,
            payment_data.get("network") or x402_cfg.network,
        )

        receipt = PaymentReceipt(
            payment_id=payment_data["payment_id"],
            payer_address=payment_data["payer_address"],
            pay_to_address=x402_cfg.pay_to_address,
            amount_usdc=round(required_usdc, 6),
            amount_atomic=required_atomic,
            network=payment_data.get("network") or x402_cfg.network,
            asset=x402_cfg.asset,
            tx_hash=settlement.tx_hash or "",
            endpoint=request.url.path,
            settled_at=datetime.now(timezone.utc).isoformat(),
        )

        if storage_inst is not None:
            await storage_inst.record_payment(receipt, rule_id=payload.rule_id, job_id=job_id)

        receipt_summary = json.dumps({
            "tx_hash": receipt.tx_hash,
            "payment_id": receipt.payment_id,
            "amount_usdc": receipt.amount_usdc,
        })
        response.headers["X-PAYMENT-RESPONSE"] = receipt_summary
        response.headers["PAYMENT-RESPONSE"] = receipt_summary

        return {
            "job_id": job_id,
            "status": "QUEUED",
            "payment": receipt.model_dump(),
        }

    @app.get("/jobs/{job_id}", tags=["Asynchronous Tasks"])
    async def get_job_status(job_id: str):
        """
        Retrieves the status, result, or error of an asynchronous evaluation job.
        """
        pool: AgentWorkerPool = app.state.worker_pool
        job = pool.get_job(job_id)
        if job is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job not found",
            )
        return {
            "job_id": job.job_id,
            "status": job.status.value if hasattr(job.status, "value") else str(job.status),
            "result": job.result,
            "error": job.error,
            "created_at": job.created_at,
            "updated_at": job.updated_at,
        }

    @app.get("/metrics/summary", tags=["Monitoring"], include_in_schema=not effective_public_evaluate_only)
    async def get_metrics_summary(target_price: float = 0.015):
        """
        Retrieves aggregated operational, token, cost, and error metrics from the ledger database.
        """
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
        if storage_inst is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Storage not configured on application state",
            )
        metrics = await storage_inst.get_summary_metrics(target_price_usd=target_price)
        metrics["background_scanner_active"] = bool(getattr(app.state, "scanner_active", False))
        return metrics

    @app.get("/logs/errors", tags=["Monitoring"], include_in_schema=not effective_public_evaluate_only)
    async def get_error_logs(limit: int = 50, stage: Optional[str] = None):
        """
        Retrieves recent operational and execution errors recorded in the ledger database.
        """
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
        if storage_inst is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Storage not configured on application state",
            )
        return await storage_inst.get_errors(limit=limit, stage=stage)

    @app.get("/payments", tags=["Payment Diagnostics"], include_in_schema=not effective_public_evaluate_only)
    async def get_payments(limit: int = 50, payer_address: Optional[str] = None):
        """
        Retrieves recent settled payments recorded in the operational ledger.
        """
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)
        if storage_inst is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Storage not configured on application state",
            )
        return await storage_inst.get_payments(limit=limit, payer_address=payer_address)

    @app.post(
        "/governance/audit-proposals",
        response_model=List[GovernanceAuditReport],
        tags=["Governance"],
        summary="Audit recent DAO governance proposals via Snapshot GraphQL or curated dataset",
        include_in_schema=not effective_public_evaluate_only,
    )
    async def audit_governance_proposals(
        request: Request,
        response: Response,
        req: Optional[GovernanceScanRequest] = None,
    ):
        """
        Audits recent DAO governance proposals for security risks, privilege escalations,
        and discrepancies using Snapshot or curated proposals.
        """
        scan_req = req or GovernanceScanRequest()
        connector = SnapshotGovernanceConnector(default_chain_id=scan_req.chain_id)
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        storage_inst: Optional[AgentStorage] = getattr(app.state, "storage", None)

        if not x402_cfg.enabled:
            return await connector.audit_proposals(
                engine=app.state.engine,
                spaces=scan_req.spaces,
                limit=scan_req.limit,
            )

        # Paid mode: when x402_cfg.enabled is True
        payment_header = (
            request.headers.get("x-payment")
            or request.headers.get("payment-signature")
            or request.headers.get("X-PAYMENT")
            or request.headers.get("PAYMENT-SIGNATURE")
        )

        if not payment_header:
            if os.getenv("X402_GATE_GOVERNANCE", "false").strip().lower() in ("true", "1", "yes"):
                return build_402_response(
                    x402_cfg,
                    request.url.path,
                    x402_cfg.price_per_eval_usdc * scan_req.limit,
                )
            # Cost-free deterministic/mock engine fallback to prevent unauthenticated credit drain
            active_engine = getattr(app.state, "engine", None)
            safe_free_engine = ConditionAgentEngine(
                rpc_url=getattr(active_engine, "rpc_url", None) if active_engine else None,
                semantic_evaluator=MockSemanticEvaluator(),
                storage=storage_inst,
            )
            return await connector.audit_proposals(
                engine=safe_free_engine,
                spaces=scan_req.spaces,
                limit=scan_req.limit,
            )

        # payment_header is present when x402_cfg.enabled is True
        required_usdc = x402_cfg.price_per_eval_usdc
        required_atomic = usdc_to_atomic(required_usdc)

        try:
            payment_data = parse_x402_header(payment_header, default_network=x402_cfg.network)
        except ValueError as exc:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=f"Malformed payment header: {exc}",
            )

        payment_data["endpoint"] = request.url.path

        payment_id = payment_data["payment_id"]
        if storage_inst and await storage_inst.is_payment_settled(payment_id):
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason="Payment already settled (replay detected)",
            )

        facilitator = getattr(app.state, "facilitator", None) or MockX402Facilitator()
        ver = await facilitator.verify(payment_data, required_atomic, x402_cfg)
        if not ver.valid:
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=ver.reason or "Payment verification failed",
            )

        try:
            reports = await connector.audit_proposals(
                engine=app.state.engine,
                spaces=scan_req.spaces,
                limit=scan_req.limit,
            )
        except Exception as exc:
            logger.exception(f"Error executing governance audit: {exc}")
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="api",
                    error_type="ServiceUnavailableNoCharge",
                    message=f"Governance audit error: {str(exc)}",
                    traceback_str=traceback.format_exc(),
                    context={"path": str(request.url.path)},
                )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "ServiceUnavailable",
                    "message": "Execution failed due to upstream error. Payment was NOT settled.",
                    "payment_settled": False,
                },
            )

        settlement = await facilitator.settle(payment_data, required_atomic, x402_cfg)
        if not settlement.settled:
            if storage_inst is not None:
                await storage_inst.log_error(
                    stage="payment",
                    error_type="SettlementError",
                    message=settlement.error or "Failed to settle",
                    context={"path": str(request.url.path)},
                )
            return build_402_response(
                x402_cfg,
                request.url.path,
                required_usdc,
                reason=settlement.error or "Payment settlement failed",
            )

        _log_x402_settled(
            request.url.path,
            required_usdc,
            settlement.tx_hash,
            payment_data.get("network") or x402_cfg.network,
        )

        receipt = PaymentReceipt(
            payment_id=payment_data["payment_id"],
            payer_address=payment_data["payer_address"],
            pay_to_address=x402_cfg.pay_to_address,
            amount_usdc=round(required_usdc, 6),
            amount_atomic=required_atomic,
            network=payment_data.get("network") or x402_cfg.network,
            asset=x402_cfg.asset,
            tx_hash=settlement.tx_hash or "",
            endpoint=request.url.path,
            settled_at=datetime.now(timezone.utc).isoformat(),
        )
        if storage_inst is not None:
            await storage_inst.record_payment(receipt)

        receipt_summary = json.dumps({
            "tx_hash": receipt.tx_hash,
            "payment_id": receipt.payment_id,
            "amount_usdc": receipt.amount_usdc,
        })
        response.headers["X-PAYMENT-RESPONSE"] = receipt_summary
        response.headers["PAYMENT-RESPONSE"] = receipt_summary

        return reports

    return app


# Module-level default application instance
app = create_app()
