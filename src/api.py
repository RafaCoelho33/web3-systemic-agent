"""
HTTP API Service Layer for Web3 Condition-Action Trigger Agent.
Built on FastAPI providing asynchronous endpoints for health monitoring,
syntactic rule pre-validation, and two-stage pipeline execution.
"""

import asyncio
from contextlib import asynccontextmanager
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
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from web3 import AsyncWeb3, AsyncHTTPProvider

try:
    from scripts.block_contract_scanner import (
        get_latest_block_number,
        scan_recent_blocks,
        audit_discovered_contracts,
    )
except ImportError:
    try:
        from block_contract_scanner import (
            get_latest_block_number,
            scan_recent_blocks,
            audit_discovered_contracts,
        )
    except ImportError:
        get_latest_block_number = None
        scan_recent_blocks = None
        audit_discovered_contracts = None

try:
    from src.schemas import (
        ConditionRulePayload,
        FinalAgentResponse,
        ChainId,
        PaymentReceipt,
    )
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
    )
except ImportError:
    from schemas import (
        ConditionRulePayload,
        FinalAgentResponse,
        ChainId,
        PaymentReceipt,
    )
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
    )

if not hasattr(X402Config, "price_atomic"):
    setattr(
        X402Config,
        "price_atomic",
        property(lambda self: usdc_to_atomic(self.price_per_eval_usdc)),
    )

logger = logging.getLogger(__name__)

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
    version: str = Field(default="1.0.0", description="Application semantic version")
    status: str = Field(default="online", description="Operational status of the service")
    x402_enabled: bool = Field(default=False, description="Whether x402 payment gate is enabled")
    x402_network: Optional[str] = Field(default=None, description="Active x402 CAIP-2 network")
    price_per_eval_usdc: float = Field(default=0.01, description="Base price in USDC per evaluation")
    pay_to_address: Optional[str] = Field(default=None, description="Recipient EVM address for x402 micropayments")
    endpoints: Dict[str, str] = Field(..., description="Canonical API endpoint route registry")


class SimpleHealthResponse(BaseModel):
    status: str = Field(default="ok", description="Basic health status")


class HealthCheckResponse(BaseModel):
    status: str = Field(..., description="Overall health status: 'ok', 'degraded', or 'error'")
    version: str = Field(default="1.0.0", description="Application version")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of inspection")
    rpc_status: Dict[int, bool] = Field(..., description="RPC connectivity per chain ID")
    semantic_provider: str = Field(..., description="Active semantic provider ('gemini', 'openai', or 'mock')")
    provider: str = Field(default="mock", description="Normalized provider identifier ('gemini', 'openai', or 'mock')")
    is_mock: bool = Field(..., description="Whether running a simulation/mock LLM")
    model: Optional[str] = Field(default=None, description="Active model name if using Gemini or OpenAI")
    x402_enabled: bool = Field(default=False, description="Whether x402 payment gate is enabled")
    x402_network: Optional[str] = Field(default=None, description="Active x402 CAIP-2 network")
    price_per_eval_usdc: float = Field(default=0.01, description="Base price in USDC per evaluation")


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
Allow: /mcp
Allow: /evaluate
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/

User-agent: GPTBot
Allow: /
Allow: /mcp
Allow: /evaluate
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/

User-agent: ClaudeBot
Allow: /
Allow: /mcp
Allow: /evaluate
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/

User-agent: PerplexityBot
Allow: /
Allow: /mcp
Allow: /evaluate
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/

User-agent: Google-Extended
Allow: /
Allow: /mcp
Allow: /evaluate
Allow: /rules/validate
Allow: /llms.txt
Allow: /llms-full.txt
Allow: /.well-known/
Disallow: /metrics/
Disallow: /logs/
Disallow: /payments
Disallow: /jobs/
"""

SECURITY_TXT_CONTENT = """Contact: https://github.com/RafaCoelho33/web3_systemic-agent/issues
Expires: 2027-12-31T23:59:59.000Z
Preferred-Languages: en, pt
Canonical: https://web3-systemic-agent.onrender.com/.well-known/security.txt
Policy: https://github.com/RafaCoelho33/web3_systemic-agent/blob/main/README.md
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

## System Overview
- **System Identifier:** `io.github.RafaCoelho33/web3-systemic-agent`
- **Name:** Web3 Systemic Agent
- **Version:** `1.0.0`
- **Public API URL:** `https://web3-systemic-agent.onrender.com`
- **Supported Chains:** Base Mainnet (`eip155:8453`), Base Sepolia (`eip155:84532`), Arbitrum One (`eip155:42161`)

## Two-Stage Hybrid Architecture
1. **Stage 1: Deterministic On-Chain Gatekeeping (Zero LLM Token Cost / Free)**
   - High-throughput EVM bytecode and calldata analysis using `ChainInspector` with local FIFO caching.
   - Extracts 4-byte function selectors, inspects target contract bytecode existence, verifies native balances, and evaluates DEX honeypot signatures.
   - Short-circuits non-matching or benign conditions with `llm_invoked=False` ($0.00 LLM token cost).
2. **Stage 2: Deep Semantic LLM Governance & Security Audit ($0.05 USDC via x402)**
   - Triggered only when Stage 1 deterministic conditions pass or high-risk administrative capabilities are detected.
   - Leverages Google Gemini (`gemini-3.5-flash-lite` with automatic cooldown failover to `gemini-3.1-flash-lite`, `gemini-2.5-flash-lite`, and `gemini-2.0-flash`).
   - Evaluates natural language claims against actual on-chain bytecode, native balance, and execution calldata.
   - Enforces deterministic policy escalation (`APPROVE`, `MANUAL_REVIEW`, `REJECT`) via `enforce_decision_policy`.

## Model Context Protocol (MCP) Streamable-HTTP (`POST /mcp`)
Connect using MCP specification `2024-11-05` via HTTP POST:
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
    "clientInfo": {"name": "autonomous-client", "version": "1.0.0"}
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

### 4. `deep_semantic_audit` (Stage 2 Paid - $0.05 USDC via x402)
- **Description:** Two-stage security audit crossing natural language proposal text with on-chain bytecode and calldata. Returns risk scores (0.0 to 10.0), flagged issues, and deterministic policy action (`APPROVE`, `MANUAL_REVIEW`, `REJECT`).
- **Arguments:**
  - `target_address` (string, required): Smart contract address under evaluation.
  - `proposal_description` (string, required): Claim or governance proposal intent.
  - `policy_prompt` (string, optional): Custom policy prompt.
  - `calldata` (string, default "0x"): Hex calldata being executed.
  - `chain_id` (integer, default 8453): EVM Chain ID.
  - `risk_threshold` (number, default 7.0): Risk threshold.
  - `x402_payment_header` (string, optional): Base64 EIP-3009 transfer authorization.
- **Payment Requirement:** If called without `x402_payment_header` or configured buyer key, returns HTTP 402 with recipient address `0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63` on Base Mainnet (`eip155:8453`).

## REST API Integration

### Static Rule Validation (Free)
- **Endpoint:** `POST https://web3-systemic-agent.onrender.com/rules/validate`
- Validates payload structure and parameters before submission.

### Deep Evaluation Execution ($0.05 USDC via x402)
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

## Security & Transparency
- **Security Policy:** `/.well-known/security.txt`
- **MCP Server Card:** `/.well-known/mcp/server-card.json`
- **Agent Card:** `/.well-known/agent.json`
- **Contact:** https://github.com/RafaCoelho33/web3_systemic-agent/issues
"""


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
        version="1.0.0",
        description=(
            "Autonomous Web3 Agent for deterministic on-chain gatekeeping "
            "and LLM-powered semantic governance/security auditing."
        ),
        lifespan=lifespan,
        docs_url=None if effective_public_evaluate_only else "/docs",
        redoc_url=None if effective_public_evaluate_only else "/redoc",
        openapi_url=None if effective_public_evaluate_only else "/openapi.json",
    )

    # Enable CORS for B2B/Micro-SaaS integration
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

    # Per-IP Sliding-Window Rate Limiter
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

    # Public Evaluate-Only Lockdown Mode
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
                "/favicon.ico",
                "/icon.svg",
                "/health",
                "/evaluate",
                "/rules/evaluate-batch",
                "/rules/validate",
                "/rules/enqueue",
                "/mcp",
                "/robots.txt",
                "/llms.txt",
                "/llms-full.txt",
                "/.well-known/mcp/server-card.json",
                "/.well-known/mcp.json",
                "/.well-known/agent.json",
                "/.well-known/security.txt",
                "/security.txt",
            }
            path = request.url.path
            if path in allowed_paths or path.startswith("/jobs/"):
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
    app.state.mcp_server = Web3SystemicMCPServer(engine=active_engine)

    # Intercept /evaluate requests for Coinbase CDP Crawler & x402 Bazaar compliance
    @app.middleware("http")
    async def x402_evaluate_interceptor(request: Request, call_next):
        if request.url.path.rstrip("/") == "/evaluate" and request.method in ("GET", "POST"):
            x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
            if x402_cfg.enabled:
                payment_hdr = (
                    request.headers.get("x-payment")
                    or request.headers.get("payment-signature")
                    or request.headers.get("x-payment-signature")
                )
                has_payment = bool(payment_hdr and payment_hdr.strip())
                if not has_payment:
                    return build_402_response(
                        x402_cfg,
                        request.url.path,
                        x402_cfg.price_per_eval_usdc,
                    )
        return await call_next(request)

    # Defensive HTTP Security Headers (applied to all responses)
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

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
        if exc.status_code >= 400:
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
    async def root():
        """
        Root discovery endpoint returning active service status, x402 payment gate configuration,
        and canonical API endpoint routes.
        """
        x402_cfg: X402Config = getattr(app.state, "x402_config", None) or X402Config()
        if getattr(app.state, "public_evaluate_only", False):
            endpoints = {
                "health": "/health",
                "validate_rule": "/rules/validate",
                "evaluate": "/evaluate",
                "evaluate_batch": "/rules/evaluate-batch",
                "enqueue_job": "/rules/enqueue",
                "mcp": "/mcp",
                "llms_txt": "/llms.txt",
                "mcp_server_card": "/.well-known/mcp/server-card.json",
                "agent_card": "/.well-known/agent.json",
            }
        else:
            endpoints = {
                "swagger_docs": "/docs",
                "health": "/health",
                "validate_rule": "/rules/validate",
                "evaluate": "/evaluate",
                "evaluate_batch": "/rules/evaluate-batch",
                "enqueue_job": "/rules/enqueue",
                "governance_audit": "/governance/audit-proposals",
                "metrics_summary": "/metrics/summary",
                "payments_ledger": "/payments",
                "error_logs": "/logs/errors",
                "mcp": "/mcp",
                "llms_txt": "/llms.txt",
                "mcp_server_card": "/.well-known/mcp/server-card.json",
                "agent_card": "/.well-known/agent.json",
            }
        return {
            "service": "Web3 Condition-Action Trigger Agent",
            "version": "1.0.0",
            "status": "online",
            "x402_enabled": x402_cfg.enabled,
            "x402_network": x402_cfg.network,
            "price_per_eval_usdc": x402_cfg.price_per_eval_usdc,
            "pay_to_address": x402_cfg.pay_to_address,
            "endpoints": endpoints,
        }

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
            mcp = Web3SystemicMCPServer(engine=getattr(app.state, "engine", None))
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

        if isinstance(body, list):
            responses = []
            for item in body:
                resp = await mcp.handle_jsonrpc(item)
                if resp is not None:
                    responses.append(resp)
            return JSONResponse(status_code=status.HTTP_200_OK, content=responses)

        rpc_resp = await mcp.handle_jsonrpc(body)
        if rpc_resp is None:
            return Response(status_code=status.HTTP_202_ACCEPTED)

        return JSONResponse(status_code=status.HTTP_200_OK, content=rpc_resp)

    # ---------------------------------------------------------------------
    # Crawler Discovery, Agent-Teaching & Security Endpoints
    # ---------------------------------------------------------------------

    @app.get("/robots.txt", include_in_schema=False)
    async def get_robots_txt():
        """Returns robots.txt rules for search engine and AI crawlers."""
        return Response(content=ROBOTS_TXT_CONTENT, media_type="text/plain; charset=utf-8")

    @app.get("/llms.txt", include_in_schema=False)
    @app.get("/llms-full.txt", include_in_schema=False)
    async def get_llms_txt():
        """Returns structured Markdown guide teaching LLMs how to use the Web3 Systemic Agent."""
        return Response(content=LLMS_TXT_CONTENT, media_type="text/plain; charset=utf-8")

    @app.get("/icon.svg", include_in_schema=False)
    async def get_icon_svg():
        """Returns static server SVG icon."""
        return Response(content=ICON_SVG_CONTENT, media_type="image/svg+xml")

    @app.get("/.well-known/mcp/server-card.json", include_in_schema=False)
    @app.get("/.well-known/mcp.json", include_in_schema=False)
    async def get_mcp_server_card():
        """Returns official MCP server card metadata."""
        public_url = (
            os.getenv("PUBLIC_API_URL")
            or os.getenv("WEB3_AGENT_URL")
            or "https://web3-systemic-agent.onrender.com"
        ).rstrip("/")
        mcp: Optional[Web3SystemicMCPServer] = getattr(app.state, "mcp_server", None)
        if mcp is None:
            mcp = Web3SystemicMCPServer(engine=getattr(app.state, "engine", None))
            app.state.mcp_server = mcp

        card = {
            "serverInfo": {
                "name": "io.github.RafaCoelho33/web3-systemic-agent",
                "title": "Web3 Systemic Agent",
                "version": "1.0.0",
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

    @app.get("/.well-known/agent.json", include_in_schema=False)
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
            mcp = Web3SystemicMCPServer(engine=getattr(app.state, "engine", None))
            app.state.mcp_server = mcp

        agent_card = {
            "name": "Web3 Systemic Agent",
            "id": "io.github.RafaCoelho33/web3-systemic-agent",
            "version": "1.0.0",
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
                "validate_rule": "/rules/validate",
                "llms_txt": "/llms.txt",
                "server_card": "/.well-known/mcp/server-card.json",
            },
            "skills": mcp.get_tools_manifest(),
        }
        return JSONResponse(status_code=status.HTTP_200_OK, content=agent_card)

    @app.get("/.well-known/security.txt", include_in_schema=False)
    @app.get("/security.txt", include_in_schema=False)
    async def get_security_txt():
        """Returns RFC 9116 security vulnerability reporting policy."""
        return Response(content=SECURITY_TXT_CONTENT, media_type="text/plain; charset=utf-8")

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
            version="1.0.0",
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
        payment_header = (
            request.headers.get("x-payment")
            or request.headers.get("payment-signature")
            or request.headers.get("X-PAYMENT")
            or request.headers.get("PAYMENT-SIGNATURE")
        )
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
        payment_header = (
            request.headers.get("x-payment")
            or request.headers.get("payment-signature")
            or request.headers.get("X-PAYMENT")
            or request.headers.get("PAYMENT-SIGNATURE")
        )
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
        payment_header = (
            request.headers.get("x-payment")
            or request.headers.get("payment-signature")
            or request.headers.get("X-PAYMENT")
            or request.headers.get("PAYMENT-SIGNATURE")
        )
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

    @app.get("/metrics/summary", tags=["Monitoring"])
    async def get_metrics_summary(target_price: float = 0.01):
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

    @app.get("/logs/errors", tags=["Monitoring"])
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

    @app.get("/payments", tags=["Payment Diagnostics"])
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
