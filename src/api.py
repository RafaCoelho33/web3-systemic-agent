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
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

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
# Application Factory
# -------------------------------------------------------------------------

def create_app(
    engine: Optional[ConditionAgentEngine] = None,
    storage: Optional[AgentStorage] = None,
    x402_config: Optional[X402Config] = None,
    facilitator: Optional[Any] = None,
    rate_limit_per_minute: Optional[int] = None,
    public_evaluate_only: Optional[bool] = None,
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

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        yield
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
                "/health",
                "/evaluate",
                "/rules/evaluate-batch",
                "/rules/validate",
                "/rules/enqueue",
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
        return await storage_inst.get_summary_metrics(target_price_usd=target_price)

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
