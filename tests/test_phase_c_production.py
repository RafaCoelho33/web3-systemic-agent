"""
Phase C Production Readiness and Sentinel Webhook Alert Test Suite.

Validates Phase C deliverables:
1. Production Containerization Artifacts:
   - Dockerfile (Python 3.11-slim, non-root appuser, HEALTHCHECK, port 8000, uvicorn entrypoint)
   - .dockerignore (excludes .env, .buyer_wallet.json, *.db, data/, etc.)
   - docker-compose.yml (maps 8000:8000, mounts ./data:/app/data, sets LEDGER_DB_PATH)
   - .env.example (complete documentation of environment variables with no secret leaks)

2. Sentinel Webhook Alert Dispatcher:
   - WebhookAlertDispatcher payload structure (Discord embeds, Slack text, x402 monetization links)
   - Graceful handling of missing webhook URL (safe return False)
   - Successful delivery with HTTP 200 and HTTP 204
   - Resilient exception handling (HTTP 500, network errors, timeouts, no unhandled exceptions)
   - Severity-based batch filtering (CRITICAL vs WARNING vs INFO)
   - End-to-end integration with governance_listener.py runner
"""

import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import AsyncMock, MagicMock, patch

from eth_account import Account
from fastapi.testclient import TestClient
import httpx
import pytest

# Ensure repo root and source paths are accessible
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
ROOT_DIR = _ROOT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
for _p in (_ROOT_DIR, _SRC_DIR, _SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.schemas import (
        ChainId,
        DeterministicResult,
        FinalAgentResponse,
        SemanticAuditResult,
    )
    from src.governance_connector import (
        GovernanceAuditReport,
        GovernanceProposal,
        WebhookAlertDispatcher,
        ALERT_SEVERITY_ORDER,
    )
    from scripts.governance_listener import run_listener
    from src.api import create_app
    from src.engine import ConditionAgentEngine
    from src.storage import AgentStorage
    from src.chain_inspector import ChainInspector
    from src.semantic_evaluator import (
        GeminiSemanticEvaluator,
        MockSemanticEvaluator,
    )
    from src.x402_payment import (
        X402Config,
        MockX402Facilitator,
        create_eip3009_payment_header,
        usdc_to_atomic,
    )
except ImportError:
    from schemas import (
        ChainId,
        DeterministicResult,
        FinalAgentResponse,
        SemanticAuditResult,
    )
    from governance_connector import (
        GovernanceAuditReport,
        GovernanceProposal,
        WebhookAlertDispatcher,
        ALERT_SEVERITY_ORDER,
    )
    from governance_listener import run_listener
    from api import create_app
    from engine import ConditionAgentEngine
    from storage import AgentStorage
    from chain_inspector import ChainInspector
    from semantic_evaluator import (
        GeminiSemanticEvaluator,
        MockSemanticEvaluator,
    )
    from x402_payment import (
        X402Config,
        MockX402Facilitator,
        create_eip3009_payment_header,
        usdc_to_atomic,
    )


class TestPhaseCDockerContainerization:
    """Test suite validating Docker and deployment configuration artifacts."""

    def test_dockerfile_exists_and_configured_securely(self):
        """Dockerfile must exist at root, use python:3.11-slim, run as appuser, expose 8000, define HEALTHCHECK, and launch uvicorn."""
        dockerfile_path = os.path.join(_ROOT_DIR, "Dockerfile")
        assert os.path.isfile(dockerfile_path), "Dockerfile must exist at project root"

        with open(dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "python:3.11-slim" in content, "Dockerfile must use python:3.11-slim base image"
        assert "USER appuser" in content, "Dockerfile must switch to non-root user appuser"
        assert "EXPOSE 8000" in content, "Dockerfile must expose port 8000"
        assert "HEALTHCHECK" in content, "Dockerfile must define a HEALTHCHECK"
        assert "uvicorn" in content and "api:app" in content, "Dockerfile must launch uvicorn with api:app"

    def test_dockerignore_protects_secrets_and_local_state(self):
        """`.dockerignore` must exist and explicitly exclude sensitive secrets and local state."""
        dockerignore_path = os.path.join(_ROOT_DIR, ".dockerignore")
        assert os.path.isfile(dockerignore_path), ".dockerignore must exist at project root"

        with open(dockerignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert ".env" in content, ".dockerignore must list .env"
        assert ".buyer_wallet.json" in content, ".dockerignore must list .buyer_wallet.json"
        assert "*.db" in content, ".dockerignore must list *.db"
        assert "data/" in content, ".dockerignore must list data/"

    def test_docker_compose_exists_and_mounts_persistent_volume(self):
        """`docker-compose.yml` must exist, map 8000:8000, mount persistent volume, and configure ledger path."""
        compose_path = os.path.join(_ROOT_DIR, "docker-compose.yml")
        assert os.path.isfile(compose_path), "docker-compose.yml must exist at project root"

        with open(compose_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "8000:8000" in content, "docker-compose.yml must map 8000:8000"
        assert "./data:/app/data" in content, "docker-compose.yml must mount ./data:/app/data"
        assert "LEDGER_DB_PATH=/app/data/agent.db" in content, "docker-compose.yml must set LEDGER_DB_PATH=/app/data/agent.db"

    def test_env_example_exists_and_contains_no_real_secrets(self):
        """`.env.example` must document required environment variables without leaking real secrets."""
        env_example_path = os.path.join(_ROOT_DIR, ".env.example")
        assert os.path.isfile(env_example_path), ".env.example must exist at project root"

        with open(env_example_path, "r", encoding="utf-8") as f:
            content = f.read()

        required_vars = [
            "GEMINI_API_KEY",
            "PAY_TO_ADDRESS",
            "X402_ENABLED",
            "X402_NETWORK",
            "X402_USE_LIVE_FACILITATOR",
            "ALERT_WEBHOOK_URL",
            "PUBLIC_API_URL",
        ]
        for var in required_vars:
            assert var in content, f".env.example must document {var}"

        # Assert no real Gemini API key is leaked (AIza followed by 20+ chars)
        real_key_match = re.search(r"AIza[0-9A-Za-z_-]{20,}", content)
        assert real_key_match is None, f"Found leaked real API key in .env.example: {real_key_match.group(0) if real_key_match else ''}"


class TestPhaseCWebhookAlertDispatcher:
    """Test suite validating automated DAO governance threat notifications via WebhookAlertDispatcher."""

    @pytest.fixture
    def sample_reports(self) -> Dict[str, GovernanceAuditReport]:
        """Provides sample reports for CRITICAL, WARNING, and INFO alert levels."""
        crit_prop = GovernanceProposal(
            proposal_id="proposal-crit-001",
            space_id="testdao.eth",
            title="Emergency Treasury Multisig Migration",
            body="Immediate migration of community treasury to an unverified address.",
            author="0x0000000000000000000000000000000000000001",
            target_address="0x4200000000000000000000000000000000000006",
            calldata="0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            chain_id=ChainId.BASE_SEPOLIA,
        )
        critical_report = GovernanceAuditReport(
            proposal=crit_prop,
            rule_id="rule-crit-001",
            agent_response=FinalAgentResponse(
                rule_id="rule-crit-001",
                chain_id=ChainId.BASE_SEPOLIA.value,
                deterministic_check=DeterministicResult(passed=True, reason="Pass"),
                llm_invoked=True,
                semantic_Evaluation=SemanticAuditResult(
                    conditions_met=True,
                    risk_score=9.5,
                    flagged_issues=["Unauthorized transferOwnership invocation", "Unverified recipient"],
                    summary="High risk hostile takeover detected",
                    recommended_action="REJECT",
                ),
            ),
            alert_level="CRITICAL",
        )

        warn_prop = GovernanceProposal(
            proposal_id="proposal-warn-002",
            space_id="testdao.eth",
            title="Proxy Logic Implementation Upgrade",
            body="Upgrading implementation contract with unverified bytecode.",
            author="0x0000000000000000000000000000000000000002",
            target_address="0x4200000000000000000000000000000000000006",
            calldata="0x3659cfe6000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            chain_id=ChainId.BASE_SEPOLIA,
        )
        warning_report = GovernanceAuditReport(
            proposal=warn_prop,
            rule_id="rule-warn-002",
            agent_response=FinalAgentResponse(
                rule_id="rule-warn-002",
                chain_id=ChainId.BASE_SEPOLIA.value,
                deterministic_check=DeterministicResult(passed=True, reason="Pass"),
                llm_invoked=True,
                semantic_Evaluation=SemanticAuditResult(
                    conditions_met=True,
                    risk_score=7.0,
                    flagged_issues=["Unverified implementation logic address"],
                    summary="Manual inspection needed for upgrade calldata",
                    recommended_action="MANUAL_REVIEW",
                ),
            ),
            alert_level="WARNING",
        )

        info_prop = GovernanceProposal(
            proposal_id="proposal-info-003",
            space_id="testdao.eth",
            title="Routine Fee Tier Parameter Adjustment",
            body="Routine parameter adjustment for fee tiers.",
            author="0x0000000000000000000000000000000000000003",
            target_address="0x4200000000000000000000000000000000000006",
            calldata="0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000",
            chain_id=ChainId.BASE_SEPOLIA,
        )
        info_report = GovernanceAuditReport(
            proposal=info_prop,
            rule_id="rule-info-003",
            agent_response=FinalAgentResponse(
                rule_id="rule-info-003",
                chain_id=ChainId.BASE_SEPOLIA.value,
                deterministic_check=DeterministicResult(passed=True, reason="Pass"),
                llm_invoked=True,
                semantic_Evaluation=SemanticAuditResult(
                    conditions_met=False,
                    risk_score=1.5,
                    flagged_issues=[],
                    summary="Benign routine parameters",
                    recommended_action="APPROVE",
                ),
            ),
            alert_level="INFO",
        )

        return {
            "CRITICAL": critical_report,
            "WARNING": warning_report,
            "INFO": info_report,
        }

    def test_format_alert_payload_structure(self, sample_reports):
        """`format_alert_payload` produces multi-platform compliant JSON with Discord embeds, Slack text, and x402 links."""
        critical_report = sample_reports["CRITICAL"]
        dispatcher = WebhookAlertDispatcher(
            webhook_url="https://discord.com/api/webhooks/test",
            public_api_url="https://audit.example.com",
            price_usdc=0.05,
        )
        payload = dispatcher.format_alert_payload(critical_report)

        assert "content" in payload, "Payload must include 'content' key for Discord"
        assert "embeds" in payload, "Payload must include 'embeds' key for Discord"
        assert "text" in payload, "Payload must include 'text' key for Slack"
        assert payload["alert_level"] == "CRITICAL"
        assert payload["x402_audit_endpoint"] == "https://audit.example.com/evaluate"
        assert payload["price_usdc"] == 0.05
        assert payload["decision"] == "REJECT"
        assert payload["risk_score"] == 9.5
        assert isinstance(payload["embeds"], list) and len(payload["embeds"]) > 0
        assert payload["embeds"][0]["title"].startswith("[CRITICAL]")

    @pytest.mark.asyncio
    async def test_dispatch_alert_returns_false_when_no_webhook_url(self, monkeypatch, sample_reports):
        """When no webhook URL is configured, `dispatch_alert` must return False without attempting network I/O."""
        critical_report = sample_reports["CRITICAL"]
        monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
        dispatcher = WebhookAlertDispatcher(webhook_url=None)
        assert dispatcher.webhook_url is None

        result = await dispatcher.dispatch_alert(critical_report)
        assert result is False

    @pytest.mark.asyncio
    async def test_dispatch_alert_success_200_and_204(self, sample_reports):
        """`dispatch_alert` returns True on HTTP 200 or 204 status codes and invokes post with the expected URL."""
        critical_report = sample_reports["CRITICAL"]

        # Case 1: HTTP 204 (Standard Discord webhook success response)
        mock_client_204 = AsyncMock(spec=httpx.AsyncClient)
        mock_client_204.post.return_value = httpx.Response(status_code=204)

        dispatcher_204 = WebhookAlertDispatcher(
            webhook_url="https://discord.com/api/webhooks/204",
            client=mock_client_204,
        )
        success_204 = await dispatcher_204.dispatch_alert(critical_report)
        assert success_204 is True
        mock_client_204.post.assert_awaited_once()
        assert mock_client_204.post.await_args[0][0] == "https://discord.com/api/webhooks/204"

        # Case 2: HTTP 200 (Standard Slack / generic HTTP webhook success response)
        mock_client_200 = AsyncMock(spec=httpx.AsyncClient)
        mock_client_200.post.return_value = httpx.Response(status_code=200, json={"ok": True})

        dispatcher_200 = WebhookAlertDispatcher(
            webhook_url="https://hooks.slack.com/services/200",
            client=mock_client_200,
        )
        success_200 = await dispatcher_200.dispatch_alert(critical_report)
        assert success_200 is True
        mock_client_200.post.assert_awaited_once()
        assert mock_client_200.post.await_args[0][0] == "https://hooks.slack.com/services/200"

    @pytest.mark.asyncio
    async def test_dispatch_alert_handles_http_error_and_exception_gracefully(self, sample_reports):
        """`dispatch_alert` must catch errors (HTTP 500, network disconnects, timeouts) and return False gracefully."""
        critical_report = sample_reports["CRITICAL"]

        # 1. HTTP 500 Server Error
        mock_client_500 = AsyncMock(spec=httpx.AsyncClient)
        mock_client_500.post.return_value = httpx.Response(status_code=500, text="Internal Server Error")
        dispatcher_500 = WebhookAlertDispatcher(
            webhook_url="https://webhook.site/500",
            client=mock_client_500,
        )
        assert await dispatcher_500.dispatch_alert(critical_report) is False

        # 2. Connection refused exception
        mock_client_conn = AsyncMock(spec=httpx.AsyncClient)
        mock_client_conn.post.side_effect = httpx.ConnectError("Connection refused")
        dispatcher_conn = WebhookAlertDispatcher(
            webhook_url="https://webhook.site/offline",
            client=mock_client_conn,
        )
        assert await dispatcher_conn.dispatch_alert(critical_report) is False

        # 3. Timeout exception
        mock_client_timeout = AsyncMock(spec=httpx.AsyncClient)
        mock_client_timeout.post.side_effect = httpx.TimeoutException("Request timed out")
        dispatcher_timeout = WebhookAlertDispatcher(
            webhook_url="https://webhook.site/timeout",
            client=mock_client_timeout,
        )
        assert await dispatcher_timeout.dispatch_alert(critical_report) is False

    @pytest.mark.asyncio
    async def test_dispatch_batch_filters_by_min_alert_level(self, sample_reports):
        """`dispatch_batch` filters reports according to min_alert_level severity thresholds."""
        reports = [
            sample_reports["INFO"],
            sample_reports["WARNING"],
            sample_reports["CRITICAL"],
        ]

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = httpx.Response(status_code=200)

        dispatcher = WebhookAlertDispatcher(
            webhook_url="https://discord.com/api/webhooks/test",
            client=mock_client,
        )

        # min_alert_level="CRITICAL" -> dispatches only 1 (CRITICAL)
        mock_client.post.reset_mock()
        dispatched_crit = await dispatcher.dispatch_batch(reports, min_alert_level="CRITICAL")
        assert dispatched_crit == 1
        assert mock_client.post.await_count == 1

        # min_alert_level="WARNING" -> dispatches 2 (WARNING + CRITICAL)
        mock_client.post.reset_mock()
        dispatched_warn = await dispatcher.dispatch_batch(reports, min_alert_level="WARNING")
        assert dispatched_warn == 2
        assert mock_client.post.await_count == 2

        # min_alert_level="INFO" -> dispatches all 3 (INFO + WARNING + CRITICAL)
        mock_client.post.reset_mock()
        dispatched_info = await dispatcher.dispatch_batch(reports, min_alert_level="INFO")
        assert dispatched_info == 3
        assert mock_client.post.await_count == 3

    @pytest.mark.asyncio
    async def test_governance_listener_with_webhook_url(self):
        """`run_listener` passes configured webhook URL to WebhookAlertDispatcher and triggers dispatch_batch."""
        with patch.object(
            WebhookAlertDispatcher, "dispatch_batch", new_callable=AsyncMock
        ) as mock_dispatch:
            mock_dispatch.return_value = 1
            exit_code = await run_listener(
                limit=2,
                curated=True,
                webhook_url="https://hooks.example.com/test",
                min_alert_level="WARNING",
            )
            assert exit_code == 0
            assert mock_dispatch.await_count == 1
            call_args, call_kwargs = mock_dispatch.call_args
            assert len(call_args[0]) == 2
            assert call_kwargs.get("min_alert_level") == "WARNING"


@pytest.fixture
def temp_storage(tmp_path: Path) -> AgentStorage:
    """Provides an isolated SQLite AgentStorage instance backed by tmp_path."""
    db_file = tmp_path / "test_phase_c_security.db"
    return AgentStorage(db_path=str(db_file))


class TestPhaseCSecurityHardening:
    """
    Test suite validating Phase C security hardening protections:
    1. Per-IP Rate Limiting with Cloudflare CF-Connecting-IP header support.
    2. Zero-LLM-drain cost protection on /governance/audit-proposals for unauthenticated requests.
    3. Strict gate 402 Payment Required enforcement when configured.
    4. Authenticated proposal auditing with EIP-3009 payment settlement.
    5. Live facilitator default configuration in deployment templates.
    """

    def test_rate_limiter_blocks_excessive_requests_from_same_ip(self, temp_storage):
        """Rate limiter blocks excessive requests from the same IP with 429 Too Many Requests and Retry-After header."""
        app = create_app(storage=temp_storage, rate_limit_per_minute=3)
        client = TestClient(app)

        for _ in range(3):
            resp = client.get("/")
            assert resp.status_code == 200

        resp4 = client.get("/")
        assert resp4.status_code == 429
        assert resp4.headers.get("retry-after") == "60" or resp4.headers.get("Retry-After") == "60"
        data = resp4.json()
        assert data.get("error") == "TooManyRequests"

    def test_rate_limiter_isolates_ips_via_cloudflare_header(self, temp_storage):
        """Rate limiter identifies clients using CF-Connecting-IP so an attacking IP does not block legitimate IPs."""
        app = create_app(storage=temp_storage, rate_limit_per_minute=2)
        client = TestClient(app)

        cf_attacker = {"CF-Connecting-IP": "203.0.113.99"}
        cf_legitimate = {"CF-Connecting-IP": "198.51.100.42"}

        for _ in range(2):
            resp = client.get("/", headers=cf_attacker)
            assert resp.status_code == 200

        resp3 = client.get("/", headers=cf_attacker)
        assert resp3.status_code == 429

        resp_legit = client.get("/", headers=cf_legitimate)
        assert resp_legit.status_code == 200

    def test_governance_audit_proposals_unauthenticated_never_invokes_paid_llm(self, temp_storage):
        """Unauthenticated requests to /governance/audit-proposals never invoke the paid LLM engine."""
        paid_evaluator = MagicMock(spec=GeminiSemanticEvaluator)
        paid_evaluator.evaluate = AsyncMock(
            side_effect=AssertionError("Paid LLM should not be invoked without payment!")
        )

        paid_engine = ConditionAgentEngine(
            rpc_url="https://sepolia.base.org",
            semantic_evaluator=paid_evaluator,
            storage=temp_storage,
        )
        paid_engine.process_rule = AsyncMock(
            side_effect=AssertionError("Paid LLM should not be invoked without payment!")
        )

        cfg = X402Config(enabled=True)
        app = create_app(engine=paid_engine, storage=temp_storage, x402_config=cfg, public_evaluate_only=False)
        client = TestClient(app)

        async def mock_eval_det(*args, **kwargs):
            return DeterministicResult(
                passed=True,
                reason="ok",
                observed_data={},
            )

        with patch.object(ChainInspector, "evaluate_deterministic", side_effect=mock_eval_det):
            resp = client.post("/governance/audit-proposals", json={"limit": 1})
            assert resp.status_code == 200
            paid_engine.process_rule.assert_not_called()

    def test_governance_audit_proposals_strict_gate_returns_402_when_configured(
        self, temp_storage, monkeypatch
    ):
        """When X402_GATE_GOVERNANCE is configured, unauthenticated requests return 402 Payment Required."""
        monkeypatch.setenv("X402_GATE_GOVERNANCE", "true")
        cfg = X402Config(enabled=True)
        app = create_app(storage=temp_storage, x402_config=cfg, public_evaluate_only=False)
        client = TestClient(app)

        resp = client.post("/governance/audit-proposals", json={"limit": 1})
        assert resp.status_code == 402
        assert resp.headers.get("X-PAYMENT-REQUIRED") == "true" or "Payment" in resp.text

    def test_governance_audit_proposals_with_valid_payment_invokes_paid_engine_and_settles(
        self, temp_storage
    ):
        """Valid EIP-3009 payment invokes the paid engine, returns 200, and records settlement in ledger."""
        buyer = Account.create()
        cfg = X402Config(enabled=True)
        facilitator = MockX402Facilitator()

        paid_evaluator = MockSemanticEvaluator()
        paid_engine = ConditionAgentEngine(
            rpc_url="https://sepolia.base.org",
            semantic_evaluator=paid_evaluator,
            storage=temp_storage,
        )

        app = create_app(
            engine=paid_engine,
            storage=temp_storage,
            x402_config=cfg,
            facilitator=facilitator,
            public_evaluate_only=False,
        )
        client = TestClient(app)

        payment_header = create_eip3009_payment_header(
            account=buyer,
            pay_to_address=cfg.pay_to_address,
            amount_atomic=usdc_to_atomic(cfg.price_per_eval_usdc),
            network=cfg.network,
        )

        async def mock_eval_det(*args, **kwargs):
            return DeterministicResult(
                passed=True,
                reason="ok",
                observed_data={},
            )

        with patch.object(ChainInspector, "evaluate_deterministic", side_effect=mock_eval_det), \
             patch.object(paid_engine, "process_rule", wraps=paid_engine.process_rule) as spy_process:
            resp = client.post(
                "/governance/audit-proposals",
                json={"limit": 1},
                headers={"X-PAYMENT": payment_header},
            )
            assert resp.status_code == 200
            assert spy_process.called

            payments_resp = client.get("/payments")
            assert payments_resp.status_code == 200
            payments = payments_resp.json()
            assert len(payments) >= 1
            assert payments[0]["payer_address"].lower() == buyer.address.lower()

    def test_env_example_live_facilitator_configured(self):
        """`.env.example` documents X402_USE_LIVE_FACILITATOR for facilitator mode configuration."""
        env_example_path = os.path.join(_ROOT_DIR, ".env.example")
        assert os.path.isfile(env_example_path), ".env.example must exist at project root"
        with open(env_example_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "X402_USE_LIVE_FACILITATOR" in content
        assert re.search(r"^X402_USE_LIVE_FACILITATOR\s*=", content, re.MULTILINE) is not None

    def test_public_evaluate_only_blocks_docs_and_internal_endpoints(self, temp_storage):
        """In public_evaluate_only lockdown mode, docs, metrics, logs, payments, and governance endpoints return 403."""
        cfg = X402Config(enabled=True)
        app = create_app(storage=temp_storage, x402_config=cfg, public_evaluate_only=True)
        client = TestClient(app)

        # 1. Verify restricted endpoints return 403 Forbidden
        restricted_endpoints = [
            ("GET", "/docs"),
            ("GET", "/redoc"),
            ("GET", "/openapi.json"),
            ("GET", "/metrics/summary"),
            ("GET", "/logs/errors"),
            ("GET", "/payments"),
            ("POST", "/governance/audit-proposals"),
        ]
        for method, endpoint in restricted_endpoints:
            if method == "GET":
                resp = client.get(endpoint)
            else:
                resp = client.post(endpoint, json={"limit": 1})
            assert resp.status_code == 403, f"{endpoint} expected 403, got {resp.status_code}"
            data = resp.json()
            assert data.get("error") == "Forbidden" or "Forbidden" in resp.text

        # 2. Verify GET / returns 200, swagger_docs/docs not exposed, evaluate is exposed
        root_resp = client.get("/")
        assert root_resp.status_code == 200
        root_data = root_resp.json()
        endpoints = root_data.get("endpoints", {})
        assert "swagger_docs" not in endpoints
        assert "/docs" not in endpoints.values()
        assert "evaluate" in endpoints
        assert endpoints["evaluate"] == "/evaluate"

        # 3. Verify evaluation-related endpoints are not blocked by 403
        val_resp = client.post(
            "/rules/validate",
            json={
                "rule_id": "test-validate",
                "chain_id": 84532,
                "deterministic": {"target_address": "0x0000000000000000000000000000000000000001"},
            },
        )
        assert val_resp.status_code != 403

        eval_resp = client.post(
            "/evaluate",
            json={
                "rule_id": "rule-eval-lockdown",
                "chain_id": 84532,
                "deterministic": {"target_address": "0x0000000000000000000000000000000000000001"},
                "semantic": {"enabled": False, "policy_prompt": "none"},
            },
        )
        assert eval_resp.status_code == 402

    def test_public_evaluate_only_allows_admin_key_bypass_when_configured(
        self, temp_storage, monkeypatch
    ):
        """When ADMIN_API_KEY is configured, requests with X-Admin-Api-Key bypass the lockdown."""
        monkeypatch.setenv("ADMIN_API_KEY", "test-secret-admin-key")
        app = create_app(storage=temp_storage, public_evaluate_only=True)
        client = TestClient(app)

        # Without admin key header -> 403 Forbidden
        unauth_resp = client.get("/metrics/summary")
        assert unauth_resp.status_code == 403

        # With valid X-Admin-Api-Key header -> 200 OK
        auth_resp = client.get(
            "/metrics/summary",
            headers={"X-Admin-Api-Key": "test-secret-admin-key"},
        )
        assert auth_resp.status_code == 200


class TestRepositoryLicense:
    """Validates repository licensing and usage terms under Apache License 2.0."""

    def test_license_is_apache_2_0(self):
        """LICENSE, README.md, and pyproject.toml must declare Apache License 2.0."""
        license_path = Path(ROOT_DIR) / "LICENSE"
        readme_path = Path(ROOT_DIR) / "README.md"
        pyproject_path = Path(ROOT_DIR) / "pyproject.toml"

        assert license_path.is_file(), f"LICENSE file must exist at repo root: {license_path}"
        assert readme_path.is_file(), f"README.md file must exist at repo root: {readme_path}"
        assert pyproject_path.is_file(), f"pyproject.toml file must exist at repo root: {pyproject_path}"

        license_content = license_path.read_text(encoding="utf-8")
        assert "Apache License" in license_content, "LICENSE must contain 'Apache License'"
        assert "Version 2.0" in license_content, "LICENSE must contain 'Version 2.0'"

        readme_content = readme_path.read_text(encoding="utf-8")
        assert "Apache License 2.0" in readme_content, "README.md must contain 'Apache License 2.0'"

        pyproject_content = pyproject_path.read_text(encoding="utf-8")
        assert 'license = "Apache-2.0"' in pyproject_content, "pyproject.toml must declare 'Apache-2.0'"


class TestPhaseCBazaarAndCDPMainnet:
    """Validates Bazaar discovery metadata extensions and CDP facilitator authentication provider."""

    def test_bazaar_discovery_extension_included_in_402_response(self):
        """HTTP 402 payload must include Bazaar discovery extensions and rich metadata."""
        import json
        from src.x402_payment import X402Config, build_402_response

        cfg = X402Config(enabled=True)
        response = build_402_response(cfg, "/evaluate", 0.05)
        body = json.loads(response.body)

        assert body.get("x402Version") == 2, "Expected x402Version == 2 for Bazaar discovery"
        assert "extensions" in body, "Expected 'extensions' key in 402 response body"
        assert "bazaar" in body["extensions"], "Expected 'bazaar' extension in 402 response body"

        accept_item = body["accepts"][0]
        assert accept_item.get("discoverable") is True, "Expected accepts[0].discoverable to be True"
        assert accept_item.get("mimeType") == "application/json", "Expected accepts[0].mimeType to be application/json"
        assert "Pre-Transaction Security Firewall" in accept_item.get("description", ""), (
            "Expected 'Pre-Transaction Security Firewall' in accepts[0].description"
        )

        bazaar_ext = body["extensions"]["bazaar"]
        assert "info" in bazaar_ext, "Expected 'info' in extensions.bazaar"
        assert "schema" in bazaar_ext, "Expected 'schema' in extensions.bazaar"
        assert bazaar_ext["info"]["input"]["method"] == "POST", "Expected bazaar.info.input.method to be POST"
        assert accept_item["amount"] == "50000"
        assert accept_item["maxAmountRequired"] == "50000"
        assert accept_item["amount_usdc"] == 0.05
        assert accept_item["asset"] == cfg.usdc_contract_address
        assert accept_item["usdcAddress"] == cfg.usdc_contract_address
        assert accept_item["maxTimeoutSeconds"] == 300
        assert response.headers.get("X-PAYMENT-REQUIRED") == "true"
        pr_header = response.headers.get("Payment-Required")
        assert pr_header is not None
        assert json.loads(base64.b64decode(pr_header).decode("utf-8")) == body

    def test_bazaar_fallback_without_sdk_has_method_post(self, monkeypatch):
        """Bazaar discovery extension fallback contains method='POST' when x402 SDK is absent."""
        import src.x402_payment as x402_mod
        monkeypatch.setattr(x402_mod, "HAS_X402_SDK", False)
        ext = x402_mod.build_bazaar_discovery_extension("/evaluate")
        assert ext["bazaar"]["info"]["input"]["method"] == "POST"
        assert ext["bazaar"]["info"]["input"]["type"] == "http"
        assert ext["bazaar"]["info"]["input"]["bodyType"] == "json"

    def test_coinbase_cdp_crawler_get_evaluate_returns_402(self, temp_storage):
        """Coinbase CDP crawler GET /evaluate returns HTTP 402 with Bazaar discovery metadata."""
        from src.api import create_app
        from src.x402_payment import X402Config
        from fastapi.testclient import TestClient

        cfg = X402Config(enabled=True)
        app = create_app(storage=temp_storage, x402_config=cfg)
        client = TestClient(app)

        resp = client.get("/evaluate")
        assert resp.status_code == 402
        assert resp.headers.get("X-PAYMENT-REQUIRED") == "true"
        pr_header = resp.headers.get("Payment-Required")
        assert pr_header is not None
        assert json.loads(base64.b64decode(pr_header).decode("utf-8")) == resp.json()

        data = resp.json()
        assert "extensions" in data
        assert "bazaar" in data["extensions"]
        assert data["extensions"]["bazaar"]["info"]["input"]["method"] == "POST"
        assert data["accepts"][0]["amount"] == "10000"
        assert data["accepts"][0]["asset"] == cfg.usdc_contract_address

    def test_coinbase_cdp_crawler_post_evaluate_empty_body_returns_402(self, temp_storage):
        """Coinbase CDP crawler POST /evaluate with empty body or no payment header returns HTTP 402, not 422."""
        from src.api import create_app
        from src.x402_payment import X402Config
        from fastapi.testclient import TestClient

        cfg = X402Config(enabled=True)
        app = create_app(storage=temp_storage, x402_config=cfg)
        client = TestClient(app)

        # Empty body {} without payment headers must return 402 directly
        resp_empty = client.post("/evaluate", json={})
        assert resp_empty.status_code == 402
        assert resp_empty.headers.get("X-PAYMENT-REQUIRED") == "true"
        pr_empty = resp_empty.headers.get("Payment-Required")
        assert pr_empty is not None
        assert json.loads(base64.b64decode(pr_empty).decode("utf-8")) == resp_empty.json()

        # Arbitrary body without payment headers must return 402 directly
        resp_bad = client.post("/evaluate", json={"invalid": "payload"})
        assert resp_bad.status_code == 402
        assert resp_bad.headers.get("X-PAYMENT-REQUIRED") == "true"
        pr_bad = resp_bad.headers.get("Payment-Required")
        assert pr_bad is not None
        assert json.loads(base64.b64decode(pr_bad).decode("utf-8")) == resp_bad.json()

    def test_evaluate_post_with_payment_header_and_invalid_body_returns_422(self, temp_storage):
        """POST /evaluate with payment header and invalid body triggers FastAPI validation and returns 422."""
        from src.api import create_app
        from src.x402_payment import X402Config
        from fastapi.testclient import TestClient

        cfg = X402Config(enabled=True)
        app = create_app(storage=temp_storage, x402_config=cfg)
        client = TestClient(app)

        # With payment header present, request proceeds to schema validation
        fake_payment_hdr = '{"payment_id": "test-pay-1", "payer_address": "0x1111111111111111111111111111111111111111", "amount_atomic": 10000, "signature": "0xvalid"}'
        resp = client.post("/evaluate", json={"bad": "payload"}, headers={"X-PAYMENT": fake_payment_hdr})
        assert resp.status_code == 422

    def test_cdp_api_key_config_and_auth_provider(self, monkeypatch):
        """X402Config recognizes CDP API keys and CDPFacilitatorAuthProvider provides auth headers."""
        monkeypatch.setenv("CDP_API_KEY_ID", "cdp-key-id-123")
        monkeypatch.setenv("CDP_API_KEY_SECRET", "cdp-secret-xyz")
        monkeypatch.delenv("FACILITATOR_URL", raising=False)

        from src.x402_payment import X402Config, CDPFacilitatorAuthProvider

        cfg = X402Config(enabled=True, network="eip155:8453")
        assert cfg.has_cdp_credentials() is True
        assert cfg.facilitator_url == "https://api.cdp.coinbase.com/platform/v2/x402"

        provider = CDPFacilitatorAuthProvider(cfg.cdp_api_key_id, cfg.cdp_api_key_secret)
        headers = provider.get_auth_headers()
        assert headers.verify["X-CDP-API-KEY-ID"] == "cdp-key-id-123"
        assert "Bearer cdp-secret-xyz" in headers.settle["Authorization"]

    def test_cdp_jwt_signing_ed25519_and_mainnet_url_override(self, monkeypatch):
        """Generates valid Ed25519 signed JWT for CDP and overrides FACILITATOR_URL on Base Mainnet."""
        import base64
        from src.x402_payment import X402Config, CDPFacilitatorAuthProvider

        ed25519_b64 = base64.b64encode(b"\x11" * 32).decode("ascii")
        monkeypatch.setenv("CDP_API_KEY_ID", "organizations/org-1/apiKeys/key-1")
        monkeypatch.setenv("CDP_API_KEY_SECRET", ed25519_b64)
        monkeypatch.setenv("FACILITATOR_URL", "https://x402.org/facilitator")

        cfg = X402Config(enabled=True, network="eip155:8453")
        assert cfg.facilitator_url == "https://api.cdp.coinbase.com/platform/v2/x402"

        provider = CDPFacilitatorAuthProvider(cfg.cdp_api_key_id, cfg.cdp_api_key_secret)
        headers = provider.get_auth_headers()

        assert headers.verify["Authorization"].startswith("Bearer ")
        token = headers.verify["Authorization"][len("Bearer "):]
        assert len(token.split(".")) == 3

    def test_cdp_jwt_signing_ed25519_48_byte_pkcs8_der(self):
        """Generates real 48-byte PKCS#8 DER Ed25519 key, builds CDP JWT, and verifies cryptographic signature."""
        import base64
        import json
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from src.x402_payment import CDPFacilitatorAuthProvider

        private_key = ed25519.Ed25519PrivateKey.generate()
        der_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert len(der_bytes) == 48

        api_key_id = "e6a4b123-4567-89ab-cdef-0123456789ab"
        api_key_secret = base64.b64encode(der_bytes).decode("ascii")

        provider = CDPFacilitatorAuthProvider(api_key_id=api_key_id, api_key_secret=api_key_secret)
        headers = provider.get_auth_headers()

        auth_header = headers.verify["Authorization"]
        assert auth_header.startswith("Bearer ")
        token = auth_header[len("Bearer "):]
        jwt_parts = token.split(".")
        assert len(jwt_parts) == 3

        def _b64_url_decode(s: str) -> bytes:
            padding = "=" * ((4 - len(s) % 4) % 4)
            return base64.urlsafe_b64decode(s + padding)

        h_b64, p_b64, s_b64 = jwt_parts
        jwt_header = json.loads(_b64_url_decode(h_b64).decode("utf-8"))
        jwt_payload = json.loads(_b64_url_decode(p_b64).decode("utf-8"))
        sig_bytes = _b64_url_decode(s_b64)
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")

        assert jwt_header["alg"] == "EdDSA"
        assert jwt_header["kid"] == api_key_id
        assert jwt_payload["sub"] == api_key_id
        assert jwt_payload["iss"] == "cdp"
        assert "POST api.cdp.coinbase.com/platform/v2/x402/verify" in jwt_payload["uris"]

        private_key.public_key().verify(sig_bytes, signing_input)

    def test_cdp_jwt_signing_ecdsa_pem_and_64_byte_raw(self):
        """Generates CDP JWTs from 64-byte raw base64 key (EdDSA) and SECP256R1 ECDSA PEM (ES256)."""
        import base64
        import json
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from src.x402_payment import CDPFacilitatorAuthProvider

        def _b64_url_decode(s: str) -> bytes:
            padding = "=" * ((4 - len(s) % 4) % 4)
            return base64.urlsafe_b64decode(s + padding)

        raw_64_bytes = b"\x22" * 64
        raw_64_b64 = base64.b64encode(raw_64_bytes).decode("ascii")
        provider_64 = CDPFacilitatorAuthProvider(api_key_id="key-64-raw", api_key_secret=raw_64_b64)
        headers_64 = provider_64.get_auth_headers()
        assert headers_64.verify["Authorization"].startswith("Bearer ")
        parts_64 = headers_64.verify["Authorization"][len("Bearer "):].split(".")
        assert len(parts_64) == 3
        jwt_header_64 = json.loads(_b64_url_decode(parts_64[0]).decode("utf-8"))
        assert jwt_header_64["alg"] == "EdDSA"

        ec_key = ec.generate_private_key(ec.SECP256R1())
        pem_bytes = ec_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        provider_ec = CDPFacilitatorAuthProvider(api_key_id="key-ecdsa-pem", api_key_secret=pem_bytes.decode("ascii"))
        headers_ec = provider_ec.get_auth_headers()
        assert headers_ec.verify["Authorization"].startswith("Bearer ")
        parts_ec = headers_ec.verify["Authorization"][len("Bearer "):].split(".")
        assert len(parts_ec) == 3
        jwt_header_ec = json.loads(_b64_url_decode(parts_ec[0]).decode("utf-8"))
        assert jwt_header_ec["alg"] == "ES256"

    @pytest.mark.asyncio
    async def test_http_facilitator_rest_fallback_uses_signed_jwt(self):
        """HTTPX402Facilitator REST fallback attaches signed 3-part Bearer JWT and API Key ID header."""
        import base64
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from src.x402_payment import X402Config, HTTPX402Facilitator

        private_key = ed25519.Ed25519PrivateKey.generate()
        der_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert len(der_bytes) == 48
        der_b64 = base64.b64encode(der_bytes).decode("ascii")

        cfg = X402Config(
            enabled=True,
            network="eip155:8453",
            cdp_api_key_id="uuid-key-1",
            cdp_api_key_secret=der_b64,
        )

        mock_resp = MagicMock(
            status_code=200,
            json=lambda: {
                "valid": True,
                "payment_id": "p1",
                "payer_address": "0x1111111111111111111111111111111111111111",
                "amount_atomic": 50000,
                "amount_usdc": 0.05,
            },
        )
        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=mock_resp)

        facilitator = HTTPX402Facilitator(client=mock_client)
        payment_data = {
            "payment_id": "p1",
            "payer_address": "0x1111111111111111111111111111111111111111",
            "amount_atomic": 50000,
        }
        res = await facilitator.verify(payment_data, 50000, cfg)
        assert res.valid is True

        called_headers = mock_client.post.call_args.kwargs["headers"]
        assert "Authorization" in called_headers
        auth_hdr = called_headers["Authorization"]
        assert auth_hdr.startswith("Bearer ")
        assert auth_hdr != f"Bearer {der_b64}"
        jwt_token = auth_hdr[len("Bearer "):]
        parts = jwt_token.split(".")
        assert len(parts) == 3
        assert called_headers["X-CDP-API-KEY-ID"] == "uuid-key-1"

        json_payload = mock_client.post.call_args.kwargs["json"]
        assert json_payload["x402Version"] == 2
        assert "paymentPayload" in json_payload
        assert "paymentRequirements" in json_payload
        assert json_payload["paymentPayload"]["x402Version"] == 2

    @pytest.mark.asyncio
    async def test_http_facilitator_rest_fallback_settle_payload(self):
        """HTTPX402Facilitator REST fallback settle sends x402 V2 payload with paymentPayload and paymentRequirements."""
        import base64
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from src.x402_payment import X402Config, HTTPX402Facilitator

        private_key = ed25519.Ed25519PrivateKey.generate()
        der_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        der_b64 = base64.b64encode(der_bytes).decode("ascii")

        cfg = X402Config(
            enabled=True,
            network="eip155:8453",
            cdp_api_key_id="uuid-key-settle",
            cdp_api_key_secret=der_b64,
        )

        mock_resp = MagicMock(
            status_code=200,
            json=lambda: {
                "success": True,
                "transaction": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            },
        )
        mock_client = MagicMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=mock_resp)

        facilitator = HTTPX402Facilitator(client=mock_client)
        payment_data = {
            "payment_id": "p-settle-1",
            "payer_address": "0x1111111111111111111111111111111111111111",
            "amount_atomic": 50000,
        }
        res = await facilitator.settle(payment_data, 50000, cfg)
        assert res.settled is True
        assert res.tx_hash == "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

        # Verify headers
        called_headers = mock_client.post.call_args.kwargs["headers"]
        assert "Authorization" in called_headers
        assert called_headers["Authorization"].startswith("Bearer ")
        assert called_headers["X-CDP-API-KEY-ID"] == "uuid-key-settle"

        # Verify x402 V2 REST payload
        json_payload = mock_client.post.call_args.kwargs["json"]
        assert json_payload["x402Version"] == 2
        assert "paymentPayload" in json_payload
        assert "paymentRequirements" in json_payload
        assert json_payload["paymentPayload"]["x402Version"] == 2
        assert json_payload["paymentRequirements"]["amount"] == "50000"




