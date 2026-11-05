"""
Comprehensive Unit & Edge-Case Test Suite for Phase B1.
Tests every section of the Phase B1 Specification Contract:
1. .gitignore and requirements.txt
2. SemanticAuditResult telemetry fields and LLMAuditOutput field strictness
3. LLM input cap, token telemetry extraction & cost estimation
4. SQLite Storage (AgentStorage) & error logging with secret scrubbing and resilience
5. Reporting CLI (src/report.py)
6. JobStore TTL and bounded capacity eviction & worker pool error logging
7. Engine & API integration (batch size limit, diagnostic endpoints, storage logging resilience)
"""

import asyncio
import copy
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

# -----------------------------------------------------------------------------
# Module Setup & Path Resolution (matching project conventions)
# -----------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(ROOT_DIR) in ("src", "tests"):
    ROOT_DIR = os.path.abspath(os.path.join(ROOT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")

for p in (ROOT_DIR, SRC_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import src.schemas as schemas_module
    import src.chain_inspector as chain_inspector_module
    import src.semantic_evaluator as semantic_evaluator_module
    import src.task_worker as task_worker_module
    import src.engine as engine_module
    import src.api as api_module

    sys.modules.setdefault("schemas", schemas_module)
    sys.modules.setdefault("chain_inspector", chain_inspector_module)
    sys.modules.setdefault("semantic_evaluator", semantic_evaluator_module)
    sys.modules.setdefault("task_worker", task_worker_module)
    sys.modules.setdefault("engine", engine_module)
    sys.modules.setdefault("api", api_module)
except ImportError:
    import schemas as schemas_module
    import chain_inspector as chain_inspector_module
    import semantic_evaluator as semantic_evaluator_module
    import task_worker as task_worker_module
    import engine as engine_module
    import api as api_module

    sys.modules.setdefault("src.schemas", schemas_module)
    sys.modules.setdefault("src.chain_inspector", chain_inspector_module)
    sys.modules.setdefault("src.semantic_evaluator", semantic_evaluator_module)
    sys.modules.setdefault("src.task_worker", task_worker_module)
    sys.modules.setdefault("src.engine", engine_module)
    sys.modules.setdefault("src.api", api_module)

from schemas import (
    ChainId,
    DeterministicCondition,
    SemanticCondition,
    ConditionRulePayload,
    DeterministicResult,
    SemanticAuditResult,
    LLMAuditOutput,
    FinalAgentResponse,
    JobStatus,
)
from chain_inspector import ChainInspector
from semantic_evaluator import (
    MockSemanticEvaluator,
    OpenAISemanticEvaluator,
    GeminiSemanticEvaluator,
    get_semantic_evaluator,
)
from task_worker import (
    JobStore,
    JobRecord,
    AgentWorkerPool,
)
from engine import ConditionAgentEngine
from api import create_app


# Helper to dynamically import storage and report once created by implementation subagent
def get_storage_module():
    try:
        import src.storage as storage_mod
        sys.modules.setdefault("storage", storage_mod)
        return storage_mod
    except ImportError:
        import storage as storage_mod
        sys.modules.setdefault("src.storage", storage_mod)
        return storage_mod


def get_report_module():
    try:
        import src.report as report_mod
        sys.modules.setdefault("report", report_mod)
        return report_mod
    except ImportError:
        import report as report_mod
        sys.modules.setdefault("src.report", report_mod)
        return report_mod


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def clean_inspector_cache_and_env(monkeypatch):
    """Guarantees ChainInspector caches are wiped and strips real LLM API keys."""
    if hasattr(ChainInspector, "clear_cache"):
        ChainInspector.clear_cache()
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    yield
    if hasattr(ChainInspector, "clear_cache"):
        ChainInspector.clear_cache()


@pytest.fixture
def base_payload() -> ConditionRulePayload:
    return ConditionRulePayload(
        rule_id="b1-test-rule-001",
        chain_id=ChainId.BASE_SEPOLIA,
        deterministic=DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            min_value_wei=1000000000000000000,
            required_function_selectors=["0xf2fde38b"],
            check_native_balance=False,
        ),
        semantic=SemanticCondition(
            enabled=True,
            policy_prompt="Audit DAO administrative operations.",
            risk_threshold=7.0,
        ),
        context_metadata={
            "tx_value_wei": 2000000000000000000,
            "calldata": "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "proposal_description": "Administrative update for review.",
        },
    )


# =============================================================================
# 1. .gitignore and requirements.txt Tests
# =============================================================================
class TestSection1GitignoreAndRequirements:
    def test_gitignore_contains_required_b1_entries(self):
        """Contract 1: .gitignore must contain data/, *.db, and retain existing entries."""
        gitignore_path = Path(ROOT_DIR) / ".gitignore"
        assert gitignore_path.exists(), f".gitignore not found at {gitignore_path}"

        lines = [line.strip() for line in gitignore_path.read_text(encoding="utf-8").splitlines()]
        entries = set(line for line in lines if line and not line.startswith("#"))

        # Newly required entries
        for req in ["data/", "*.db"]:
            assert req in entries, f"Missing required .gitignore entry: {req}"

        # Existing entries preserved
        for existing in [".env", "__pycache__/", ".pytest_cache/"]:
            assert existing in entries, f"Existing entry was removed from .gitignore: {existing}"

    def test_requirements_contains_aiosqlite(self):
        """Contract 1: requirements.txt must include aiosqlite>=0.20.0 (or equivalent requirement)."""
        req_path = Path(ROOT_DIR) / "requirements.txt"
        assert req_path.exists(), f"requirements.txt not found at {req_path}"

        content = req_path.read_text(encoding="utf-8")
        aiosqlite_lines = [
            line.strip() for line in content.splitlines()
            if line.strip().startswith("aiosqlite")
        ]
        assert len(aiosqlite_lines) >= 1, "Missing aiosqlite entry in requirements.txt"
        assert "aiosqlite" in aiosqlite_lines[0]


# =============================================================================
# 2. Schemas Tests (SemanticAuditResult & LLMAuditOutput)
# =============================================================================
class TestSection2Schemas:
    def test_semantic_audit_result_telemetry_defaults(self):
        """Contract 2: SemanticAuditResult telemetry fields must have valid defaults for backward compatibility."""
        res = SemanticAuditResult(
            conditions_met=True,
            risk_score=5.5,
            summary="Moderate risk detected",
            recommended_action="MANUAL_REVIEW",
        )
        assert res.provider is None
        assert res.model is None
        assert res.input_tokens == 0
        assert res.output_tokens == 0
        assert res.estimated_cost_usd == 0.0
        assert res.latency_ms == 0.0

    def test_semantic_audit_result_telemetry_explicit_values(self):
        """Contract 2: SemanticAuditResult properly stores explicit telemetry fields."""
        res = SemanticAuditResult(
            conditions_met=False,
            risk_score=1.2,
            summary="Low risk",
            recommended_action="APPROVE",
            provider="openai",
            model="gpt-4o-mini",
            input_tokens=1500,
            output_tokens=250,
            estimated_cost_usd=0.000375,
            latency_ms=452.8,
        )
        assert res.provider == "openai"
        assert res.model == "gpt-4o-mini"
        assert res.input_tokens == 1500
        assert res.output_tokens == 250
        assert res.estimated_cost_usd == 0.000375
        assert res.latency_ms == 452.8

    def test_semantic_audit_result_telemetry_validation_constraints(self):
        """Contract 2: Negative tokens, costs, or latencies must violate ge=0 constraints."""
        with pytest.raises(ValidationError):
            SemanticAuditResult(
                conditions_met=True,
                risk_score=5.0,
                summary="Invalid",
                recommended_action="MANUAL_REVIEW",
                input_tokens=-1,
            )

        with pytest.raises(ValidationError):
            SemanticAuditResult(
                conditions_met=True,
                risk_score=5.0,
                summary="Invalid",
                recommended_action="MANUAL_REVIEW",
                output_tokens=-5,
            )

        with pytest.raises(ValidationError):
            SemanticAuditResult(
                conditions_met=True,
                risk_score=5.0,
                summary="Invalid",
                recommended_action="MANUAL_REVIEW",
                estimated_cost_usd=-0.01,
            )

        with pytest.raises(ValidationError):
            SemanticAuditResult(
                conditions_met=True,
                risk_score=5.0,
                summary="Invalid",
                recommended_action="MANUAL_REVIEW",
                latency_ms=-10.0,
            )

    def test_llm_audit_output_strictly_five_core_fields(self):
        """Contract 2: LLMAuditOutput must strictly have only the 5 core fields and no telemetry fields."""
        fields = set(LLMAuditOutput.model_fields.keys())
        expected = {
            "conditions_met",
            "risk_score",
            "flagged_issues",
            "summary",
            "recommended_action",
        }
        assert fields == expected, f"LLMAuditOutput has unexpected fields: {fields - expected}"


# =============================================================================
# 3. LLM Input Cap, Token Telemetry & Cost Estimation
# =============================================================================
class TestSection3InputCapAndCostEstimation:
    def test_default_llm_max_input_chars_constant(self):
        """Contract 3: Constant DEFAULT_LLM_MAX_INPUT_CHARS = 32000."""
        assert hasattr(semantic_evaluator_module, "DEFAULT_LLM_MAX_INPUT_CHARS")
        assert semantic_evaluator_module.DEFAULT_LLM_MAX_INPUT_CHARS == 32000

    def test_get_llm_max_input_chars_precedence(self, monkeypatch):
        """Contract 3: get_llm_max_input_chars precedence: override > env var > default."""
        fn = getattr(semantic_evaluator_module, "get_llm_max_input_chars")
        assert fn is not None

        # 1. Default when unset
        monkeypatch.delenv("LLM_MAX_INPUT_CHARS", raising=False)
        assert fn() == 32000

        # 2. Env override
        monkeypatch.setenv("LLM_MAX_INPUT_CHARS", "16000")
        assert fn() == 16000

        # 3. Explicit override beats env var
        assert fn(override=8000) == 8000

    def test_pricing_table_structure(self):
        """Contract 3: MODEL_PRICING_PER_1M and DEFAULT_PRICING_PER_1M exist and contain required entries."""
        pricing = getattr(semantic_evaluator_module, "MODEL_PRICING_PER_1M")
        default_pricing = getattr(semantic_evaluator_module, "DEFAULT_PRICING_PER_1M")

        assert isinstance(pricing, dict)
        assert default_pricing == (0.30, 1.20)

        required_models = [
            "gemini-2.0-flash",
            "gemini-2.5-flash",
            "gemini-1.5-flash",
            "gpt-4o-mini",
            "gpt-4o",
            "mock",
        ]
        for m in required_models:
            assert m in pricing, f"Missing model in MODEL_PRICING_PER_1M: {m}"
            assert isinstance(pricing[m], tuple) and len(pricing[m]) == 2

    def test_estimate_llm_cost_usd_zero_and_mock(self):
        """Contract 3: estimate_llm_cost_usd returns 0.0 for None model, mock, and zero/negative tokens."""
        fn = getattr(semantic_evaluator_module, "estimate_llm_cost_usd")

        assert fn(None, 1000, 500) == 0.0
        assert fn("mock", 1000, 500) == 0.0
        assert fn("MOCK", 1000, 500) == 0.0
        assert fn("gpt-4o", 0, 0) == 0.0
        assert fn("gpt-4o", -10, -5) == 0.0

    def test_estimate_llm_cost_usd_exact_and_prefix_models(self):
        """Contract 3: Cost calculation exact matching and prefix matching."""
        fn = getattr(semantic_evaluator_module, "estimate_llm_cost_usd")

        # gpt-4o-mini: in 0.15 / 1M, out 0.60 / 1M
        # 10_000 in, 2_000 out => 10_000 * 0.15 / 1e6 + 2_000 * 0.60 / 1e6 = 0.0015 + 0.0012 = 0.0027
        cost_mini = fn("gpt-4o-mini", 10000, 2000)
        assert cost_mini == 0.0027

        # Prefix matching: gpt-4o-mini-2024-07-18
        cost_mini_dated = fn("gpt-4o-mini-2024-07-18", 10000, 2000)
        assert cost_mini_dated == 0.0027

        # gpt-4o: in 2.50 / 1M, out 10.00 / 1M
        cost_4o = fn("gpt-4o", 10000, 1000)
        # 10000 * 2.50 / 1e6 + 1000 * 10.00 / 1e6 = 0.025 + 0.01 = 0.035
        assert cost_4o == 0.035

        # Prefix matching: gpt-4o-2024-05-13
        assert fn("gpt-4o-2024-05-13", 10000, 1000) == 0.035

        # gemini-2.0-flash prefix matching
        cost_gemini = fn("gemini-2.0-flash-exp", 100000, 50000)
        # in 0.10, out 0.40 => 0.01 + 0.02 = 0.03
        assert cost_gemini == 0.03

        # Default fallback for unknown model (0.30 in, 1.20 out)
        cost_unknown = fn("claude-3-opus", 100000, 50000)
        # 100k * 0.30 / 1e6 + 50k * 1.20 / 1e6 = 0.03 + 0.06 = 0.09
        assert cost_unknown == 0.09

    def test_prepare_bounded_context_non_mutation_and_truncation(self):
        """Contract 3: prepare_bounded_context must never mutate input dict and must truncate over-limit data."""
        fn = getattr(semantic_evaluator_module, "prepare_bounded_context")

        # 1. Below limit
        small_ctx = {"key": "small value", "nums": [1, 2, 3]}
        small_copy = copy.deepcopy(small_ctx)
        bounded, was_truncated = fn(small_ctx, max_chars=1000)
        assert was_truncated is False
        assert bounded == small_copy
        assert small_ctx == small_copy

        # 2. Above limit
        large_ctx = {
            "title": "DAO Proposal",
            "body": "A" * 50000,
            "extra": {"nested": "B" * 10000},
        }
        large_copy = copy.deepcopy(large_ctx)
        bounded, was_truncated = fn(large_ctx, max_chars=500)

        # Non-mutation assertion
        assert large_ctx == large_copy
        assert len(large_ctx["body"]) == 50000
        assert was_truncated is True

        # Truncation marker check
        serialized_bounded = json.dumps(bounded, default=str)
        assert "[TRUNCATED]" in serialized_bounded
        assert len(serialized_bounded) <= 1200  # reasonably close to limit

    @pytest.mark.asyncio
    async def test_mock_evaluator_telemetry_and_truncation_flag(self):
        """Contract 3: MockSemanticEvaluator populates telemetry and flags truncation when exceeding limit."""
        evaluator = MockSemanticEvaluator(max_input_chars=300)
        cond = SemanticCondition(policy_prompt="Test policy", risk_threshold=7.0)
        observed = {"contract_has_code": True}

        # 1. Normal context below limit
        res_normal = await evaluator.evaluate(cond, observed, {"msg": "short"})
        assert res_normal.provider == "mock"
        assert res_normal.model == "mock"
        assert res_normal.input_tokens == 0
        assert res_normal.output_tokens == 0
        assert res_normal.estimated_cost_usd == 0.0
        assert res_normal.latency_ms >= 0.0
        assert not any("truncated" in issue.lower() for issue in res_normal.flagged_issues)

        # 2. Large context above limit
        res_truncated = await evaluator.evaluate(cond, observed, {"large_payload": "X" * 1000})
        truncation_flag = "Context metadata truncated due to LLM_MAX_INPUT_CHARS limit"
        assert any(truncation_flag in issue for issue in res_truncated.flagged_issues)

    @pytest.mark.asyncio
    async def test_openai_evaluator_usage_extraction_and_telemetry(self, monkeypatch):
        """Contract 3: OpenAISemanticEvaluator extracts usage tokens, computes cost, and flags truncation."""
        mock_response = MagicMock()
        parsed_out = LLMAuditOutput(
            conditions_met=False,
            risk_score=2.0,
            flagged_issues=[],
            summary="Audited cleanly",
            recommended_action="APPROVE",
        )
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    parsed=parsed_out,
                    content=parsed_out.model_dump_json(),
                )
            )
        ]
        # Usage with real ints
        mock_response.usage = MagicMock(prompt_tokens=1500, completion_tokens=250)

        mock_client = MagicMock()
        mock_client.beta.chat.completions.parse = AsyncMock(return_value=mock_response)
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        evaluator = OpenAISemanticEvaluator(api_key="mock-key", model="gpt-4o-mini", max_input_chars=200)
        evaluator.client = mock_client

        cond = SemanticCondition(policy_prompt="Policy test", risk_threshold=7.0)
        observed = {"contract_has_code": True}
        meta = {"giant_field": "Z" * 500}

        res = await evaluator.evaluate(cond, observed, meta)

        assert res.provider == "openai"
        assert res.model == "gpt-4o-mini"
        assert res.input_tokens == 1500
        assert res.output_tokens == 250
        assert res.estimated_cost_usd > 0.0
        assert res.latency_ms >= 0.0
        # Truncation issue appended
        truncation_flag = "Context metadata truncated due to LLM_MAX_INPUT_CHARS limit"
        assert any(truncation_flag in issue for issue in res.flagged_issues)

    @pytest.mark.asyncio
    async def test_openai_evaluator_usage_none_or_magicmock_guard(self):
        """Contract 3: OpenAISemanticEvaluator guards against usage=None or MagicMock non-int attributes."""
        mock_response = MagicMock()
        parsed_out = LLMAuditOutput(
            conditions_met=False,
            risk_score=1.0,
            flagged_issues=[],
            summary="Safe",
            recommended_action="APPROVE",
        )
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    parsed=parsed_out,
                    content=parsed_out.model_dump_json(),
                )
            )
        ]
        # Usage is None
        mock_response.usage = None

        mock_client = MagicMock()
        mock_client.beta.chat.completions.parse = AsyncMock(return_value=mock_response)
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        evaluator = OpenAISemanticEvaluator(api_key="mock-key", model="gpt-4o-mini")
        evaluator.client = mock_client

        cond = SemanticCondition(policy_prompt="Policy", risk_threshold=7.0)
        res = await evaluator.evaluate(cond, {}, {})

        assert res.input_tokens == 0
        assert res.output_tokens == 0
        assert res.estimated_cost_usd == 0.0

    @pytest.mark.asyncio
    async def test_openai_evaluator_cache_hit_sets_zero_cost(self):
        """Contract 3: Semantic cache hit on OpenAISemanticEvaluator sets estimated_cost_usd=0.0 and tokens=0."""
        mock_response = MagicMock()
        parsed_out = LLMAuditOutput(
            conditions_met=False,
            risk_score=1.0,
            flagged_issues=[],
            summary="Safe",
            recommended_action="APPROVE",
        )
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    parsed=parsed_out,
                    content=parsed_out.model_dump_json(),
                )
            )
        ]
        mock_response.usage = MagicMock(prompt_tokens=1000, completion_tokens=100)

        mock_client = MagicMock()
        mock_client.beta.chat.completions.parse = AsyncMock(return_value=mock_response)
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        evaluator = OpenAISemanticEvaluator(api_key="mock-key", model="gpt-4o-mini")
        evaluator.client = mock_client

        cond = SemanticCondition(policy_prompt="Deterministic Policy", risk_threshold=7.0)
        observed = {"contract_has_code": True}
        meta = {"proposal_id": 42}

        # 1st call: cache miss
        res1 = await evaluator.evaluate(cond, observed, meta)
        assert res1.cached is False
        assert res1.estimated_cost_usd > 0.0

        # 2nd call: cache hit
        res2 = await evaluator.evaluate(cond, observed, meta)
        assert res2.cached is True
        assert res2.estimated_cost_usd == 0.0
        assert res2.input_tokens == 0
        assert res2.output_tokens == 0

    @pytest.mark.asyncio
    async def test_gemini_evaluator_usage_metadata_extraction_and_cache(self):
        """Contract 3: GeminiSemanticEvaluator extracts usage_metadata, computes cost, handles cache hit & truncation."""
        parsed_out = LLMAuditOutput(
            conditions_met=False,
            risk_score=2.5,
            flagged_issues=[],
            summary="Gemini verified",
            recommended_action="APPROVE",
        )
        mock_response = MagicMock()
        mock_response.parsed = parsed_out
        mock_response.text = parsed_out.model_dump_json()
        mock_response.usage_metadata = MagicMock(prompt_token_count=800, candidates_token_count=150)

        mock_client = MagicMock()
        mock_client.aio = MagicMock()
        mock_client.aio.models = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)

        evaluator = GeminiSemanticEvaluator(api_key="mock-gemini-key", model="gemini-2.0-flash", max_input_chars=150)
        evaluator.client = mock_client

        cond = SemanticCondition(policy_prompt="Gemini Policy", risk_threshold=7.0)
        observed = {"chain_id": 84532}
        meta = {"data": "W" * 400}

        # 1st call (triggers truncation flag and token extraction)
        res1 = await evaluator.evaluate(cond, observed, meta)
        assert res1.provider == "gemini"
        assert res1.input_tokens == 800
        assert res1.output_tokens == 150
        assert res1.estimated_cost_usd > 0.0
        truncation_flag = "Context metadata truncated due to LLM_MAX_INPUT_CHARS limit"
        assert any(truncation_flag in issue for issue in res1.flagged_issues)

        # 2nd call (cache hit)
        res2 = await evaluator.evaluate(cond, observed, meta)
        assert res2.cached is True
        assert res2.estimated_cost_usd == 0.0
        assert res2.input_tokens == 0
        assert res2.output_tokens == 0


# =============================================================================
# 4. SQLite Storage (AgentStorage) & Error Logging
# =============================================================================
class TestSection4StorageAndErrorLog:
    def test_redact_secrets_comprehensive(self):
        """Contract 4: redact_secrets scrubs sensitive keys and API tokens while preserving token metrics."""
        storage_mod = get_storage_module()
        redact = storage_mod.redact_secrets

        data = {
            "api_key": "sensitive-api-key-12345",
            "secret_token": "shhh-secret",
            "password": "my-secret-password",
            "nested": {
                "private_key": "0xabcdef1234567890",
                "authorization": "Bearer xyz",
            },
            # Must PRESERVE these token metrics:
            "input_tokens": 1200,
            "output_tokens": 300,
            "prompt_tokens": 1200,
            "completion_tokens": 300,
            "candidates_token_count": 300,
            "prompt_token_count": 1200,
            # String values containing keys:
            "raw_log": "Failed on Google AIzaSyD12345678901234567890 and OpenAI sk-abc1234567890def123456",
            "clean_value": "harmless data",
        }

        redacted = redact(data)

        # Redacted keys
        assert redacted["api_key"] == "***REDACTED***"
        assert redacted["secret_token"] == "***REDACTED***"
        assert redacted["password"] == "***REDACTED***"
        assert redacted["nested"]["private_key"] == "***REDACTED***"
        assert redacted["nested"]["authorization"] == "***REDACTED***"

        # Preserved token count keys
        assert redacted["input_tokens"] == 1200
        assert redacted["output_tokens"] == 300
        assert redacted["prompt_tokens"] == 1200
        assert redacted["completion_tokens"] == 300
        assert redacted["candidates_token_count"] == 300
        assert redacted["prompt_token_count"] == 1200

        # Pattern redaction inside string values
        assert "AIzaSy" not in redacted["raw_log"]
        assert "sk-abc" not in redacted["raw_log"]
        assert "***REDACTED***" in redacted["raw_log"]

        # Clean value untouched
        assert redacted["clean_value"] == "harmless data"

    @pytest.mark.asyncio
    async def test_storage_initialization_and_table_creation(self, tmp_path):
        """Contract 4: AgentStorage initializes SQLite file and creates evaluations and error_log tables."""
        storage_mod = get_storage_module()
        db_file = tmp_path / "test_storage.db"
        storage = storage_mod.AgentStorage(db_path=str(db_file))

        await storage.initialize()
        assert db_file.exists()

        import aiosqlite
        async with aiosqlite.connect(str(db_file)) as db:
            async with db.execute("SELECT name FROM sqlite_master WHERE type='table';") as cursor:
                rows = await cursor.fetchall()
                tables = {r[0] for r in rows}
                assert "evaluations" in tables
                assert "error_log" in tables

    @pytest.mark.asyncio
    async def test_storage_record_evaluation_stage1_halted(self, tmp_path, base_payload):
        """Contract 4: Record evaluation where Stage 1 halted (llm_invoked=0, decision=None)."""
        storage_mod = get_storage_module()
        db_file = tmp_path / "test_eval_halted.db"
        storage = storage_mod.AgentStorage(db_path=str(db_file))

        resp = FinalAgentResponse(
            rule_id=base_payload.rule_id,
            chain_id=84532,
            deterministic_check=DeterministicResult(
                passed=False,
                reason="Value too low",
                observed_data={"tx_value_wei": 0},
            ),
            llm_invoked=False,
            semantic_Evaluation=None,
        )

        row_id = await storage.record_evaluation(base_payload, resp, source="engine", latency_ms=15.2)
        assert row_id is not None

        evals = await storage.get_evaluations(limit=10)
        assert len(evals) == 1
        rec = evals[0]
        assert rec["rule_id"] == base_payload.rule_id
        assert rec["stage1_passed"] == 0
        assert rec["llm_invoked"] == 0
        assert rec["decision"] is None
        assert rec["status"] == "ok"
        assert rec["est_cost_usd"] == 0.0

    @pytest.mark.asyncio
    async def test_storage_record_evaluation_stage2_executed(self, tmp_path, base_payload):
        """Contract 4: Record evaluation where Stage 2 ran (llm_invoked=1, decision stored)."""
        storage_mod = get_storage_module()
        db_file = tmp_path / "test_eval_llm.db"
        storage = storage_mod.AgentStorage(db_path=str(db_file))

        resp = FinalAgentResponse(
            rule_id=base_payload.rule_id,
            chain_id=84532,
            deterministic_check=DeterministicResult(
                passed=True,
                reason="Conditions matched",
                observed_data={"tx_value_wei": 2000000000000000000},
            ),
            llm_invoked=True,
            semantic_Evaluation=SemanticAuditResult(
                conditions_met=True,
                risk_score=8.5,
                summary="High risk detected",
                recommended_action="REJECT",
                provider="openai",
                model="gpt-4o",
                input_tokens=2000,
                output_tokens=400,
                estimated_cost_usd=0.009,
                latency_ms=620.0,
            ),
        )

        row_id = await storage.record_evaluation(base_payload, resp, source="api", job_id="job-123")
        assert row_id is not None

        evals = await storage.get_evaluations(limit=10, rule_id=base_payload.rule_id)
        assert len(evals) == 1
        rec = evals[0]
        assert rec["stage1_passed"] == 1
        assert rec["llm_invoked"] == 1
        assert rec["decision"] == "REJECT"
        assert rec["provider"] == "openai"
        assert rec["model"] == "gpt-4o"
        assert rec["input_tokens"] == 2000
        assert rec["output_tokens"] == 400
        assert rec["est_cost_usd"] == 0.009
        assert rec["job_id"] == "job-123"

    @pytest.mark.asyncio
    async def test_storage_log_error_across_stages_and_redaction(self, tmp_path):
        """Contract 4: log_error logs across required stages and redacts secrets in context/message."""
        storage_mod = get_storage_module()
        db_file = tmp_path / "test_error_log.db"
        storage = storage_mod.AgentStorage(db_path=str(db_file))

        stages = ["validation", "stage1_rpc", "stage2_llm", "worker", "api", "storage"]
        for st in stages:
            row_id = await storage.log_error(
                stage=st,
                error_type="TestError",
                message=f"Error in {st} with sk-test1234567890abcdef",
                rule_id="rule-err",
                context={"api_key": "secret123", "input_tokens": 50},
            )
            assert row_id is not None

        errors = await storage.get_errors(limit=20)
        assert len(errors) == len(stages)

        for err in errors:
            assert "sk-test" not in err["message"]
            assert "***REDACTED***" in err["message"]
            if err["context_json"]:
                ctx = json.loads(err["context_json"])
                assert ctx["api_key"] == "***REDACTED***"
                assert ctx["input_tokens"] == 50

    @pytest.mark.asyncio
    async def test_storage_get_summary_metrics_populated(self, tmp_path, base_payload):
        """Contract 4: get_summary_metrics computes correct filter rate, costs, percentiles, and errors."""
        storage_mod = get_storage_module()
        db_file = tmp_path / "test_summary.db"
        storage = storage_mod.AgentStorage(db_path=str(db_file))

        # Add 3 Stage 1 halted evaluations (cost 0.0)
        for i in range(3):
            resp_halt = FinalAgentResponse(
                rule_id=f"rule-{i}",
                chain_id=84532,
                deterministic_check=DeterministicResult(passed=False, reason="Halt"),
                llm_invoked=False,
                semantic_Evaluation=None,
            )
            await storage.record_evaluation(base_payload, resp_halt)

        # Add 1 Stage 2 executed evaluation (cost 0.005)
        resp_exec = FinalAgentResponse(
            rule_id="rule-llm",
            chain_id=84532,
            deterministic_check=DeterministicResult(passed=True, reason="Pass"),
            llm_invoked=True,
            semantic_Evaluation=SemanticAuditResult(
                conditions_met=False,
                risk_score=2.0,
                summary="Ok",
                recommended_action="APPROVE",
                input_tokens=1000,
                output_tokens=200,
                estimated_cost_usd=0.005,
            ),
        )
        await storage.record_evaluation(base_payload, resp_exec)

        # Log 2 errors (1 stage1_rpc, 1 worker)
        await storage.log_error("stage1_rpc", "RPCError", "Timeout")
        await storage.log_error("worker", "WorkerError", "Worker crashed")

        metrics = await storage.get_summary_metrics(target_price_usd=0.01)

        assert metrics["total_evaluations"] == 4
        assert metrics["stage1_halted_count"] == 3
        # Check filter rate key (support both case variations defensively)
        filter_rate = metrics.get("stage1_Filter_rate_pct")
        if filter_rate is None:
            filter_rate = metrics.get("stage1_filter_rate_pct")
        assert filter_rate == 75.0
        assert metrics["llm_invoked_count"] == 1
        assert metrics["total_cost_usd"] == 0.005
        assert metrics["avg_cost_per_eval_usd"] == 0.00125
        assert metrics["avg_cost_per_llm_call_usd"] == 0.005
        assert metrics["max_cost_usd"] == 0.005
        assert metrics["target_price_usd"] == 0.01
        assert metrics["price_covers_max_cost"] is True
        assert metrics["total_errors"] == 2
        assert metrics["errors_by_stage"]["stage1_rpc"] == 1
        assert metrics["errors_by_stage"]["worker"] == 1

    @pytest.mark.asyncio
    async def test_storage_get_summary_metrics_empty_db(self, tmp_path):
        """Contract 4: get_summary_metrics handles empty database without division by zero errors."""
        storage_mod = get_storage_module()
        db_file = tmp_path / "test_empty_summary.db"
        storage = storage_mod.AgentStorage(db_path=str(db_file))

        metrics = await storage.get_summary_metrics(target_price_usd=0.01)

        assert metrics["total_evaluations"] == 0
        assert metrics["total_cost_usd"] == 0.0
        assert metrics["avg_cost_per_eval_usd"] == 0.0
        assert metrics["price_covers_max_cost"] is True
        assert metrics["total_errors"] == 0

    @pytest.mark.asyncio
    async def test_storage_resilience_unwritable_path(self, base_payload):
        """Contract 4: AgentStorage never raises on invalid or unwritable paths; returns None gracefully."""
        storage_mod = get_storage_module()
        # Non-writable / impossible path on Windows
        bad_storage = storage_mod.AgentStorage(db_path="Z:\\impossible_path_not_existing\\agent.db")

        resp = FinalAgentResponse(
            rule_id=base_payload.rule_id,
            chain_id=84532,
            deterministic_check=DeterministicResult(passed=False, reason="Halt"),
            llm_invoked=False,
            semantic_Evaluation=None,
        )

        eval_res = await bad_storage.record_evaluation(base_payload, resp)
        assert eval_res is None

        err_res = await bad_storage.log_error("validation", "BadPathError", "Disk inaccessible")
        assert err_res is None


# =============================================================================
# 5. Reporting CLI (src/report.py)
# =============================================================================
class TestSection5ReportingCli:
    @pytest.mark.asyncio
    async def test_generate_report_and_format_report_text(self, tmp_path, base_payload):
        """Contract 5: generate_report and format_report_text generate clean summary on populated DB."""
        storage_mod = get_storage_module()
        report_mod = get_report_module()

        db_file = tmp_path / "test_report.db"
        storage = storage_mod.AgentStorage(db_path=str(db_file))

        # Seed data
        resp = FinalAgentResponse(
            rule_id=base_payload.rule_id,
            chain_id=84532,
            deterministic_check=DeterministicResult(passed=False, reason="Halt"),
            llm_invoked=False,
            semantic_Evaluation=None,
        )
        await storage.record_evaluation(base_payload, resp)
        await storage.log_error("stage1_rpc", "Timeout", "RPC timeout")

        metrics = await report_mod.generate_report(db_path=str(db_file), target_price_usd=0.05)
        assert metrics["total_evaluations"] == 1

        text = report_mod.format_report_text(metrics)
        assert isinstance(text, str)
        assert "Total Evaluations: 1" in text or "1" in text
        assert "stage1_rpc" in text or "Stage 1" in text

    def test_format_report_text_empty_metrics(self):
        """Contract 5: format_report_text handles empty metrics dictionary gracefully."""
        report_mod = get_report_module()
        empty_metrics = {
            "total_evaluations": 0,
            "stage1_halted_count": 0,
            "stage1_Filter_rate_pct": 0.0,
            "llm_invoked_count": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost_usd": 0.0,
            "avg_cost_per_eval_usd": 0.0,
            "avg_cost_per_llm_call_usd": 0.0,
            "max_cost_usd": 0.0,
            "p95_cost_usd": 0.0,
            "target_price_usd": 0.01,
            "price_covers_max_cost": True,
            "errors_by_stage": {},
            "total_errors": 0,
        }
        text = report_mod.format_report_text(empty_metrics)
        assert isinstance(text, str)
        assert len(text) > 20


# =============================================================================
# 6. JobStore TTL & Bounded Capacity Eviction & Worker Pool Error Logging
# =============================================================================
class TestSection6JobStoreTTLAndBoundedCapacity:
    def test_jobstore_default_constants(self):
        """Contract 6: Constants DEFAULT_JOB_TTL_SECONDS = 3600 and DEFAULT_MAX_JOBS = 10000."""
        assert hasattr(task_worker_module, "DEFAULT_JOB_TTL_SECONDS")
        assert hasattr(task_worker_module, "DEFAULT_MAX_JOBS")
        assert task_worker_module.DEFAULT_JOB_TTL_SECONDS == 3600
        assert task_worker_module.DEFAULT_MAX_JOBS == 10000

    def test_jobstore_init_args_and_env(self, monkeypatch):
        """Contract 6: JobStore respects constructor args and environment overrides."""
        # 1. Defaults
        store_default = JobStore()
        assert store_default.ttl_seconds == 3600.0
        assert store_default.max_jobs == 10000

        # 2. Env overrides
        monkeypatch.setenv("JOB_TTL_SECONDS", "7200")
        monkeypatch.setenv("JOB_MAX_COUNT", "500")
        store_env = JobStore()
        assert store_env.ttl_seconds == 7200.0
        assert store_env.max_jobs == 500

        # 3. Explicit args override env
        store_explicit = JobStore(ttl_seconds=120.0, max_jobs=50)
        assert store_explicit.ttl_seconds == 120.0
        assert store_explicit.max_jobs == 50

    def test_jobstore_ttl_cleanup_evicts_terminal_jobs_only(self, base_payload):
        """Contract 6: cleanup_expired evicts terminal jobs older than ttl_seconds, keeping active jobs."""
        store = JobStore(ttl_seconds=10.0, max_jobs=100)

        # Create jobs
        j1 = store.create_job(base_payload, job_id="job-completed")
        j2 = store.create_job(base_payload, job_id="job-failed")
        j3 = store.create_job(base_payload, job_id="job-queued")
        j4 = store.create_job(base_payload, job_id="job-processing")

        store.update_job("job-completed", status=JobStatus.COMPLETED)
        store.update_job("job-failed", status=JobStatus.FAILED)
        store.update_job("job-processing", status=JobStatus.PROCESSING)

        # Backdate timestamps in store._job_updated_at and store._job_created_at
        for jid in ["job-completed", "job-failed", "job-queued", "job-processing"]:
            store._job_updated_at[jid] = time.time() - 50.0
            store._job_created_at[jid] = time.time() - 50.0

        evicted = store.cleanup_expired()
        assert evicted >= 2

        # Terminal jobs evicted
        assert store.get_job("job-completed") is None
        assert store.get_job("job-failed") is None

        # Active jobs retained!
        assert store.get_job("job-queued") is not None
        assert store.get_job("job-processing") is not None

    def test_jobstore_capacity_eviction_prefers_terminal_jobs(self, base_payload):
        """Contract 6: When max_jobs exceeded, evicts oldest terminal job first before active jobs."""
        store = JobStore(ttl_seconds=3600.0, max_jobs=3)

        # Fill capacity with 1 terminal and 2 active jobs
        j1 = store.create_job(base_payload, job_id="term-1")
        time.sleep(0.01)
        j2 = store.create_job(base_payload, job_id="active-2")
        time.sleep(0.01)
        j3 = store.create_job(base_payload, job_id="active-3")

        store.update_job("term-1", status=JobStatus.COMPLETED)
        store.update_job("active-2", status=JobStatus.PROCESSING)
        # active-3 remains QUEUED

        # Add 4th job -> triggers eviction
        j4 = store.create_job(base_payload, job_id="new-4")

        # Oldest terminal job (term-1) should be evicted
        assert store.get_job("term-1") is None
        # Active jobs must NOT be evicted while terminal jobs exist
        assert store.get_job("active-2") is not None
        assert store.get_job("active-3") is not None
        assert store.get_job("new-4") is not None

    def test_jobstore_capacity_eviction_fifo_fallback(self, base_payload):
        """Contract 6: When max_jobs exceeded and NO terminal jobs exist, evicts FIFO (oldest active)."""
        store = JobStore(ttl_seconds=3600.0, max_jobs=2)

        j1 = store.create_job(base_payload, job_id="queued-1")
        time.sleep(0.01)
        j2 = store.create_job(base_payload, job_id="queued-2")

        # Both jobs are active QUEUED. Add 3rd job
        j3 = store.create_job(base_payload, job_id="queued-3")

        # FIFO eviction: queued-1 evicted
        assert store.get_job("queued-1") is None
        assert store.get_job("queued-2") is not None
        assert store.get_job("queued-3") is not None

    @pytest.mark.asyncio
    async def test_worker_pool_logs_worker_stage_error_to_storage(self, base_payload):
        """Contract 6: AgentWorkerPool logs 'worker' stage error to storage when job execution fails."""
        mock_storage = AsyncMock()
        mock_engine = MagicMock()
        mock_engine.process_rule = AsyncMock(side_effect=RuntimeError("Engine exploded"))

        pool = AgentWorkerPool(
            engine=mock_engine,
            storage=mock_storage,
            num_workers=1,
        )

        pool.start()
        try:
            job_id = pool.enqueue(base_payload)

            # Wait for worker loop to pick up and process job
            j = None
            for _ in range(50):
                j = pool.get_job(job_id)
                if j and j.status == JobStatus.FAILED:
                    break
                await asyncio.sleep(0.05)

            assert j is not None
            assert j.status == JobStatus.FAILED
            assert "Engine exploded" in (j.error or "")

            # Verify storage error logging
            mock_storage.log_error.assert_awaited()
            call_kwargs = mock_storage.log_error.await_args.kwargs
            assert call_kwargs.get("stage") == "worker"
            assert call_kwargs.get("error_type") == "RuntimeError"
            assert "Engine exploded" in call_kwargs.get("message")
            assert call_kwargs.get("job_id") == job_id
        finally:
            await pool.shutdown()


# =============================================================================
# 7. Engine & API Wiring
# =============================================================================
class TestSection7EngineAndApiWiring:
    @pytest.mark.asyncio
    async def test_engine_records_evaluation_to_injected_storage(self, base_payload):
        """Contract 7: ConditionAgentEngine calls storage.record_evaluation upon processing a rule."""
        mock_storage = AsyncMock()
        mock_evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(
            storage=mock_storage,
            semantic_evaluator=mock_evaluator,
        )

        with patch.object(
            ChainInspector,
            "evaluate_deterministic",
            AsyncMock(
                return_value=DeterministicResult(
                    passed=False,
                    reason="Halt for test",
                    observed_data={},
                )
            ),
        ):
            resp = await engine.process_rule(base_payload, source="test-source", job_id="test-job-42")

        assert resp.rule_id == base_payload.rule_id
        mock_storage.record_evaluation.assert_awaited_once()
        kwargs = mock_storage.record_evaluation.await_args.kwargs
        assert kwargs["source"] == "test-source"
        assert kwargs["job_id"] == "test-job-42"
        assert "latency_ms" in kwargs

    @pytest.mark.asyncio
    async def test_engine_logs_stage1_rpc_error_to_storage(self, base_payload):
        """Contract 7: ConditionAgentEngine logs to storage with stage='stage1_rpc' when RPC check fails."""
        mock_storage = AsyncMock()
        engine = ConditionAgentEngine(storage=mock_storage, semantic_evaluator=MockSemanticEvaluator())

        with patch.object(
            ChainInspector,
            "evaluate_deterministic",
            AsyncMock(
                return_value=DeterministicResult(
                    passed=False,
                    reason="RPC error occurred",
                    observed_data={"detail": "fail"},
                    error="RPC Connection Refused",
                )
            ),
        ):
            await engine.process_rule(base_payload, job_id="rpc-fail-job")

        # Verify storage.log_error called for stage1_rpc
        found_rpc_log = False
        for call in mock_storage.log_error.await_args_list:
            if call.kwargs.get("stage") == "stage1_rpc":
                found_rpc_log = True
                assert call.kwargs.get("error_type") == "RPCError"
                assert "RPC Connection Refused" in call.kwargs.get("message")
                assert call.kwargs.get("job_id") == "rpc-fail-job"
        assert found_rpc_log, "stage1_rpc error was not logged to storage"

    @pytest.mark.asyncio
    async def test_engine_logs_stage2_llm_fallback_error_to_storage(self, base_payload):
        """Contract 7: ConditionAgentEngine logs to storage with stage='stage2_llm' when LLM fallback triggers."""
        mock_storage = AsyncMock()
        mock_eval = MagicMock()
        mock_eval.evaluate = AsyncMock(
            return_value=SemanticAuditResult(
                conditions_met=True,
                risk_score=9.0,
                flagged_issues=["LLM provider failure: Timeout after 3 retries"],
                summary="Fallback triggered",
                recommended_action="REJECT",
            )
        )

        engine = ConditionAgentEngine(storage=mock_storage, semantic_evaluator=mock_eval)

        with patch.object(
            ChainInspector,
            "evaluate_deterministic",
            AsyncMock(
                return_value=DeterministicResult(
                    passed=True,
                    reason="Deterministic conditions matched",
                    observed_data={"tx_value_wei": 2000000000000000000},
                )
            ),
        ):
            await engine.process_rule(base_payload, job_id="llm-fallback-job")

        found_llm_log = False
        for call in mock_storage.log_error.await_args_list:
            if call.kwargs.get("stage") == "stage2_llm":
                found_llm_log = True
                assert call.kwargs.get("error_type") == "LLMFallbackError"
                assert "LLM provider failure" in call.kwargs.get("message")
        assert found_llm_log, "stage2_llm error was not logged to storage"

    def test_api_batch_size_limit_422(self, base_payload):
        """Contract 7: POST /rules/evaluate-batch returns HTTP 422 when exceeding BATCH_MAX_ITEMS."""
        app = create_app()
        client = TestClient(app)

        batch_limit = getattr(api_module, "DEFAULT_BATCH_MAX_ITEMS", 50)
        oversized_batch = [base_payload.model_dump(mode="json") for _ in range(batch_limit + 1)]

        resp = client.post("/rules/evaluate-batch", json=oversized_batch)
        assert resp.status_code == 422
        data = resp.json()
        assert "Batch size" in data.get("message", "") or "exceeds maximum allowed" in data.get("message", "") or "BatchSizeLimitExceeded" in str(data)

    def test_api_batch_max_items_env_override(self, monkeypatch, base_payload):
        """Contract 7: BATCH_MAX_ITEMS environment variable overrides default limit."""
        monkeypatch.setenv("BATCH_MAX_ITEMS", "3")
        get_limit_fn = getattr(api_module, "get_batch_max_items")
        assert get_limit_fn() == 3

        app = create_app()
        client = TestClient(app)

        oversized = [base_payload.model_dump(mode="json") for _ in range(4)]
        resp = client.post("/rules/evaluate-batch", json=oversized)
        assert resp.status_code == 422

    def test_api_validation_error_logged_to_storage(self):
        """Contract 7: Invalid requests triggering 422 log an error with stage='validation'."""
        mock_storage = AsyncMock()
        app = create_app(storage=mock_storage)
        client = TestClient(app)

        # Send invalid JSON to /evaluate
        resp = client.post("/evaluate", json={"invalid": "payload"})
        assert resp.status_code == 422

        # Check validation error was logged
        found_val_err = False
        for call in mock_storage.log_error.await_args_list:
            if call.kwargs.get("stage") == "validation":
                found_val_err = True
        assert found_val_err, "Validation error was not logged to storage"

    def test_api_metrics_summary_endpoint(self):
        """Contract 7: GET /metrics/summary returns expected summary metrics JSON."""
        mock_storage = AsyncMock()
        mock_storage.get_summary_metrics.return_value = {
            "total_evaluations": 10,
            "stage1_halted_count": 8,
            "stage1_Filter_rate_pct": 80.0,
            "llm_invoked_count": 2,
            "total_input_tokens": 5000,
            "total_output_tokens": 1000,
            "total_cost_usd": 0.015,
            "avg_cost_per_eval_usd": 0.0015,
            "avg_cost_per_llm_call_usd": 0.0075,
            "max_cost_usd": 0.01,
            "p95_cost_usd": 0.009,
            "target_price_usd": 0.01,
            "price_covers_max_cost": False,
            "errors_by_stage": {"stage1_rpc": 1},
            "total_errors": 1,
        }

        app = create_app(storage=mock_storage)
        client = TestClient(app)

        resp = client.get("/metrics/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_evaluations"] == 10
        assert data["total_errors"] == 1

    def test_api_logs_errors_endpoint(self):
        """Contract 7: GET /logs/errors returns error logs with query filtering."""
        mock_storage = AsyncMock()
        mock_storage.get_errors.return_value = [
            {"id": 1, "stage": "stage1_rpc", "error_type": "Timeout", "message": "Timed out"}
        ]

        app = create_app(storage=mock_storage)
        client = TestClient(app)

        resp = client.get("/logs/errors?limit=10&stage=stage1_rpc")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["stage"] == "stage1_rpc"
        mock_storage.get_errors.assert_awaited_with(limit=10, stage="stage1_rpc")

    def test_api_evaluate_resilient_to_storage_failure(self, base_payload):
        """Contract 7: POST /evaluate succeeds even if storage.record_evaluation fails."""
        mock_storage = AsyncMock()
        mock_storage.record_evaluation = AsyncMock(side_effect=RuntimeError("Storage disk failure"))

        app = create_app(storage=mock_storage)
        client = TestClient(app)

        with patch.object(
            ChainInspector,
            "evaluate_deterministic",
            AsyncMock(
                return_value=DeterministicResult(
                    passed=False,
                    reason="Halt deterministic",
                    observed_data={},
                )
            ),
        ):
            resp = client.post("/evaluate", json=base_payload.model_dump(mode="json"))

        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == base_payload.rule_id
        assert data["llm_invoked"] is False
