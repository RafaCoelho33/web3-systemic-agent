"""
Comprehensive Edge-Case Test Matrix for Fix Contract Review.
Validates items: C1, C2, C5, A1, C3/C4, A2, A3, A5, and Hygiene.
"""

import ast
import asyncio
import inspect
import os
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from web3 import Web3
from web3.exceptions import Web3Exception

# -----------------------------------------------------------------------------
# Module Setup & Path Resolution (conforming to src/test_agent.py style)
# -----------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(ROOT_DIR) == "src":
    ROOT_DIR = os.path.abspath(os.path.join(ROOT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")

for p in (ROOT_DIR, SRC_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import src.schemas as schemas_module
    import src.chain_inspector as chain_inspector_module
    import src.semantic_evaluator as semantic_evaluator_module
    import src.engine as engine_module
    import src.api as api_module

    sys.modules.setdefault("schemas", schemas_module)
    sys.modules.setdefault("chain_inspector", chain_inspector_module)
    sys.modules.setdefault("semantic_evaluator", semantic_evaluator_module)
    sys.modules.setdefault("engine", engine_module)
    sys.modules.setdefault("api", api_module)
except ImportError:
    import schemas as schemas_module
    import chain_inspector as chain_inspector_module
    import semantic_evaluator as semantic_evaluator_module
    import engine as engine_module
    import api as api_module

    sys.modules.setdefault("src.schemas", schemas_module)
    sys.modules.setdefault("src.chain_inspector", chain_inspector_module)
    sys.modules.setdefault("src.semantic_evaluator", semantic_evaluator_module)
    sys.modules.setdefault("src.engine", engine_module)
    sys.modules.setdefault("src.api", api_module)

from schemas import (
    ChainId,
    DeterministicCondition,
    SemanticCondition,
    ConditionRulePayload,
    DeterministicResult,
    SemanticAuditResult,
    FinalAgentResponse,
)
from chain_inspector import ChainInspector
from semantic_evaluator import (
    MockSemanticEvaluator,
    OpenAISemanticEvaluator,
    GeminiSemanticEvaluator,
    get_semantic_evaluator,
)
from engine import ConditionAgentEngine
from api import create_app

# Safe references to newly contracted symbols
LLMAuditOutput = getattr(schemas_module, "LLMAuditOutput", None)
enforce_decision_policy = getattr(semantic_evaluator_module, "enforce_decision_policy", None)


# -----------------------------------------------------------------------------
# Defensively Isolated Test Fixtures
# -----------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def clean_inspector_cache_and_env(monkeypatch):
    """
    Guarantees ChainInspector caches are wiped before and after every test,
    and strips real LLM API keys by default to prevent accidental external calls.
    """
    if hasattr(ChainInspector, "clear_cache"):
        ChainInspector.clear_cache()
    # Strip LLM keys to ensure no real network calls are attempted
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    yield
    if hasattr(ChainInspector, "clear_cache"):
        ChainInspector.clear_cache()


@pytest.fixture
def base_valid_payload():
    return {
        "rule_id": "review-fix-rule-001",
        "chain_id": 84532,
        "deterministic": {
            "target_address": "0x4200000000000000000000000000000000000006",
            "min_value_wei": 1000000000000000000,
            "required_function_selectors": ["0xf2fde38b"],
            "check_native_balance": False,
        },
        "semantic": {
            "enabled": True,
            "policy_prompt": "Audit DAO administrative operations.",
            "risk_threshold": 7.0,
        },
        "context_metadata": {
            "tx_value_wei": 2000000000000000000,
            "calldata": "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "proposal_description": "Administrative update for review.",
        },
    }


# =============================================================================
# C1: .gitignore Tests
# =============================================================================
class TestC1Gitignore:
    def test_c1_gitignore_contains_required_entries(self):
        """Contract C1: .gitignore must contain .env, __pycache__/, .pytest_cache/, *.pyc."""
        gitignore_path = Path(ROOT_DIR) / ".gitignore"
        assert gitignore_path.exists(), f".gitignore not found at {gitignore_path}"

        lines = [line.strip() for line in gitignore_path.read_text(encoding="utf-8").splitlines()]
        # Strip comments and empties
        entries = set(line for line in lines if line and not line.startswith("#"))

        required = [".env", "__pycache__/", ".pytest_cache/", "*.pyc"]
        for req in required:
            assert req in entries, f"Missing required .gitignore entry: {req}"


# =============================================================================
# C2: Bytecode Cache & Inspector Enhancements
# =============================================================================
class TestC2BytecodeCache:
    @pytest.mark.asyncio
    async def test_c2_cache_key_includes_chain_id_same_address_triggers_two_calls(self):
        """
        Contract C2: Cache key is f"{chain_id}:{checksum_address}".
        Querying the same target address on chain 8453 vs 84532 must trigger two get_code calls.
        """
        target = "0x4200000000000000000000000000000000000006"
        checksum_target = Web3.to_checksum_address(target)

        with patch("src.chain_inspector.AsyncWeb3") as mock_w3_cls_src, \
             patch("chain_inspector.AsyncWeb3", mock_w3_cls_src, create=True):
            mock_w3 = MagicMock()
            mock_w3.eth.get_code = AsyncMock(return_value=b"\x60\x80\x60\x40")
            mock_w3.eth.get_balance = AsyncMock(return_value=2 * 10**18)
            mock_w3.is_connected = AsyncMock(return_value=True)
            mock_w3_cls_src.return_value = mock_w3

            cond = DeterministicCondition(
                target_address=target,
                min_value_wei=0,
                check_native_balance=False,
            )
            ctx = {"tx_value_wei": 0, "calldata": "0x"}

            # First invocation on Base Mainnet (8453)
            insp_8453 = ChainInspector(chain_id=8453)
            res_8453 = await insp_8453.evaluate_deterministic(cond, ctx)
            assert res_8453.passed is True

            # Second invocation on Base Sepolia (84532) with identical address
            insp_84532 = ChainInspector(chain_id=84532)
            res_84532 = await insp_84532.evaluate_deterministic(cond, ctx)
            assert res_84532.passed is True

            # Must have called get_code twice because chain_id differs
            assert mock_w3.eth.get_code.await_count == 2

            # Verify the exact cache keys conform to f"{chain_id}:{checksum_address}"
            expected_key_8453 = f"8453:{checksum_target}"
            expected_key_84532 = f"84532:{checksum_target}"
            assert expected_key_8453 in ChainInspector._bytecode_cache
            assert expected_key_84532 in ChainInspector._bytecode_cache

    @pytest.mark.asyncio
    async def test_c2_both_branches_write_cache_with_chain_id_key(self):
        """Contract C2: Both check_native_balance=True and False write f"{chain_id}:{checksum_address}"."""
        target_a = "0x0000000000000000000000000000000000000001"
        target_b = "0x0000000000000000000000000000000000000002"
        c_a = Web3.to_checksum_address(target_a)
        c_b = Web3.to_checksum_address(target_b)

        with patch("src.chain_inspector.AsyncWeb3") as mock_w3_cls_src, \
             patch("chain_inspector.AsyncWeb3", mock_w3_cls_src, create=True):
            mock_w3 = MagicMock()
            mock_w3.eth.get_code = AsyncMock(return_value=b"\x60\x80")
            mock_w3.eth.get_balance = AsyncMock(return_value=10**18)
            mock_w3.from_wei = MagicMock(return_value=1.0)
            mock_w3_cls_src.return_value = mock_w3

            insp = ChainInspector(chain_id=8453)

            # Branch 1: check_native_balance = True
            cond_true = DeterministicCondition(target_address=target_a, check_native_balance=True)
            await insp.evaluate_deterministic(cond_true, {"calldata": "0x"})
            assert f"8453:{c_a}" in ChainInspector._bytecode_cache

            # Branch 2: check_native_balance = False
            cond_false = DeterministicCondition(target_address=target_b, check_native_balance=False)
            await insp.evaluate_deterministic(cond_false, {"calldata": "0x"})
            assert f"8453:{c_b}" in ChainInspector._bytecode_cache

    @pytest.mark.asyncio
    async def test_c2_bytecode_cache_bounded_fifo(self):
        """Contract C2: Bytecode cache bounded to BYTECODE_CACHE_MAX = 1024 entries (FIFO eviction)."""
        max_bound = getattr(ChainInspector, "BYTECODE_CACHE_MAX", 1024)
        assert max_bound == 1024, f"Expected BYTECODE_CACHE_MAX == 1024, got {max_bound}"

        with patch("src.chain_inspector.AsyncWeb3") as mock_w3_cls_src, \
             patch("chain_inspector.AsyncWeb3", mock_w3_cls_src, create=True):
            mock_w3 = MagicMock()
            mock_w3.eth.get_code = AsyncMock(return_value=b"\x60")
            mock_w3_cls_src.return_value = mock_w3

            insp = ChainInspector(chain_id=8453)

            # Pre-populate cache to max capacity: 1024 items
            ChainInspector.clear_cache()
            first_key = f"8453:{Web3.to_checksum_address(f'0x{1:040x}')}"
            for i in range(1, 1025):
                addr = Web3.to_checksum_address(f"0x{i:040x}")
                ChainInspector._bytecode_cache[f"8453:{addr}"] = b"\x60"

            assert len(ChainInspector._bytecode_cache) == 1024
            assert first_key in ChainInspector._bytecode_cache

            # Trigger 1025th insertion through evaluate_deterministic
            target_1025 = Web3.to_checksum_address(f"0x{1025:040x}")
            cond = DeterministicCondition(target_address=target_1025, check_native_balance=False)
            await insp.evaluate_deterministic(cond, {"calldata": "0x"})

            # Bound must not exceed 1024
            assert len(ChainInspector._bytecode_cache) <= 1024
            # Oldest entry must have been evicted (FIFO)
            assert first_key not in ChainInspector._bytecode_cache
            # Newest entry must be present
            assert f"8453:{target_1025}" in ChainInspector._bytecode_cache

    def test_c2_clear_cache_classmethod(self):
        """Contract C2: ChainInspector.clear_cache() clears both bytecode and web3 caches."""
        ChainInspector._bytecode_cache["dummy:key"] = b"\x12\x34"
        ChainInspector._web3_cache["dummy:web3"] = MagicMock()

        ChainInspector.clear_cache()
        assert len(ChainInspector._bytecode_cache) == 0
        assert len(ChainInspector._web3_cache) == 0

    def test_c2_inspect_calldata_selector_is_staticmethod(self):
        """Contract C2: inspect_calldata_selector becomes a @staticmethod callable on class and instance."""
        # Static check via inspect.getattr_static
        raw_attr = inspect.getattr_static(ChainInspector, "inspect_calldata_selector")
        assert isinstance(raw_attr, staticmethod), "inspect_calldata_selector must be decorated with @staticmethod"

        # Calling as classmethod / staticmethod without instantiating
        res_class = ChainInspector.inspect_calldata_selector("0xa9059cbb0000000000000000")
        assert res_class == {"selector": "0xa9059cbb", "signature": "transfer(address,uint256)"}

        # Calling on instance
        with patch("src.chain_inspector.AsyncWeb3"):
            insp = ChainInspector(chain_id=8453)
            res_inst = insp.inspect_calldata_selector("0xf2fde38b")
            assert res_inst == {"selector": "0xf2fde38b", "signature": "transferOwnership(address)"}


# =============================================================================
# C5: DeterministicResult Error Handling
# =============================================================================
class TestC5Stage1Errors:
    def test_c5_deterministic_result_error_field_defaults_none(self):
        """Contract C5: DeterministicResult gains error: Optional[str] = None."""
        res_pass = DeterministicResult(passed=True, reason="Normal pass")
        assert res_pass.error is None

        res_fail = DeterministicResult(passed=False, reason="Normal condition rejection")
        assert res_fail.error is None

    @pytest.mark.asyncio
    async def test_c5_deterministic_result_error_set_only_on_rpc_error(self):
        """
        Contract C5: On RPC exception, passed=False, reason starts with 'RPC/Evaluation error:',
        and error=str(exc). On normal evaluation failure, error is None.
        """
        # Normal evaluation failure (balance below min) -> error is None
        with patch("src.chain_inspector.AsyncWeb3") as mock_w3_cls_src, \
             patch("chain_inspector.AsyncWeb3", mock_w3_cls_src, create=True):
            mock_w3 = MagicMock()
            mock_w3.eth.get_code = AsyncMock(return_value=b"\x60\x80")
            mock_w3_cls_src.return_value = mock_w3

            insp = ChainInspector(chain_id=8453)
            cond = DeterministicCondition(
                target_address="0x4200000000000000000000000000000000000006",
                min_value_wei=1000,
                check_native_balance=False,
            )
            res_normal_fail = await insp.evaluate_deterministic(cond, {"tx_value_wei": 100})
            assert res_normal_fail.passed is False
            assert res_normal_fail.error is None
            assert not res_normal_fail.reason.startswith("RPC/Evaluation error:")

        # RPC Exception -> passed=False, reason starts with 'RPC/Evaluation error:', error=str(exc)
        ChainInspector.clear_cache()
        with patch("src.chain_inspector.AsyncWeb3") as mock_w3_cls_src, \
             patch("chain_inspector.AsyncWeb3", mock_w3_cls_src, create=True):
            mock_w3_fail = MagicMock()
            rpc_exc = ConnectionResetError("Remote node dropped socket connection")
            mock_w3_fail.eth.get_code = AsyncMock(side_effect=rpc_exc)
            mock_w3_cls_src.return_value = mock_w3_fail

            insp_fail = ChainInspector(chain_id=8453)
            res_rpc_error = await insp_fail.evaluate_deterministic(cond, {"tx_value_wei": 2000})

            assert res_rpc_error.passed is False
            assert res_rpc_error.reason.startswith("RPC/Evaluation error:")
            assert res_rpc_error.error == str(rpc_exc)


# =============================================================================
# A1: RPC Resolution, Fallback & Cache Isolation
# =============================================================================
class TestA1RpcResolutionAndFallback:
    def test_a1_resolve_rpc_urls_explicit_precedence(self, monkeypatch):
        """Contract A1: Explicit str/list takes precedence over env and defaults."""
        monkeypatch.setenv("RPC_URL_8453", "https://env-rpc.com")

        # Explicit single string
        urls_str = ChainInspector.resolve_rpc_urls(8453, "https://explicit.com")
        assert urls_str == ["https://explicit.com"]

        # Explicit list
        urls_list = ChainInspector.resolve_rpc_urls(8453, ["https://exp1.com", "https://exp2.com"])
        assert urls_list == ["https://exp1.com", "https://exp2.com"]

    def test_a1_resolve_rpc_urls_env_var_precedence(self, monkeypatch):
        """Contract A1: Env var RPC_URL_<chain_id> (comma-separated, stripped, empties dropped)."""
        monkeypatch.setenv("RPC_URL_8453", " https://env1.com , , https://env2.com , ")
        urls = ChainInspector.resolve_rpc_urls(8453)
        assert urls == ["https://env1.com", "https://env2.com"]

    def test_a1_resolve_rpc_urls_default_fallback(self, monkeypatch):
        """Contract A1: Defaults to [DEFAULT_RPCS[chain_id]] when nothing is specified."""
        monkeypatch.delenv("RPC_URL_84532", raising=False)
        urls = ChainInspector.resolve_rpc_urls(84532)
        assert urls == [ChainInspector.DEFAULT_RPCS[84532]]

    def test_a1_resolve_rpc_urls_unknown_chain_raises_value_error(self, monkeypatch):
        """Contract A1: Unknown chain with nothing configured raises ValueError."""
        monkeypatch.delenv("RPC_URL_999999", raising=False)
        with pytest.raises(ValueError, match="No default RPC configured|Unknown chain"):
            ChainInspector.resolve_rpc_urls(999999)

    @pytest.mark.asyncio
    async def test_a1_fallback_to_second_url_when_first_raises(self):
        """
        Contract A1: On RPC exception with URL i, retry with URL i+1.
        Observed data records rpc_url_index of the successful provider (index 1).
        """
        url1 = "https://faulty-node.com"
        url2 = "https://healthy-node.com"

        mock_w3_1 = MagicMock()
        mock_w3_1.eth.get_code = AsyncMock(side_effect=Web3Exception("502 Bad Gateway"))

        mock_w3_2 = MagicMock()
        mock_w3_2.eth.get_code = AsyncMock(return_value=b"\x60\x80")

        instances = [mock_w3_1, mock_w3_2]

        with patch("src.chain_inspector.AsyncWeb3", side_effect=instances) as mock_w3_cls_src, \
             patch("chain_inspector.AsyncWeb3", mock_w3_cls_src, create=True):
            insp = ChainInspector(chain_id=8453, rpc_url=[url1, url2])
            cond = DeterministicCondition(
                target_address="0x4200000000000000000000000000000000000006",
                check_native_balance=False,
            )
            res = await insp.evaluate_deterministic(cond, {"calldata": "0x"})

            assert res.passed is True
            assert res.observed_data.get("rpc_url_index") == 1
            assert res.error is None

    @pytest.mark.asyncio
    async def test_a1_fallback_all_fail_returns_error_result(self):
        """Contract A1 & C5: When all fallback RPC URLs fail, return C5 error result."""
        url1 = "https://faulty-1.com"
        url2 = "https://faulty-2.com"

        mock_w3_1 = MagicMock()
        mock_w3_1.eth.get_code = AsyncMock(side_effect=Web3Exception("Timeout on node 1"))

        mock_w3_2 = MagicMock()
        mock_w3_2.eth.get_code = AsyncMock(side_effect=Web3Exception("Timeout on node 2"))

        with patch("src.chain_inspector.AsyncWeb3", side_effect=[mock_w3_1, mock_w3_2]) as mock_w3_cls_src, \
             patch("chain_inspector.AsyncWeb3", mock_w3_cls_src, create=True):
            insp = ChainInspector(chain_id=8453, rpc_url=[url1, url2])
            cond = DeterministicCondition(
                target_address="0x4200000000000000000000000000000000000006",
                check_native_balance=False,
            )
            res = await insp.evaluate_deterministic(cond, {"calldata": "0x"})

            assert res.passed is False
            assert res.reason.startswith("RPC/Evaluation error:")
            assert "Timeout on node 2" in str(res.error)

    def test_a1_use_cache_false_not_stored_in_cache(self):
        """Contract A1: use_cache=False ensures AsyncWeb3 is not stored in or read from _web3_cache."""
        ChainInspector.clear_cache()
        with patch("src.chain_inspector.AsyncWeb3") as mock_w3_cls_src, \
             patch("chain_inspector.AsyncWeb3", mock_w3_cls_src, create=True):
            mock_w3_cls_src.return_value = MagicMock()

            insp = ChainInspector(chain_id=8453, rpc_url="https://private-rpc.com", use_cache=False)
            assert len(ChainInspector._web3_cache) == 0

    @pytest.mark.asyncio
    async def test_a1_engine_per_chain_rpc_urls_map_precedence(self):
        """
        Contract A1: ConditionAgentEngine per-chain map rpc_urls[chain_id] takes precedence;
        else legacy rpc_url; else resolver defaults.
        """
        engine = ConditionAgentEngine(
            rpc_urls={8453: ["https://per-chain-8453.com"]},
            rpc_url="https://legacy-fallback.com",
            semantic_evaluator=MockSemanticEvaluator(),
        )

        with patch("src.engine.ChainInspector") as mock_insp_cls_src, \
             patch("engine.ChainInspector", mock_insp_cls_src, create=True):
            mock_insp = MagicMock()
            mock_insp.evaluate_deterministic = AsyncMock(
                return_value=DeterministicResult(passed=False, reason="Halt")
            )
            mock_insp_cls_src.return_value = mock_insp

            # 1. Processing chain 8453 (configured in rpc_urls)
            payload_8453 = ConditionRulePayload(
                rule_id="r1",
                chain_id=ChainId.BASE_MAINNET,
                deterministic=DeterministicCondition(target_address="0x4200000000000000000000000000000000000006"),
                semantic=SemanticCondition(policy_prompt="p", enabled=False),
            )
            await engine.process_rule(payload_8453)
            # Verify inspector called with per-chain RPC
            init_call_8453 = mock_insp_cls_src.call_args
            assert init_call_8453[1].get("rpc_url") == ["https://per-chain-8453.com"] or \
                   init_call_8453[0][1] == ["https://per-chain-8453.com"]

            # 2. Processing chain 84532 (not in rpc_urls -> falls back to legacy rpc_url)
            payload_84532 = ConditionRulePayload(
                rule_id="r2",
                chain_id=ChainId.BASE_SEPOLIA,
                deterministic=DeterministicCondition(target_address="0x4200000000000000000000000000000000000006"),
                semantic=SemanticCondition(policy_prompt="p", enabled=False),
            )
            await engine.process_rule(payload_84532)
            init_call_84532 = mock_insp_cls_src.call_args
            assert init_call_84532[1].get("rpc_url") == "https://legacy-fallback.com" or \
                   init_call_84532[0][1] == "https://legacy-fallback.com"


# =============================================================================
# C3 / C4: Decision Policy & Semantic Evaluator Escalation
# =============================================================================
class TestC3C4DecisionPolicy:
    def test_c3_enforce_decision_policy_matrix(self):
        """
        Contract C3: enforce_decision_policy table:
        - score >= 8.0 -> REJECT
        - score >= risk_threshold -> MANUAL_REVIEW
        - else APPROVE
        - final_action = MORE severe of (policy_action, llm_action) (never downgrade)
        - conditions_met = (risk_score >= risk_threshold)
        """
        policy_fn = getattr(semantic_evaluator_module, "enforce_decision_policy", None)
        assert policy_fn is not None, "enforce_decision_policy must be implemented in semantic_evaluator.py"

        cases = [
            # (score, threshold, llm_action, expected_final, expected_conditions_met, expected_escalated)
            (8.0, 7.0, "APPROVE", "REJECT", True, True),
            (7.99, 7.0, "APPROVE", "MANUAL_REVIEW", True, True),
            (7.0, 7.0, "APPROVE", "MANUAL_REVIEW", True, True),
            (6.99, 7.0, "APPROVE", "APPROVE", False, False),
            # Never downgrade: LLM recommends REJECT, but score is low
            (2.0, 7.0, "REJECT", "REJECT", False, False),
            # Never downgrade: LLM recommends MANUAL_REVIEW, score is low
            (3.0, 7.0, "MANUAL_REVIEW", "MANUAL_REVIEW", False, False),
            # Severity escalation from MANUAL_REVIEW to REJECT
            (8.5, 7.0, "MANUAL_REVIEW", "REJECT", True, True),
            # Score exactly at threshold 8.0
            (8.0, 8.0, "APPROVE", "REJECT", True, True),
        ]

        for score, thresh, llm_act, exp_act, exp_cond, exp_esc in cases:
            input_res = SemanticAuditResult(
                conditions_met=False,
                risk_score=score,
                flagged_issues=["Initial issue"],
                summary="Audit summary",
                recommended_action=llm_act,
                cached=False,
            )
            output_res = policy_fn(input_res, thresh)

            assert output_res.recommended_action == exp_act, (
                f"Failed action for score={score}, thresh={thresh}, llm={llm_act}: "
                f"expected {exp_act}, got {output_res.recommended_action}"
            )
            assert output_res.conditions_met == exp_cond, (
                f"Failed conditions_met for score={score}, thresh={thresh}: "
                f"expected {exp_cond}, got {output_res.conditions_met}"
            )

            escalated = any("Decision escalated by deterministic policy" in f for f in output_res.flagged_issues)
            assert escalated == exp_esc, f"Escalation flag mismatch for {llm_act} -> {exp_act}"

    def test_c3_enforce_decision_policy_flagged_message_and_no_mutation(self):
        """
        Contract C3: Appends f"Decision escalated by deterministic policy: LLM suggested {old} -> {final}".
        Returns a new copy; never mutates input.
        """
        policy_fn = getattr(semantic_evaluator_module, "enforce_decision_policy", None)
        assert policy_fn is not None, "enforce_decision_policy must be implemented in semantic_evaluator.py"

        orig_issues = ["Base vulnerability"]
        input_res = SemanticAuditResult(
            conditions_met=False,
            risk_score=9.0,
            flagged_issues=list(orig_issues),
            summary="Original summary",
            recommended_action="APPROVE",
            cached=False,
        )

        output_res = policy_fn(input_res, risk_threshold=7.0)

        # Output verification
        assert output_res is not input_res
        assert output_res.recommended_action == "REJECT"
        expected_msg = "Decision escalated by deterministic policy: LLM suggested APPROVE -> REJECT"
        assert any(expected_msg in issue for issue in output_res.flagged_issues)

        # Immutability verification of input
        assert input_res.recommended_action == "APPROVE"
        assert input_res.flagged_issues == orig_issues
        assert input_res.conditions_met is False

    @pytest.mark.asyncio
    async def test_c4_engine_applies_enforce_decision_policy_on_stage2(self, base_valid_payload):
        """
        Contract C4: Engine applies enforce_decision_policy to every Stage-2 result.
        Fake evaluator returning inconsistent score 9.5 + APPROVE must be escalated to REJECT.
        """
        inconsistent_evaluator = MagicMock()
        inconsistent_evaluator.evaluate = AsyncMock(
            return_value=SemanticAuditResult(
                conditions_met=False,
                risk_score=9.5,
                flagged_issues=["Severe reentrancy found"],
                summary="High risk detected but LLM erroneously approves",
                recommended_action="APPROVE",
                cached=False,
            )
        )

        with patch("src.engine.ChainInspector") as mock_insp_cls_src, \
             patch("engine.ChainInspector", mock_insp_cls_src, create=True):
            mock_insp = MagicMock()
            mock_insp.evaluate_deterministic = AsyncMock(
                return_value=DeterministicResult(passed=True, reason="Pass", observed_data={})
            )
            mock_insp_cls_src.return_value = mock_insp

            engine = ConditionAgentEngine(semantic_evaluator=inconsistent_evaluator)
            payload = ConditionRulePayload(**base_valid_payload)
            response: FinalAgentResponse = await engine.process_rule(payload)

            assert response.llm_invoked is True
            assert response.semantic_Evaluation is not None
            # Must be escalated to REJECT by policy
            assert response.semantic_Evaluation.recommended_action == "REJECT"
            assert response.semantic_Evaluation.conditions_met is True
            assert any(
                "Decision escalated by deterministic policy" in f
                for f in response.semantic_Evaluation.flagged_issues
            )

    @pytest.mark.asyncio
    async def test_c4_llm_fallback_openai_escalates_and_not_cached(self):
        """
        Contract C4: OpenAI client raises exception -> mock result gets flagged issue
        containing 'LLM provider failure', APPROVE escalated to MANUAL_REVIEW, not cached.
        """
        fake_client = MagicMock()
        fake_client.beta.chat.completions.parse = AsyncMock(
            side_effect=Exception("OpenAI rate limit or network unreachable")
        )

        evaluator = OpenAISemanticEvaluator(api_key="sk-test", client=fake_client, fallback_to_mock=True)
        cond = SemanticCondition(policy_prompt="Harmless administrative action", risk_threshold=7.0)
        # Context that yields low score in MockSemanticEvaluator (normally APPROVE)
        ctx = {"proposal_description": "Routine configuration update with thorough audit review completed"}
        observed = {"signature": "standard_check()", "target_address": "0x4200000000000000000000000000000000000006"}

        res = await evaluator.evaluate(cond, observed, ctx)

        assert any("LLM provider failure" in f for f in res.flagged_issues)
        assert res.recommended_action == "MANUAL_REVIEW"
        assert res.cached is False
        # Must not be stored in cache
        assert len(evaluator.cache) == 0

    @pytest.mark.asyncio
    async def test_c4_llm_fallback_gemini_escalates_and_not_cached(self):
        """
        Contract C4: Gemini client raises exception -> mock result gets flagged issue
        containing 'LLM provider failure', APPROVE escalated to MANUAL_REVIEW, not cached.
        """
        fake_client = MagicMock()
        fake_client.aio.models.generate_content = AsyncMock(
            side_effect=Exception("Gemini 503 Service Unavailable")
        )

        evaluator = GeminiSemanticEvaluator(api_key="fake-gemini-key", client=fake_client, fallback_to_mock=True)
        cond = SemanticCondition(policy_prompt="Harmless check", risk_threshold=7.0)
        ctx = {"proposal_description": "Routine verification with positive security audit"}
        observed = {"signature": "safe_ping()", "target_address": "0x4200000000000000000000000000000000000006"}

        res = await evaluator.evaluate(cond, observed, ctx)

        assert any("LLM provider failure" in f for f in res.flagged_issues)
        assert res.recommended_action == "MANUAL_REVIEW"
        assert res.cached is False
        assert len(evaluator.cache) == 0


# =============================================================================
# A2: Gemini Model Resolution Priority
# =============================================================================
class TestA2GeminiModelResolution:
    def test_a2_priority_kwarg_model(self, monkeypatch):
        """Contract A2: kwarg model takes highest priority."""
        monkeypatch.setenv("GEMINI_MODEL", "gemini-env-override")
        evaluator = GeminiSemanticEvaluator(
            client=MagicMock(),
            model="gemini-from-kwarg-model",
            model_name="gemini-from-model-name",
        )
        assert evaluator.model_name == "gemini-from-kwarg-model"
        assert evaluator.model == "gemini-from-kwarg-model"

    def test_a2_priority_kwarg_model_name(self, monkeypatch):
        """Contract A2: model_name takes precedence over env and default."""
        monkeypatch.setenv("GEMINI_MODEL", "gemini-env-override")
        evaluator = GeminiSemanticEvaluator(
            client=MagicMock(),
            model_name="gemini-from-model-name",
        )
        assert evaluator.model_name == "gemini-from-model-name"

    def test_a2_priority_env_var(self, monkeypatch):
        """Contract A2: env GEMINI_MODEL takes precedence over default."""
        monkeypatch.setenv("GEMINI_MODEL", "gemini-1.5-pro-custom")
        evaluator = GeminiSemanticEvaluator(client=MagicMock())
        assert evaluator.model_name == "gemini-1.5-pro-custom"

    def test_a2_priority_default(self, monkeypatch):
        """Contract A2: Defaults to 'gemini-2.0-flash' when no arg or env is specified."""
        monkeypatch.delenv("GEMINI_MODEL", raising=False)
        evaluator = GeminiSemanticEvaluator(client=MagicMock())
        assert evaluator.model_name == "gemini-2.0-flash"

    def test_a2_get_semantic_evaluator_does_not_inject_default_model(self, monkeypatch):
        """Contract A2: get_semantic_evaluator must not inject a default model name."""
        monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-env-test")
        fake_client = MagicMock()
        with patch("google.genai.Client", return_value=fake_client, create=True):
            evaluator = get_semantic_evaluator(
                provider="gemini",
                api_key="fake-key",
                fallback_to_mock=False,
            )
            assert evaluator.model_name == "gemini-2.5-env-test"


# =============================================================================
# A3: LLM Output Schema (LLMAuditOutput)
# =============================================================================
class TestA3LLMOutputSchema:
    def test_a3_llm_audit_output_schema_structure(self):
        """
        Contract A3: LLMAuditOutput has same fields as SemanticAuditResult EXCEPT 'cached'.
        All fields required (flagged_issues required, no defaults).
        """
        assert LLMAuditOutput is not None, "LLMAuditOutput must be defined in schemas.py"

        fields = LLMAuditOutput.model_fields
        assert "cached" not in fields, "LLMAuditOutput must NOT contain 'cached' field"
        assert "conditions_met" in fields
        assert "risk_score" in fields
        assert "flagged_issues" in fields
        assert "summary" in fields
        assert "recommended_action" in fields

        # Verify flagged_issues is strictly required (omission raises ValidationError)
        with pytest.raises(ValidationError):
            LLMAuditOutput(
                conditions_met=True,
                risk_score=5.0,
                summary="Missing flagged issues",
                recommended_action="APPROVE",
            )

    @pytest.mark.asyncio
    async def test_a3_openai_parse_called_with_llm_audit_output(self):
        """Contract A3: OpenAI parse called with response_format=LLMAuditOutput using fake client."""
        assert LLMAuditOutput is not None

        fake_client = MagicMock()
        fake_parsed = LLMAuditOutput(
            conditions_met=True,
            risk_score=8.5,
            flagged_issues=["Unverified logic"],
            summary="OpenAI structured evaluation",
            recommended_action="REJECT",
        )
        fake_choice = MagicMock()
        fake_choice.message.parsed = fake_parsed
        fake_completion = MagicMock(choices=[fake_choice])
        fake_client.beta.chat.completions.parse = AsyncMock(return_value=fake_completion)

        evaluator = OpenAISemanticEvaluator(api_key="sk-test", client=fake_client)
        cond = SemanticCondition(policy_prompt="p", risk_threshold=7.0)
        res = await evaluator.evaluate(cond, {}, {})

        # Assert response_format was LLMAuditOutput
        parse_kwargs = fake_client.beta.chat.completions.parse.call_args[1]
        assert parse_kwargs.get("response_format") == LLMAuditOutput

        # Converted to SemanticAuditResult with cached=False
        assert isinstance(res, SemanticAuditResult)
        assert res.cached is False
        assert res.recommended_action == "REJECT"

    @pytest.mark.asyncio
    async def test_a3_gemini_generate_content_configured_with_llm_audit_output(self):
        """Contract A3: Gemini generate_content called with response_schema=LLMAuditOutput."""
        assert LLMAuditOutput is not None

        fake_client = MagicMock()
        fake_parsed = LLMAuditOutput(
            conditions_met=False,
            risk_score=2.0,
            flagged_issues=[],
            summary="Gemini structured evaluation",
            recommended_action="APPROVE",
        )
        fake_response = MagicMock(parsed=fake_parsed)
        fake_client.aio.models.generate_content = AsyncMock(return_value=fake_response)

        evaluator = GeminiSemanticEvaluator(api_key="fake-key", client=fake_client)
        cond = SemanticCondition(policy_prompt="p", risk_threshold=7.0)
        res = await evaluator.evaluate(cond, {}, {})

        call_kwargs = fake_client.aio.models.generate_content.call_args[1]
        config = call_kwargs.get("config")
        schema = getattr(config, "response_schema", None) or (config.get("response_schema") if isinstance(config, dict) else None)
        assert schema == LLMAuditOutput

        assert isinstance(res, SemanticAuditResult)
        assert res.cached is False


# =============================================================================
# A5: Schema Validation & Normalization
# =============================================================================
class TestA5SchemaValidation:
    def test_a5_function_selectors_validation_and_lowercasing(self):
        """
        Contract A5: DeterministicCondition.required_function_selectors:
        each must match ^0x[0-9a-fA-F]{8}$ else ValueError; normalized to lowercase.
        """
        # Valid uppercase normalized to lowercase
        cond = DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            required_function_selectors=["0xA9059CBB", "0x095EA7B3"],
        )
        assert cond.required_function_selectors == ["0xa9059cbb", "0x095ea7b3"]

        # Invalid formats
        invalid_selectors = [
            ["0xa905"],            # Too short
            ["0xa9059cbb11"],        # Too long
            ["a9059cbb"],            # Missing 0x prefix
            ["0xZZZZZZZZ"],          # Non-hex characters
            ["0x1234567g"],          # Invalid hex character 'g'
        ]
        for inv in invalid_selectors:
            with pytest.raises(ValidationError):
                DeterministicCondition(
                    target_address="0x4200000000000000000000000000000000000006",
                    required_function_selectors=inv,
                )

    def test_a5_recommended_action_normalization_and_rejection(self):
        """
        Contract A5: recommended_action Literal['APPROVE','REJECT','MANUAL_REVIEW'];
        mode='before' validator strips + uppercases strings; invalid raises ValidationError.
        """
        # Valid strings normalized
        for raw, expected in [("approve ", "APPROVE"), (" reject\n", "REJECT"), ("manual_review", "MANUAL_REVIEW")]:
            res = SemanticAuditResult(
                conditions_met=True,
                risk_score=7.0,
                flagged_issues=[],
                summary="Validation check",
                recommended_action=raw,
            )
            assert res.recommended_action == expected

        # Rejection of invalid actions
        for invalid in ["UNKNOWN", "DISAPPROVE", "PENDING", "", "REVIEW"]:
            with pytest.raises(ValidationError):
                SemanticAuditResult(
                    conditions_met=True,
                    risk_score=7.0,
                    flagged_issues=[],
                    summary="Invalid action check",
                    recommended_action=invalid,
                )

    def test_a5_rules_validate_endpoint_returns_422_on_invalid_selector(self, base_valid_payload):
        """Contract A5: POST /rules/validate with invalid selector returns 422 (schema validation error)."""
        app = create_app(engine=ConditionAgentEngine(semantic_evaluator=MockSemanticEvaluator()))
        client = TestClient(app)

        invalid_payload = dict(base_valid_payload)
        invalid_payload["deterministic"] = dict(base_valid_payload["deterministic"])
        invalid_payload["deterministic"]["required_function_selectors"] = ["0xinvalid_sel"]

        response = client.post("/rules/validate", json=invalid_payload)
        assert response.status_code == 422, f"Expected 422, got {response.status_code}: {response.text}"


# =============================================================================
# Hygiene Tests
# =============================================================================
class TestHygiene:
    def test_hygiene_engine_no_module_level_logging_basic_config(self):
        """Contract Hygiene: engine.py must not call logging.basicConfig at module level."""
        engine_file = Path(ROOT_DIR) / "src" / "engine.py"
        assert engine_file.exists(), "src/engine.py not found"

        tree = ast.parse(engine_file.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "basicConfig":
                    pytest.fail("Found top-level logging.basicConfig in src/engine.py. It must only be called inside __main__.")

    def test_hygiene_cors_allow_credentials_false_when_origins_has_wildcard(self, monkeypatch):
        """Contract Hygiene: CORS allow_credentials = ('*' not in origins); False when wildcard present."""
        # 1. Default origins ("*") -> allow_credentials must be False
        monkeypatch.delenv("CORS_ALLOW_ORIGINS", raising=False)
        app_wildcard = create_app(engine=ConditionAgentEngine(semantic_evaluator=MockSemanticEvaluator()))

        # Check CORS middleware options
        cors_middleware = next((m for m in app_wildcard.user_middleware if "CORSMiddleware" in m.cls.__name__), None)
        assert cors_middleware is not None, "CORSMiddleware not found on app"
        assert cors_middleware.kwargs.get("allow_credentials") is False, \
               "CORS allow_credentials must be False when origins contains '*'"

        # 2. Specific explicit origins -> allow_credentials must be True
        monkeypatch.setenv("CORS_ALLOW_ORIGINS", "https://trusted-client.org,https://portal.io")
        app_specific = create_app(engine=ConditionAgentEngine(semantic_evaluator=MockSemanticEvaluator()))
        cors_specific = next((m for m in app_specific.user_middleware if "CORSMiddleware" in m.cls.__name__), None)
        assert cors_specific.kwargs.get("allow_credentials") is True

    def test_hygiene_health_probes_use_cache_false(self):
        """Contract Hygiene: /health probes use ChainInspector(..., use_cache=False)."""
        app = create_app(engine=ConditionAgentEngine(semantic_evaluator=MockSemanticEvaluator()))
        client = TestClient(app)

        with patch("src.api.ChainInspector") as mock_insp_cls_src, \
             patch("api.ChainInspector", mock_insp_cls_src, create=True):
            mock_insp = MagicMock()
            mock_insp.verify_connection = AsyncMock(return_value=True)
            mock_insp_cls_src.return_value = mock_insp
            mock_insp_cls_src.DEFAULT_RPCS = ChainInspector.DEFAULT_RPCS

            client.get("/health")

            assert mock_insp_cls_src.call_count >= 1
            for call in mock_insp_cls_src.call_args_list:
                use_cache_val = call[1].get("use_cache")
                assert use_cache_val is False, f"Expected /health probe to use use_cache=False, got {use_cache_val}"

    def test_hygiene_pytest_ini_contains_not_integration_marker(self):
        """Contract Hygiene: pytest.ini contains addopts with -m 'not integration'."""
        ini_path = Path(ROOT_DIR) / "pytest.ini"
        assert ini_path.exists(), "pytest.ini not found"
        content = ini_path.read_text(encoding="utf-8")
        assert "not integration" in content, "pytest.ini addopts must filter out integration tests: -m 'not integration'"

    def test_hygiene_requirements_txt_exists_and_contains_deps(self):
        """Contract Hygiene: requirements.txt exists with >= dependencies matching installed ones."""
        req_path = Path(ROOT_DIR) / "requirements.txt"
        assert req_path.exists(), "requirements.txt does not exist at project root"

        content = req_path.read_text(encoding="utf-8")
        expected_pkgs = ["web3", "pydantic", "fastapi", "uvicorn", "pytest", "pytest-asyncio"]
        for pkg in expected_pkgs:
            assert pkg in content, f"Expected {pkg} in requirements.txt"
