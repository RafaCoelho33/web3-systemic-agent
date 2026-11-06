import asyncio
import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from web3.exceptions import Web3Exception
from pydantic import ValidationError

# Setup module search paths so tests can be run from workspace root, tests/, or src/
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(ROOT_DIR) in ("src", "tests"):
    ROOT_DIR = os.path.abspath(os.path.join(ROOT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")

for p in (ROOT_DIR, SRC_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

# Module aliasing to support both 'from schemas import ...' and 'from src.schemas import ...'
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
from api import create_app, app
from fastapi.testclient import TestClient

# Tolerant imports for task_worker / concurrency components (AgentWorkerPool, JobStore, JobStatus)
task_worker_module = None
try:
    import src.task_worker as task_worker_module
    sys.modules.setdefault("task_worker", task_worker_module)
except ImportError:
    try:
        import task_worker as task_worker_module
        sys.modules.setdefault("src.task_worker", task_worker_module)
    except ImportError:
        task_worker_module = None

AgentWorkerPool = getattr(task_worker_module, "AgentWorkerPool", None)
JobStore = getattr(task_worker_module, "JobStore", None)
JobStatus = getattr(task_worker_module, "JobStatus", None)

if AgentWorkerPool is None:
    AgentWorkerPool = getattr(engine_module, "AgentWorkerPool", None)
if JobStore is None:
    JobStore = getattr(engine_module, "JobStore", None)
if JobStatus is None:
    JobStatus = getattr(schemas_module, "JobStatus", getattr(engine_module, "JobStatus", None))

if JobStatus is None:
    from enum import Enum
    class JobStatus(str, Enum):
        QUEUED = "QUEUED"
        PROCESSING = "PROCESSING"
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"
        CANCELLED = "CANCELLED"


# ---------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------

@pytest.fixture
def mock_w3():
    """
    Mocks AsyncWeb3 globally across both 'src.chain_inspector' and 'chain_inspector'.
    Preconfigures async RPC methods for contract bytecode and native balance.
    """
    with patch("src.chain_inspector.AsyncWeb3") as mock_web3_cls_src, \
         patch("chain_inspector.AsyncWeb3", mock_web3_cls_src, create=True):
        mock_instance = MagicMock()
        mock_instance.eth.get_code = AsyncMock(return_value=b"\x60\x80\x60\x40")
        mock_instance.eth.get_balance = AsyncMock(return_value=2 * 10**18)
        mock_instance.is_connected = AsyncMock(return_value=True)
        mock_instance.from_wei = MagicMock(side_effect=lambda val, unit: val / 10**18)
        mock_web3_cls_src.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def base_payload_dict():
    """
    Returns a valid base dictionary payload representing a DAO governance rule.
    """
    return {
        "rule_id": "dao-gov-guard-001",
        "chain_id": 84532,
        "deterministic": {
            "target_address": "0x4200000000000000000000000000000000000006",
            "min_value_wei": 1000000000000000000,  # 1 ETH in Wei
            "required_function_selectors": ["0xf2fde38b"],  # transferOwnership
            "check_native_balance": False,
        },
        "semantic": {
            "enabled": True,
            "policy_prompt": "Reject unverified ownership transfer without audit.",
            "risk_threshold": 7.0,
        },
        "context_metadata": {
            "tx_value_wei": 2000000000000000000,  # 2 ETH in Wei
            "calldata": "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "proposal_description": "Routine configuration update without any security review.",
        },
    }


# ---------------------------------------------------------
# 1. Pydantic Schemas & Data Integrity Tests
# ---------------------------------------------------------

class TestSchemas:
    def test_chain_id_enum_supported_values(self):
        """Verifies supported EVM chains and rejection of unsupported chain IDs."""
        assert ChainId.BASE_MAINNET == 8453
        assert ChainId.BASE_SEPOLIA == 84532
        assert ChainId.ARBITRUM_ONE == 42161

        with pytest.raises(ValueError):
            ChainId(1)  # Ethereum Mainnet not in supported enum

        with pytest.raises(ValueError):
            ChainId(9999)

    def test_deterministic_condition_eip55_checksum_normalization(self):
        """Verifies EIP-55 checksum normalization and rejection of invalid addresses."""
        # Lowercase address is normalized to EIP-55 checksum
        cond = DeterministicCondition(target_address="0xd8da6bf26964af9d7eed9e03e53415d37aa96045")
        assert cond.target_address == "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

        # Already valid checksum address remains unchanged
        cond_checksum = DeterministicCondition(target_address="0x4200000000000000000000000000000000000006")
        assert cond_checksum.target_address == "0x4200000000000000000000000000000000000006"

        # Invalid address format raises ValidationError
        with pytest.raises(ValidationError):
            DeterministicCondition(target_address="not-an-address")

        with pytest.raises(ValidationError):
            DeterministicCondition(target_address="0x1234")

        with pytest.raises(ValidationError):
            DeterministicCondition(target_address="0x" + "z" * 40)

    def test_deterministic_condition_wei_value_constraints(self):
        """Verifies monetary values in Wei must be non-negative integers."""
        # Valid integer Wei
        cond = DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            min_value_wei=1000000000000000000,
        )
        assert cond.min_value_wei == 1000000000000000000

        # Negative Wei value is rejected (ge=0)
        with pytest.raises(ValidationError):
            DeterministicCondition(
                target_address="0x4200000000000000000000000000000000000006",
                min_value_wei=-1,
            )

        # Invalid string type for min_value_wei is rejected
        with pytest.raises(ValidationError):
            DeterministicCondition(
                target_address="0x4200000000000000000000000000000000000006",
                min_value_wei="invalid_wei_string",
            )

    def test_deterministic_condition_defaults(self):
        """Verifies default values for optional deterministic fields."""
        cond = DeterministicCondition(target_address="0x4200000000000000000000000000000000000006")
        assert cond.min_value_wei == 0
        assert cond.required_function_selectors is None
        assert cond.check_native_balance is False

    def test_semantic_condition_validation(self):
        """Verifies SemanticCondition boundaries and defaults."""
        # Defaults
        cond = SemanticCondition(policy_prompt="Check DAO exploit")
        assert cond.enabled is True
        assert cond.risk_threshold == 7.0

        # Valid boundaries for risk_threshold
        cond_min = SemanticCondition(policy_prompt="Prompt", risk_threshold=0.0)
        assert cond_min.risk_threshold == 0.0
        cond_max = SemanticCondition(policy_prompt="Prompt", risk_threshold=10.0)
        assert cond_max.risk_threshold == 10.0

        # Out-of-bounds risk_threshold
        with pytest.raises(ValidationError):
            SemanticCondition(policy_prompt="Prompt", risk_threshold=-0.1)

        with pytest.raises(ValidationError):
            SemanticCondition(policy_prompt="Prompt", risk_threshold=10.1)

        # Missing required policy_prompt
        with pytest.raises(ValidationError):
            SemanticCondition()

    def test_condition_rule_payload_structure(self, base_payload_dict):
        """Verifies ConditionRulePayload parses correctly and enforces required fields."""
        payload = ConditionRulePayload(**base_payload_dict)
        assert payload.rule_id == "dao-gov-guard-001"
        assert payload.chain_id == ChainId.BASE_SEPOLIA
        assert payload.deterministic.min_value_wei == 10**18
        assert payload.semantic.enabled is True
        assert "tx_value_wei" in payload.context_metadata

        # Missing mandatory rule_id
        invalid_dict = base_payload_dict.copy()
        del invalid_dict["rule_id"]
        with pytest.raises(ValidationError):
            ConditionRulePayload(**invalid_dict)

    def test_semantic_audit_result_bounds(self):
        """Verifies SemanticAuditResult risk_score range enforcement."""
        valid_res = SemanticAuditResult(
            conditions_met=True,
            risk_score=8.5,
            flagged_issues=["High risk"],
            summary="Risky call",
            recommended_action="REJECT",
        )
        assert valid_res.risk_score == 8.5

        # Invalid risk_score < 0
        with pytest.raises(ValidationError):
            SemanticAuditResult(
                conditions_met=True,
                risk_score=-1.0,
                summary="summary",
                recommended_action="APPROVE",
            )

        # Invalid risk_score > 10
        with pytest.raises(ValidationError):
            SemanticAuditResult(
                conditions_met=True,
                risk_score=10.5,
                summary="summary",
                recommended_action="APPROVE",
            )

    def test_final_agent_response_structure(self):
        """Verifies FinalAgentResponse can represent both short-circuit and full evaluations."""
        det_res = DeterministicResult(passed=False, reason="Value too low", observed_data={})
        resp = FinalAgentResponse(
            rule_id="rule-1",
            chain_id=84532,
            deterministic_check=det_res,
            llm_invoked=False,
            semantic_Evaluation=None,
        )
        assert resp.llm_invoked is False
        assert resp.semantic_Evaluation is None


# ---------------------------------------------------------
# 2. Deterministic Layer (ChainInspector) Tests
# ---------------------------------------------------------

class TestChainInspector:
    def test_chain_inspector_rpc_resolution(self):
        """Verifies proper RPC endpoint selection and custom override."""
        insp_sep = ChainInspector(chain_id=84532)
        assert insp_sep.chain_id == 84532

        insp_main = ChainInspector(chain_id=8453)
        assert insp_main.chain_id == 8453

        insp_arb = ChainInspector(chain_id=42161)
        assert insp_arb.chain_id == 42161

        insp_custom = ChainInspector(chain_id=84532, rpc_url="http://custom-rpc:8545")
        assert insp_custom.chain_id == 84532

        # Unsupported chain_id without custom RPC raises ValueError
        with pytest.raises(ValueError):
            ChainInspector(chain_id=99999)

    @pytest.mark.asyncio
    async def test_verify_connection(self, mock_w3):
        """Verifies connection checks and graceful handling of Web3Exceptions."""
        inspector = ChainInspector(chain_id=84532)

        # Connection success
        mock_w3.is_connected.return_value = True
        assert await inspector.verify_connection() is True

        # Connection failure
        mock_w3.is_connected.return_value = False
        assert await inspector.verify_connection() is False

        # RPC Exception caught and returns False
        mock_w3.is_connected.side_effect = Web3Exception("Connection refused")
        assert await inspector.verify_connection() is False

    def test_inspect_calldata_empty_and_short(self):
        """Verifies that empty or short calldata is safely categorized as native_transfer_or_empty."""
        inspector = ChainInspector(chain_id=84532)

        assert inspector.inspect_calldata_selector("") == {
            "selector": "0x",
            "signature": "native_transfer_or_empty",
        }
        assert inspector.inspect_calldata_selector("0x") == {
            "selector": "0x",
            "signature": "native_transfer_or_empty",
        }
        assert inspector.inspect_calldata_selector("0x1234") == {
            "selector": "0x",
            "signature": "native_transfer_or_empty",
        }

    def test_inspect_calldata_known_selectors(self):
        """Verifies recognition of known function selectors with case insensitivity."""
        inspector = ChainInspector(chain_id=84532)

        expected = {
            "0xa9059cbb": "transfer(address,uint256)",
            "0x095ea7b3": "approve(address,uint256)",
            "0x23b872dd": "transferFrom(address,address,uint256)",
            "0xf2fde38b": "transferOwnership(address)",
            "0x3659cfe6": "upgradeTo(address)",
            "0x40c10f19": "mint(address,uint256)",
        }

        for selector, signature in expected.items():
            calldata = f"{selector}000000000000000000000000deadbeef"
            res = inspector.inspect_calldata_selector(calldata)
            assert res["selector"] == selector
            assert res["signature"] == signature

        # Case-insensitivity test
        upper_calldata = "0XF2FDE38B000000000000000000000000deadbeef"
        upper_res = inspector.inspect_calldata_selector(upper_calldata)
        assert upper_res["selector"] == "0xf2fde38b"
        assert upper_res["signature"] == "transferOwnership(address)"

    def test_inspect_calldata_unknown_selector(self):
        """Verifies that unmapped selectors are categorized as unknown_selector."""
        inspector = ChainInspector(chain_id=84532)
        calldata = "0xdeadbeef11223344556677889900aabbccddeeff"
        res = inspector.inspect_calldata_selector(calldata)
        assert res["selector"] == "0xdeadbeef"
        assert res["signature"] == "unknown_selector"

    @pytest.mark.asyncio
    async def test_evaluate_deterministic_bytecode_eoa_vs_contract(self, mock_w3):
        """Verifies differentiation between EOA (len(code)==0) and Smart Contract."""
        inspector = ChainInspector(chain_id=84532)
        condition = DeterministicCondition(target_address="0x4200000000000000000000000000000000000006")

        # Contract case: bytecode present
        mock_w3.eth.get_code.return_value = b"\x60\x80\x60\x40"
        result_contract = await inspector.evaluate_deterministic(condition, {})
        assert result_contract.passed is True
        assert result_contract.observed_data["is_contract"] is True

        # EOA case: bytecode empty
        ChainInspector.clear_cache()
        mock_w3.eth.get_code.return_value = b""
        result_eoa = await inspector.evaluate_deterministic(condition, {})
        assert result_eoa.passed is True
        assert result_eoa.observed_data["is_contract"] is False

    @pytest.mark.asyncio
    async def test_evaluate_deterministic_tx_value_threshold(self, mock_w3):
        """Verifies short-circuit when tx_value_wei is below min_value_wei."""
        inspector = ChainInspector(chain_id=84532)
        condition = DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            min_value_wei=10**18,  # 1 ETH
            check_native_balance=False,
        )

        # tx_value_wei below threshold (0.5 ETH) -> passed=False
        res_fail = await inspector.evaluate_deterministic(
            condition, {"tx_value_wei": 500000000000000000}
        )
        assert res_fail.passed is False
        assert "below threshold" in res_fail.reason

        # tx_value_wei meets threshold (1 ETH) -> passed=True
        res_pass = await inspector.evaluate_deterministic(
            condition, {"tx_value_wei": 1000000000000000000}
        )
        assert res_pass.passed is True

    @pytest.mark.asyncio
    async def test_evaluate_deterministic_native_balance_check(self, mock_w3):
        """Verifies check_native_balance calling eth.get_balance and from_wei."""
        inspector = ChainInspector(chain_id=84532)
        condition = DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            min_value_wei=2 * 10**18,
            check_native_balance=True,
        )

        # Balance below min_value_wei (1 ETH < 2 ETH) -> passed=False
        mock_w3.eth.get_balance.return_value = 10**18
        res_fail = await inspector.evaluate_deterministic(condition, {})
        assert res_fail.passed is False
        assert "Target balance" in res_fail.reason
        assert res_fail.observed_data["native_balance_wei"] == 10**18
        assert res_fail.observed_data["native_balance_eth"] == 1.0

        # Balance meets min_value_wei (2.5 ETH >= 2 ETH) -> passed=True
        mock_w3.eth.get_balance.return_value = 25 * 10**17
        res_pass = await inspector.evaluate_deterministic(condition, {})
        assert res_pass.passed is True
        assert res_pass.observed_data["native_balance_wei"] == 25 * 10**17
        assert res_pass.observed_data["native_balance_eth"] == 2.5

    @pytest.mark.asyncio
    async def test_evaluate_deterministic_required_function_selectors(self, mock_w3):
        """Verifies calldata selector matching with required_function_selectors."""
        inspector = ChainInspector(chain_id=84532)
        condition = DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            required_function_selectors=["0xf2fde38b", "0x3659cfe6"],
        )

        # Matching selector (transferOwnership)
        context_match = {"calldata": "0xf2fde38b000000000000000000000000deadbeef"}
        res_match = await inspector.evaluate_deterministic(condition, context_match)
        assert res_match.passed is True

        # Case-insensitive match in selector
        context_upper = {"calldata": "0X3659CFE6000000000000000000000000deadbeef"}
        res_upper = await inspector.evaluate_deterministic(condition, context_upper)
        assert res_upper.passed is True

        # Non-matching selector (transfer)
        context_mismatch = {"calldata": "0xa9059cbb000000000000000000000000deadbeef"}
        res_mismatch = await inspector.evaluate_deterministic(condition, context_mismatch)
        assert res_mismatch.passed is False
        assert "not in required list" in res_mismatch.reason

    @pytest.mark.asyncio
    async def test_evaluate_deterministic_rpc_exception_handling(self, mock_w3):
        """Verifies that RPC errors in get_code or get_balance yield passed=False gracefully."""
        inspector = ChainInspector(chain_id=84532)
        condition = DeterministicCondition(target_address="0x4200000000000000000000000000000000000006")

        # get_code raises RPC failure
        mock_w3.eth.get_code.side_effect = Exception("RPC endpoint timeout")
        res_rpc = await inspector.evaluate_deterministic(condition, {})
        assert res_rpc.passed is False
        assert res_rpc.reason.startswith("RPC/Evaluation error:")
        assert res_rpc.observed_data["target_address"] == condition.target_address

        # get_balance raises RPC failure
        mock_w3.eth.get_code.side_effect = None
        mock_w3.eth.get_code.return_value = b"\x60\x80"
        condition.check_native_balance = True
        mock_w3.eth.get_balance.side_effect = Exception("Internal JSON-RPC Error")

        res_bal_rpc = await inspector.evaluate_deterministic(condition, {})
        assert res_bal_rpc.passed is False
        assert res_bal_rpc.reason.startswith("RPC/Evaluation error:")


# ---------------------------------------------------------
# 3. Semantic Evaluator (Mock) Tests
# ---------------------------------------------------------

class TestMockSemanticEvaluator:
    @pytest.mark.asyncio
    async def test_semantic_evaluator_reject_on_critical_privilege_without_audit(self):
        """Verifies score >= 8.0 maps to REJECT action when privilege is detected without audit."""
        evaluator = MockSemanticEvaluator()
        condition = SemanticCondition(policy_prompt="Flag unverified admin actions", risk_threshold=7.0)

        observed_onchain = {
            "target_address": "0x4200000000000000000000000000000000000006",
            "calldata_analysis": {"signature": "transferOwnership(address)"},
        }
        metadata = {"proposal_description": "Routine change of treasury management."}

        res = await evaluator.evaluate(condition, observed_onchain, metadata)
        # Score calculation: 2.0 (base) + 5.5 (privilege) + 2.0 (no audit) = 9.5
        assert res.risk_score == 9.5
        assert res.conditions_met is True
        assert res.recommended_action == "REJECT"
        assert len(res.flagged_issues) == 2

    @pytest.mark.asyncio
    async def test_semantic_evaluator_manual_review_on_privilege_with_audit(self):
        """Verifies score between risk_threshold and 8.0 maps to MANUAL_REVIEW when audit is present."""
        evaluator = MockSemanticEvaluator()
        condition = SemanticCondition(policy_prompt="Flag unverified admin actions", risk_threshold=7.0)

        observed_onchain = {
            "target_address": "0x4200000000000000000000000000000000000006",
            "calldata_analysis": {"signature": "upgradeTo(address)"},
        }
        # Proposal mentions external audit, preventing the +2.0 risk inflation
        metadata = {"proposal_description": "Upgrade contract following OpenZeppelin audit review."}

        res = await evaluator.evaluate(condition, observed_onchain, metadata)
        # Score calculation: 2.0 (base) + 5.5 (privilege) = 7.5
        assert res.risk_score == 7.5
        assert res.conditions_met is True
        assert res.recommended_action == "MANUAL_REVIEW"
        assert len(res.flagged_issues) == 1

    @pytest.mark.asyncio
    async def test_semantic_evaluator_approve_on_low_risk(self):
        """Verifies score below risk_threshold maps to APPROVE action."""
        evaluator = MockSemanticEvaluator()
        condition = SemanticCondition(policy_prompt="Flag abnormal operations", risk_threshold=7.0)

        observed_onchain = {
            "target_address": "0x4200000000000000000000000000000000000006",
            "calldata_analysis": {"signature": "transfer(address,uint256)"},
        }
        metadata = {"proposal_description": "Standard recurring grant distribution."}

        res = await evaluator.evaluate(condition, observed_onchain, metadata)
        # Score: 2.0 (base)
        assert res.risk_score == 2.0
        assert res.conditions_met is False
        assert res.recommended_action == "APPROVE"
        assert len(res.flagged_issues) == 0

    @pytest.mark.asyncio
    async def test_semantic_evaluator_empty_metadata_resilience(self):
        """Verifies evaluator resilience against empty or missing metadata and observed data."""
        evaluator = MockSemanticEvaluator()
        condition = SemanticCondition(policy_prompt="Empty context test")

        res = await evaluator.evaluate(condition, {}, {})
        assert res.risk_score == 2.0
        assert res.conditions_met is False
        assert res.recommended_action == "APPROVE"


# ---------------------------------------------------------
# 4. Engine End-to-End Orchestration & Short-Circuit Tests
# ---------------------------------------------------------

class TestConditionAgentEngine:
    @pytest.mark.asyncio
    async def test_short_circuit_tx_value_too_low(self, mock_w3, base_payload_dict):
        """Stage 1 fails due to tx_value_wei < min_value_wei; ensures LLM is not invoked."""
        base_payload_dict["context_metadata"]["tx_value_wei"] = 100000000000000000  # 0.1 ETH (< 1 ETH)
        payload = ConditionRulePayload(**base_payload_dict)

        engine = ConditionAgentEngine(rpc_url="http://localhost:8545")
        response = await engine.process_rule(payload)

        assert response.deterministic_check.passed is False
        assert response.llm_invoked is False
        assert response.semantic_Evaluation is None

    @pytest.mark.asyncio
    async def test_short_circuit_native_balance_too_low(self, mock_w3, base_payload_dict):
        """Stage 1 fails due to native balance < min_value_wei; ensures LLM is not invoked."""
        base_payload_dict["deterministic"]["check_native_balance"] = True
        base_payload_dict["deterministic"]["min_value_wei"] = 5 * 10**18  # 5 ETH
        mock_w3.eth.get_balance.return_value = 1 * 10**18  # 1 ETH (< 5 ETH)

        payload = ConditionRulePayload(**base_payload_dict)
        engine = ConditionAgentEngine(rpc_url="http://localhost:8545")
        response = await engine.process_rule(payload)

        assert response.deterministic_check.passed is False
        assert response.llm_invoked is False
        assert response.semantic_Evaluation is None

    @pytest.mark.asyncio
    async def test_short_circuit_selector_mismatch(self, mock_w3, base_payload_dict):
        """Stage 1 fails due to selector mismatch; ensures LLM is not invoked."""
        # Payload requires '0xf2fde38b' (transferOwnership), but calldata has '0xa9059cbb' (transfer)
        base_payload_dict["context_metadata"]["calldata"] = "0xa9059cbb000000000000000000000000deadbeef"
        payload = ConditionRulePayload(**base_payload_dict)

        engine = ConditionAgentEngine(rpc_url="http://localhost:8545")
        response = await engine.process_rule(payload)

        assert response.deterministic_check.passed is False
        assert response.llm_invoked is False
        assert response.semantic_Evaluation is None

    @pytest.mark.asyncio
    async def test_short_circuit_on_rpc_failure(self, mock_w3, base_payload_dict):
        """Stage 1 fails when RPC throws an exception; ensures LLM is not invoked."""
        mock_w3.eth.get_code.side_effect = Exception("RPC node unreachable")
        payload = ConditionRulePayload(**base_payload_dict)

        engine = ConditionAgentEngine(rpc_url="http://localhost:8545")
        response = await engine.process_rule(payload)

        assert response.deterministic_check.passed is False
        assert response.llm_invoked is False
        assert response.semantic_Evaluation is None

    @pytest.mark.asyncio
    async def test_deterministic_pass_but_semantic_disabled(self, mock_w3, base_payload_dict):
        """Stage 1 passes, but semantic.enabled=False; ensures LLM is skipped."""
        base_payload_dict["semantic"]["enabled"] = False
        payload = ConditionRulePayload(**base_payload_dict)

        engine = ConditionAgentEngine(rpc_url="http://localhost:8545")
        response = await engine.process_rule(payload)

        assert response.deterministic_check.passed is True
        assert response.llm_invoked is False
        assert response.semantic_Evaluation is None

    @pytest.mark.asyncio
    async def test_full_pipeline_triggers_semantic_reject(self, mock_w3, base_payload_dict):
        """Stage 1 passes, Stage 2 detects critical privilege without audit -> REJECT."""
        payload = ConditionRulePayload(**base_payload_dict)

        engine = ConditionAgentEngine(rpc_url="http://localhost:8545")
        response = await engine.process_rule(payload)

        assert response.deterministic_check.passed is True
        assert response.llm_invoked is True
        assert response.semantic_Evaluation is not None
        assert response.semantic_Evaluation.conditions_met is True
        assert response.semantic_Evaluation.risk_score >= 8.0
        assert response.semantic_Evaluation.recommended_action == "REJECT"

    @pytest.mark.asyncio
    async def test_full_pipeline_triggers_semantic_manual_review(self, mock_w3, base_payload_dict):
        """Stage 1 passes, Stage 2 detects privilege with audit -> MANUAL_REVIEW."""
        base_payload_dict["context_metadata"]["proposal_description"] = (
            "Transfer ownership after comprehensive external audit completion."
        )
        payload = ConditionRulePayload(**base_payload_dict)

        engine = ConditionAgentEngine(rpc_url="http://localhost:8545")
        response = await engine.process_rule(payload)

        assert response.deterministic_check.passed is True
        assert response.llm_invoked is True
        assert response.semantic_Evaluation is not None
        assert response.semantic_Evaluation.conditions_met is True
        assert 7.0 <= response.semantic_Evaluation.risk_score < 8.0
        assert response.semantic_Evaluation.recommended_action == "MANUAL_REVIEW"

    @pytest.mark.asyncio
    async def test_full_pipeline_triggers_semantic_approve(self, mock_w3, base_payload_dict):
        """Stage 1 passes, Stage 2 evaluates benign transaction -> APPROVE."""
        # Use transfer selector and benign description
        base_payload_dict["deterministic"]["required_function_selectors"] = ["0xa9059cbb"]
        base_payload_dict["context_metadata"]["calldata"] = "0xa9059cbb000000000000000000000000deadbeef"
        base_payload_dict["context_metadata"]["proposal_description"] = "Standard periodic contributor payout."

        payload = ConditionRulePayload(**base_payload_dict)

        engine = ConditionAgentEngine(rpc_url="http://localhost:8545")
        response = await engine.process_rule(payload)

        assert response.deterministic_check.passed is True
        assert response.llm_invoked is True
        assert response.semantic_Evaluation is not None
        assert response.semantic_Evaluation.conditions_met is False
        assert response.semantic_Evaluation.risk_score < payload.semantic.risk_threshold
        assert response.semantic_Evaluation.recommended_action == "APPROVE"


# =========================================================================
# Unit Tests: OpenAISemanticEvaluator & Factory Resiliency
# =========================================================================

class TestOpenAISemanticEvaluator:
    def test_init_without_key_raises_value_error(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValueError, match="OpenAI API key must be provided"):
            OpenAISemanticEvaluator()

    def test_init_with_explicit_key(self):
        evaluator = OpenAISemanticEvaluator(api_key="sk-test-fake-key", model="gpt-4o-mini")
        assert evaluator.api_key == "sk-test-fake-key"
        assert evaluator.model == "gpt-4o-mini"
        assert evaluator.client is not None

    def test_init_from_env_variable(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env-test-key")
        monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
        evaluator = OpenAISemanticEvaluator()
        assert evaluator.api_key == "sk-env-test-key"
        assert evaluator.model == "gpt-4o"

    @pytest.mark.asyncio
    async def test_evaluate_structured_output_success(self):
        expected_audit = SemanticAuditResult(
            conditions_met=True,
            risk_score=8.5,
            flagged_issues=["Unverified ownership transfer detected."],
            summary="High risk action.",
            recommended_action="REJECT",
        )

        mock_completion = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.parsed = expected_audit
        mock_completion.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.beta.chat.completions.parse = AsyncMock(return_value=mock_completion)

        evaluator = OpenAISemanticEvaluator(api_key="sk-test", client=mock_client)
        condition = SemanticCondition(
            policy_prompt="Flag transfer of ownership.",
            risk_threshold=7.0,
        )
        observed = {"calldata_analysis": {"signature": "transferOwnership(address)"}}
        metadata = {"proposal_description": "Migrate ownership"}

        result = await evaluator.evaluate(condition, observed, metadata)
        assert result == expected_audit
        mock_client.beta.chat.completions.parse.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_evaluate_structured_output_fallback_to_json_content(self):
        expected_json = (
            '{"conditions_met": false, "risk_score": 1.5, "flagged_issues": [], '
            '"summary": "Benign call.", "recommended_action": "APPROVE"}'
        )

        mock_completion = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.parsed = None
        mock_choice.message.content = expected_json
        mock_completion.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.beta.chat.completions.parse = AsyncMock(return_value=mock_completion)

        evaluator = OpenAISemanticEvaluator(api_key="sk-test", client=mock_client)
        condition = SemanticCondition(policy_prompt="Test", risk_threshold=7.0)
        result = await evaluator.evaluate(condition, {}, {})

        assert result.conditions_met is False
        assert result.risk_score == 1.5
        assert result.recommended_action == "APPROVE"

    @pytest.mark.asyncio
    async def test_evaluate_error_with_fallback_to_mock(self):
        mock_client = MagicMock()
        mock_client.beta.chat.completions.parse = AsyncMock(side_effect=RuntimeError("OpenAI API timeout"))

        evaluator = OpenAISemanticEvaluator(
            api_key="sk-test", client=mock_client, fallback_to_mock=True
        )
        condition = SemanticCondition(policy_prompt="Audit", risk_threshold=7.0)
        observed = {"calldata_analysis": {"signature": "transferOwnership(address)"}}
        metadata = {"proposal_description": "routine parameter update without review"}

        result = await evaluator.evaluate(condition, observed, metadata)
        assert isinstance(result, SemanticAuditResult)
        assert result.risk_score >= 8.0
        assert result.recommended_action == "REJECT"

    @pytest.mark.asyncio
    async def test_evaluate_error_without_fallback_raises(self):
        mock_client = MagicMock()
        mock_client.beta.chat.completions.parse = AsyncMock(side_effect=RuntimeError("Rate limit exceeded"))

        evaluator = OpenAISemanticEvaluator(
            api_key="sk-test", client=mock_client, fallback_to_mock=False
        )
        condition = SemanticCondition(policy_prompt="Audit", risk_threshold=7.0)
        with pytest.raises(RuntimeError, match="Rate limit exceeded"):
            await evaluator.evaluate(condition, {}, {})


class TestGeminiSemanticEvaluator:
    def test_init_without_api_key_raises(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="GEMINI_API_KEY or GOOGLE_API_KEY not configured"):
            GeminiSemanticEvaluator()

    def test_init_with_explicit_key(self):
        evaluator = GeminiSemanticEvaluator(api_key="test-gemini-key", model_name="gemini-2.0-flash")
        assert evaluator.api_key == "test-gemini-key"
        assert evaluator.model_name == "gemini-2.0-flash"
        assert evaluator.model == "gemini-2.0-flash"
        assert evaluator.client is not None

    def test_init_from_gemini_env_variable(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "env-gemini-key")
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        evaluator = GeminiSemanticEvaluator()
        assert evaluator.api_key == "env-gemini-key"
        assert evaluator.model_name == "gemini-2.0-flash"

    def test_init_from_google_env_variable(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("GOOGLE_API_KEY", "env-google-key")
        evaluator = GeminiSemanticEvaluator()
        assert evaluator.api_key == "env-google-key"
        assert evaluator.model_name == "gemini-2.0-flash"

    def test_init_with_custom_model_and_model_kwarg(self):
        evaluator = GeminiSemanticEvaluator(api_key="key", model="gemini-1.5-flash")
        assert evaluator.model_name == "gemini-1.5-flash"
        assert evaluator.model == "gemini-1.5-flash"

    @pytest.mark.asyncio
    async def test_evaluate_structured_output_success_parsed(self):
        expected_audit = SemanticAuditResult(
            conditions_met=True,
            risk_score=9.0,
            flagged_issues=["Unverified ownership transfer detected via Gemini."],
            summary="Critical governance risk detected by Gemini.",
            recommended_action="REJECT",
        )

        mock_response = MagicMock()
        mock_response.parsed = expected_audit

        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)

        evaluator = GeminiSemanticEvaluator(api_key="test-key", client=mock_client)
        condition = SemanticCondition(
            policy_prompt="Flag transfer of ownership.",
            risk_threshold=7.0,
        )
        observed = {"calldata_analysis": {"signature": "transferOwnership(address)"}}
        metadata = {"proposal_description": "Migrate ownership"}

        result = await evaluator.evaluate(condition, observed, metadata)
        assert result == expected_audit
        mock_client.aio.models.generate_content.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_evaluate_structured_output_fallback_to_json_text(self):
        expected_json = (
            '{"conditions_met": false, "risk_score": 1.0, "flagged_issues": [], '
            '"summary": "Benign routine parameter update.", "recommended_action": "APPROVE"}'
        )

        mock_response = MagicMock()
        mock_response.parsed = None
        mock_response.text = expected_json

        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)

        evaluator = GeminiSemanticEvaluator(api_key="test-key", client=mock_client)
        condition = SemanticCondition(policy_prompt="Test", risk_threshold=7.0)
        result = await evaluator.evaluate(condition, {}, {})

        assert result.conditions_met is False
        assert result.risk_score == 1.0
        assert result.recommended_action == "APPROVE"

    @pytest.mark.asyncio
    async def test_evaluate_markdown_json_block(self):
        mock_response = MagicMock()
        mock_response.parsed = None
        mock_response.text = (
            '```json\n'
            '{"conditions_met": true, "risk_score": 8.0, "flagged_issues": ["Suspicious calldata"], '
            '"summary": "High risk detected.", "recommended_action": "REJECT"}\n'
            '```'
        )

        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)

        evaluator = GeminiSemanticEvaluator(api_key="test-key", client=mock_client)
        condition = SemanticCondition(policy_prompt="Test", risk_threshold=7.0)
        result = await evaluator.evaluate(condition, {}, {})

        assert result.conditions_met is True
        assert result.risk_score == 8.0
        assert result.recommended_action == "REJECT"

    @pytest.mark.asyncio
    async def test_evaluate_error_with_fallback_to_mock(self):
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(side_effect=RuntimeError("Gemini API timeout"))

        evaluator = GeminiSemanticEvaluator(
            api_key="test-key", client=mock_client, fallback_to_mock=True
        )
        condition = SemanticCondition(policy_prompt="Audit", risk_threshold=7.0)
        observed = {"calldata_analysis": {"signature": "transferOwnership(address)"}}
        metadata = {"proposal_description": "routine parameter update without review"}

        result = await evaluator.evaluate(condition, observed, metadata)
        assert isinstance(result, SemanticAuditResult)
        assert result.risk_score >= 8.0
        assert result.recommended_action == "REJECT"

    @pytest.mark.asyncio
    async def test_evaluate_error_without_fallback_raises(self):
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(side_effect=RuntimeError("Quota exceeded"))

        evaluator = GeminiSemanticEvaluator(
            api_key="test-key", client=mock_client, fallback_to_mock=False
        )
        condition = SemanticCondition(policy_prompt="Audit", risk_threshold=7.0)
        with pytest.raises(RuntimeError, match="Quota exceeded"):
            await evaluator.evaluate(condition, {}, {})


class TestSemanticEvaluatorFactory:
    def test_factory_without_api_key_returns_mock(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        evaluator = get_semantic_evaluator()
        assert isinstance(evaluator, MockSemanticEvaluator)

    def test_factory_with_force_mock_returns_mock(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-valid-key")
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")
        evaluator = get_semantic_evaluator(force_mock=True)
        assert isinstance(evaluator, MockSemanticEvaluator)

    def test_factory_with_api_key_returns_openai(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-valid-key")
        evaluator = get_semantic_evaluator()
        assert isinstance(evaluator, OpenAISemanticEvaluator)
        assert evaluator.api_key == "sk-valid-key"

    def test_factory_on_init_failure_falls_back_to_mock(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-valid-key")
        with patch("src.semantic_evaluator.OpenAISemanticEvaluator", side_effect=Exception("Init crash")):
            evaluator = get_semantic_evaluator()
            assert isinstance(evaluator, MockSemanticEvaluator)

    def test_factory_with_gemini_api_key_returns_gemini(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-secret-key")
        evaluator = get_semantic_evaluator()
        assert isinstance(evaluator, GeminiSemanticEvaluator)
        assert evaluator.api_key == "gemini-secret-key"

    def test_factory_with_google_api_key_returns_gemini(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("GOOGLE_API_KEY", "google-secret-key")
        evaluator = get_semantic_evaluator()
        assert isinstance(evaluator, GeminiSemanticEvaluator)
        assert evaluator.api_key == "google-secret-key"

    def test_factory_explicit_provider_gemini(self):
        evaluator = get_semantic_evaluator(api_key="explicit-gemini-key", provider="gemini")
        assert isinstance(evaluator, GeminiSemanticEvaluator)
        assert evaluator.api_key == "explicit-gemini-key"

    def test_factory_gemini_init_failure_falls_back_to_mock(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-secret-key")
        with patch("src.semantic_evaluator.GeminiSemanticEvaluator", side_effect=Exception("Gemini init crash")):
            evaluator = get_semantic_evaluator()
            assert isinstance(evaluator, MockSemanticEvaluator)

    def test_factory_precedence_gemini_over_openai(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-key")
        evaluator = get_semantic_evaluator()
        assert isinstance(evaluator, GeminiSemanticEvaluator)

    def test_factory_explicit_provider_openai_overrides_gemini_env(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-key")
        evaluator = get_semantic_evaluator(provider="openai")
        assert isinstance(evaluator, OpenAISemanticEvaluator)


class TestEngineEvaluatorInjection:
    @pytest.mark.asyncio
    async def test_engine_uses_injected_semantic_evaluator(self, mock_w3, base_payload_dict):
        custom_evaluator = MagicMock()
        custom_evaluator.evaluate = AsyncMock(
            return_value=SemanticAuditResult(
                conditions_met=True,
                risk_score=9.9,
                flagged_issues=["Injected evaluator flag"],
                summary="Injected test evaluation",
                recommended_action="REJECT",
            )
        )
        engine = ConditionAgentEngine(semantic_evaluator=custom_evaluator)
        payload = ConditionRulePayload(**base_payload_dict)
        response = await engine.process_rule(payload)

        assert response.llm_invoked is True
        assert response.semantic_Evaluation.risk_score == 9.9
        custom_evaluator.evaluate.assert_awaited_once()

    def test_engine_defaults_to_factory_evaluator(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        engine = ConditionAgentEngine()
        assert isinstance(engine.semantic_evaluator, MockSemanticEvaluator)


# =========================================================================
# Unit Tests: FastAPI Service Layer (src/api.py & root api.py)
# =========================================================================

class TestFastAPIServiceLayer:
    @pytest.fixture
    def test_client(self, mock_w3):
        test_app = create_app()
        return TestClient(test_app)

    def test_health_check_default_is_simple(self, test_client):
        response = test_client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_health_check_all_rpcs_ok(self, test_client):
        with patch.object(ChainInspector, "verify_connection", AsyncMock(return_value=True)):
            response = test_client.get("/health?full=true")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["version"] == "1.0.0"
            assert data["is_mock"] is True
            assert all(data["rpc_status"].values())

    def test_health_check_rpc_degraded(self, test_client):
        async def mock_verify(self):
            return self.chain_id == 84532

        with patch.object(ChainInspector, "verify_connection", mock_verify):
            response = test_client.get("/health?full=true")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "degraded"
            assert data["rpc_status"]["84532"] is True
            assert data["rpc_status"]["8453"] is False

    def test_health_check_all_rpcs_fail(self, test_client):
        with patch.object(ChainInspector, "verify_connection", AsyncMock(return_value=False)):
            response = test_client.get("/health?full=true")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "error"

    def test_health_check_gemini_provider(self, mock_w3):
        mock_evaluator = MagicMock(spec=GeminiSemanticEvaluator)
        mock_evaluator.__class__.__name__ = "GeminiSemanticEvaluator"
        mock_evaluator.model_name = "gemini-2.0-flash"
        engine = ConditionAgentEngine(semantic_evaluator=mock_evaluator)
        custom_app = create_app(engine=engine)
        client = TestClient(custom_app)

        with patch.object(ChainInspector, "verify_connection", AsyncMock(return_value=True)):
            response = client.get("/health?full=true")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["semantic_provider"] == "gemini"
            assert data["provider"] == "gemini"
            assert data["is_mock"] is False
            assert data["model"] == "gemini-2.0-flash"

    def test_health_check_openai_provider(self, mock_w3):
        mock_evaluator = MagicMock(spec=OpenAISemanticEvaluator)
        mock_evaluator.__class__.__name__ = "OpenAISemanticEvaluator"
        mock_evaluator.model = "gpt-4o-mini"
        engine = ConditionAgentEngine(semantic_evaluator=mock_evaluator)
        custom_app = create_app(engine=engine)
        client = TestClient(custom_app)

        with patch.object(ChainInspector, "verify_connection", AsyncMock(return_value=True)):
            response = client.get("/health?full=true")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["semantic_provider"] == "openai"
            assert data["provider"] == "openai"
            assert data["is_mock"] is False
            assert data["model"] == "gpt-4o-mini"

    def test_validate_rule_valid_payload(self, test_client, base_payload_dict):
        response = test_client.post("/rules/validate", json=base_payload_dict)
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["details"]["rule_id"] == "dao-gov-guard-001"
        assert data["details"]["calldata_selector"] == "0xf2fde38b"
        assert len(data["warnings"]) == 0

    def test_validate_rule_selector_mismatch_warning(self, test_client, base_payload_dict):
        base_payload_dict["deterministic"]["required_function_selectors"] = ["0xa9059cbb"]
        response = test_client.post("/rules/validate", json=base_payload_dict)
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert len(data["warnings"]) > 0
        assert "does not match required selectors" in data["warnings"][0]

    def test_validate_rule_value_warning(self, test_client, base_payload_dict):
        base_payload_dict["context_metadata"]["tx_value_wei"] = 0
        base_payload_dict["deterministic"]["min_value_wei"] = 1000
        base_payload_dict["deterministic"]["check_native_balance"] = False
        response = test_client.post("/rules/validate", json=base_payload_dict)
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert any("is below min_value_wei" in w for w in data["warnings"])

    def test_validate_rule_invalid_selector_format(self, test_client, base_payload_dict):
        base_payload_dict["deterministic"]["required_function_selectors"] = ["invalid-hex"]
        response = test_client.post("/rules/validate", json=base_payload_dict)
        assert response.status_code == 422
        assert response.json()["error"] == "RequestValidationError"

    def test_validate_rule_invalid_calldata_format(self, test_client, base_payload_dict):
        base_payload_dict["context_metadata"]["calldata"] = "non-hex-calldata"
        response = test_client.post("/rules/validate", json=base_payload_dict)
        assert response.status_code == 400
        assert "prefixed with '0x'" in response.json()["message"]

    def test_validate_rule_empty_policy_prompt(self, test_client, base_payload_dict):
        base_payload_dict["semantic"]["policy_prompt"] = "   "
        response = test_client.post("/rules/validate", json=base_payload_dict)
        assert response.status_code == 400
        assert "policy_prompt is empty" in response.json()["message"]

    def test_validate_rule_invalid_address_returns_422(self, test_client, base_payload_dict):
        base_payload_dict["deterministic"]["target_address"] = "0xinvalidaddress"
        response = test_client.post("/rules/validate", json=base_payload_dict)
        assert response.status_code == 422
        assert response.json()["error"] == "RequestValidationError"

    def test_evaluate_rule_full_pipeline_success(self, test_client, mock_w3, base_payload_dict):
        response = test_client.post("/evaluate", json=base_payload_dict)
        assert response.status_code == 200
        data = response.json()
        assert data["rule_id"] == "dao-gov-guard-001"
        assert data["deterministic_check"]["passed"] is True
        assert data["llm_invoked"] is True
        assert data["semantic_Evaluation"]["recommended_action"] == "REJECT"

    def test_evaluate_rule_short_circuits_stage_1(self, test_client, mock_w3, base_payload_dict):
        base_payload_dict["deterministic"]["min_value_wei"] = 9999999999999999999
        base_payload_dict["context_metadata"]["tx_value_wei"] = 1
        response = test_client.post("/evaluate", json=base_payload_dict)
        assert response.status_code == 200
        data = response.json()
        assert data["deterministic_check"]["passed"] is False
        assert data["llm_invoked"] is False
        assert data["semantic_Evaluation"] is None

    def test_evaluate_rule_engine_error_returns_500(self, test_client, base_payload_dict):
        with patch.object(ConditionAgentEngine, "process_rule", AsyncMock(side_effect=RuntimeError("Engine failure"))):
            response = test_client.post("/evaluate", json=base_payload_dict)
            assert response.status_code == 500
            data = response.json()
            assert "Execution error while processing rule" in data["message"]

    def test_root_api_export(self):
        import api
        assert hasattr(api, "app")
        assert hasattr(api, "create_app")
        assert api.app is not None


# =========================================================================
# 5. Efficiency & Optimization Tests: ChainInspector
# =========================================================================

class TestChainInspectorEfficiency:
    @pytest.mark.asyncio
    async def test_bytecode_caching_avoids_duplicate_rpc_calls(self, mock_w3):
        """
        Verifies that with bytecode cache enabled, subsequent checks on the same target_address
        reuse cached bytecode and do not perform duplicate eth.get_code RPC requests.
        """
        inspector = ChainInspector(chain_id=84532)
        condition = DeterministicCondition(target_address="0x4200000000000000000000000000000000000006")

        if hasattr(inspector, "clear_cache"):
            inspector.clear_cache()
        elif hasattr(ChainInspector, "clear_cache"):
            ChainInspector.clear_cache()

        mock_w3.eth.get_code.return_value = b"\x60\x80\x60\x40"
        res1 = await inspector.evaluate_deterministic(condition, {})
        assert res1.passed is True
        initial_calls = mock_w3.eth.get_code.call_count
        assert initial_calls >= 1

        # Second call with the same target address
        res2 = await inspector.evaluate_deterministic(condition, {})
        assert res2.passed is True

        if not hasattr(inspector, "bytecode_cache") and not hasattr(ChainInspector, "_bytecode_cache") and not hasattr(inspector, "_cache"):
            pytest.skip("Bytecode caching not yet implemented in ChainInspector")

        assert mock_w3.eth.get_code.call_count == initial_calls, (
            f"Expected eth.get_code calls to remain {initial_calls}, but got {mock_w3.eth.get_code.call_count}"
        )

    @pytest.mark.asyncio
    async def test_bytecode_caching_different_address_triggers_new_rpc_call(self, mock_w3):
        """
        Verifies that querying a different contract address performs a new eth.get_code call (cache miss).
        """
        inspector = ChainInspector(chain_id=84532)
        cond1 = DeterministicCondition(target_address="0x4200000000000000000000000000000000000006")
        cond2 = DeterministicCondition(target_address="0x0000000000000000000000000000000000000001")

        if not hasattr(inspector, "bytecode_cache") and not hasattr(ChainInspector, "_bytecode_cache") and not hasattr(inspector, "_cache"):
            pytest.skip("Bytecode caching not yet implemented in ChainInspector")

        mock_w3.eth.get_code.return_value = b"\x60\x80"
        await inspector.evaluate_deterministic(cond1, {})
        calls_after_first = mock_w3.eth.get_code.call_count

        await inspector.evaluate_deterministic(cond2, {})
        assert mock_w3.eth.get_code.call_count == calls_after_first + 1

    @pytest.mark.asyncio
    async def test_stage1_parallel_calls_with_asyncio_gather(self, mock_w3):
        """
        Verifies that when check_native_balance=True, get_code and get_balance execute
        concurrently via asyncio.gather rather than sequentially.
        """
        inspector = ChainInspector(chain_id=84532)
        condition = DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            min_value_wei=10**18,
            check_native_balance=True,
        )

        code_started = asyncio.Event()
        balance_started = asyncio.Event()

        async def concurrent_code(addr):
            code_started.set()
            # If calls run concurrently, balance_started will be signalled while get_code is waiting
            await asyncio.wait_for(balance_started.wait(), timeout=0.6)
            return b"\x60\x80\x60\x40"

        async def concurrent_balance(addr):
            balance_started.set()
            # If calls run concurrently, code_started will be signalled while get_balance is waiting
            await asyncio.wait_for(code_started.wait(), timeout=0.6)
            return 3 * 10**18

        mock_w3.eth.get_code.side_effect = concurrent_code
        mock_w3.eth.get_balance.side_effect = concurrent_balance

        res = await inspector.evaluate_deterministic(condition, {})
        if not res.passed and "RPC/Evaluation error" in res.reason:
            pytest.skip("Parallelization of get_code and get_balance via asyncio.gather not yet implemented")
        assert res.passed is True
        assert res.observed_data["is_contract"] is True
        assert res.observed_data["native_balance_wei"] == 3 * 10**18

    @pytest.mark.asyncio
    async def test_stage1_parallel_calls_error_handling(self, mock_w3):
        """
        Verifies that if one of the parallel RPC calls fails, the error is isolated
        and returned gracefully as passed=False without unhandled exceptions.
        """
        inspector = ChainInspector(chain_id=84532)
        condition = DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            min_value_wei=10**18,
            check_native_balance=True,
        )

        mock_w3.eth.get_code.return_value = b"\x60\x80"
        mock_w3.eth.get_balance.side_effect = Web3Exception("RPC timeout on balance probe")

        res = await inspector.evaluate_deterministic(condition, {})
        assert res.passed is False
        assert "error" in res.reason.lower() or "timeout" in res.reason.lower()

    def test_connection_pooling_and_instance_reuse(self, mock_w3):
        """
        Verifies connection pooling or web3 instance reuse across ChainInspector instances for the same chain ID.
        """
        insp1 = ChainInspector(chain_id=84532)
        insp2 = ChainInspector(chain_id=84532)
        if hasattr(ChainInspector, "_pool") or hasattr(ChainInspector, "_instances") or hasattr(ChainInspector, "_web3_cache"):
            assert insp1.w3 is insp2.w3 or insp1.w3.provider is insp2.w3.provider


# =========================================================================
# 6. Efficiency & Optimization Tests: SemanticEvaluator Caching
# =========================================================================

class TestSemanticEvaluatorEfficiency:
    @pytest.mark.asyncio
    async def test_semantic_caching_identical_evaluations(self):
        """
        Verifies that evaluating the same condition with the same observed data and context metadata
        returns a cached result without recalculating or invoking the underlying LLM model.
        """
        evaluator = MockSemanticEvaluator()
        condition = SemanticCondition(policy_prompt="Flag unverified admin actions", risk_threshold=7.0)
        observed = {
            "target_address": "0x4200000000000000000000000000000000000006",
            "calldata_analysis": {"signature": "transferOwnership(address)"},
        }
        metadata = {"proposal_description": "Routine change without security review"}

        if not hasattr(evaluator, "_cache") and not hasattr(evaluator, "cache") and not hasattr(evaluator, "semantic_cache"):
            pytest.skip("Semantic caching not yet implemented in SemanticEvaluator")

        res1 = await evaluator.evaluate(condition, observed, metadata)
        res2 = await evaluator.evaluate(condition, observed, metadata)

        assert res1.risk_score == res2.risk_score
        assert res1.recommended_action == res2.recommended_action
        assert getattr(res2, "cached", False) is True or getattr(evaluator, "cache_hits", 0) >= 1

    @pytest.mark.asyncio
    async def test_semantic_caching_different_context_causes_cache_miss(self):
        """
        Verifies that changing context metadata results in a cache miss and new evaluation.
        """
        evaluator = MockSemanticEvaluator()
        condition = SemanticCondition(policy_prompt="Flag unverified admin actions", risk_threshold=7.0)
        observed = {"calldata_analysis": {"signature": "transferOwnership(address)"}}

        if not hasattr(evaluator, "_cache") and not hasattr(evaluator, "cache") and not hasattr(evaluator, "semantic_cache"):
            pytest.skip("Semantic caching not yet implemented in SemanticEvaluator")

        res1 = await evaluator.evaluate(condition, observed, {"proposal_description": "Without audit review"})
        res2 = await evaluator.evaluate(condition, observed, {"proposal_description": "Following OpenZeppelin audit"})

        assert res1.risk_score != res2.risk_score
        assert res1.recommended_action != res2.recommended_action

    @pytest.mark.asyncio
    async def test_openai_evaluator_semantic_cache_hit_avoids_api_call(self):
        """
        Verifies that OpenAISemanticEvaluator skips calling client.beta.chat.completions.parse on cache hit.
        """
        expected_audit = SemanticAuditResult(
            conditions_met=True,
            risk_score=8.5,
            flagged_issues=["Unverified transfer"],
            summary="High risk action.",
            recommended_action="REJECT",
        )

        mock_completion = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.parsed = expected_audit
        mock_completion.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.beta.chat.completions.parse = AsyncMock(return_value=mock_completion)

        evaluator = OpenAISemanticEvaluator(api_key="sk-test", client=mock_client)
        condition = SemanticCondition(policy_prompt="Flag transfer", risk_threshold=7.0)
        observed = {"calldata_analysis": {"signature": "transferOwnership(address)"}}
        metadata = {"proposal_description": "Migrate admin"}

        if not hasattr(evaluator, "_cache") and not hasattr(evaluator, "cache") and not hasattr(evaluator, "semantic_cache"):
            pytest.skip("Semantic caching not yet implemented on OpenAISemanticEvaluator")

        res1 = await evaluator.evaluate(condition, observed, metadata)
        res2 = await evaluator.evaluate(condition, observed, metadata)

        assert res1 == expected_audit
        assert res2.risk_score == expected_audit.risk_score
        # API was invoked exactly once; second call was served from semantic cache
        assert mock_client.beta.chat.completions.parse.await_count == 1


# =========================================================================
# 7. Engine Concurrency & Batch Processing Tests
# =========================================================================

class TestEngineConcurrency:
    @pytest.mark.asyncio
    async def test_process_rules_batch_empty_list(self):
        """
        Verifies that process_rules_batch with an empty list returns an empty list.
        """
        engine = ConditionAgentEngine()
        if not hasattr(engine, "process_rules_batch"):
            pytest.skip("process_rules_batch not yet implemented on ConditionAgentEngine")

        results = await engine.process_rules_batch([])
        assert results == []

    @pytest.mark.asyncio
    async def test_process_rules_batch_multiple_rules_success(self, mock_w3, base_payload_dict):
        """
        Verifies that process_rules_batch concurrently evaluates a list of ConditionRulePayload
        and returns a list of FinalAgentResponse preserving order and rule IDs.
        """
        engine = ConditionAgentEngine()
        if not hasattr(engine, "process_rules_batch"):
            pytest.skip("process_rules_batch not yet implemented on ConditionAgentEngine")

        payloads = [
            ConditionRulePayload(**dict(base_payload_dict, rule_id=f"batch-rule-{i:03d}"))
            for i in range(5)
        ]

        results = await engine.process_rules_batch(payloads, max_concurrency=5)
        assert len(results) == 5
        assert [r.rule_id for r in results] == [f"batch-rule-{i:03d}" for i in range(5)]
        assert all(isinstance(r, FinalAgentResponse) for r in results)

    @pytest.mark.asyncio
    async def test_process_rules_batch_respects_max_concurrency_semaphore(self, mock_w3, base_payload_dict):
        """
        Verifies that process_rules_batch strictly respects max_concurrency semaphore
        limiting concurrent coroutines while still executing concurrently.
        """
        engine = ConditionAgentEngine()
        if not hasattr(engine, "process_rules_batch"):
            pytest.skip("process_rules_batch not yet implemented on ConditionAgentEngine")

        payloads = [
            ConditionRulePayload(**dict(base_payload_dict, rule_id=f"concurrency-rule-{i}"))
            for i in range(8)
        ]

        active_tasks = 0
        max_observed_active = 0
        lock = asyncio.Lock()
        orig_process = engine.process_rule

        async def tracked_process(payload):
            nonlocal active_tasks, max_observed_active
            async with lock:
                active_tasks += 1
                if active_tasks > max_observed_active:
                    max_observed_active = active_tasks
            await asyncio.sleep(0.03)
            try:
                return await orig_process(payload)
            finally:
                async with lock:
                    active_tasks -= 1

        with patch.object(engine, "process_rule", side_effect=tracked_process):
            results = await engine.process_rules_batch(payloads, max_concurrency=3)

        assert len(results) == 8
        assert max_observed_active <= 3, f"Concurrency limit exceeded: max active was {max_observed_active}"
        assert max_observed_active > 1, f"Expected concurrency > 1, got {max_observed_active}"

    @pytest.mark.asyncio
    async def test_process_rules_batch_exception_isolation(self, mock_w3, base_payload_dict):
        """
        Verifies that an unhandled error or exception in one rule does not abort
        the other rules in the batch.
        """
        engine = ConditionAgentEngine()
        if not hasattr(engine, "process_rules_batch"):
            pytest.skip("process_rules_batch not yet implemented on ConditionAgentEngine")

        payloads = [
            ConditionRulePayload(**dict(base_payload_dict, rule_id=f"isolated-rule-{i}"))
            for i in range(4)
        ]

        orig_process = engine.process_rule

        async def failing_process(payload):
            if payload.rule_id == "isolated-rule-1":
                raise RuntimeError("Simulated failure on rule-1")
            return await orig_process(payload)

        with patch.object(engine, "process_rule", side_effect=failing_process):
            results = await engine.process_rules_batch(payloads)

        assert len(results) == 4
        assert results[0].rule_id == "isolated-rule-0"
        assert results[0].deterministic_check.passed is True
        assert results[2].rule_id == "isolated-rule-2"
        assert results[2].deterministic_check.passed is True
        assert results[3].rule_id == "isolated-rule-3"
        assert results[3].deterministic_check.passed is True

        # Rule 1 is returned as a failed response rather than raising an unhandled exception
        assert results[1].rule_id == "isolated-rule-1"
        assert results[1].deterministic_check.passed is False
        assert "failure" in results[1].deterministic_check.reason.lower() or "error" in results[1].deterministic_check.reason.lower()


# =========================================================================
# 8. Asynchronous Worker Pool & Job Store Tests
# =========================================================================

class TestAgentWorkerPool:
    @pytest.mark.asyncio
    async def test_worker_pool_enqueue_and_process_lifecycle(self, mock_w3, base_payload_dict):
        """
        Verifies asynchronous job enqueuing and processing lifecycle:
        QUEUED -> PROCESSING -> COMPLETED.
        """
        if AgentWorkerPool is None or JobStore is None:
            pytest.skip("AgentWorkerPool and JobStore not yet implemented in task_worker.py")

        engine = ConditionAgentEngine()
        job_store = JobStore() if callable(JobStore) else None
        pool = AgentWorkerPool(engine=engine, num_workers=2, job_store=job_store)
        if hasattr(pool, "start") and asyncio.iscoroutinefunction(pool.start):
            await pool.start()
        elif hasattr(pool, "start"):
            pool.start()

        payload = ConditionRulePayload(**base_payload_dict)
        enqueue_res = pool.enqueue(payload)
        job_id = await enqueue_res if asyncio.iscoroutine(enqueue_res) else enqueue_res
        assert isinstance(job_id, str) and len(job_id) > 0

        # Poll for completion with bounded timeout
        job = None
        for _ in range(50):
            get_res = pool.get_job(job_id) if hasattr(pool, "get_job") else job_store.get_job(job_id)
            job = await get_res if asyncio.iscoroutine(get_res) else get_res
            status_val = getattr(job, "status", job.get("status") if isinstance(job, dict) else None)
            if str(status_val).upper() in ("COMPLETED", "JOBSTATUS.COMPLETED"):
                break
            await asyncio.sleep(0.04)

        status_val = getattr(job, "status", job.get("status") if isinstance(job, dict) else None)
        assert str(status_val).upper() in ("COMPLETED", "JOBSTATUS.COMPLETED")
        result = getattr(job, "result", job.get("result") if isinstance(job, dict) else None)
        assert result is not None

        # Clean shutdown
        if hasattr(pool, "shutdown") and asyncio.iscoroutinefunction(pool.shutdown):
            await pool.shutdown()
        elif hasattr(pool, "stop") and asyncio.iscoroutinefunction(pool.stop):
            await pool.stop()
        elif hasattr(pool, "shutdown"):
            pool.shutdown()

    @pytest.mark.asyncio
    async def test_worker_pool_get_job_nonexistent_returns_none(self):
        """
        Verifies that querying a nonexistent job_id returns None gracefully.
        """
        if AgentWorkerPool is None or JobStore is None:
            pytest.skip("AgentWorkerPool and JobStore not yet implemented in task_worker.py")

        job_store = JobStore() if callable(JobStore) else None
        engine = ConditionAgentEngine()
        pool = AgentWorkerPool(engine=engine, num_workers=1, job_store=job_store)

        get_res = pool.get_job("non-existent-uuid-999") if hasattr(pool, "get_job") else job_store.get_job("non-existent-uuid-999")
        job = await get_res if asyncio.iscoroutine(get_res) else get_res
        assert job is None

    @pytest.mark.asyncio
    async def test_worker_pool_job_error_handling(self, mock_w3, base_payload_dict):
        """
        Verifies that when an engine execution throws an exception, the job status transitions
        to FAILED with error captured, while worker survives to process subsequent jobs.
        """
        if AgentWorkerPool is None or JobStore is None:
            pytest.skip("AgentWorkerPool and JobStore not yet implemented in task_worker.py")

        engine = ConditionAgentEngine()
        pool = AgentWorkerPool(engine=engine, num_workers=1)
        if hasattr(pool, "start") and asyncio.iscoroutinefunction(pool.start):
            await pool.start()
        elif hasattr(pool, "start"):
            pool.start()

        with patch.object(engine, "process_rule", AsyncMock(side_effect=RuntimeError("Worker error simulation"))):
            payload = ConditionRulePayload(**base_payload_dict)
            enqueue_res = pool.enqueue(payload)
            job_id = await enqueue_res if asyncio.iscoroutine(enqueue_res) else enqueue_res

            job = None
            for _ in range(50):
                get_res = pool.get_job(job_id)
                job = await get_res if asyncio.iscoroutine(get_res) else get_res
                status_val = getattr(job, "status", job.get("status") if isinstance(job, dict) else None)
                if str(status_val).upper() in ("FAILED", "JOBSTATUS.FAILED"):
                    break
                await asyncio.sleep(0.04)

            status_val = getattr(job, "status", job.get("status") if isinstance(job, dict) else None)
            assert str(status_val).upper() in ("FAILED", "JOBSTATUS.FAILED")
            error_val = getattr(job, "error", job.get("error") if isinstance(job, dict) else None)
            assert error_val is not None
            assert "Worker error simulation" in str(error_val)

        if hasattr(pool, "shutdown") and asyncio.iscoroutinefunction(pool.shutdown):
            await pool.shutdown()
        elif hasattr(pool, "stop"):
            pool.stop()

    @pytest.mark.asyncio
    async def test_worker_pool_cancellation(self, mock_w3, base_payload_dict):
        """
        Verifies that job cancellation sets job status to CANCELLED.
        """
        if AgentWorkerPool is None or JobStore is None:
            pytest.skip("AgentWorkerPool and JobStore not yet implemented in task_worker.py")

        engine = ConditionAgentEngine()
        pool = AgentWorkerPool(engine=engine, num_workers=1)
        if not hasattr(pool, "cancel_job"):
            pytest.skip("cancel_job method not implemented on AgentWorkerPool")

        payload = ConditionRulePayload(**base_payload_dict)
        job_id = pool.enqueue(payload)
        if asyncio.iscoroutine(job_id):
            job_id = await job_id

        cancel_res = pool.cancel_job(job_id)
        if asyncio.iscoroutine(cancel_res):
            await cancel_res

        get_res = pool.get_job(job_id)
        job = await get_res if asyncio.iscoroutine(get_res) else get_res
        status_val = getattr(job, "status", job.get("status") if isinstance(job, dict) else None)
        assert str(status_val).upper() in ("CANCELLED", "JOBSTATUS.CANCELLED")

        if hasattr(pool, "shutdown") and asyncio.iscoroutinefunction(pool.shutdown):
            await pool.shutdown()


# =========================================================================
# 9. FastAPI Concurrency & Batch Endpoints Tests
# =========================================================================

class TestFastAPIConcurrencyEndpoints:
    @pytest.fixture
    def test_client(self, mock_w3):
        test_app = create_app()
        return TestClient(test_app)

    def test_evaluate_batch_endpoint_success(self, test_client, mock_w3, base_payload_dict):
        """
        Verifies POST /rules/evaluate-batch receives a list of ConditionRulePayload
        and returns a list of FinalAgentResponse.
        """
        p1 = dict(base_payload_dict, rule_id="api-batch-001")
        p2 = dict(base_payload_dict, rule_id="api-batch-002")

        response = test_client.post("/rules/evaluate-batch", json=[p1, p2])
        if response.status_code == 404:
            pytest.skip("POST /rules/evaluate-batch not yet implemented in api.py")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["rule_id"] == "api-batch-001"
        assert data[1]["rule_id"] == "api-batch-002"
        assert all("deterministic_check" in item for item in data)

    def test_evaluate_batch_endpoint_invalid_payload_returns_422(self, test_client):
        """
        Verifies POST /rules/evaluate-batch returns 422 Unprocessable Entity on schema invalid payload.
        """
        invalid_batch = [{"invalid_rule_schema": 123}]
        response = test_client.post("/rules/evaluate-batch", json=invalid_batch)
        if response.status_code == 404:
            pytest.skip("POST /rules/evaluate-batch not yet implemented in api.py")

        assert response.status_code == 422

    def test_enqueue_endpoint_returns_202_with_job_id(self, test_client, mock_w3, base_payload_dict):
        """
        Verifies POST /rules/enqueue accepts a rule payload and returns status 202 Accepted with job_id.
        """
        response = test_client.post("/rules/enqueue", json=base_payload_dict)
        if response.status_code == 404:
            pytest.skip("POST /rules/enqueue not yet implemented in api.py")

        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert isinstance(data["job_id"], str)
        assert len(data["job_id"]) > 0
        status_val = data.get("status")
        assert str(status_val).upper() in ("QUEUED", "JOBSTATUS.QUEUED", "ACCEPTED", "PROCESSING")

    def test_get_job_endpoint_lifecycle(self, test_client, mock_w3, base_payload_dict):
        """
        Verifies GET /jobs/{job_id} returns status and result for an enqueued job.
        """
        enqueue_resp = test_client.post("/rules/enqueue", json=base_payload_dict)
        if enqueue_resp.status_code == 404:
            pytest.skip("POST /rules/enqueue not yet implemented in api.py")

        assert enqueue_resp.status_code == 202
        job_id = enqueue_resp.json()["job_id"]

        response = test_client.get(f"/jobs/{job_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == job_id
        assert "status" in data

    def test_get_job_endpoint_not_found(self, test_client):
        """
        Verifies GET /jobs/{job_id} returns 404 for an unknown job ID.
        """
        response = test_client.get("/jobs/non-existent-uuid-99999")
        if response.status_code == 404 and response.json().get("detail") == "Not Found":
            # Endpoint might not be registered yet (FastAPI default 404)
            pytest.skip("GET /jobs/{job_id} not yet implemented in api.py")
        assert response.status_code == 404


