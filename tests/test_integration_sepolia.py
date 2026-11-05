import os
import sys
import asyncio
import pytest
import pytest_asyncio
from web3 import AsyncWeb3, AsyncHTTPProvider

# Ensure workspace root and src directory are on sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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

    sys.modules.setdefault("schemas", schemas_module)
    sys.modules.setdefault("chain_inspector", chain_inspector_module)
    sys.modules.setdefault("semantic_evaluator", semantic_evaluator_module)
    sys.modules.setdefault("engine", engine_module)
except ImportError:
    import schemas as schemas_module
    import chain_inspector as chain_inspector_module
    import semantic_evaluator as semantic_evaluator_module
    import engine as engine_module

    sys.modules.setdefault("src.schemas", schemas_module)
    sys.modules.setdefault("src.chain_inspector", chain_inspector_module)
    sys.modules.setdefault("src.semantic_evaluator", semantic_evaluator_module)
    sys.modules.setdefault("src.engine", engine_module)

from unittest.mock import patch

from schemas import (
    ChainId,
    DeterministicCondition,
    SemanticCondition,
    ConditionRulePayload,
    FinalAgentResponse,
)
from chain_inspector import ChainInspector
from engine import ConditionAgentEngine
from semantic_evaluator import MockSemanticEvaluator


# ---------------------------------------------------------------------------
# Constants for Base Sepolia Testnet
# ---------------------------------------------------------------------------
BASE_SEPOLIA_CHAIN_ID = 84532
BASE_SEPOLIA_RPC = "https://sepolia.base.org"
# Official Wrapped Ether (WETH9) address on Base Sepolia
WETH9_ADDRESS = "0x4200000000000000000000000000000000000006"
# Standard Externally Owned Account (EOA) for bytecode absence test
VITALIK_EOA_ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


# ---------------------------------------------------------------------------
# Fixtures and Network Health Verification
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def ensure_sepolia_available():
    """
    Verifies that the Base Sepolia public RPC endpoint is accessible.
    If the endpoint is unreachable, down, or times out, gracefully skips
    the test to prevent CI/local offline build disruptions.
    """
    inspector = ChainInspector(chain_id=BASE_SEPOLIA_CHAIN_ID, rpc_url=BASE_SEPOLIA_RPC)
    try:
        is_connected = await asyncio.wait_for(inspector.verify_connection(), timeout=10.0)
        if not is_connected:
            pytest.skip("Base Sepolia public RPC (https://sepolia.base.org) returned is_connected=False.")
    except Exception as exc:
        pytest.skip(f"Base Sepolia public RPC connection failed or timed out: {exc}")

    try:
        yield inspector
    finally:
        try:
            disconnect_fn = getattr(inspector.w3.provider, "disconnect", None)
            if disconnect_fn:
                res = disconnect_fn()
                if asyncio.iscoroutine(res):
                    await res
        except Exception:
            pass


@pytest_asyncio.fixture
async def sepolia_engine(ensure_sepolia_available):
    """
    Provides a real ConditionAgentEngine targeting Base Sepolia.
    Tracks instantiated ChainInspectors and gracefully disconnects their
    AsyncHTTPProviders on fixture teardown to prevent unclosed aiohttp sessions.
    """
    engine = ConditionAgentEngine(
        rpc_url=BASE_SEPOLIA_RPC, semantic_evaluator=MockSemanticEvaluator()
    )
    active_inspectors = []

    class TrackingChainInspector(ChainInspector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            active_inspectors.append(self)

    with patch("engine.ChainInspector", TrackingChainInspector), \
         patch("src.engine.ChainInspector", TrackingChainInspector):
        try:
            yield engine
        finally:
            for insp in active_inspectors:
                try:
                    disconnect_fn = getattr(insp.w3.provider, "disconnect", None)
                    if disconnect_fn:
                        res = disconnect_fn()
                        if asyncio.iscoroutine(res):
                            await res
                except Exception:
                    pass



@pytest.fixture
def sepolia_weth_transfer_payload():
    """
    Constructs a sample ConditionRulePayload targeting WETH9 on Base Sepolia
    with an ERC-20 transfer calldata payload.
    """
    return {
        "rule_id": "sepolia-weth-transfer-guard-001",
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "deterministic": {
            "target_address": WETH9_ADDRESS,
            "min_value_wei": 1000,
            "required_function_selectors": ["0xa9059cbb"],  # transfer(address,uint256)
            "check_native_balance": False,
        },
        "semantic": {
            "enabled": True,
            "policy_prompt": "Audit any transfer over 1000 wei for governance approval.",
            "risk_threshold": 7.0,
        },
        "context_metadata": {
            "tx_value_wei": 5000,
            # ERC-20 transfer(to=0xdead...beef, amount=5000)
            "calldata": "0xa9059cbb000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0000000000000000000000000000000000000000000000000000000000001388",
            "proposal_description": "Grant distribution to core protocol developer.",
        },
    }


# ---------------------------------------------------------------------------
# 1. ChainInspector On-Chain Tests (Base Sepolia)
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSepoliaChainInspector:
    """
    Real on-chain tests validating ChainInspector against Base Sepolia RPC.
    Does NOT use mocks: all RPC calls are dispatched live to https://sepolia.base.org.
    """

    @pytest.mark.asyncio
    async def test_sepolia_verify_connection_and_chain_id(self, ensure_sepolia_available):
        """Verifies direct RPC handshake and confirms Base Sepolia Chain ID (84532)."""
        inspector = ensure_sepolia_available

        is_connected = await inspector.verify_connection()
        assert is_connected is True

        chain_id = await inspector.w3.eth.chain_id
        assert chain_id == BASE_SEPOLIA_CHAIN_ID

        block_number = await inspector.w3.eth.block_number
        assert block_number > 0

    @pytest.mark.asyncio
    async def test_sepolia_bytecode_detection_contract(self, ensure_sepolia_available):
        """Verifies that WETH9 on Base Sepolia is correctly recognized as a Smart Contract (is_contract == True)."""
        inspector = ensure_sepolia_available

        condition = DeterministicCondition(
            target_address=WETH9_ADDRESS,
            min_value_wei=0,
            check_native_balance=False,
        )

        result = await inspector.evaluate_deterministic(condition=condition, context={})
        assert result.passed is True
        assert result.observed_data["target_address"] == WETH9_ADDRESS
        assert result.observed_data["is_contract"] is True

        # Directly query RPC to double-check bytecode size
        bytecode = await inspector.w3.eth.get_code(WETH9_ADDRESS)
        assert len(bytecode) > 0

    @pytest.mark.asyncio
    async def test_sepolia_bytecode_detection_eoa(self, ensure_sepolia_available):
        """Verifies that an EOA address has no deployed bytecode (is_contract == False)."""
        inspector = ensure_sepolia_available

        condition = DeterministicCondition(
            target_address=VITALIK_EOA_ADDRESS,
            min_value_wei=0,
            check_native_balance=False,
        )

        result = await inspector.evaluate_deterministic(condition=condition, context={})
        assert result.passed is True
        assert result.observed_data["target_address"] == VITALIK_EOA_ADDRESS
        assert result.observed_data["is_contract"] is False

        # Directly query RPC to confirm empty bytecode
        bytecode = await inspector.w3.eth.get_code(VITALIK_EOA_ADDRESS)
        assert len(bytecode) == 0

    @pytest.mark.asyncio
    async def test_sepolia_calldata_selector_filtering_match(self, ensure_sepolia_available):
        """Verifies selector match (0xa9059cbb - transfer) against Base Sepolia contract."""
        inspector = ensure_sepolia_available

        condition = DeterministicCondition(
            target_address=WETH9_ADDRESS,
            min_value_wei=1000,
            required_function_selectors=["0xa9059cbb"],
        )
        context = {
            "tx_value_wei": 2000,
            "calldata": "0xa9059cbb000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0000000000000000000000000000000000000000000000000000000000000001",
        }

        result = await inspector.evaluate_deterministic(condition=condition, context=context)
        assert result.passed is True
        calldata_info = result.observed_data.get("calldata_analysis", {})
        assert calldata_info.get("selector") == "0xa9059cbb"
        assert calldata_info.get("signature") == "transfer(address,uint256)"

    @pytest.mark.asyncio
    async def test_sepolia_calldata_selector_filtering_mismatch(self, ensure_sepolia_available):
        """Verifies selector mismatch failure when calldata contains transfer but rule demands transferOwnership."""
        inspector = ensure_sepolia_available

        condition = DeterministicCondition(
            target_address=WETH9_ADDRESS,
            required_function_selectors=["0xf2fde38b"],  # transferOwnership required
        )
        context = {
            "calldata": "0xa9059cbb000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        }

        result = await inspector.evaluate_deterministic(condition=condition, context=context)
        assert result.passed is False
        assert "not in required list" in result.reason
        assert result.observed_data["calldata_analysis"]["selector"] == "0xa9059cbb"

    @pytest.mark.asyncio
    async def test_sepolia_native_balance_query(self, ensure_sepolia_available):
        """Verifies check_native_balance against Base Sepolia live RPC."""
        inspector = ensure_sepolia_available

        # WETH9 contract holds native ETH deposited on Base Sepolia
        condition = DeterministicCondition(
            target_address=WETH9_ADDRESS,
            min_value_wei=1,  # Require at least 1 wei
            check_native_balance=True,
        )

        result = await inspector.evaluate_deterministic(condition=condition, context={})
        assert result.passed is True
        assert result.observed_data["native_balance_wei"] >= 1
        assert result.observed_data["native_balance_eth"] > 0.0

        # Now test with an excessively high threshold (1,000,000 ETH) to trigger deterministic failure
        excessive_condition = DeterministicCondition(
            target_address=WETH9_ADDRESS,
            min_value_wei=1_000_000 * 10**18,
            check_native_balance=True,
        )

        fail_result = await inspector.evaluate_deterministic(condition=excessive_condition, context={})
        assert fail_result.passed is False
        assert "below threshold" in fail_result.reason


# ---------------------------------------------------------------------------
# 2. ConditionAgentEngine On-Chain Integration Tests (Base Sepolia)
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSepoliaConditionAgentEngine:
    """
    End-to-end integration tests for ConditionAgentEngine interacting with Base Sepolia.
    Validates stage 1 on-chain gatekeeper + stage 2 semantic evaluation.
    """

    @pytest.mark.asyncio
    async def test_engine_sepolia_stage1_pass_invokes_semantic_evaluator(
        self, sepolia_engine, sepolia_weth_transfer_payload
    ):
        """
        Stage 1 passes deterministically on Base Sepolia (valid WETH contract, sufficient value, matching selector).
        Asserts Stage 2 Semantic Evaluator is invoked (llm_invoked == True).
        """
        payload = ConditionRulePayload(**sepolia_weth_transfer_payload)
        response: FinalAgentResponse = await sepolia_engine.process_rule(payload)

        # Stage 1 assertions
        assert response.chain_id == BASE_SEPOLIA_CHAIN_ID
        assert response.deterministic_check.passed is True
        assert response.deterministic_check.observed_data["is_contract"] is True
        assert response.deterministic_check.observed_data["calldata_analysis"]["selector"] == "0xa9059cbb"

        # Stage 2 assertions
        assert response.llm_invoked is True
        assert response.semantic_Evaluation is not None
        assert response.semantic_Evaluation.recommended_action == "APPROVE"
        assert response.semantic_Evaluation.risk_score < payload.semantic.risk_threshold

    @pytest.mark.asyncio
    async def test_engine_sepolia_stage1_pass_critical_privilege_reject(
        self, sepolia_engine, sepolia_weth_transfer_payload
    ):
        """
        Stage 1 passes, but Stage 2 detects a critical privilege call (transferOwnership)
        lacking external audit documentation -> triggers REJECT.
        """
        sepolia_weth_transfer_payload["deterministic"]["required_function_selectors"] = ["0xf2fde38b"]
        sepolia_weth_transfer_payload["context_metadata"]["calldata"] = (
            "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        )
        sepolia_weth_transfer_payload["context_metadata"]["proposal_description"] = (
            "Routine admin upgrade without external security review."
        )

        payload = ConditionRulePayload(**sepolia_weth_transfer_payload)
        response: FinalAgentResponse = await sepolia_engine.process_rule(payload)

        assert response.deterministic_check.passed is True
        assert response.llm_invoked is True
        assert response.semantic_Evaluation is not None
        assert response.semantic_Evaluation.conditions_met is True
        assert response.semantic_Evaluation.risk_score >= 8.0
        assert response.semantic_Evaluation.recommended_action == "REJECT"

    @pytest.mark.asyncio
    async def test_engine_sepolia_stage1_fail_tx_value_too_low(
        self, sepolia_engine, sepolia_weth_transfer_payload
    ):
        """
        Stage 1 fails deterministically due to tx_value_wei < min_value_wei.
        Asserts short-circuit occurs at zero LLM token cost (llm_invoked == False).
        """
        # Set high min_value_wei (1 ETH) while tx_value_wei is only 500 wei
        sepolia_weth_transfer_payload["deterministic"]["min_value_wei"] = 10**18
        sepolia_weth_transfer_payload["context_metadata"]["tx_value_wei"] = 500

        payload = ConditionRulePayload(**sepolia_weth_transfer_payload)
        response: FinalAgentResponse = await sepolia_engine.process_rule(payload)

        # Must halt at Stage 1
        assert response.deterministic_check.passed is False
        assert "below threshold" in response.deterministic_check.reason
        assert response.llm_invoked is False
        assert response.semantic_Evaluation is None

    @pytest.mark.asyncio
    async def test_engine_sepolia_stage1_fail_selector_mismatch(
        self, sepolia_engine, sepolia_weth_transfer_payload
    ):
        """
        Stage 1 fails deterministically due to calldata function selector mismatch.
        Asserts short-circuit occurs and LLM is not invoked.
        """
        # Rule expects upgradeTo (0x3659cfe6), but calldata is transfer (0xa9059cbb)
        sepolia_weth_transfer_payload["deterministic"]["required_function_selectors"] = ["0x3659cfe6"]

        payload = ConditionRulePayload(**sepolia_weth_transfer_payload)
        response: FinalAgentResponse = await sepolia_engine.process_rule(payload)

        assert response.deterministic_check.passed is False
        assert "not in required list" in response.deterministic_check.reason
        assert response.llm_invoked is False
        assert response.semantic_Evaluation is None

    @pytest.mark.asyncio
    async def test_engine_sepolia_stage1_pass_semantic_disabled(
        self, sepolia_engine, sepolia_weth_transfer_payload
    ):
        """
        Stage 1 passes on Base Sepolia, but semantic evaluation is explicitly disabled
        (semantic.enabled == False). Asserts llm_invoked == False.
        """
        sepolia_weth_transfer_payload["semantic"]["enabled"] = False

        payload = ConditionRulePayload(**sepolia_weth_transfer_payload)
        response: FinalAgentResponse = await sepolia_engine.process_rule(payload)

        assert response.deterministic_check.passed is True
        assert response.llm_invoked is False
        assert response.semantic_Evaluation is None
