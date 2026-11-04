"""
Condition Agent Engine orchestrating the two-stage execution pipeline:
Stage 1: Deterministic Web3 check (zero LLM token consumption)
Stage 2: Semantic LLM evaluation (triggered only when deterministic conditions match)
"""

import asyncio
import inspect
import logging
import os
import sys
import time
from typing import Optional, Any, List, Dict, Union

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.schemas import ConditionRulePayload, FinalAgentResponse, DeterministicResult
    from src.chain_inspector import ChainInspector
    from src.semantic_evaluator import (
        MockSemanticEvaluator,
        OpenAISemanticEvaluator,
        GeminiSemanticEvaluator,
        get_semantic_evaluator,
        enforce_decision_policy,
        SemanticEvaluatorProtocol,
    )
    from src.storage import AgentStorage
except ImportError:
    from schemas import ConditionRulePayload, FinalAgentResponse, DeterministicResult
    from chain_inspector import ChainInspector
    from semantic_evaluator import (
        MockSemanticEvaluator,
        OpenAISemanticEvaluator,
        GeminiSemanticEvaluator,
        get_semantic_evaluator,
        enforce_decision_policy,
        SemanticEvaluatorProtocol,
    )
    from storage import AgentStorage

logger = logging.getLogger(__name__)


class ConditionAgentEngine:
    """
    Orchestrates the two-stage pipeline:
    Stage 1: Deterministic Web3 check (Zero LLM cost)
    Stage 2: Semantic LLM evaluation (Triggered only if Stage 1 passes)
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        semantic_evaluator: Optional[Any] = None,
        rpc_urls: Optional[Dict[int, Union[str, List[str]]]] = None,
        storage: Optional[AgentStorage] = None,
    ):
        self.rpc_url = rpc_url
        self.rpc_urls = rpc_urls or {}
        self.semantic_evaluator = (
            semantic_evaluator if semantic_evaluator is not None else get_semantic_evaluator()
        )
        self.storage = storage if storage is not None else AgentStorage()

    async def process_rule(
        self,
        payload: ConditionRulePayload,
        source: str = "engine",
        job_id: Optional[str] = None,
    ) -> FinalAgentResponse:
        start_time = time.perf_counter()
        logger.info(f"Processing rule '{payload.rule_id}' on chain {payload.chain_id.value}")

        chain_id_val = (
            payload.chain_id.value
            if hasattr(payload.chain_id, "value")
            else int(payload.chain_id)
        )
        resolved_rpc = None
        if self.rpc_urls and chain_id_val in self.rpc_urls:
            resolved_rpc = self.rpc_urls[chain_id_val]
        elif self.rpc_url is not None:
            resolved_rpc = self.rpc_url

        inspector = ChainInspector(chain_id=chain_id_val, rpc_url=resolved_rpc)

        # Stage 1: Deterministic Gatekeeper
        det_result = await inspector.evaluate_deterministic(
            condition=payload.deterministic,
            context=payload.context_metadata,
        )

        if det_result.error is not None:
            try:
                await self.storage.log_error(
                    stage="stage1_rpc",
                    error_type="RPCError",
                    message=det_result.error,
                    rule_id=payload.rule_id,
                    job_id=job_id,
                    context=det_result.observed_data,
                )
            except Exception:
                pass

        if not det_result.passed or not payload.semantic.enabled:
            logger.info(
                f"Rule '{payload.rule_id}' halted at Stage 1 (Passed={det_result.passed}). LLM not invoked."
            )
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            final_response = FinalAgentResponse(
                rule_id=payload.rule_id,
                chain_id=chain_id_val,
                deterministic_check=det_result,
                llm_invoked=False,
                semantic_Evaluation=None,
            )
            try:
                await self.storage.record_evaluation(
                    payload,
                    final_response,
                    source=source,
                    job_id=job_id,
                    latency_ms=elapsed_ms,
                )
            except Exception:
                pass
            return final_response

        # Stage 2: Semantic Evaluation (Only reached when deterministic conditions match)
        logger.info(f"Stage 1 passed for '{payload.rule_id}'. Invoking Stage 2 Semantic Evaluator...")
        sem_result = await self.semantic_evaluator.evaluate(
            condition=payload.semantic,
            observed_onchain=det_result.observed_data,
            metadata=payload.context_metadata,
        )

        sem_result = enforce_decision_policy(
            sem_result, payload.semantic.risk_threshold
        )

        if sem_result.flagged_issues and any(
            "LLM provider failure" in issue for issue in sem_result.flagged_issues
        ):
            try:
                await self.storage.log_error(
                    stage="stage2_llm",
                    error_type="LLMFallbackError",
                    message="; ".join(sem_result.flagged_issues),
                    rule_id=payload.rule_id,
                    job_id=job_id,
                )
            except Exception:
                pass

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        final_response = FinalAgentResponse(
            rule_id=payload.rule_id,
            chain_id=chain_id_val,
            deterministic_check=det_result,
            llm_invoked=True,
            semantic_Evaluation=sem_result,
        )
        try:
            await self.storage.record_evaluation(
                payload,
                final_response,
                source=source,
                job_id=job_id,
                latency_ms=elapsed_ms,
            )
        except Exception:
            pass
        return final_response

    async def process_rules_batch(
        self,
        payloads: List[ConditionRulePayload],
        max_concurrency: int = 10,
    ) -> List[FinalAgentResponse]:
        """
        Concurrently processes a list of ConditionRulePayload with max concurrency bounded
        by an asyncio.Semaphore. Preserves original list order and isolates execution failures.
        """
        if not payloads:
            return []

        semaphore = asyncio.Semaphore(max_concurrency)

        async def _process_with_semaphore(payload: ConditionRulePayload) -> FinalAgentResponse:
            async with semaphore:
                try:
                    try:
                        sig = inspect.signature(self.process_rule)
                        accepts_source = "source" in sig.parameters or any(
                            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
                        )
                    except Exception:
                        accepts_source = True

                    if accepts_source:
                        try:
                            return await self.process_rule(payload, source="batch")
                        except TypeError:
                            return await self.process_rule(payload)
                    else:
                        return await self.process_rule(payload)
                except Exception as exc:
                    logger.exception(f"Exception while processing rule '{payload.rule_id}' in batch: {exc}")
                    chain_id_val = (
                        payload.chain_id.value
                        if hasattr(payload.chain_id, "value")
                        else int(payload.chain_id)
                    )
                    return FinalAgentResponse(
                        rule_id=payload.rule_id,
                        chain_id=chain_id_val,
                        deterministic_check=DeterministicResult(
                            passed=False,
                            reason=f"Execution error: {exc}",
                            observed_data={},
                            error=str(exc),
                        ),
                        llm_invoked=False,
                        semantic_Evaluation=None,
                    )

        tasks = [_process_with_semaphore(p) for p in payloads]
        return list(await asyncio.gather(*tasks))


async def main():
    # Example JSON payload representing a DAO proposal check on Base Sepolia
    sample_json_payload = {
        "rule_id": "dao-gov-guard-001",
        "chain_id": 84532,
        "deterministic": {
            "target_address": "0x4200000000000000000000000000000000000006",  # WETH on Base
            "min_value_wei": 1000000000000000000,  # 1 ETH in Wei
            "required_function_selectors": ["0xf2fde38b", "0xa9059cbb"],
            "check_native_balance": False,
        },
        "semantic": {
            "enabled": True,
            "policy_prompt": "Flag any ownership transfer or treasury movement above 1 ETH lacking an external security audit.",
            "risk_threshold": 7.0,
        },
        "context_metadata": {
            "tx_value_wei": 2500000000000000000,  # 2.5 ETH
            "calldata": "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "proposal_description": "Routine parameter update to optimize treasury yield farming strategies.",
        },
    }

    payload = ConditionRulePayload(**sample_json_payload)
    engine = ConditionAgentEngine()
    result = await engine.process_rule(payload)
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    asyncio.run(main())
