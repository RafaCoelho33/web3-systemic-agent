"""
Live On-Chain Evaluation Scenarios on Base Sepolia.

Executes 5 real on-chain scenarios via ConditionAgentEngine with Stage 1
deterministic verification and Stage 2 Gemini LLM evaluation:
  - Scenario 1 (Benign): Routine parameter/transfer proposal -> APPROVE
  - Scenario 2 (Exploit): Calldata executes transferOwnership, misleading text -> REJECT
  - Scenario 3 (Audited Critical): Calldata executes upgradeTo with audit -> MANUAL_REVIEW
  - Scenario 4 (Stage 1 Short-Circuit): Selector mismatch -> Stage 1 fails, 0 tokens
  - Scenario 5 (Context Truncation): Proposal > 40,000 chars -> Bounded to 32k, no error
"""

import asyncio
import os
import sys
import time
from typing import List, Dict, Any, Optional

# 1. Ensure src and root directories are in sys.path
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# 2. Call dotenv.load_dotenv(override=False) so GEMINI_API_KEY is loaded
import dotenv

_env_file = os.path.join(_ROOT_DIR, ".env")
if os.path.exists(_env_file):
    dotenv.load_dotenv(_env_file, override=False)
dotenv.load_dotenv(override=False)

# Configure responsive Gemini model default
if "GEMINI_MODEL" not in os.environ:
    os.environ["GEMINI_MODEL"] = "gemini-3.1-flash-lite"

from src.schemas import (
    ChainId,
    ConditionRulePayload,
    DeterministicCondition,
    SemanticCondition,
    FinalAgentResponse,
)
from src.engine import ConditionAgentEngine
from src.storage import AgentStorage
from src.report import generate_report, format_report_text
from src.semantic_evaluator import DEFAULT_LLM_MAX_INPUT_CHARS

# Known contract on Base Sepolia (WETH9 / Wrapped Ether system contract)
BASE_SEPOLIA_WETH = "0x4200000000000000000000000000000000000006"


def build_scenarios() -> List[Dict[str, Any]]:
    """Builds the 5 evaluation scenarios targeting Base Sepolia."""

    # Scenario 1 (Benign): Routine parameter/transfer proposal -> expected APPROVE
    s1 = ConditionRulePayload(
        rule_id="SCENARIO-1-BENIGN",
        chain_id=ChainId.BASE_SEPOLIA,
        deterministic=DeterministicCondition(
            target_address=BASE_SEPOLIA_WETH,
            min_value_wei=0,
        ),
        semantic=SemanticCondition(
            policy_prompt=(
                "Flag discrepancies between proposal description and actual on-chain actions, "
                "unverified contract upgrades, or unauthorized ownership transfers."
            ),
            risk_threshold=7.0,
        ),
        context_metadata={
            "calldata": "0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000001",
            "proposal_description": (
                "Routine transfer of 1 wei WETH to ecosystem partner as budgeted and verified in grant proposal."
            ),
            "tx_value_wei": 0,
        },
    )

    # Scenario 2 (Exploit): Calldata executes 0xf2fde38b (transferOwnership), misleading text -> expected REJECT
    s2 = ConditionRulePayload(
        rule_id="SCENARIO-2-EXPLOIT",
        chain_id=ChainId.BASE_SEPOLIA,
        deterministic=DeterministicCondition(
            target_address=BASE_SEPOLIA_WETH,
            min_value_wei=0,
        ),
        semantic=SemanticCondition(
            policy_prompt=(
                "Strictly reject any proposal that attempts to transfer contract ownership or "
                "execute unauthorized administrative takeovers under misleading or routine maintenance pretenses."
            ),
            risk_threshold=7.0,
        ),
        context_metadata={
            "calldata": "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "proposal_description": (
                "Routine yield optimization parameter update. No audit required for this standard config."
            ),
            "tx_value_wei": 0,
        },
    )

    # Scenario 3 (Audited Critical): Calldata executes 0x3659cfe6 (upgradeTo) with audit -> expected MANUAL_REVIEW
    s3 = ConditionRulePayload(
        rule_id="SCENARIO-3-AUDITED-CRITICAL",
        chain_id=ChainId.BASE_SEPOLIA,
        deterministic=DeterministicCondition(
            target_address=BASE_SEPOLIA_WETH,
            min_value_wei=0,
        ),
        semantic=SemanticCondition(
            policy_prompt=(
                "Contract upgrades (upgradeTo) represent high operational changes and must always be queued for "
                "manual review (action MANUAL_REVIEW, risk_score 7.0 to 7.9) if accompanied by a verified external audit. "
                "Reject only if completely unaudited or malicious."
            ),
            risk_threshold=7.0,
        ),
        context_metadata={
            "calldata": "0x3659cfe60000000000000000000000002222222222222222222222222222222222222222",
            "proposal_description": (
                "Upgrade logic implementation to v2. Audited by OpenZeppelin with zero findings."
            ),
            "tx_value_wei": 0,
        },
    )

    # Scenario 4 (Stage 1 Short-Circuit): Required selectors ["0x3659cfe6"], calldata has 0xa9059cbb -> Stage 1 fails
    s4 = ConditionRulePayload(
        rule_id="SCENARIO-4-SHORT-CIRCUIT",
        chain_id=ChainId.BASE_SEPOLIA,
        deterministic=DeterministicCondition(
            target_address=BASE_SEPOLIA_WETH,
            required_function_selectors=["0x3659cfe6"],
        ),
        semantic=SemanticCondition(
            policy_prompt="Flag discrepancies between proposal description and actual on-chain actions.",
            risk_threshold=7.0,
        ),
        context_metadata={
            "calldata": "0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000001",
            "proposal_description": "Routine transfer proposal with selector 0xa9059cbb.",
            "tx_value_wei": 0,
        },
    )

    # Scenario 5 (Context Truncation): Proposal description with >40,000 characters -> verifies truncation to 32k
    raw_desc = (
        "Routine grant transfer for Base Sepolia WETH ecosystem partner as budgeted and verified.\n"
        + ("Comprehensive operational audit logs, governance discussion transcripts, and appendices: " * 650)
    )
    s5 = ConditionRulePayload(
        rule_id="SCENARIO-5-TRUNCATION",
        chain_id=ChainId.BASE_SEPOLIA,
        deterministic=DeterministicCondition(
            target_address=BASE_SEPOLIA_WETH,
            min_value_wei=0,
        ),
        semantic=SemanticCondition(
            policy_prompt=(
                "Flag discrepancies between proposal description and actual on-chain actions, "
                "unverified upgrades, or unauthorized transfers."
            ),
            risk_threshold=7.0,
        ),
        context_metadata={
            "calldata": "0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000001",
            "proposal_description": raw_desc,
            "tx_value_wei": 0,
        },
    )

    return [
        {
            "payload": s1,
            "name": "Scenario 1 (Benign Routine Transfer)",
            "expected_decision": "APPROVE",
            "notes": "Expected APPROVE, low risk",
        },
        {
            "payload": s2,
            "name": "Scenario 2 (Exploit: transferOwnership)",
            "expected_decision": "REJECT",
            "notes": "Expected REJECT, risk score >= 8.0",
        },
        {
            "payload": s3,
            "name": "Scenario 3 (Audited Critical upgradeTo)",
            "expected_decision": "MANUAL_REVIEW",
            "notes": "Expected MANUAL_REVIEW, audited high-privilege",
        },
        {
            "payload": s4,
            "name": "Scenario 4 (Stage 1 Short-Circuit)",
            "expected_decision": "SHORT_CIRCUIT",
            "notes": "Expected Stage 1 failure, 0 LLM tokens",
        },
        {
            "payload": s5,
            "name": "Scenario 5 (Context Truncation >40k chars)",
            "expected_decision": "TRUNCATED_PASS",
            "notes": f"Expected truncation to {DEFAULT_LLM_MAX_INPUT_CHARS} chars, no crash",
        },
    ]


async def run_live_scenarios() -> List[Dict[str, Any]]:
    print("=" * 105)
    print("      EXECUTING LIVE ON-CHAIN SCENARIOS ON BASE SEPOLIA (CHAIN ID 84532)      ")
    print("=" * 105)
    print(f"Target Contract : {BASE_SEPOLIA_WETH} (Base Sepolia WETH)")
    print(f"Gemini Model    : {os.getenv('GEMINI_MODEL', 'gemini-3.1-flash-lite')}")
    print(f"API Key Active  : {bool(os.getenv('GEMINI_API_KEY'))}")
    print("-" * 105)

    storage = AgentStorage()
    engine = ConditionAgentEngine(rpc_url=None, storage=storage)
    scenarios = build_scenarios()

    results_summary: List[Dict[str, Any]] = []

    for idx, item in enumerate(scenarios, 1):
        payload: ConditionRulePayload = item["payload"]
        name = item["name"]
        print(f"\n[{idx}/5] Executing {name}...")

        # Small pacing pause between calls to avoid API burst limits
        if idx > 1:
            await asyncio.sleep(1.5)

        start_t = time.perf_counter()
        response: FinalAgentResponse = await engine.process_rule(payload, source="live_test")
        latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)

        s1_passed = response.deterministic_check.passed
        llm_invoked = response.llm_invoked

        if response.semantic_Evaluation is not None:
            sem = response.semantic_Evaluation
            risk_score = f"{sem.risk_score:.1f}"
            decision = sem.recommended_action
            tokens_in = sem.input_tokens
            tokens_out = sem.output_tokens
            cost_usd = sem.estimated_cost_usd
            flagged = sem.flagged_issues
            summary = sem.summary
        else:
            risk_score = "N/A"
            decision = "HALTED"
            tokens_in = 0
            tokens_out = 0
            cost_usd = 0.0
            flagged = []
            summary = response.deterministic_check.reason

        # Specific assertions / verifications for each scenario
        if payload.rule_id == "SCENARIO-1-BENIGN":
            assert s1_passed is True, "Scenario 1 Stage 1 must pass"
            assert llm_invoked is True, "Scenario 1 must invoke LLM"
            print(f"    -> Result: Decision={decision}, Risk Score={risk_score}")

        elif payload.rule_id == "SCENARIO-2-EXPLOIT":
            assert s1_passed is True, "Scenario 2 Stage 1 must pass"
            assert llm_invoked is True, "Scenario 2 must invoke LLM"
            print(f"    -> Result: Decision={decision}, Risk Score={risk_score}")

        elif payload.rule_id == "SCENARIO-3-AUDITED-CRITICAL":
            assert s1_passed is True, "Scenario 3 Stage 1 must pass"
            assert llm_invoked is True, "Scenario 3 must invoke LLM"
            print(f"    -> Result: Decision={decision}, Risk Score={risk_score}")

        elif payload.rule_id == "SCENARIO-4-SHORT-CIRCUIT":
            assert s1_passed is False, "Scenario 4 Stage 1 must fail"
            assert llm_invoked is False, "Scenario 4 must NOT invoke LLM"
            assert tokens_in == 0 and tokens_out == 0, "Scenario 4 must consume 0 tokens"
            print(f"    -> Result: Stage 1 Halted cleanly. Reason: {summary}")

        elif payload.rule_id == "SCENARIO-5-TRUNCATION":
            assert s1_passed is True, "Scenario 5 Stage 1 must pass"
            assert llm_invoked is True, "Scenario 5 must invoke LLM"
            has_truncation_flag = any("truncated" in str(f).lower() for f in flagged)
            assert has_truncation_flag, "Scenario 5 must have truncation alert in flagged_issues"
            print(f"    -> Result: Context truncated to 32k. Alert verified in flagged_issues.")

        summary_row = {
            "rule_id": payload.rule_id,
            "s1_passed": str(s1_passed),
            "llm_invoked": str(llm_invoked),
            "risk_score": risk_score,
            "decision": decision,
            "tokens": f"{tokens_in} / {tokens_out}",
            "cost_usd": f"${cost_usd:.6f}",
            "latency_ms": f"{latency_ms:.1f}",
            "notes": item["notes"],
        }
        results_summary.append(summary_row)

    # 5. Print a concise summary table in the terminal
    print("\n" + "=" * 105)
    print("                                      SCENARIO EXECUTION SUMMARY TABLE                                      ")
    print("=" * 105)
    header = (
        f"| {'Rule ID':<26} | {'S1 Passed':<9} | {'LLM Invoked':<11} | "
        f"{'Risk Score':<10} | {'Decision':<13} | {'Tokens (In/Out)':<15} | "
        f"{'Est Cost (USD)':<14} | {'Latency (ms)':<12} |"
    )
    separator = "+" + "+".join(["-" * (len(col) + 2) for col in [
        " " * 26, " " * 9, " " * 11, " " * 10, " " * 13, " " * 15, " " * 14, " " * 12
    ]]) + "+"

    print(separator)
    print(header)
    print(separator)
    for r in results_summary:
        row = (
            f"| {r['rule_id']:<26} | {r['s1_passed']:<9} | {r['llm_invoked']:<11} | "
            f"{r['risk_score']:<10} | {r['decision']:<13} | {r['tokens']:<15} | "
            f"{r['cost_usd']:<14} | {r['latency_ms']:<12} |"
        )
        print(row)
    print(separator)

    # 6. At the end, invoke generate_report() from src.report and print formatted operational report
    print("\n[Operational Reporting] Generating ledger metrics from storage...")
    metrics = await generate_report(db_path=storage.db_path)
    report_text = format_report_text(metrics)
    print("\n" + report_text)

    return results_summary


def main() -> None:
    asyncio.run(run_live_scenarios())


if __name__ == "__main__":
    main()
