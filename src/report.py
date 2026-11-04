"""
Report and Diagnostics CLI for Web3 Condition-Action Trigger Agent.
Queries SQLite operational ledger to generate human-readable metrics summaries,
Stage 1 filter rate performance, LLM token/cost telemetry, and error distributions.

Usage:
    python -m src.report [--db PATH] [--price USD]
    python src/report.py [--db PATH] [--price USD]
"""

import argparse
import asyncio
import os
import sys
from typing import Dict, Any, Optional

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.storage import AgentStorage, get_default_db_path
except ImportError:
    from storage import AgentStorage, get_default_db_path


async def generate_report(
    db_path: Optional[str] = None, target_price_usd: float = 0.01
) -> Dict[str, Any]:
    """
    Connects to the AgentStorage database and computes summary metrics.
    """
    storage = AgentStorage(db_path=db_path)
    return await storage.get_summary_metrics(target_price_usd=target_price_usd)


def format_report_text(metrics: Dict[str, Any]) -> str:
    """
    Formats the summary metrics dictionary into a clean, human-readable terminal report.
    """
    total_evals = metrics.get("total_evaluations", 0)
    stage1_halted = metrics.get("stage1_halted_count", 0)
    filter_rate = metrics.get("stage1_filter_rate_pct", metrics.get("stage1_Filter_rate_pct", 0.0))
    llm_invoked = metrics.get("llm_invoked_count", 0)

    total_in_tok = metrics.get("total_input_tokens", 0)
    total_out_tok = metrics.get("total_output_tokens", 0)
    total_tokens = total_in_tok + total_out_tok
    total_cost = metrics.get("total_cost_usd", 0.0)
    avg_cost_eval = metrics.get("avg_cost_per_eval_usd", 0.0)
    avg_cost_llm = metrics.get("avg_cost_per_llm_call_usd", 0.0)
    max_cost = metrics.get("max_cost_usd", 0.0)
    p95_cost = metrics.get("p95_cost_usd", 0.0)

    target_price = metrics.get("target_price_usd", 0.01)
    covers_max = metrics.get("price_covers_max_cost", True)
    margin_status = "PASS (Covers Max Cost)" if covers_max else "FAIL (Exceeds Target Price)"

    total_payments = metrics.get("total_payments_settled")
    total_rev = metrics.get("total_revenue_usdc")
    net_profit = metrics.get("net_profit_usd")

    total_errors = metrics.get("total_errors", 0)
    errors_by_stage = metrics.get("errors_by_stage", {})

    lines = [
        "=" * 64,
        "   Web3 Condition-Action Trigger Agent: Operational Report   ",
        "=" * 64,
        f"Total Evaluations Processed : {total_evals}",
        f"Stage 1 Halted (Filtered)   : {stage1_halted}",
        f"Stage 1 Filter Efficiency   : {filter_rate:.2f}%",
        f"Stage 2 LLM Calls Invoked   : {llm_invoked}",
        "-" * 64,
        "LLM Token & Cost Telemetry:",
        f"  Input Tokens Consumed     : {total_in_tok:,}",
        f"  Output Tokens Generated   : {total_out_tok:,}",
        f"  Total Tokens              : {total_tokens:,}",
        f"  Total Estimated Cost (USD): ${total_cost:.6f}",
        f"  Avg Cost per Evaluation   : ${avg_cost_eval:.6f}",
        f"  Avg Cost per LLM Call     : ${avg_cost_llm:.6f}",
        f"  P95 Evaluation Cost (USD) : ${p95_cost:.6f}",
        f"  Max Evaluation Cost (USD) : ${max_cost:.6f}",
        "-" * 64,
        "Commercial Margin Feasibility:",
        f"  Target Price per Eval     : ${target_price:.4f}",
        f"  Margin Status             : {margin_status}",
    ]

    if total_payments is not None or total_rev is not None:
        lines.extend([
            "-" * 64,
            "x402 Micropayment Telemetry:",
            f"  Total Payments Settled    : {int(total_payments or 0)}",
            f"  Total Settled Revenue     : ${float(total_rev or 0.0):.6f} USDC",
            f"  Net Profit (Revenue-Cost) : ${float(net_profit or 0.0):.6f} USD",
        ])

    lines.extend([
        "-" * 64,
        f"Operational Error Log (Total: {total_errors}):",
    ])

    if not errors_by_stage:
        lines.append("  No operational errors recorded.")
    else:
        for stage, count in sorted(errors_by_stage.items()):
            lines.append(f"  Stage '{stage}': {count} error(s)")

    lines.append("=" * 64)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Web3 Condition-Action Trigger Agent Ledger Reporting CLI"
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to SQLite ledger database (defaults to LEDGER_DB_PATH or data/agent.db)",
    )
    parser.add_argument(
        "--price",
        type=float,
        default=0.01,
        help="Target commercial price per evaluation in USD (default: 0.01)",
    )

    args = parser.parse_args()
    metrics = asyncio.run(generate_report(db_path=args.db, target_price_usd=args.price))
    report_text = format_report_text(metrics)
    print(report_text)


if __name__ == "__main__":
    main()
