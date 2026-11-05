"""
Governance Listener and Autonomous Security Scanner.

Polls DAO proposals from Snapshot or loads curated proposals, executes two-stage
deterministic bytecode and semantic LLM audits, displays an ASCII audit table,
and prints cumulative operational and financial metrics.

Usage:
    python scripts/governance_listener.py --curated
    python scripts/governance_listener.py --limit 3
"""

import argparse
import asyncio
import logging
import os
import sys
from typing import List, Optional

try:
    import dotenv
    dotenv.load_dotenv(override=False)
except ImportError:
    pass

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.schemas import ChainId
    from src.engine import ConditionAgentEngine
    from src.semantic_evaluator import MockSemanticEvaluator
    from src.governance_connector import (
        SnapshotGovernanceConnector,
        GovernanceProposal,
        GovernanceAuditReport,
        get_curated_dao_proposals,
    )
    from src.report import generate_report, format_report_text
except ImportError:
    from schemas import ChainId
    from engine import ConditionAgentEngine
    from semantic_evaluator import MockSemanticEvaluator
    from governance_connector import (
        SnapshotGovernanceConnector,
        GovernanceProposal,
        GovernanceAuditReport,
        get_curated_dao_proposals,
    )
    from report import generate_report, format_report_text

logger = logging.getLogger(__name__)


def print_audit_table(reports: List[GovernanceAuditReport]) -> None:
    """
    Renders an ASCII table of audited proposals displaying ID, space, alert level,
    decision, risk score, token usage, and USD evaluation cost.
    """
    headers = ["Proposal ID", "Space", "Alert Level", "Decision", "Score", "Tokens", "Cost USD"]
    rows = []
    for r in reports:
        prop_id = r.proposal.proposal_id[:16]
        space = r.proposal.space_id[:22]
        alert = r.alert_level
        sem = r.agent_response.semantic_Evaluation
        decision = sem.recommended_action if sem else "SKIPPED"
        score = f"{sem.risk_score:.1f}" if sem else "N/A"
        tokens = str(sem.input_tokens + sem.output_tokens) if sem else "0"
        cost = f"${sem.estimated_cost_usd:.6f}" if sem else "$0.000000"
        rows.append([prop_id, space, alert, decision, score, tokens, cost])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(val))

    separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_str = "|" + "|".join(f" {headers[i].ljust(col_widths[i])} " for i in range(len(headers))) + "|"

    print("\n" + separator)
    print(header_str)
    print(separator)
    for row in rows:
        row_str = "|" + "|".join(f" {row[i].ljust(col_widths[i])} " for i in range(len(row))) + "|"
        print(row_str)
    print(separator + "\n")


async def run_listener(
    limit: int = 3,
    curated: bool = False,
    spaces: Optional[List[str]] = None,
) -> int:
    """
    Executes governance listener scan on Base Sepolia.
    """
    print(f"[*] Initializing ConditionAgentEngine on Base Sepolia (curated={curated}, limit={limit})...")
    if curated:
        evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(semantic_evaluator=evaluator)
    else:
        engine = ConditionAgentEngine()
    connector = SnapshotGovernanceConnector(default_chain_id=ChainId.BASE_SEPOLIA)

    if curated:
        print("[*] Loading deterministic curated DAO proposals...")
        proposals = get_curated_dao_proposals(default_chain_id=ChainId.BASE_SEPOLIA, limit=limit)
        reports = await connector.audit_proposals(engine=engine, proposals=proposals)
    else:
        target_spaces = spaces or connector.DEFAULT_SPACES
        print(f"[*] Polling Snapshot proposals for spaces: {', '.join(target_spaces)}...")
        reports = await connector.audit_proposals(engine=engine, spaces=target_spaces, limit=limit)

    print(f"[+] Successfully audited {len(reports)} proposals.")
    print_audit_table(reports)

    print("=" * 60)
    print("OPERATIONAL & FINANCIAL LEDGER METRICS")
    print("=" * 60)
    metrics = await generate_report(db_path=engine.storage.db_path)
    print(format_report_text(metrics))

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Autonomous DAO Governance Listener & Security Scanner"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Maximum number of proposals to inspect (default: 3)",
    )
    parser.add_argument(
        "--curated",
        action="store_true",
        default=False,
        help="Use deterministic curated DAO test proposals",
    )
    parser.add_argument(
        "--space",
        action="append",
        dest="spaces",
        help="Snapshot space identifier (e.g. 'arbitrumfoundation.eth'). Can be specified multiple times.",
    )

    args = parser.parse_args()
    exit_code = asyncio.run(
        run_listener(limit=args.limit, curated=args.curated, spaces=args.spaces)
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
