"""
Autonomous DAO Governance Proposal Monitor & Security Daemon (Engine 2).

Continuously monitors Snapshot/Tally DAO governance proposals across major ecosystems,
extracts on-chain calldata and execution targets, performs two-stage deterministic
and semantic risk evaluations via ConditionAgentEngine, logs reports to the SQLite
ledger (data/agent.db), and dispatches webhook alerts with x402 monetization links.

Monitored Default DAOs:
    - uniswap.eth (Uniswap)
    - arbitrumfoundation.eth (Arbitrum)
    - ens.eth (ENS)
    - opcollective.eth (Optimism)
    - aave.eth (Aave)
    - aerodrome.eth (Aerodrome on Base)

Usage Examples:
    # 1. Single scan dry-run across default DAOs (offline mock data, 0 LLM cost):
    python scripts/governance_daemon.py --dry-run --once

    # 2. Single scan live Snapshot across default DAOs:
    python scripts/governance_daemon.py --once --limit 3

    # 3. Continuous daemon polling every 120 seconds:
    python scripts/governance_daemon.py --poll-interval 120

    # 4. Monitor specific spaces with custom webhook alerts:
    python scripts/governance_daemon.py --spaces uniswap.eth,aave.eth --webhook-url https://discord.com/api/webhooks/...

    # 5. Continuous daemon with custom limit and minimum alert severity:
    python scripts/governance_daemon.py --limit 5 --min-alert-level CRITICAL
"""

import argparse
import asyncio
from datetime import datetime, timezone
import json
import logging
import os
import sys
from typing import Dict, Any, Optional, List, Set, Union, Literal

# Guarded dotenv loading: skipped during pytest execution or if python-dotenv not installed
if "pytest" not in sys.modules:
    try:
        import dotenv
        _CURRENT_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
        _PARENT_ROOT = os.path.abspath(os.path.join(_CURRENT_SCRIPT_DIR, ".."))
        _env_file = os.path.join(_PARENT_ROOT, ".env")
        if os.path.exists(_env_file):
            dotenv.load_dotenv(_env_file, override=False)
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
    import aiosqlite
except ImportError:
    aiosqlite = None  # type: ignore

try:
    from src.schemas import ChainId, FinalAgentResponse
    from src.engine import ConditionAgentEngine
    from src.semantic_evaluator import MockSemanticEvaluator
    from src.storage import AgentStorage
    from src.governance_connector import (
        SnapshotGovernanceConnector,
        GovernanceProposal,
        GovernanceAuditReport,
        WebhookAlertDispatcher,
        extract_onchain_hints,
        get_curated_dao_proposals,
    )
except ImportError:
    from schemas import ChainId, FinalAgentResponse
    from engine import ConditionAgentEngine
    from semantic_evaluator import MockSemanticEvaluator
    from storage import AgentStorage
    from governance_connector import (
        SnapshotGovernanceConnector,
        GovernanceProposal,
        GovernanceAuditReport,
        WebhookAlertDispatcher,
        extract_onchain_hints,
        get_curated_dao_proposals,
    )

logger = logging.getLogger("governance_daemon")

DEFAULT_MONITORED_SPACES: List[str] = [
    "uniswap.eth",
    "arbitrumfoundation.eth",
    "ens.eth",
    "opcollective.eth",
    "aave.eth",
    "aerodrome.eth",
]


def parse_spaces(spaces_input: Optional[Union[List[str], str]]) -> List[str]:
    """
    Parses and sanitizes DAO space identifiers from either a list or comma-separated string.
    Falls back to DEFAULT_MONITORED_SPACES when empty.
    """
    if not spaces_input:
        return list(DEFAULT_MONITORED_SPACES)

    if isinstance(spaces_input, str):
        parts = [s.strip() for s in spaces_input.split(",") if s.strip()]
        return parts if parts else list(DEFAULT_MONITORED_SPACES)

    resolved: List[str] = []
    for item in spaces_input:
        for s in item.split(","):
            s_clean = s.strip()
            if s_clean and s_clean not in resolved:
                resolved.append(s_clean)
    return resolved if resolved else list(DEFAULT_MONITORED_SPACES)


def get_mock_daemon_proposals(
    spaces: List[str],
    limit: int = 3,
    chain_id: ChainId = ChainId.BASE_SEPOLIA,
) -> List[GovernanceProposal]:
    """
    Generates deterministic, highly realistic mock governance proposals covering
    benign actions, suspicious administrative privilege escalations, and proxy upgrades
    for offline testing and --dry-run simulations.
    """
    mock_catalog: Dict[str, List[GovernanceProposal]] = {
        "uniswap.eth": [
            GovernanceProposal(
                proposal_id="mock-uni-001",
                space_id="uniswap.eth",
                title="Deploy Uniswap v3 Fee Tier to Base Mainnet",
                body=(
                    "Deploy Uniswap v3 pool factory with 1bp fee tier on Base. "
                    "Target contract at 0x4200000000000000000000000000000000000006. "
                    "Calldata: 0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000"
                ),
                author="0x1111111111111111111111111111111111111111",
                state="active",
                created=1710000000,
                target_address="0x4200000000000000000000000000000000000006",
                calldata="0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000",
                tx_value_wei=0,
                chain_id=chain_id,
            )
        ],
        "arbitrumfoundation.eth": [
            GovernanceProposal(
                proposal_id="mock-arb-002",
                space_id="arbitrumfoundation.eth",
                title="Arbitrum Bridge L2 Adapter UUPS Implementation Upgrade",
                body=(
                    "Upgrade implementation contract for L2 bridge adapter at 0x4200000000000000000000000000000000000006 using upgradeTo. "
                    "Comprehensive security audit completed by OpenZeppelin with zero critical findings. "
                    "Calldata: 0x3659cfe6000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                ),
                author="0x7777777777777777777777777777777777777777",
                state="active",
                created=1710001000,
                target_address="0x4200000000000000000000000000000000000006",
                calldata="0x3659cfe6000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                tx_value_wei=0,
                chain_id=chain_id,
            )
        ],
        "ens.eth": [
            GovernanceProposal(
                proposal_id="mock-ens-003",
                space_id="ens.eth",
                title="Routine DNS Gateway Maintenance & Parameter Update",
                body=(
                    "Routine parameter adjustment for ENS DNS gateway and resolver config at 0x4200000000000000000000000000000000000006. "
                    "Executing configuration sync without audit. "
                    "Calldata: 0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                ),
                author="0x6666666666666666666666666666666666666666",
                state="active",
                created=1710002000,
                target_address="0x4200000000000000000000000000000000000006",
                calldata="0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                tx_value_wei=0,
                chain_id=chain_id,
            )
        ],
        "opcollective.eth": [
            GovernanceProposal(
                proposal_id="mock-op-004",
                space_id="opcollective.eth",
                title="Optimism RetroPGF Round 5 Infrastructure Grant",
                body=(
                    "Disburse 50,000 OP tokens from treasury to dev tooling guild at 0x4200000000000000000000000000000000000006. "
                    "Transfer verified by foundation council. "
                    "Calldata: 0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000"
                ),
                author="0x3333333333333333333333333333333333333333",
                state="active",
                created=1710003000,
                target_address="0x4200000000000000000000000000000000000006",
                calldata="0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000",
                tx_value_wei=0,
                chain_id=chain_id,
            )
        ],
        "aave.eth": [
            GovernanceProposal(
                proposal_id="mock-aave-005",
                space_id="aave.eth",
                title="Aave v3 Liquidity Pool Incentive Reallocation",
                body=(
                    "Allocate 100,000 USDC from community treasury for secondary market liquidity rewards. "
                    "Target liquidity vault at 0x4200000000000000000000000000000000000006 via transfer(0x1111111111111111111111111111111111111111, 100000000000). "
                    "Calldata: 0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000"
                ),
                author="0x5555555555555555555555555555555555555555",
                state="active",
                created=1710004000,
                target_address="0x4200000000000000000000000000000000000006",
                calldata="0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000",
                tx_value_wei=0,
                chain_id=chain_id,
            )
        ],
        "aerodrome.eth": [
            GovernanceProposal(
                proposal_id="mock-aero-006",
                space_id="aerodrome.eth",
                title="Aerodrome Slipstream Concentrated Pool Gauge Creation",
                body=(
                    "Create gauge for WETH/USDC slipstream pool at 0x4200000000000000000000000000000000000006 with standard voting weights. "
                    "Calldata: 0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000"
                ),
                author="0x4444444444444444444444444444444444444444",
                state="active",
                created=1710005000,
                target_address="0x4200000000000000000000000000000000000006",
                calldata="0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000",
                tx_value_wei=0,
                chain_id=chain_id,
            )
        ],
    }

    results: List[GovernanceProposal] = []
    for sp in spaces:
        props = mock_catalog.get(sp)
        if not props:
            # Dynamically synthesize a clean generic proposal for unknown spaces
            props = [
                GovernanceProposal(
                    proposal_id=f"mock-{sp[:6]}-999",
                    space_id=sp,
                    title=f"Standard Treasury Allocation for {sp}",
                    body=(
                        f"Routine governance action for {sp} at 0x4200000000000000000000000000000000000006. "
                        "Calldata: 0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000"
                    ),
                    author="0x8888888888888888888888888888888888888888",
                    state="active",
                    created=1710006000,
                    target_address="0x4200000000000000000000000000000000000006",
                    calldata="0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000",
                    tx_value_wei=0,
                    chain_id=chain_id,
                )
            ]
        results.extend(props[:limit])

    return results


async def load_audited_proposal_ids(storage: AgentStorage) -> Set[str]:
    """
    Preloads previously audited proposal IDs and governance rule IDs from the SQLite ledger
    to prevent redundant audits across daemon restarts.
    """
    seen: Set[str] = set()
    if aiosqlite is None:
        return seen

    try:
        await storage.initialize()
        if storage.db_path != ":memory:" and not os.path.exists(storage.db_path):
            return seen

        async with aiosqlite.connect(storage.db_path) as db:
            cursor = await db.execute(
                "SELECT rule_id, request_json FROM evaluations WHERE rule_id LIKE 'gov-%'"
            )
            rows = await cursor.fetchall()
            for rule_id, req_json in rows:
                if rule_id:
                    seen.add(rule_id)
                if req_json:
                    try:
                        data = json.loads(req_json)
                        ctx = data.get("context_metadata", {})
                        pid = ctx.get("proposal_id")
                        if pid:
                            seen.add(str(pid))
                    except Exception:
                        pass
    except Exception as exc:
        logger.debug(f"Unable to preload audited proposals from {storage.db_path}: {exc}")

    return seen


def print_audit_table(reports: List[GovernanceAuditReport]) -> None:
    """
    Renders an ASCII table of audited governance proposals displaying ID, space,
    alert level, semantic decision, risk score, tokens, and USD cost.
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
    if rows:
        for row in rows:
            row_str = "|" + "|".join(f" {row[i].ljust(col_widths[i])} " for i in range(len(row))) + "|"
            print(row_str)
    else:
        empty_msg = "No new proposals audited."
        total_w = sum(col_widths) + 3 * len(col_widths) - 1
        print(f"| {empty_msg.ljust(total_w - 2)} |")
    print(separator + "\n")


async def audit_governance_proposals(
    connector: SnapshotGovernanceConnector,
    engine: ConditionAgentEngine,
    proposals: List[GovernanceProposal],
    source: str = "governance_daemon",
) -> List[GovernanceAuditReport]:
    """
    Executes end-to-end security audits across governance proposals, ensuring
    evaluation records are tagged and stored in AgentStorage with the specified source.
    """
    reports: List[GovernanceAuditReport] = []
    for prop in proposals:
        payload = connector.proposal_to_rule_payload(prop)
        resp = await engine.process_rule(payload, source=source)

        if resp.semantic_Evaluation is None:
            alert_level: Literal["CRITICAL", "WARNING", "INFO"] = "INFO"
        elif resp.semantic_Evaluation.recommended_action == "REJECT":
            alert_level = "CRITICAL"
        elif resp.semantic_Evaluation.recommended_action == "MANUAL_REVIEW":
            alert_level = "WARNING"
        else:
            alert_level = "INFO"

        reports.append(
            GovernanceAuditReport(
                proposal=prop,
                rule_id=payload.rule_id,
                agent_response=resp,
                alert_level=alert_level,
            )
        )
    return reports


async def run_governance_daemon(
    poll_interval: float = 120.0,
    once: bool = False,
    dry_run: bool = False,
    limit: int = 3,
    spaces: Optional[Union[List[str], str]] = None,
    webhook_url: Optional[str] = None,
    public_api_url: Optional[str] = None,
    min_alert_level: str = "WARNING",
    engine: Optional[ConditionAgentEngine] = None,
    storage: Optional[AgentStorage] = None,
    connector: Optional[SnapshotGovernanceConnector] = None,
    max_iterations: Optional[int] = None,
    db_path: Optional[str] = None,
) -> List[GovernanceAuditReport]:
    """
    Autonomous governance daemon loop monitoring DAOs via Snapshot.

    Parameters:
        poll_interval: Sleep duration in seconds between discovery cycles (default: 120.0).
        once: If True, executes only one scan round and terminates.
        dry_run: If True, uses deterministic mock proposals and MockSemanticEvaluator.
        limit: Maximum number of proposals to inspect per DAO space (default: 3).
        spaces: List or comma-separated string of DAO space identifiers.
        webhook_url: Optional webhook URL for threat alerts (overrides ALERT_WEBHOOK_URL).
        public_api_url: Public API base URL included in x402 alert links.
        min_alert_level: Minimum alert severity to trigger webhook notifications (default: WARNING).
        engine: Optional pre-configured ConditionAgentEngine instance.
        storage: Optional pre-configured AgentStorage instance.
        connector: Optional pre-configured SnapshotGovernanceConnector instance.
        max_iterations: Optional maximum loop iterations before exiting (primarily for testing).
        db_path: Optional SQLite database file path.

    Returns:
        List of all GovernanceAuditReport instances audited during the run.
    """
    target_spaces = parse_spaces(spaces)
    active_webhook = webhook_url or os.getenv("ALERT_WEBHOOK_URL")

    # Storage setup
    storage_instance = storage if storage is not None else AgentStorage(db_path=db_path)
    await storage_instance.initialize()

    # Preload already audited proposals to ensure deduplication
    seen_proposal_ids: Set[str] = set()
    preloaded = await load_audited_proposal_ids(storage_instance)
    seen_proposal_ids.update(preloaded)

    # Engine setup
    if engine is not None:
        active_engine = engine
    elif dry_run:
        evaluator = MockSemanticEvaluator()
        active_engine = ConditionAgentEngine(
            semantic_evaluator=evaluator,
            storage=storage_instance,
        )
    else:
        active_engine = ConditionAgentEngine(
            storage=storage_instance,
        )

    # Connector setup
    active_connector = connector or SnapshotGovernanceConnector(
        default_chain_id=ChainId.BASE_SEPOLIA
    )

    all_audited_reports: List[GovernanceAuditReport] = []
    iteration = 0

    print("=" * 72)
    print("Web3 Condition-Action Trigger Agent: DAO Governance Daemon (Engine 2)")
    print("=" * 72)
    print(f"[*] Target Spaces ({len(target_spaces)}): {', '.join(target_spaces)}")
    print(f"[*] Mode: {'DRY-RUN (Simulated)' if dry_run else 'LIVE SNAPSHOT GRAPHQL'}")
    print(f"[*] Execution: {'SINGLE PASS (--once)' if once else f'CONTINUOUS (poll: {poll_interval}s)'}")
    print(f"[*] Limit per space: {limit}")
    if active_webhook:
        print(f"[*] Webhook Dispatch: ENABLED (min_level={min_alert_level})")
    print(f"[*] Ledger Persistence: {storage_instance.db_path}")
    print("=" * 72 + "\n")

    try:
        while True:
            iteration += 1
            timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[{timestamp_str}] [Iteration #{iteration}] Scanning governance proposals...")

            cycle_reports: List[GovernanceAuditReport] = []

            # 1. Discover proposals
            discovered_proposals: List[GovernanceProposal] = []
            if dry_run:
                discovered_proposals = get_mock_daemon_proposals(target_spaces, limit=limit)
            else:
                for space in target_spaces:
                    try:
                        props = await active_connector.fetch_proposals(
                            spaces=[space],
                            limit=max(limit * 2, 5),
                            state="all",
                            use_curated_fallback=True,
                        )
                        # Prefer active proposals, fallback to most recent if none active
                        active_props = [p for p in props if p.state.lower() == "active"]
                        selected = active_props[:limit] if active_props else props[:limit]

                        # Apply heuristic on-chain hint extraction
                        for p in selected:
                            hints = extract_onchain_hints(p.body)
                            if hints.get("target_address"):
                                p.target_address = hints["target_address"]
                            if hints.get("calldata") and hints["calldata"] != "0x":
                                p.calldata = hints["calldata"]

                        discovered_proposals.extend(selected)
                    except Exception as exc:
                        logger.warning(f"Error fetching Snapshot proposals for space '{space}': {exc}")

            # 2. Filter out already processed proposals
            new_proposals: List[GovernanceProposal] = []
            for prop in discovered_proposals:
                rule_id = f"gov-{prop.space_id}-{prop.proposal_id[:12]}"
                if prop.proposal_id in seen_proposal_ids or rule_id in seen_proposal_ids:
                    logger.debug(f"Skipping already audited proposal: {prop.proposal_id}")
                    continue
                new_proposals.append(prop)

            # 3. Audit newly discovered proposals
            if new_proposals:
                print(f"[+] Discovered {len(new_proposals)} new un-audited proposal(s). Running audits...")
                cycle_reports = await audit_governance_proposals(
                    connector=active_connector,
                    engine=active_engine,
                    proposals=new_proposals,
                    source="governance_daemon",
                )

                # Record into seen tracking set
                for r in cycle_reports:
                    seen_proposal_ids.add(r.proposal.proposal_id)
                    seen_proposal_ids.add(r.rule_id)
                all_audited_reports.extend(cycle_reports)

                # 4. Display ASCII table
                print_audit_table(cycle_reports)

                # 5. Webhook dispatch
                if active_webhook:
                    dispatcher = WebhookAlertDispatcher(
                        webhook_url=active_webhook,
                        public_api_url=public_api_url,
                    )
                    sent_count = await dispatcher.dispatch_batch(
                        cycle_reports,
                        min_alert_level=min_alert_level,
                    )
                    print(f"[+] Dispatched {sent_count} webhook alert(s) (min_level={min_alert_level}).")

                # Metrics summary
                rejections = [r for r in cycle_reports if r.alert_level == "CRITICAL"]
                warnings = [r for r in cycle_reports if r.alert_level == "WARNING"]
                info = [r for r in cycle_reports if r.alert_level == "INFO"]
                print(
                    f"[*] Iteration #{iteration} Summary: {len(cycle_reports)} audited | "
                    f"Critical: {len(rejections)} | Warning: {len(warnings)} | Info: {len(info)}\n"
                )
            else:
                print(f"[*] Iteration #{iteration}: All {len(discovered_proposals)} proposal(s) previously audited. No new actions.")

            if once:
                print("[*] Single scan cycle (--once) completed.")
                break

            if max_iterations is not None and iteration >= max_iterations:
                print(f"[*] Reached max iterations ({max_iterations}). Exiting daemon loop.")
                break

            print(f"[*] Sleeping for {poll_interval}s until next poll cycle (Press Ctrl+C to stop)...")
            await asyncio.sleep(poll_interval)

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[*] Governance daemon stopped by user or cancellation signal.")

    return all_audited_reports


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses command-line arguments for the governance daemon."""
    parser = argparse.ArgumentParser(
        description="Autonomous DAO Governance Proposal Monitor & Security Daemon (Engine 2)"
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=120.0,
        help="Polling interval in seconds between governance proposal scans (default: 120.0)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        default=False,
        help="Execute a single discovery and audit cycle then exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Run in offline dry-run mode using curated mock proposals and MockSemanticEvaluator",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Maximum number of proposals to inspect per DAO space (default: 3)",
    )
    parser.add_argument(
        "--spaces",
        type=str,
        default=None,
        help="Comma-separated list of Snapshot space identifiers (e.g. 'uniswap.eth,arbitrumfoundation.eth')",
    )
    parser.add_argument(
        "--space",
        action="append",
        dest="space_list",
        default=None,
        help="Single Snapshot space identifier (can be repeated, e.g. --space ens.eth --space aave.eth)",
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        default=None,
        help="Optional Discord/Slack/HTTP webhook URL for threat notifications (overrides ALERT_WEBHOOK_URL env)",
    )
    parser.add_argument(
        "--public-url",
        type=str,
        default=None,
        help="Public API base URL included in x402 alert links",
    )
    parser.add_argument(
        "--min-alert-level",
        type=str,
        default="WARNING",
        choices=["INFO", "WARNING", "CRITICAL"],
        help="Minimum alert severity to trigger webhook dispatch (default: WARNING)",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional SQLite database path (defaults to data/agent.db)",
    )
    return parser.parse_args(args)


def main() -> None:
    """CLI entrypoint for running the governance daemon."""
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    combined_spaces = []
    if args.spaces:
        combined_spaces.append(args.spaces)
    if args.space_list:
        combined_spaces.extend(args.space_list)
    spaces_input = combined_spaces if combined_spaces else None

    asyncio.run(
        run_governance_daemon(
            poll_interval=args.poll_interval,
            once=args.once,
            dry_run=args.dry_run,
            limit=args.limit,
            spaces=spaces_input,
            webhook_url=args.webhook_url,
            public_api_url=args.public_url,
            min_alert_level=args.min_alert_level,
            db_path=args.db_path,
        )
    )


if __name__ == "__main__":
    main()
