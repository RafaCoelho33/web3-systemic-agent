"""
Active Multi-Channel Contract Hunter CLI for Base Mainnet & DAO Governance.

Executes autonomous, zero-API-key, zero-gas discovery cycles across 5 channels
(Base Mainnet block deployments, Aerodrome/Uniswap v3 DEX pools, GeckoTerminal New Pools,
DexScreener Token Profiles, and Snapshot DAO proposals), renders an ASCII audit table,
and persists findings to the SQLite AgentStorage ledger.

Usage Examples:
    # 1. Offline dry-run simulation (zero network calls, zero LLM cost):
    python scripts/active_contract_hunter.py --dry-run --once

    # 2. Single live hunt cycle across specific channels:
    python scripts/active_contract_hunter.py --once --channels geckoterminal_base,dexscreener_base --limit 3

    # 3. Continuous daemon polling every 60 seconds with webhook alerts:
    python scripts/active_contract_hunter.py --continuous --poll-interval 60 --webhook-url https://discord.com/api/webhooks/...

    # 4. Custom RPC and SQLite DB path:
    python scripts/active_contract_hunter.py --once --rpc-url https://mainnet.base.org --db-path data/agent.db
"""

import argparse
import asyncio
import logging
import os
import sys
from typing import Any, Dict, List, Optional

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
    from src.discovery_hunter import ActiveContractHunter, SUPPORTED_CHANNELS
    from src.storage import AgentStorage
except ImportError:
    from discovery_hunter import ActiveContractHunter, SUPPORTED_CHANNELS
    from storage import AgentStorage

logger = logging.getLogger("active_contract_hunter")

DEFAULT_CHANNELS_CSV = ",".join(SUPPORTED_CHANNELS)


def print_hunt_table(results: List[Dict[str, Any]]) -> None:
    """Renders an ASCII table displaying channel, target address/ID, risk score, decision, and llm_invoked."""
    headers = [
        "Canal",
        "Endereço / Alvo",
        "Risco",
        "Decisão",
        "llm_invoked",
    ]
    rows: List[List[str]] = []
    for r in results:
        channel = str(r.get("channel", "N/A"))
        target = str(r.get("target", "N/A"))
        if len(target) > 46:
            target = target[:43] + "..."
        risk_val = r.get("risk_score", 0.0)
        risk_str = f"{float(risk_val):.1f}" if risk_val is not None else "N/A"
        decision = str(r.get("decision", "N/A"))
        llm_invoked = str(bool(r.get("llm_invoked", False)))
        rows.append([channel, target, risk_str, decision, llm_invoked])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(val))

    separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_line = "|" + "|".join(f" {headers[i].ljust(col_widths[i])} " for i in range(len(headers))) + "|"

    print("\n" + separator)
    print(header_line)
    print(separator)
    if rows:
        for row in rows:
            print("|" + "|".join(f" {row[i].ljust(col_widths[i])} " for i in range(len(row))) + "|")
    else:
        empty_msg = "Nenhum contrato ou proposta descoberto neste ciclo."
        total_w = sum(col_widths) + 3 * len(col_widths) - 1
        print(f"| {empty_msg.ljust(max(1, total_w - 2))} |")
    print(separator + "\n")


def parse_channels(channels_csv: str) -> List[str]:
    """Parses comma-separated discovery channel names into a validated list."""
    parsed = [c.strip() for c in channels_csv.split(",") if c.strip()]
    if not parsed:
        return list(SUPPORTED_CHANNELS)
    invalid = [c for c in parsed if c not in SUPPORTED_CHANNELS]
    if invalid:
        raise ValueError(
            f"Unsupported channel(s): {', '.join(invalid)}. "
            f"Valid options: {', '.join(SUPPORTED_CHANNELS)}"
        )
    return parsed


async def run_hunter(args: argparse.Namespace) -> Dict[str, Any]:
    """Executes one or continuous discovery cycles using ActiveContractHunter."""
    channels = parse_channels(args.channels)
    storage = AgentStorage(db_path=args.db_path)
    await storage.initialize()

    hunter = ActiveContractHunter(
        storage=storage,
        rpc_url=args.rpc_url,
        webhook_url=args.webhook_url,
        public_api_url=args.public_url,
    )

    print("=" * 72)
    print("Web3 Systemic Agent: Active Multi-Channel Contract Hunter")
    print("=" * 72)
    print(f"[*] Mode: {'DRY-RUN (Simulated)' if args.dry_run else 'LIVE MULTI-CHANNEL'}")
    print(f"[*] Channels ({len(channels)}): {', '.join(channels)}")
    print(f"[*] Limit per channel: {args.limit}")
    print(f"[*] SQLite Ledger: {storage.db_path}")
    print("=" * 72)

    if args.continuous and not args.once:
        print(f"[*] Starting continuous hunter loop (poll_interval={args.poll_interval}s). Press Ctrl+C to stop.")
        last_summary: Dict[str, Any] = {}
        try:
            while True:
                last_summary = await hunter.run_hunt_cycle(
                    channels=channels,
                    limit_per_channel=args.limit,
                    dry_run=args.dry_run,
                )
                print_hunt_table(last_summary.get("results", []))
                print(
                    f"[*] Cycle summary: discovered={last_summary['total_discovered']} | "
                    f"audited={last_summary['total_audited']} | "
                    f"high_risk={last_summary['high_risk_count']}"
                )
                await asyncio.sleep(max(0.1, float(args.poll_interval)))
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n[*] Continuous hunter stopped.")
        return last_summary

    summary = await hunter.run_hunt_cycle(
        channels=channels,
        limit_per_channel=args.limit,
        dry_run=args.dry_run,
    )
    print_hunt_table(summary.get("results", []))
    print(
        f"[*] Hunt Summary: discovered={summary['total_discovered']} | "
        f"audited={summary['total_audited']} | "
        f"high_risk={summary['high_risk_count']}"
    )
    return summary


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses CLI arguments for scripts/active_contract_hunter.py."""
    parser = argparse.ArgumentParser(
        description="Autonomous 5-Channel Active Contract & Governance Hunter"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Run deterministic offline simulation without external HTTP/RPC/LLM calls",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        default=False,
        help="Execute a single hunt cycle and exit (default behavior if --continuous is not set)",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        default=False,
        help="Run continuous polling daemon across selected channels",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=60.0,
        help="Polling interval in seconds for --continuous mode (default: 60.0)",
    )
    parser.add_argument(
        "--channels",
        type=str,
        default=DEFAULT_CHANNELS_CSV,
        help=f"Comma-separated list of channels (default: {DEFAULT_CHANNELS_CSV})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=2,
        help="Maximum items to discover and audit per channel (default: 2)",
    )
    parser.add_argument(
        "--rpc-url",
        type=str,
        default=None,
        help="Optional Base Mainnet RPC URL override",
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        default=None,
        help="Optional Discord/Slack/HTTP webhook URL for CRITICAL/REJECT alerts",
    )
    parser.add_argument(
        "--public-url",
        type=str,
        default=None,
        help="Optional public API URL included in x402 webhook payloads",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional SQLite ledger database path (default: data/agent.db)",
    )
    return parser.parse_args(args)


def main() -> int:
    """CLI entrypoint."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = parse_args()
    try:
        asyncio.run(run_hunter(args))
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        logger.error(f"Active hunter failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
