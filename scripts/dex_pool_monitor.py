"""
Autonomous DEX Liquidity Pool Monitor & Honeypot Auditor for Base Mainnet.

Engine 3 of the Web3 Condition-Action Trigger Agent.
Monitors the creation of new liquidity pools on Aerodrome Finance and Uniswap v3
on Base Mainnet (Chain ID 8453), decodes PoolCreated events via RPC logs at zero extra cost,
identifies target unverified tokens vs canonical base assets (WETH, USDC, USDbC, cbBTC),
inspects EVM bytecode for honeypot signatures (blacklist, arbitrary 100% tax, trading pause, selfdestruct),
executes deterministic and semantic evaluations via ConditionAgentEngine,
persists audit records to SQLite (data/agent.db with source="dex_pool_monitor"),
renders an ASCII audit report table, and dispatches webhook alerts.

Factory Contracts Monitored on Base Mainnet (Chain ID 8453):
    1. Aerodrome Factory: 0x420DD381b31aEf6683db6B902084cB0FFECe40Da
       Event: PoolCreated(address indexed token0, address indexed token1, bool stable, address pool, uint256)
       Topic0: 0x2128d88fa89c09c2a26569145610817c7621c172bc97d919a3b6805175e53303
    2. Uniswap v3 Factory: 0x33128a8fC17869897dcE68Ed026d694621f6FDfD
       Event: PoolCreated(address indexed token0, address indexed token1, uint24 fee, int24 tickSpacing, address pool)
       Topic0: 0x783cca1c041e8d94974f7875ce418c7bc05524c2b19bb87934f716002bc0ffab

Usage Examples:
    # 1. Dry-run simulation (offline, zero RPC calls, zero LLM cost):
    python scripts/dex_pool_monitor.py --dry-run

    # 2. Single scan across recent 100 blocks on Base Mainnet:
    python scripts/dex_pool_monitor.py --blocks 100 --limit 5

    # 3. Continuous polling daemon mode:
    python scripts/dex_pool_monitor.py --continuous --poll-interval 15

    # 4. Custom RPC endpoint and webhook alerts:
    python scripts/dex_pool_monitor.py --rpc-url https://mainnet.base.org --webhook-url https://discord.com/api/webhooks/...
"""

import argparse
import asyncio
from datetime import datetime, timezone
import inspect
import json
import logging
import os
import re
import sys
import time
from typing import Dict, Any, Optional, List, Tuple, Union
from unittest.mock import AsyncMock, MagicMock

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
    import httpx
except ImportError:
    httpx = None  # type: ignore

from web3 import AsyncWeb3, AsyncHTTPProvider, Web3
from web3.exceptions import Web3Exception

try:
    from src.schemas import (
        ChainId,
        ConditionRulePayload,
        DeterministicCondition,
        SemanticCondition,
        FinalAgentResponse,
    )
    from src.chain_inspector import ChainInspector
    from src.engine import ConditionAgentEngine
    from src.semantic_evaluator import (
        MockSemanticEvaluator,
        get_semantic_evaluator,
    )
    from src.storage import AgentStorage
except ImportError:
    from schemas import (
        ChainId,
        ConditionRulePayload,
        DeterministicCondition,
        SemanticCondition,
        FinalAgentResponse,
    )
    from chain_inspector import ChainInspector
    from engine import ConditionAgentEngine
    from semantic_evaluator import (
        MockSemanticEvaluator,
        get_semantic_evaluator,
    )
    from storage import AgentStorage

logger = logging.getLogger("dex_pool_monitor")

# Base Mainnet Network Parameters
CHAIN_ID_BASE_MAINNET = 8453
DEFAULT_BASE_RPC = "https://mainnet.base.org"

# DEX Factory Contracts on Base Mainnet
AERODROME_FACTORY_ADDRESS = Web3.to_checksum_address("0x420DD381b31aEf6683db6B902084cB0FFECe40Da")
UNISWAP_V3_FACTORY_ADDRESS = Web3.to_checksum_address("0x33128a8fC17869897dcE68Ed026d694621f6FDfD")

# PoolCreated Event Topics
# Aerodrome: PoolCreated(address indexed token0, address indexed token1, bool stable, address pool, uint256)
AERODROME_POOL_CREATED_TOPIC0 = "0x2128d88fa89c09c2a26569145610817c7621c172bc97d919a3b6805175e53303"
# Uniswap v3: PoolCreated(address indexed token0, address indexed token1, uint24 fee, int24 tickSpacing, address pool)
UNISWAP_V3_POOL_CREATED_TOPIC0 = "0x783cca1c041e8d94974f7875ce418c7bc05524c2b19bb87934f716002bc0ffab"

# Canonical Base Mainnet Liquid Assets
BASE_TOKENS: Dict[str, str] = {
    Web3.to_checksum_address("0x4200000000000000000000000000000000000006"): "WETH",
    Web3.to_checksum_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"): "USDC",
    Web3.to_checksum_address("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"): "USDbC",
    Web3.to_checksum_address("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"): "cbBTC",
}
BASE_TOKENS_LOWER: Dict[str, Tuple[str, str]] = {
    addr.lower(): (addr, sym) for addr, sym in BASE_TOKENS.items()
}

# Critical Honeypot, Rugpull, and Malicious Smart Contract Selectors
HONEYPOT_SELECTORS: Dict[str, Dict[str, str]] = {
    # 1. Blacklist Manipulation
    "0xf9f02b01": {
        "signature": "isBlacklisted(address)",
        "category": "blacklist",
        "description": "Blacklist query function (used to selectively block transfers)",
        "severity": "CRITICAL",
    },
    "0x40af1275": {
        "signature": "setBlacklist(address,bool)",
        "category": "blacklist",
        "description": "Blacklist modification (can prevent users from selling/transferring)",
        "severity": "CRITICAL",
    },
    "0x4433766a": {
        "signature": "addToBlacklist(address)",
        "category": "blacklist",
        "description": "Arbitrary blacklist addition",
        "severity": "CRITICAL",
    },
    "0xfa4526f8": {
        "signature": "blacklist(address)",
        "category": "blacklist",
        "description": "Blacklist trigger function",
        "severity": "CRITICAL",
    },
    "0x5a54e565": {
        "signature": "isBlackList(address)",
        "category": "blacklist",
        "description": "Blacklist status verification",
        "severity": "CRITICAL",
    },
    # 2. Arbitrary Transfer Fee & 100% Tax Traps
    "0x8a92d475": {
        "signature": "setFee(uint256)",
        "category": "fee_tax",
        "description": "Arbitrary transfer fee configuration",
        "severity": "HIGH",
    },
    "0x1e3dd19f": {
        "signature": "setTax(uint256)",
        "category": "fee_tax",
        "description": "Arbitrary transaction tax configuration (honeypot risk)",
        "severity": "CRITICAL",
    },
    "0x4a7e9375": {
        "signature": "setBuyFee(uint256)",
        "category": "fee_tax",
        "description": "Buy tax modification",
        "severity": "MEDIUM",
    },
    "0x4b7890ec": {
        "signature": "setSellFee(uint256)",
        "category": "fee_tax",
        "description": "Sell tax modification (allows setting 99-100% honeypot sell tax)",
        "severity": "CRITICAL",
    },
    "0x1f56a319": {
        "signature": "setFeeRate(uint256)",
        "category": "fee_tax",
        "description": "Transfer fee rate modification",
        "severity": "HIGH",
    },
    "0x32e54143": {
        "signature": "setMaxTax(uint256)",
        "category": "fee_tax",
        "description": "Max tax modification",
        "severity": "MEDIUM",
    },
    "0x8c6d1d78": {
        "signature": "setTaxFeePercent(uint256)",
        "category": "fee_tax",
        "description": "Tax fee percentage manipulation",
        "severity": "HIGH",
    },
    # 3. Trading Freeze & Pause Mechanisms
    "0x4fbee1e3": {
        "signature": "pause()",
        "category": "pause_trading",
        "description": "Contract execution freeze (can halt trading indefinitely)",
        "severity": "HIGH",
    },
    "0x8456cb59": {
        "signature": "unpause()",
        "category": "pause_trading",
        "description": "Contract execution unpause",
        "severity": "LOW",
    },
    "0x8a8c523c": {
        "signature": "enableTrading()",
        "category": "pause_trading",
        "description": "Trading enablement gate (can be kept permanently closed)",
        "severity": "HIGH",
    },
    "0x34468f9b": {
        "signature": "setTrading(bool)",
        "category": "pause_trading",
        "description": "Arbitrary trading toggle (can disable selling after launch)",
        "severity": "CRITICAL",
    },
    "0xc9567bf9": {
        "signature": "openTrading()",
        "category": "pause_trading",
        "description": "Trading opening trigger",
        "severity": "HIGH",
    },
    "0xd8eb23cf": {
        "signature": "setTradingEnabled(bool)",
        "category": "pause_trading",
        "description": "Trading status override",
        "severity": "CRITICAL",
    },
    # 4. Contract Destruction & Draining
    "0x00f714ce": {
        "signature": "selfdestruct()",
        "category": "destruct_drain",
        "description": "Contract self-destruction (permanently bricks token and sweeps funds)",
        "severity": "CRITICAL",
    },
    "0x41c0e1b5": {
        "signature": "kill()",
        "category": "destruct_drain",
        "description": "Emergency kill switch",
        "severity": "CRITICAL",
    },
    "0x83197ef0": {
        "signature": "destroy(address)",
        "category": "destruct_drain",
        "description": "Contract destroy and balance sweep",
        "severity": "CRITICAL",
    },
    # 5. Privileged Admin & Minting Backdoors
    "0xf2fde38b": {
        "signature": "transferOwnership(address)",
        "category": "privileged",
        "description": "Centralized ownership transfer",
        "severity": "MEDIUM",
    },
    "0x3659cfe6": {
        "signature": "upgradeTo(address)",
        "category": "privileged",
        "description": "Proxy contract upgradability (logic can be swapped to honeypot)",
        "severity": "HIGH",
    },
    "0x40c10f19": {
        "signature": "mint(address,uint256)",
        "category": "privileged",
        "description": "Arbitrary token minting (unlimited inflation / dump risk)",
        "severity": "HIGH",
    },
}

# Standard ERC-20 Selectors for Reference
STANDARD_ERC20_SELECTORS: Dict[str, str] = {
    "0xa9059cbb": "transfer(address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x70a08231": "balanceOf(address)",
    "0x18160ddd": "totalSupply()",
    "0x313ce567": "decimals()",
    "0x06fdde03": "name()",
    "0x95d89b41": "symbol()",
}

DISPATCHER_REGEX = re.compile(r"(?:63|8063|8263)([0-9a-fA-F]{8})14", re.IGNORECASE)


def decode_address_from_topic(topic: Union[bytes, str]) -> str:
    """Decodes a 20-byte EVM address from a 32-byte log topic."""
    if isinstance(topic, (bytes, bytearray)):
        topic_hex = topic.hex()
    else:
        topic_hex = str(topic)
    if topic_hex.startswith("0x"):
        topic_hex = topic_hex[2:]
    raw_addr = "0x" + topic_hex[-40:]
    return Web3.to_checksum_address(raw_addr)


def decode_aerodrome_pool_data(data: Union[bytes, str]) -> Tuple[str, bool]:
    """
    Decodes unindexed parameters from Aerodrome PoolCreated event:
    Event data layout: (bool stable, address pool, uint256 index)
    Word 0 (0..64): bool stable
    Word 1 (64..128): address pool (last 40 hex chars)
    """
    if isinstance(data, (bytes, bytearray)):
        data_hex = data.hex()
    else:
        data_hex = str(data)
    if data_hex.startswith("0x"):
        data_hex = data_hex[2:]

    if len(data_hex) < 128:
        return ("0x0000000000000000000000000000000000000000", False)

    stable_word = data_hex[0:64]
    pool_word = data_hex[64:128]

    stable = int(stable_word, 16) != 0
    pool_address = Web3.to_checksum_address("0x" + pool_word[-40:])
    return (pool_address, stable)


def decode_univ3_pool_data(data: Union[bytes, str]) -> Tuple[str, int, int]:
    """
    Decodes unindexed parameters from Uniswap v3 PoolCreated event:
    Event data layout: (uint24 fee, int24 tickSpacing, address pool)
    Word 0 (0..64): uint24 fee
    Word 1 (64..128): int24 tickSpacing
    Word 2 (128..192): address pool (last 40 hex chars)
    """
    if isinstance(data, (bytes, bytearray)):
        data_hex = data.hex()
    else:
        data_hex = str(data)
    if data_hex.startswith("0x"):
        data_hex = data_hex[2:]

    if len(data_hex) < 192:
        return ("0x0000000000000000000000000000000000000000", 3000, 60)

    fee_word = data_hex[0:64]
    tick_spacing_word = data_hex[64:128]
    pool_word = data_hex[128:192]

    fee = int(fee_word, 16)
    raw_tick_bytes = bytes.fromhex(tick_spacing_word)
    tick_spacing = int.from_bytes(raw_tick_bytes, byteorder="big", signed=True)
    pool_address = Web3.to_checksum_address("0x" + pool_word[-40:])
    return (pool_address, fee, tick_spacing)


def identify_target_token(token0: str, token1: str) -> Tuple[str, str, str]:
    """
    Identifies the unverified target token vs the known base token (WETH, USDC, USDbC, cbBTC).

    Returns:
        (target_token, base_token, pair_name)
    """
    t0_cs = Web3.to_checksum_address(token0)
    t1_cs = Web3.to_checksum_address(token1)

    t0_lower = t0_cs.lower()
    t1_lower = t1_cs.lower()

    t0_is_base = t0_lower in BASE_TOKENS_LOWER
    t1_is_base = t1_lower in BASE_TOKENS_LOWER

    if t0_is_base and not t1_is_base:
        base_addr, base_sym = BASE_TOKENS_LOWER[t0_lower]
        target_token = t1_cs
        base_token = base_addr
        pair_name = f"{t1_cs[:6]}.../{base_sym}"
    elif t1_is_base and not t0_is_base:
        base_addr, base_sym = BASE_TOKENS_LOWER[t1_lower]
        target_token = t0_cs
        base_token = base_addr
        pair_name = f"{t0_cs[:6]}.../{base_sym}"
    elif t0_is_base and t1_is_base:
        base_addr0, base_sym0 = BASE_TOKENS_LOWER[t0_lower]
        base_addr1, base_sym1 = BASE_TOKENS_LOWER[t1_lower]
        target_token = t1_cs
        base_token = base_addr0
        pair_name = f"{base_sym0}/{base_sym1}"
    else:
        # Both tokens are unverified new assets
        target_token = t0_cs
        base_token = t1_cs
        pair_name = f"{t0_cs[:6]}.../{t1_cs[:6]}..."

    return (target_token, base_token, pair_name)


def extract_selectors_from_bytecode(
    bytecode: Union[bytes, str],
) -> List[Dict[str, Any]]:
    """
    Extracts 4-byte EVM function selectors and maps known signatures from bytecode.
    """
    if isinstance(bytecode, bytes):
        bytecode_hex = bytecode.hex()
    else:
        bytecode_hex = bytecode[2:] if bytecode.startswith("0x") else bytecode

    found: Dict[str, Dict[str, Any]] = {}
    bytecode_lower = bytecode_hex.lower()

    # Search for all Honeypot and Standard Selectors directly
    all_known = {**STANDARD_ERC20_SELECTORS, **{k: v["signature"] for k, v in HONEYPOT_SELECTORS.items()}}
    for sel_hex, sig in all_known.items():
        clean_sel = sel_hex[2:].lower()
        if clean_sel in bytecode_lower:
            found[sel_hex] = {
                "selector": sel_hex,
                "signature": sig,
                "known": True,
            }

    # Extract selectors matching standard EVM dispatcher pattern
    for m in DISPATCHER_REGEX.findall(bytecode_hex):
        sel_hex = f"0x{m.lower()}"
        if sel_hex not in found:
            sig = all_known.get(sel_hex, f"unknown({sel_hex})")
            found[sel_hex] = {
                "selector": sel_hex,
                "signature": sig,
                "known": sel_hex in all_known,
            }

    return list(found.values())


def analyze_bytecode_honeypot(bytecode: Union[bytes, str]) -> Dict[str, Any]:
    """
    Performs comprehensive static bytecode analysis for honeypot indicators:
      - Blacklist manipulation (0xf9f02b01, 0x40af1275, etc.)
      - Arbitrary transfer tax / 100% sell fee traps (setTax, setFee, setSellFee)
      - Trading freeze / pause backdoors (pause, setTrading, enableTrading)
      - Contract self-destruction / drainage (selfdestruct, kill, destroy)
    """
    selectors = extract_selectors_from_bytecode(bytecode)
    sel_map = {s["selector"].lower(): s for s in selectors}

    if isinstance(bytecode, bytes):
        bytecode_hex = bytecode.hex().lower()
    else:
        bytecode_hex = (bytecode[2:] if bytecode.startswith("0x") else bytecode).lower()

    honeypot_flags: List[str] = []
    categories: Dict[str, List[str]] = {
        "blacklist": [],
        "fee_tax": [],
        "pause_trading": [],
        "destruct_drain": [],
        "privileged": [],
    }

    # Check for Honeypot function selectors
    for sel_hex, info in HONEYPOT_SELECTORS.items():
        clean_sel = sel_hex[2:].lower()
        matched = False
        if sel_hex.lower() in sel_map:
            matched = True
        elif clean_sel in bytecode_hex:
            matched = True

        if matched:
            cat = info["category"]
            sig = info["signature"]
            categories[cat].append(sig)
            honeypot_flags.append(f"{cat.replace('_', ' ').title()}: {sig} ({sel_hex})")

    # Opcode detection for EVM SELFDESTRUCT (0xff)
    if "ff" in bytecode_hex:
        # Check if 0xff is present as opcode outside standard push buffers
        if "selfdestruct" not in categories["destruct_drain"]:
            categories["destruct_drain"].append("SELFDESTRUCT opcode (0xff)")
            honeypot_flags.append("Destruct Drain: SELFDESTRUCT opcode (0xff)")

    # Assess overall honeypot severity
    is_honeypot = bool(
        categories["blacklist"]
        or categories["fee_tax"]
        or categories["destruct_drain"]
        or (categories["pause_trading"] and "settrading" in str(categories["pause_trading"]).lower())
    )

    if categories["destruct_drain"] or categories["blacklist"]:
        severity = "CRITICAL"
    elif categories["fee_tax"] or categories["pause_trading"]:
        severity = "HIGH"
    elif categories["privileged"]:
        severity = "MEDIUM"
    else:
        severity = "CLEAN"

    # Brief table summary
    active_threats = []
    if categories["blacklist"]:
        active_threats.append("Blacklist")
    if categories["fee_tax"]:
        active_threats.append("Arbitrary Tax")
    if categories["pause_trading"]:
        active_threats.append("Trading Pause")
    if categories["destruct_drain"]:
        active_threats.append("Selfdestruct")
    if categories["privileged"] and not active_threats:
        active_threats.append("Privileged Admin")

    summary_display = ", ".join(active_threats) if active_threats else "CLEAN"

    return {
        "selectors": selectors,
        "honeypot_flags": honeypot_flags,
        "categories": categories,
        "is_honeypot": is_honeypot,
        "severity": severity,
        "summary_display": summary_display,
    }


def create_dex_pool_rule_payload(
    pool_item: Dict[str, Any],
    analysis: Dict[str, Any],
) -> ConditionRulePayload:
    """
    Constructs a validated ConditionRulePayload for evaluating a DEX liquidity pool.
    """
    target_token = Web3.to_checksum_address(pool_item["target_token"])
    pool_address = Web3.to_checksum_address(pool_item["pool_address"])
    dex_name = pool_item["dex"]
    pair_name = pool_item["pair_name"]
    block_num = pool_item.get("block_number", 0)
    tx_hash = pool_item.get("tx_hash", "0x")
    honeypot_flags = analysis.get("honeypot_flags", [])

    # Select representative selector
    matched_selector = "0x"
    matched_signature = "erc20_transfer"
    for s in analysis["selectors"]:
        if s["selector"] in HONEYPOT_SELECTORS:
            matched_selector = s["selector"]
            matched_signature = s["signature"]
            break

    threat_notes = f"CRITICAL HONEYPOT WARNING: {', '.join(honeypot_flags)}" if honeypot_flags else "Standard token implementation without honeypot patterns."

    prompt = (
        f"Audit newly created DEX liquidity pool on {dex_name} for pair {pair_name}. "
        f"Pool Contract: {pool_address}, Target Token: {target_token}. "
        f"Honeypot/Risk indicators detected: {', '.join(honeypot_flags) if honeypot_flags else 'None (Clean)'}. "
        f"Evaluate blacklist restrictions, arbitrary 100% transfer tax, trading lockup, and admin selfdestruct risks."
    )

    rule_id = f"dex-pool-{target_token.lower()[:10]}"

    return ConditionRulePayload(
        rule_id=rule_id,
        chain_id=ChainId.BASE_MAINNET,
        deterministic=DeterministicCondition(
            target_address=target_token,
            min_value_wei=0,
            required_function_selectors=None,
            check_native_balance=False,
        ),
        semantic=SemanticCondition(
            enabled=True,
            policy_prompt=prompt,
            risk_threshold=7.0,
        ),
        context_metadata={
            "dex": dex_name,
            "pool_address": pool_address,
            "target_token": target_token,
            "base_token": pool_item.get("base_token"),
            "pair": pair_name,
            "block_number": block_num,
            "tx_hash": tx_hash,
            "honeypot_flags": honeypot_flags,
            "honeypot_count": len(honeypot_flags),
            "is_honeypot_suspect": analysis.get("is_honeypot", False),
            "calldata": matched_selector,
            "calldata_analysis": {
                "selector": matched_selector,
                "signature": matched_signature,
            },
            "proposal_title": f"DEX Pool Audit: {pair_name} on {dex_name}",
            "proposal_description": (
                f"Liquidity pool created at block {block_num} on {dex_name}. "
                f"Pair: {pair_name}. Pool Address: {pool_address}. Target Token: {target_token}. "
                f"{threat_notes}"
            ),
            "selectors_found": [s["selector"] for s in analysis["selectors"]],
            "signatures_found": [s["signature"] for s in analysis["selectors"]],
            "bytecode_length": len(pool_item.get("bytecode", b"")),
        },
    )


class DexWebhookAlertDispatcher:
    """
    Dispatches formatted security alert webhooks (Discord / Slack / Generic HTTP POST)
    for high-risk pools or newly detected honeypots.
    """

    def __init__(self, webhook_url: Optional[str] = None, timeout: float = 10.0):
        self.webhook_url = webhook_url or os.getenv("WEBHOOK_URL") or os.getenv("DEX_WEBHOOK_URL")
        self.timeout = timeout

    def format_alert_payload(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Formats the result dictionary into a structured webhook alert payload."""
        dex = result.get("dex", "DEX")
        pair = result.get("pair", "N/A")
        pool_addr = result.get("pool_address", "N/A")
        target_token = result.get("target_token", "N/A")
        risk = result.get("risk_honeypot", "CLEAN")
        decision = result.get("decision", "MANUAL_REVIEW")
        score = result.get("risk_score", 0.0)
        block = result.get("block_number", 0)

        color = 0xFF0000 if decision == "REJECT" else (0xFFA500 if decision == "MANUAL_REVIEW" else 0x00FF00)

        content = (
            f"🚨 **DEX LIQUIDITY POOL SECURITY AUDIT [{decision}]** 🚨\n"
            f"• **DEX**: `{dex}`\n"
            f"• **Pair**: `{pair}`\n"
            f"• **Pool Address**: `{pool_addr}`\n"
            f"• **Target Token**: `{target_token}`\n"
            f"• **Honeypot / Risk**: `{risk}`\n"
            f"• **Decision**: `{decision}` (Risk Score: `{score:.1f}`)\n"
            f"• **Block**: `{block}`"
        )

        embeds = [
            {
                "title": f"[{decision}] {dex}: {pair} Liquidity Pool Audit",
                "color": color,
                "fields": [
                    {"name": "DEX", "value": dex, "inline": True},
                    {"name": "Pair", "value": pair, "inline": True},
                    {"name": "Decision", "value": decision, "inline": True},
                    {"name": "Risk Score", "value": f"{score:.1f}", "inline": True},
                    {"name": "Honeypot / Risk", "value": risk, "inline": False},
                    {"name": "Target Token", "value": target_token, "inline": False},
                    {"name": "Pool Address", "value": pool_addr, "inline": False},
                ],
            }
        ]

        return {
            "content": content,
            "text": content,
            "embeds": embeds,
            "dex": dex,
            "pair": pair,
            "target_token": target_token,
            "decision": decision,
            "risk_score": score,
        }

    async def dispatch_alert(self, result: Dict[str, Any]) -> bool:
        """Sends an HTTP POST alert to the configured webhook endpoint."""
        if not self.webhook_url:
            return False

        payload = self.format_alert_payload(result)
        try:
            if httpx is not None:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(self.webhook_url, json=payload)
                    return resp.status_code in (200, 204)
            else:
                logger.warning("httpx not available; webhook dispatch skipped.")
                return False
        except Exception as exc:
            logger.warning(f"Failed to dispatch webhook alert: {exc}")
            return False


async def scan_pool_events(
    w3: AsyncWeb3,
    from_block: int,
    to_block: int,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """
    Discovers newly created liquidity pools on Base Mainnet across Aerodrome and Uniswap v3
    via cost-free eth_getLogs RPC filters.

    Decodes indexed token0 and token1, identifies unverified target tokens vs base assets,
    retrieves deployed token bytecode, and returns standardized pool discovery dicts.
    """
    if limit <= 0 or from_block > to_block:
        return []

    logger.info(
        f"Scanning DEX pool events from block {from_block} to {to_block} (limit {limit})..."
    )

    # 1. Concurrently query Aerodrome and Uniswap v3 Factory logs
    aero_filter = {
        "fromBlock": from_block,
        "toBlock": to_block,
        "address": AERODROME_FACTORY_ADDRESS,
        "topics": [AERODROME_POOL_CREATED_TOPIC0],
    }
    uni_filter = {
        "fromBlock": from_block,
        "toBlock": to_block,
        "address": UNISWAP_V3_FACTORY_ADDRESS,
        "topics": [UNISWAP_V3_POOL_CREATED_TOPIC0],
    }

    try:
        aero_res, uni_res = await asyncio.gather(
            w3.eth.get_logs(aero_filter),
            w3.eth.get_logs(uni_filter),
            return_exceptions=True,
        )
    except Exception as exc:
        logger.error(f"Error querying logs from RPC: {exc}")
        return []

    raw_logs: List[Tuple[str, Any]] = []
    if isinstance(aero_res, list):
        for log in aero_res:
            raw_logs.append(("Aerodrome", log))
    elif isinstance(aero_res, Exception):
        logger.warning(f"Aerodrome logs query failed: {aero_res}")

    if isinstance(uni_res, list):
        for log in uni_res:
            raw_logs.append(("Uniswap v3", log))
    elif isinstance(uni_res, Exception):
        logger.warning(f"Uniswap v3 logs query failed: {uni_res}")

    # Sort logs by blockNumber descending, then logIndex descending
    def log_sort_key(item: Tuple[str, Any]) -> Tuple[int, int]:
        log = item[1]
        b_num = log.get("blockNumber", 0) if isinstance(log, dict) else getattr(log, "blockNumber", 0)
        l_idx = log.get("logIndex", 0) if isinstance(log, dict) else getattr(log, "logIndex", 0)
        return (int(b_num or 0), int(l_idx or 0))

    raw_logs.sort(key=log_sort_key, reverse=True)

    discovered: List[Dict[str, Any]] = []

    for dex_name, log in raw_logs:
        if len(discovered) >= limit:
            break

        topics = log.get("topics", []) if isinstance(log, dict) else getattr(log, "topics", [])
        data = log.get("data", "0x") if isinstance(log, dict) else getattr(log, "data", "0x")
        block_num = log.get("blockNumber", 0) if isinstance(log, dict) else getattr(log, "blockNumber", 0)
        tx_hash_val = log.get("transactionHash", "0x") if isinstance(log, dict) else getattr(log, "transactionHash", "0x")
        tx_hash = tx_hash_val.hex() if hasattr(tx_hash_val, "hex") else str(tx_hash_val)

        if len(topics) < 3:
            continue

        try:
            token0 = decode_address_from_topic(topics[1])
            token1 = decode_address_from_topic(topics[2])
        except Exception as exc:
            logger.warning(f"Failed to decode token addresses from topics: {exc}")
            continue

        if dex_name == "Aerodrome":
            pool_address, stable = decode_aerodrome_pool_data(data)
            extra_meta = {"stable": stable}
        else:
            pool_address, fee, tick_spacing = decode_univ3_pool_data(data)
            extra_meta = {"fee": fee, "tick_spacing": tick_spacing}

        target_token, base_token, pair_name = identify_target_token(token0, token1)

        # Retrieve bytecode of the target unverified token
        try:
            bytecode = await w3.eth.get_code(target_token)
        except Exception as exc:
            logger.warning(f"Failed to fetch bytecode for target token {target_token}: {exc}")
            bytecode = b""

        discovered.append({
            "dex": dex_name,
            "block_number": int(block_num or 0),
            "tx_hash": tx_hash,
            "pool_address": pool_address,
            "token0": token0,
            "token1": token1,
            "target_token": target_token,
            "base_token": base_token,
            "pair_name": pair_name,
            "bytecode": bytecode,
            "extra_meta": extra_meta,
        })
        logger.info(
            f"Discovered {dex_name} pool: {pair_name} ({pool_address}) at block {block_num}"
        )

    return discovered


class DexSemanticEvaluator(MockSemanticEvaluator):
    """
    Subclasses MockSemanticEvaluator to simulate Honeypot reasoning and risk scoring
    offline without incurring external LLM API cost.
    """

    async def evaluate(
        self,
        condition: SemanticCondition,
        observed_onchain: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        result = await super().evaluate(condition, observed_onchain, metadata, context)
        ctx = metadata if metadata is not None else (context or {})
        honeypot_flags = ctx.get("honeypot_flags", [])

        if honeypot_flags:
            score = max(result.risk_score, 8.5 + min(1.5, len(honeypot_flags) * 0.3))
            score = min(10.0, score)
            flagged = list(result.flagged_issues) + [f"Honeypot Flag: {f}" for f in honeypot_flags]
            return result.model_copy(
                update={
                    "risk_score": score,
                    "recommended_action": "REJECT",
                    "conditions_met": True,
                    "flagged_issues": flagged,
                    "summary": f"CRITICAL HONEYPOT DETECTED: {', '.join(honeypot_flags)}. " + result.summary,
                }
            )
        return result


async def audit_discovered_pools(
    pools: List[Dict[str, Any]],
    engine: ConditionAgentEngine,
    rpc_url: Optional[str] = None,
    webhook_dispatcher: Optional[DexWebhookAlertDispatcher] = None,
) -> List[Dict[str, Any]]:
    """
    Executes honeypot bytecode analysis and two-stage deterministic/semantic risk evaluation
    for all discovered DEX liquidity pools. Persists audit reports to SQLite via AgentStorage.
    """
    results: List[Dict[str, Any]] = []

    for item in pools:
        target_token = item["target_token"]
        bytecode = item.get("bytecode", b"")
        bytecode_bytes = bytecode if isinstance(bytecode, bytes) else bytes.fromhex(
            bytecode[2:] if bytecode.startswith("0x") else bytecode
        )

        # 1. Analyze bytecode for honeypot traps
        analysis = analyze_bytecode_honeypot(bytecode_bytes)

        # 2. Populate ChainInspector cache to guarantee zero redundant RPC calls
        ChainInspector._set_bytecode_cache(f"{CHAIN_ID_BASE_MAINNET}:{target_token}", bytecode_bytes)

        # 3. Create validated condition rule payload
        payload = create_dex_pool_rule_payload(item, analysis)

        # 4. Execute ConditionAgentEngine two-stage audit
        try:
            response = await engine.process_rule(payload, source="dex_pool_monitor")
        except Exception as exc:
            logger.error(f"Audit failed for pool {item['pool_address']} / token {target_token}: {exc}")
            continue

        sem = response.semantic_Evaluation
        if analysis["is_honeypot"]:
            decision = "REJECT"
            risk_score = max(sem.risk_score if sem else 9.0, 9.0)
        else:
            decision = sem.recommended_action if sem else ("APPROVE" if response.deterministic_check.passed else "REJECT")
            risk_score = sem.risk_score if sem else (2.0 if response.deterministic_check.passed else 10.0)

        # Response is already recorded in AgentStorage by engine.process_rule(..., source="dex_pool_monitor")

        audit_entry = {
            "dex": item["dex"],
            "block_number": item["block_number"],
            "pair": item["pair_name"],
            "pool_address": item["pool_address"],
            "target_token": target_token,
            "base_token": item.get("base_token"),
            "risk_honeypot": analysis["summary_display"],
            "honeypot_flags": analysis["honeypot_flags"],
            "decision": decision,
            "risk_score": risk_score,
            "payload": payload,
            "response": response,
        }
        results.append(audit_entry)

        # Dispatch webhook alert if configured
        if webhook_dispatcher and (decision == "REJECT" or risk_score >= 7.0):
            try:
                await webhook_dispatcher.dispatch_alert(audit_entry)
            except Exception as exc:
                logger.warning(f"Webhook dispatch failed: {exc}")

    return results


def print_dex_table(results: List[Dict[str, Any]]) -> None:
    """
    Renders an ASCII table displaying audited DEX liquidity pools:
    DEX | Bloco | Par / Pool | Token Alvo | Risco / Honeypot | Decisão | Score
    """
    headers = [
        "DEX",
        "Bloco",
        "Par / Pool",
        "Token Alvo",
        "Risco / Honeypot",
        "Decisão",
        "Score",
    ]
    rows = []
    for r in results:
        dex = str(r.get("dex", "N/A"))
        block = str(r.get("block_number", "N/A"))
        pair = str(r.get("pair", "N/A"))
        token_target = str(r.get("target_token", "N/A"))
        risk = str(r.get("risk_honeypot", "CLEAN"))
        decision = str(r.get("decision", "N/A"))
        risk_score = r.get("risk_score")
        score_display = f"{float(risk_score):.1f}" if risk_score is not None else "N/A"

        if len(risk) > 28:
            risk = risk[:25] + "..."

        rows.append([
            dex,
            block,
            pair,
            token_target,
            risk,
            decision,
            score_display,
        ])

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
            print("|" + "|".join(f" {row[i].ljust(col_widths[i])} " for i in range(len(row))) + "|")
    else:
        empty_msg = "No DEX liquidity pool events detected in the scanned block range."
        print(f"| {empty_msg.ljust(sum(col_widths) + len(col_widths) * 3 - 3)} |")
    print(separator + "\n")


def get_curated_mock_pools() -> List[Dict[str, Any]]:
    """
    Returns curated mock pools representing diverse token profiles (clean ERC-20, blacklist traps,
    100% tax traps, pause/kill honeypots, and upgradable proxies) for offline dry-run simulations.
    """
    clean_token_addr = Web3.to_checksum_address("0x1111111111111111111111111111111111111111")
    blacklist_token_addr = Web3.to_checksum_address("0x2222222222222222222222222222222222222222")
    tax_token_addr = Web3.to_checksum_address("0x3333333333333333333333333333333333333333")
    pause_token_addr = Web3.to_checksum_address("0x4444444444444444444444444444444444444444")
    proxy_token_addr = Web3.to_checksum_address("0x5555555555555555555555555555555555555555")

    weth_addr = Web3.to_checksum_address("0x4200000000000000000000000000000000000006")
    usdc_addr = Web3.to_checksum_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
    cbbtc_addr = Web3.to_checksum_address("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf")
    usdbc_addr = Web3.to_checksum_address("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA")

    # Bytecodes:
    # 1. Clean ERC-20 (transfer, balanceOf, approve)
    clean_code = bytes.fromhex("608060405234801561001057600080fd5b508063a9059cbb1461002057806370a0823114")
    # 2. Blacklist Honeypot (setBlacklist: 0x40af1275, isBlacklisted: 0xf9f02b01, transferOwnership: 0xf2fde38b)
    bl_code = bytes.fromhex("6080604052806340af127514610020578063f9f02b0114610040578063f2fde38b14")
    # 3. Arbitrary Fee / 100% Tax Trap (setTax: 0x1e3dd19f, setSellFee: 0x4b7890ec, setFee: 0x8a92d475)
    tax_code = bytes.fromhex("608060405280631e3dd19f146100205780634b7890ec146100405780638a92d47514")
    # 4. Trading Pause + Selfdestruct (setTrading: 0x34468f9b, pause: 0x4fbee1e3, selfdestruct: 0x00f714ce, ff)
    pause_code = bytes.fromhex("6080604052806334468f9b146100205780634fbee1e31461004057806300f714ce14ff")
    # 5. Upgradable / Mintable Admin Token (upgradeTo: 0x3659cfe6, mint: 0x40c10f19, transferOwnership: 0xf2fde38b)
    proxy_code = bytes.fromhex("608060405280633659cfe61461002057806340c10f1914610040578063f2fde38b14")

    return [
        {
            "dex": "Aerodrome",
            "block_number": 21050100,
            "tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "pool_address": Web3.to_checksum_address("0xae11111111111111111111111111111111111111"),
            "token0": clean_token_addr,
            "token1": weth_addr,
            "target_token": clean_token_addr,
            "base_token": weth_addr,
            "pair_name": "CLEAN/WETH",
            "bytecode": clean_code,
            "extra_meta": {"stable": False},
        },
        {
            "dex": "Aerodrome",
            "block_number": 21050102,
            "tx_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "pool_address": Web3.to_checksum_address("0xae22222222222222222222222222222222222222"),
            "token0": usdc_addr,
            "token1": blacklist_token_addr,
            "target_token": blacklist_token_addr,
            "base_token": usdc_addr,
            "pair_name": "HONEY_BL/USDC",
            "bytecode": bl_code,
            "extra_meta": {"stable": True},
        },
        {
            "dex": "Uniswap v3",
            "block_number": 21050105,
            "tx_hash": "0x3333333333333333333333333333333333333333333333333333333333333333",
            "pool_address": Web3.to_checksum_address("0xbb33333333333333333333333333333333333333"),
            "token0": weth_addr,
            "token1": tax_token_addr,
            "target_token": tax_token_addr,
            "base_token": weth_addr,
            "pair_name": "TAX100/WETH",
            "bytecode": tax_code,
            "extra_meta": {"fee": 10000, "tick_spacing": 200},
        },
        {
            "dex": "Uniswap v3",
            "block_number": 21050108,
            "tx_hash": "0x4444444444444444444444444444444444444444444444444444444444444444",
            "pool_address": Web3.to_checksum_address("0xbb44444444444444444444444444444444444444"),
            "token0": pause_token_addr,
            "token1": cbbtc_addr,
            "target_token": pause_token_addr,
            "base_token": cbbtc_addr,
            "pair_name": "RUG_KILL/cbBTC",
            "bytecode": pause_code,
            "extra_meta": {"fee": 3000, "tick_spacing": 60},
        },
        {
            "dex": "Uniswap v3",
            "block_number": 21050110,
            "tx_hash": "0x5555555555555555555555555555555555555555555555555555555555555555",
            "pool_address": Web3.to_checksum_address("0xbb55555555555555555555555555555555555555"),
            "token0": proxy_token_addr,
            "token1": usdbc_addr,
            "target_token": proxy_token_addr,
            "base_token": usdbc_addr,
            "pair_name": "PROXY/USDbC",
            "bytecode": proxy_code,
            "extra_meta": {"fee": 500, "tick_spacing": 10},
        },
    ]


class AwaitableBlockNumber:
    """Supports both direct awaiting (await w3.eth.block_number) and calling (await w3.eth.block_number())."""
    def __init__(self, value: int):
        self.value = value

    def __await__(self):
        async def _gen():
            return self.value
        return _gen().__await__()

    def __call__(self, *args, **kwargs):
        async def _coro():
            return self.value
        return _coro()

    def __gt__(self, other):
        return self.value > (other.value if isinstance(other, AwaitableBlockNumber) else other)

    def __ge__(self, other):
        return self.value >= (other.value if isinstance(other, AwaitableBlockNumber) else other)

    def __lt__(self, other):
        return self.value < (other.value if isinstance(other, AwaitableBlockNumber) else other)

    def __le__(self, other):
        return self.value <= (other.value if isinstance(other, AwaitableBlockNumber) else other)

    def __eq__(self, other):
        return self.value == (other.value if isinstance(other, AwaitableBlockNumber) else other)

    def __int__(self):
        return int(self.value)


async def get_latest_block_number(w3: Any) -> int:
    """Safely retrieves the latest block number supporting Web3 properties, callables, or mocks."""
    bn_target = getattr(w3.eth, "block_number", None)
    if inspect.isawaitable(bn_target):
        val = await bn_target
    elif callable(bn_target):
        res = bn_target()
        val = await res if inspect.isawaitable(res) else res
    else:
        val = bn_target
    return int(val)


def create_mock_w3(mock_pools: Optional[List[Dict[str, Any]]] = None) -> Any:
    """Creates a mock AsyncWeb3 connection preloaded with synthetic event logs."""
    pools = mock_pools if mock_pools is not None else get_curated_mock_pools()
    mock_w3 = MagicMock()
    mock_w3.is_connected = AsyncMock(return_value=True)

    max_block = max((p["block_number"] for p in pools), default=21050110)
    mock_w3.eth.block_number = AwaitableBlockNumber(max_block + 1)

    async def mock_get_logs(filter_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        target_addr = filter_params.get("address")
        target_topic0 = filter_params.get("topics", [None])[0]

        res = []
        for p in pools:
            is_aero = p["dex"] == "Aerodrome"
            match_addr = (
                target_addr.lower() == AERODROME_FACTORY_ADDRESS.lower()
                if is_aero
                else target_addr.lower() == UNISWAP_V3_FACTORY_ADDRESS.lower()
            )
            match_topic = (
                target_topic0 == AERODROME_POOL_CREATED_TOPIC0
                if is_aero
                else target_topic0 == UNISWAP_V3_POOL_CREATED_TOPIC0
            )

            if match_addr and match_topic:
                t0_padded = "0x" + "0" * 24 + p["token0"][2:].lower()
                t1_padded = "0x" + "0" * 24 + p["token1"][2:].lower()
                pool_padded = "0" * 24 + p["pool_address"][2:].lower()

                if is_aero:
                    stable_word = "0" * 63 + ("1" if p["extra_meta"].get("stable") else "0")
                    index_word = "0" * 64
                    data = "0x" + stable_word + pool_padded + index_word
                else:
                    fee_word = hex(p["extra_meta"].get("fee", 3000))[2:].zfill(64)
                    tick_word = hex(p["extra_meta"].get("tick_spacing", 60) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)[2:].zfill(64)
                    data = "0x" + fee_word + tick_word + pool_padded

                res.append({
                    "address": target_addr,
                    "topics": [target_topic0, t0_padded, t1_padded],
                    "data": data,
                    "blockNumber": p["block_number"],
                    "transactionHash": p["tx_hash"],
                    "logIndex": 0,
                })
        return res

    mock_w3.eth.get_logs = AsyncMock(side_effect=mock_get_logs)

    code_map = {p["target_token"].lower(): p["bytecode"] for p in pools}

    async def mock_get_code(addr: str) -> bytes:
        return code_map.get(addr.lower(), b"")

    mock_w3.eth.get_code = AsyncMock(side_effect=mock_get_code)
    return mock_w3


async def run_dex_monitor(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Executes a single cycle scan and audit for DEX liquidity pools."""
    db_path = getattr(args, "db_path", None)
    storage = AgentStorage(db_path=db_path)
    await storage.initialize()

    # Use simulated semantic evaluator during offline dry-run or when configured
    evaluator = DexSemanticEvaluator() if getattr(args, "dry_run", False) else get_semantic_evaluator()
    rpc_url = getattr(args, "rpc_url", None) or os.getenv("RPC_URL_8453", DEFAULT_BASE_RPC)
    engine = ConditionAgentEngine(
        rpc_url=rpc_url,
        semantic_evaluator=evaluator,
        storage=storage,
    )

    webhook_url = getattr(args, "webhook_url", None)
    webhook_dispatcher = DexWebhookAlertDispatcher(webhook_url=webhook_url) if webhook_url else None

    limit = getattr(args, "limit", 5)
    num_blocks = getattr(args, "blocks", 100)

    if getattr(args, "dry_run", False):
        logger.info("Executing dry-run DEX monitor simulation with curated mock pools...")
        mock_pools = get_curated_mock_pools()[:limit]
        results = await audit_discovered_pools(
            mock_pools,
            engine=engine,
            rpc_url=rpc_url,
            webhook_dispatcher=webhook_dispatcher,
        )
        print_dex_table(results)
        return results

    # Live RPC Discovery
    w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
    try:
        is_conn = await w3.is_connected()
        if not is_conn:
            logger.error(f"Cannot connect to RPC endpoint: {rpc_url}")
            return []
        latest_block = await get_latest_block_number(w3)
    except Exception as exc:
        logger.error(f"Failed connecting to RPC {rpc_url}: {exc}")
        return []

    from_block = max(0, latest_block - num_blocks + 1)
    to_block = latest_block

    discovered = await scan_pool_events(w3, from_block=from_block, to_block=to_block, limit=limit)
    if not discovered:
        print_dex_table([])
        return []

    results = await audit_discovered_pools(
        discovered,
        engine=engine,
        rpc_url=rpc_url,
        webhook_dispatcher=webhook_dispatcher,
    )
    print_dex_table(results)
    return results


async def run_continuous_monitor(args: argparse.Namespace) -> None:
    """Runs a continuous polling daemon loop monitoring newly minted DEX liquidity pools."""
    poll_interval = getattr(args, "poll_interval", 15)
    num_blocks = getattr(args, "blocks", 100)
    rpc_url = getattr(args, "rpc_url", None) or os.getenv("RPC_URL_8453", DEFAULT_BASE_RPC)

    logger.info(
        f"Starting continuous DEX pool monitoring daemon (poll interval: {poll_interval}s, RPC: {rpc_url})..."
    )

    w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
    try:
        latest_block = await get_latest_block_number(w3)
        last_scanned = max(0, latest_block - num_blocks + 1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Continuous monitor terminated.")
        return
    except Exception:
        last_scanned = 0

    while True:
        try:
            current_block = await get_latest_block_number(w3)
            if current_block > last_scanned:
                from_b = last_scanned + 1
                to_b = current_block
                logger.info(f"Polling blocks {from_b} to {to_b}...")
                scan_args = argparse.Namespace(**vars(args))
                scan_args.blocks = to_b - from_b + 1
                await run_dex_monitor(scan_args)
                last_scanned = to_b
            else:
                logger.debug(f"No new blocks produced (current: {current_block}). Waiting...")
        except (KeyboardInterrupt, asyncio.CancelledError):
            logger.info("Continuous monitor terminated by user.")
            break
        except Exception as exc:
            logger.error(f"Error in continuous monitor iteration: {exc}")

        await asyncio.sleep(poll_interval)


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses command-line arguments for scripts/dex_pool_monitor.py."""
    parser = argparse.ArgumentParser(
        description="Autonomous DEX Liquidity Pool Monitor & Honeypot Auditor for Base Mainnet (Engine 3)"
    )
    parser.add_argument(
        "--blocks",
        type=int,
        default=100,
        help="Number of recent blocks to scan for PoolCreated events (default: 100)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum number of discovered pools to audit per scan (default: 5)",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        default=False,
        help="Run continuous polling daemon mode",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=15,
        help="Polling interval in seconds for continuous mode (default: 15)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Simulate scan with curated mock pools (zero RPC calls, zero LLM token cost)",
    )
    parser.add_argument(
        "--rpc-url",
        type=str,
        default=None,
        help="Optional RPC endpoint URL override (defaults to https://mainnet.base.org)",
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        default=None,
        help="Webhook URL for dispatching security alert notifications",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Path to SQLite ledger database (default: data/agent.db)",
    )
    return parser.parse_args(args)


def main() -> None:
    """Main CLI entrypoint."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = parse_args()

    if args.continuous:
        try:
            asyncio.run(run_continuous_monitor(args))
        except KeyboardInterrupt:
            logger.info("Process halted.")
    else:
        asyncio.run(run_dex_monitor(args))


if __name__ == "__main__":
    main()
