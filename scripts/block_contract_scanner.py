"""
Autonomous On-Chain Block Scanner and Security Auditor for Base Mainnet.

Engine 1 of the Web3 Condition-Action Trigger Agent.
Scans newly produced EVM blocks on Base Mainnet (Chain ID 8453) in real-time or batch mode,
detects smart contract deployments (tx.to is None), extracts deployed bytecode and 4-byte
function selectors, executes deterministic and semantic risk audits, displays an ASCII table,
and persists audit reports to the SQLite ledger (AgentStorage).

Usage Examples:
    # 1. Run dry-run simulation (offline, zero external network dependency, cost zero):
    python scripts/block_contract_scanner.py --dry-run

    # 2. Scan the last 10 blocks on Base Mainnet with a limit of 5 contracts:
    python scripts/block_contract_scanner.py --blocks 10 --limit 5

    # 3. Run continuous monitoring loop polling every ~2 seconds:
    python scripts/block_contract_scanner.py --continuous

    # 4. Custom RPC endpoint override:
    python scripts/block_contract_scanner.py --rpc-url https://mainnet.base.org --blocks 20
"""

import argparse
import asyncio
import inspect
import logging
import os
import re
import sys
import time
from typing import Dict, Any, Optional, List, Union
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

logger = logging.getLogger("block_contract_scanner")

DEFAULT_BASE_RPC = "https://mainnet.base.org"
CHAIN_ID_BASE_MAINNET = 8453

# Known 4-byte EVM function selectors mapped to canonical signatures
KNOWN_SELECTORS: Dict[str, str] = {
    # ERC-20 & ERC-721 Standards
    "0xa9059cbb": "transfer(address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x70a08231": "balanceOf(address)",
    "0x18160ddd": "totalSupply()",
    "0x313ce567": "decimals()",
    "0x06fdde03": "name()",
    "0x95d89b41": "symbol()",
    # Ownership & Privileged Access Control
    "0xf2fde38b": "transferOwnership(address)",
    "0x715018a6": "renounceOwnership()",
    "0x8da5cb5b": "owner()",
    # Minting & Burning
    "0x40c10f19": "mint(address,uint256)",
    "0xa0712d68": "mint(uint256)",
    "0x42966c68": "burn(uint256)",
    "0x79cc6790": "burnFrom(address,uint256)",
    # Upgradability & Proxies
    "0x3659cfe6": "upgradeTo(address)",
    "0x4f1f2732": "upgradeToAndCall(address,bytes)",
    "0x52d19004": "implementation()",
    # Pausability
    "0x4fbee1e3": "pause()",
    "0x8456cb59": "unpause()",
    "0x5c975abb": "paused()",
    # Destruction / High Risk
    "0x83197ef0": "destroy(address)",
    "0x41c0e1b5": "kill()",
    "0x00f714ce": "selfdestruct()",
    # Vaults / Wrapped Assets
    "0xd0e30db0": "deposit()",
    "0x2e1a7d4d": "withdraw(uint256)",
}

HIGH_RISK_KEYWORDS = (
    "transferownership",
    "renounceownership",
    "upgradeto",
    "destroy",
    "kill",
    "selfdestruct",
    "mint",
    "pause",
)

DISPATCHER_REGEX = re.compile(r"(?:63|8063|8263)([0-9a-fA-F]{8})14", re.IGNORECASE)


def extract_selectors_from_bytecode(
    bytecode: Union[bytes, str],
    tx_input: Optional[Union[bytes, str]] = None,
) -> List[Dict[str, str]]:
    """
    Extracts 4-byte function selectors from smart contract bytecode and deployment calldata.
    Identifies known signatures and flags privileged or high-risk capabilities.
    """
    if isinstance(bytecode, bytes):
        bytecode_hex = bytecode.hex()
    else:
        bytecode_hex = bytecode[2:] if bytecode.startswith("0x") else bytecode

    found: Dict[str, Dict[str, str]] = {}
    bytecode_lower = bytecode_hex.lower()

    # 1. Search known selectors directly within bytecode
    for sel_hex, sig in KNOWN_SELECTORS.items():
        clean_sel = sel_hex[2:].lower()
        if clean_sel in bytecode_lower:
            found[sel_hex] = {
                "selector": sel_hex,
                "signature": sig,
                "known": True,
            }

    # 2. Extract selectors from standard EVM dispatcher opcodes (PUSH4 <sel> EQ)
    for m in DISPATCHER_REGEX.findall(bytecode_hex):
        sel_hex = f"0x{m.lower()}"
        if sel_hex not in found:
            sig = KNOWN_SELECTORS.get(sel_hex, f"unknown({sel_hex})")
            found[sel_hex] = {
                "selector": sel_hex,
                "signature": sig,
                "known": sel_hex in KNOWN_SELECTORS,
            }

    # 3. If deployment calldata (tx_input) is provided, inspect initialization calldata
    if tx_input:
        if isinstance(tx_input, bytes):
            input_hex = tx_input.hex()
        else:
            input_hex = tx_input[2:] if tx_input.startswith("0x") else tx_input
        input_lower = input_hex.lower()
        for sel_hex, sig in KNOWN_SELECTORS.items():
            clean_sel = sel_hex[2:].lower()
            if clean_sel in input_lower and sel_hex not in found:
                found[sel_hex] = {
                    "selector": sel_hex,
                    "signature": sig,
                    "known": True,
                }

    return list(found.values())


def is_high_risk_signature(signature: str) -> bool:
    """Checks whether a function signature indicates admin control or contract termination."""
    sig_lower = signature.lower()
    return any(kw in sig_lower for kw in HIGH_RISK_KEYWORDS)


def create_deployment_rule_payload(
    contract_address: str,
    tx_hash: str,
    block_number: int,
    deployer: str,
    selectors: List[Dict[str, str]],
    bytecode_length: int,
    require_high_risk_for_llm: bool = False,
) -> ConditionRulePayload:
    """
    Constructs a validated ConditionRulePayload for evaluating a newly discovered smart contract.
    """
    checksummed_address = Web3.to_checksum_address(contract_address)
    signatures = [s["signature"] for s in selectors]
    high_risk_found = [s["signature"] for s in selectors if is_high_risk_signature(s["signature"])]
    semantic_enabled = bool(high_risk_found) if require_high_risk_for_llm else True

    # Determine priority selector for deterministic calldata analysis
    matched_selector = "0x"
    matched_signature = "deployment"
    if high_risk_found:
        for s in selectors:
            if is_high_risk_signature(s["signature"]):
                matched_selector = s["selector"]
                matched_signature = s["signature"]
                break
    elif selectors:
        matched_selector = selectors[0]["selector"]
        matched_signature = selectors[0]["signature"]

    proposal_desc = (
        f"Audit newly deployed contract at block {block_number} by {deployer}. "
        f"Contract Address: {checksummed_address}. Bytecode size: {bytecode_length} bytes. "
        f"Detected function signatures: {', '.join(signatures) if signatures else 'None'}. "
    )
    if high_risk_found:
        proposal_desc += f"CRITICAL: Contains privileged capabilities: {', '.join(high_risk_found)}."

    prompt = (
        f"Audit newly deployed smart contract at {checksummed_address} on Base Mainnet. "
        f"Block: {block_number}, Deployer: {deployer}. "
        f"Identified function selectors: {', '.join(signatures) if signatures else 'None'}. "
        f"Assess decentralization risk, admin backdoor risks, unconstrained minting or self-destruction capabilities."
    )

    rule_id = f"block-deploy-{contract_address.lower()[:10]}"

    return ConditionRulePayload(
        rule_id=rule_id,
        chain_id=ChainId.BASE_MAINNET,
        deterministic=DeterministicCondition(
            target_address=checksummed_address,
            min_value_wei=0,
            required_function_selectors=None,
            check_native_balance=False,
        ),
        semantic=SemanticCondition(
            enabled=semantic_enabled,
            policy_prompt=prompt,
            risk_threshold=7.0,
        ),
        context_metadata={
            "contract_address": checksummed_address,
            "tx_hash": tx_hash,
            "block_number": block_number,
            "deployer": deployer,
            "calldata": matched_selector,
            "calldata_analysis": {
                "selector": matched_selector,
                "signature": matched_signature,
            },
            "proposal_title": f"Contract Deployment: {checksummed_address}",
            "proposal_description": proposal_desc,
            "selectors_found": [s["selector"] for s in selectors],
            "signatures_found": signatures,
            "bytecode_length": bytecode_length,
        },
    )


async def get_latest_block_number(w3: AsyncWeb3) -> int:
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


async def scan_recent_blocks(
    w3: AsyncWeb3,
    num_blocks: int = 5,
    limit: int = 10,
    start_block: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Scans the latest num_blocks blocks on Base Mainnet for contract creation transactions.

    Filters transactions where tx.to is None (contract creation), retrieves receipts,
    and returns metadata for non-empty deployed contracts up to `limit`.

    Parameters:
        w3: An active AsyncWeb3 connection instance.
        num_blocks: Number of blocks to scan backwards from latest (default: 5).
        limit: Maximum number of deployed contracts to discover (default: 10).
        start_block: Optional explicit starting block number (defaults to latest block).

    Returns:
        List of dictionaries with discovered contract deployment metadata.
    """
    if limit <= 0 or num_blocks <= 0:
        return []

    try:
        if start_block is None:
            latest_block_num = await get_latest_block_number(w3)
        else:
            latest_block_num = start_block
    except Exception as exc:
        logger.error(f"Failed to fetch latest block number: {exc}")
        return []

    from_block = max(0, latest_block_num - num_blocks + 1)
    logger.info(f"Scanning blocks {from_block} to {latest_block_num} (total {num_blocks} blocks, limit {limit})...")

    discovered: List[Dict[str, Any]] = []

    # Iterate from newest to oldest block
    for b_num in range(latest_block_num, from_block - 1, -1):
        if len(discovered) >= limit:
            break

        try:
            block = await w3.eth.get_block(b_num, full_transactions=True)
        except Exception as exc:
            logger.warning(f"Could not retrieve block {b_num}: {exc}")
            continue

        if not block:
            continue

        raw_txs = block.get("transactions", []) if isinstance(block, dict) else getattr(block, "transactions", [])

        for tx in raw_txs:
            if len(discovered) >= limit:
                break

            # In EVM, contract creation transactions have tx.to is None
            to_addr = tx.get("to") if isinstance(tx, dict) else getattr(tx, "to", None)
            if to_addr is not None:
                continue

            # Extract transaction hash
            tx_h = tx.get("hash") if isinstance(tx, dict) else getattr(tx, "hash", None)
            if not tx_h:
                continue

            tx_hash_str = tx_h.hex() if hasattr(tx_h, "hex") else str(tx_h)
            from_addr = tx.get("from") if isinstance(tx, dict) else getattr(tx, "from", "")
            tx_input = tx.get("input") if isinstance(tx, dict) else getattr(tx, "input", "0x")

            try:
                receipt = await w3.eth.get_transaction_receipt(tx_h)
            except Exception as exc:
                logger.warning(f"Failed to fetch transaction receipt for {tx_hash_str}: {exc}")
                continue

            if not receipt:
                continue

            contract_addr = (
                receipt.get("contractAddress")
                if isinstance(receipt, dict)
                else getattr(receipt, "contractAddress", None)
            )

            if not contract_addr or not Web3.is_address(contract_addr):
                continue

            checksummed_addr = Web3.to_checksum_address(contract_addr)

            # Verify bytecode exists and is non-empty
            try:
                bytecode = await w3.eth.get_code(checksummed_addr)
            except Exception as exc:
                logger.warning(f"Failed to fetch bytecode for {checksummed_addr}: {exc}")
                continue

            if not bytecode or bytecode in (b"", b"\x00", "0x", "0x0"):
                continue

            discovered.append({
                "block_number": b_num,
                "tx_hash": tx_hash_str,
                "contract_address": checksummed_addr,
                "deployer": from_addr,
                "bytecode": bytecode,
                "tx_input": tx_input,
            })
            logger.info(f"Discovered contract deployment: {checksummed_addr} at block {b_num}")

    return discovered


async def audit_discovered_contracts(
    contracts: List[Dict[str, Any]],
    engine: ConditionAgentEngine,
    rpc_url: Optional[str] = None,
    require_high_risk_for_llm: bool = False,
) -> List[Dict[str, Any]]:
    """
    Executes deterministic bytecode inspection and semantic risk audits on discovered contracts.
    Persists evaluation results to the SQLite ledger via AgentStorage.
    """
    results: List[Dict[str, Any]] = []

    for item in contracts:
        contract_addr = item["contract_address"]
        bytecode = item["bytecode"]
        tx_input = item.get("tx_input")
        block_num = item["block_number"]
        tx_hash = item["tx_hash"]
        deployer = item.get("deployer", "0x0000000000000000000000000000000000000000")

        # 1. Extract function selectors
        selectors = extract_selectors_from_bytecode(bytecode, tx_input)

        # 2. Populate ChainInspector bytecode cache to guarantee zero redundant network RPC calls
        bytecode_bytes = bytecode if isinstance(bytecode, bytes) else bytes.fromhex(
            bytecode[2:] if bytecode.startswith("0x") else bytecode
        )
        ChainInspector._set_bytecode_cache(f"{CHAIN_ID_BASE_MAINNET}:{contract_addr}", bytecode_bytes)

        # 3. Build validated payload
        payload = create_deployment_rule_payload(
            contract_address=contract_addr,
            tx_hash=tx_hash,
            block_number=block_num,
            deployer=deployer,
            selectors=selectors,
            bytecode_length=len(bytecode_bytes),
            require_high_risk_for_llm=require_high_risk_for_llm,
        )

        # 4. Execute two-stage ConditionAgentEngine audit
        try:
            response = await engine.process_rule(payload, source="block_scanner")
        except Exception as exc:
            logger.error(f"Audit failed for contract {contract_addr}: {exc}")
            continue

        sem = response.semantic_Evaluation
        decision = sem.recommended_action if sem else ("APPROVE" if response.deterministic_check.passed else "REJECT")
        risk_score = sem.risk_score if sem else (0.0 if response.deterministic_check.passed else 10.0)

        results.append({
            "block_number": block_num,
            "tx_hash": tx_hash,
            "contract_address": contract_addr,
            "deployer": deployer,
            "selectors": selectors,
            "recommendation": decision,
            "risk_score": risk_score,
            "payload": payload,
            "response": response,
        })

    return results


def print_scan_table(results: List[Dict[str, Any]]) -> None:
    """
    Renders an ASCII table displaying audited contract deployment results:
    Bloco, Tx Hash, Endereço do Contrato, Seletores Encontrados, Recomendação, Score de Risco.
    """
    headers = [
        "Bloco",
        "Tx Hash",
        "Endereço do Contrato",
        "Seletores Encontrados",
        "Recomendação",
        "Score de Risco",
    ]
    rows = []
    for r in results:
        block = str(r.get("block_number", "N/A"))
        tx_hash = str(r.get("tx_hash", "N/A"))
        if len(tx_hash) > 18:
            tx_hash_display = f"{tx_hash[:10]}...{tx_hash[-6:]}"
        else:
            tx_hash_display = tx_hash

        contract_addr = str(r.get("contract_address", "N/A"))

        selectors = r.get("selectors", [])
        if isinstance(selectors, list):
            sel_strs = []
            for s in selectors:
                if isinstance(s, dict):
                    sig = s.get("signature", s.get("selector", ""))
                    sig_name = sig.split("(")[0] if "(" in sig else sig
                    sel_strs.append(sig_name)
                else:
                    sel_strs.append(str(s))
            selectors_display = ", ".join(sel_strs) if sel_strs else "None"
        else:
            selectors_display = str(selectors)

        if len(selectors_display) > 32:
            selectors_display = selectors_display[:29] + "..."

        recommendation = str(r.get("recommendation", "N/A"))
        risk_score = r.get("risk_score")
        score_display = f"{float(risk_score):.1f}" if risk_score is not None else "N/A"

        rows.append([
            block,
            tx_hash_display,
            contract_addr,
            selectors_display,
            recommendation,
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
            row_str = "|" + "|".join(f" {row[i].ljust(col_widths[i])} " for i in range(len(row))) + "|"
            print(row_str)
    else:
        empty_notice = "Nenhum contrato detectado nos blocos selecionados."
        total_w = sum(col_widths) + 3 * len(col_widths) - 1
        print(f"| {empty_notice.ljust(total_w - 2)} |")
    print(separator + "\n")


def create_mock_w3() -> Any:
    """
    Creates an AsyncWeb3 mock simulating Base Mainnet blocks and contract deployments.
    Used for --dry-run and offline unit tests with zero external RPC dependency.
    """
    # Sample contracts for realistic auditing simulation:
    # 1. Admin proxy with transferOwnership, upgradeTo, and destroy (high risk)
    bytecode_admin = bytes.fromhex(
        "608060405234801561001057600080fd5b50"
        "8063f2fde38b1461003057"  # transferOwnership
        "80633659cfe61461005057"  # upgradeTo
        "806383197ef01461007057"  # destroy
        "600080fd"
    )
    # 2. Standard ERC-20 token (low risk)
    bytecode_erc20 = bytes.fromhex(
        "608060405234801561001057600080fd5b50"
        "8063a9059cbb1461003057"  # transfer
        "8063095ea7b31461005057"  # approve
        "806370a082311461007057"  # balanceOf
        "600080fd"
    )
    # 3. Mintable Token with pause (medium risk)
    bytecode_mintable = bytes.fromhex(
        "608060405234801561001057600080fd5b50"
        "806340c10f191461003057"  # mint
        "80634fbee1e31461005057"  # pause
        "600080fd"
    )

    contracts_db = {
        "0x1111111111111111111111111111111111111111": bytecode_admin,
        "0x2222222222222222222222222222222222222222": bytecode_erc20,
        "0x3333333333333333333333333333333333333333": bytecode_mintable,
    }

    mock_receipts = {
        "0xaaa1111111111111111111111111111111111111111111111111111111111111": {
            "contractAddress": "0x1111111111111111111111111111111111111111",
            "status": 1,
        },
        "0xbbb2222222222222222222222222222222222222222222222222222222222222": {
            "contractAddress": "0x2222222222222222222222222222222222222222",
            "status": 1,
        },
        "0xccc3333333333333333333333333333333333333333333333333333333333333": {
            "contractAddress": "0x3333333333333333333333333333333333333333",
            "status": 1,
        },
    }

    mock_blocks = {
        23419500: {
            "number": 23419500,
            "transactions": [
                {
                    "hash": "0xaaa1111111111111111111111111111111111111111111111111111111111111",
                    "from": "0xDeployer111111111111111111111111111111111",
                    "to": None,
                    "input": "0x60806040...",
                },
                {
                    "hash": "0x9990000000000000000000000000000000000000000000000000000000000000",
                    "from": "0xUserA",
                    "to": "0xUserB",  # Standard transfer, not contract creation
                    "input": "0x",
                },
            ],
        },
        23419501: {
            "number": 23419501,
            "transactions": [
                {
                    "hash": "0xbbb2222222222222222222222222222222222222222222222222222222222222",
                    "from": "0xDeployer222222222222222222222222222222222",
                    "to": None,
                    "input": "0x60806040...",
                },
                {
                    "hash": "0xccc3333333333333333333333333333333333333333333333333333333333333",
                    "from": "0xDeployer333333333333333333333333333333333",
                    "to": None,
                    "input": "0x60806040...",
                },
            ],
        },
    }

    class MockEth:
        def __init__(self):
            pass

        @property
        def block_number(self):
            async def _bn():
                return 23419501
            return _bn()

        async def get_block(self, block_identifier, full_transactions=True):
            b_num = int(block_identifier) if str(block_identifier).isdigit() else 23419501
            return mock_blocks.get(b_num, {"number": b_num, "transactions": []})

        async def get_transaction_receipt(self, tx_hash):
            tx_h_str = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
            return mock_receipts.get(tx_h_str, None)

        async def get_code(self, addr):
            chk = Web3.to_checksum_address(addr) if Web3.is_address(addr) else addr
            return contracts_db.get(chk, b"")

    class MockW3:
        def __init__(self):
            self.eth = MockEth()

        async def is_connected(self):
            return True

    return MockW3()


async def run_continuous_scanner(
    w3: AsyncWeb3,
    engine: ConditionAgentEngine,
    limit: int = 10,
    poll_interval: float = 2.0,
    max_iterations: Optional[int] = None,
    rpc_url: Optional[str] = None,
) -> None:
    """
    Executes real-time monitoring loop polling new blocks every ~poll_interval seconds.
    """
    print(f"[*] Starting continuous contract deployment scanner on Base Mainnet (poll: {poll_interval}s)...")
    print("[*] Press Ctrl+C to stop.\n")

    last_scanned_block: Optional[int] = None
    iteration = 0

    try:
        while True:
            try:
                current_block = await get_latest_block_number(w3)
                if last_scanned_block is None:
                    blocks_to_check = 1
                    start_b = current_block
                elif current_block > last_scanned_block:
                    blocks_to_check = current_block - last_scanned_block
                    start_b = current_block
                else:
                    await asyncio.sleep(poll_interval)
                    iteration += 1
                    if max_iterations is not None and iteration >= max_iterations:
                        break
                    continue

                discovered = await scan_recent_blocks(
                    w3=w3,
                    num_blocks=blocks_to_check,
                    limit=limit,
                    start_block=start_b,
                )

                if discovered:
                    results = await audit_discovered_contracts(discovered, engine, rpc_url=rpc_url)
                    print_scan_table(results)
                else:
                    print(f"[{time.strftime('%X')}] Checked block {current_block}: No new contract deployments.")

                last_scanned_block = current_block

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Error in continuous scanner loop: {exc}")

            iteration += 1
            if max_iterations is not None and iteration >= max_iterations:
                break

            await asyncio.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\n[*] Scanner stopped by user.")


async def run_scanner(
    blocks: int = 5,
    limit: int = 10,
    dry_run: bool = False,
    continuous: bool = False,
    rpc_url: Optional[str] = None,
    storage: Optional[AgentStorage] = None,
    max_continuous_iterations: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Orchestrates the block scanner workflow based on CLI flags.
    """
    resolved_rpc = rpc_url or os.getenv("RPC_URL_8453") or DEFAULT_BASE_RPC

    print("=" * 72)
    print("Web3 Condition-Action Trigger Agent: Base Mainnet Contract Scanner")
    print("=" * 72)
    print(f"[*] Target Network: Base Mainnet (Chain ID: {CHAIN_ID_BASE_MAINNET})")
    print(f"[*] Mode: {'DRY-RUN (Simulated)' if dry_run else 'LIVE ON-CHAIN'}")
    print(f"[*] Blocks to inspect: {blocks} | Limit: {limit} contracts")
    if not dry_run:
        print(f"[*] RPC Endpoint: {resolved_rpc}")
    print("=" * 72 + "\n")

    storage_instance = storage if storage is not None else AgentStorage()

    if dry_run:
        print("[*] Running with simulated mock Web3 provider and MockSemanticEvaluator...")
        evaluator = MockSemanticEvaluator()
        engine = ConditionAgentEngine(
            rpc_url=resolved_rpc,
            semantic_evaluator=evaluator,
            storage=storage_instance,
        )
        w3 = create_mock_w3()
    else:
        w3 = AsyncWeb3(AsyncHTTPProvider(resolved_rpc))
        try:
            connected = await w3.is_connected()
            if not connected:
                print(f"[!] Warning: Could not connect to RPC at {resolved_rpc}. Continuing anyway...")
        except Exception as exc:
            print(f"[!] Warning: Connection check failed: {exc}")

        engine = ConditionAgentEngine(
            rpc_url=resolved_rpc,
            storage=storage_instance,
        )

    if continuous:
        await run_continuous_scanner(
            w3=w3,
            engine=engine,
            limit=limit,
            poll_interval=2.0,
            max_iterations=max_continuous_iterations,
            rpc_url=resolved_rpc,
        )
        return []

    print(f"[*] Scanning recent {blocks} blocks for contract deployments...")
    discovered = await scan_recent_blocks(
        w3=w3,
        num_blocks=blocks,
        limit=limit,
    )

    if not discovered:
        print(f"[*] No contract deployments detected in the scanned {blocks} blocks.")
        print("[*] Tip: Use --blocks 50 or --continuous to catch new deployments on Base.")
        print_scan_table([])
        return []

    print(f"[*] Discovered {len(discovered)} contract deployments. Executing audits...")
    results = await audit_discovered_contracts(discovered, engine, rpc_url=resolved_rpc)
    print_scan_table(results)

    # Print summary metrics
    high_risks = [r for r in results if r["recommendation"] == "REJECT"]
    manual_reviews = [r for r in results if r["recommendation"] == "MANUAL_REVIEW"]
    approvals = [r for r in results if r["recommendation"] == "APPROVE"]

    print(f"[*] Audit Summary: Total: {len(results)} | Approved: {len(approvals)} | Manual Review: {len(manual_reviews)} | Rejected: {len(high_risks)}")
    print(f"[*] Evaluation records persisted to SQLite ledger: {storage_instance.db_path}\n")

    return results


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Autonomous On-Chain Block Scanner for New Smart Contracts on Base Mainnet."
    )
    parser.add_argument(
        "--blocks",
        type=int,
        default=5,
        help="Number of recent blocks to scan backwards from latest (default: 5)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of contracts to discover and audit (default: 10)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Run in dry-run mode using synthetic block data with zero external network dependency",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        default=False,
        help="Run continuously in an async loop polling new blocks every ~2 seconds",
    )
    parser.add_argument(
        "--rpc-url",
        type=str,
        default=None,
        help="Custom RPC endpoint URL (overrides RPC_URL_8453 and default https://mainnet.base.org)",
    )
    return parser.parse_args(args)


def main() -> None:
    """CLI script entrypoint."""
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    asyncio.run(
        run_scanner(
            blocks=args.blocks,
            limit=args.limit,
            dry_run=args.dry_run,
            continuous=args.continuous,
            rpc_url=args.rpc_url,
        )
    )


if __name__ == "__main__":
    main()
