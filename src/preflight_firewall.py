"""
Preflight Firewall for Web3 Agent: Pre-Sign Static Analysis, EIP-712 Inspection,
Calldata Decoding, Indirect Prompt Injection (IPI) Defense, and On-Chain Simulation (eth_call).

Provides a deterministic zero-cost security gate before signing or executing transactions.
Evaluates:
  1. Calldata selectors & arguments: flags unlimited ERC-20 approvals, Permit2, setApprovalForAll,
     ownership transfers, and proxy upgrades.
  2. EIP-712 Typed Data: inspects Permit / Permit2 allowances and detects Gnosis Safe SafeTx DelegateCall.
  3. Indirect Prompt Injection (IPI): scans text and EIP-712 fields for hidden/zero-width Unicode
     characters and adversarial prompt injection patterns.
  4. On-chain eth_call Simulation: simulates transaction execution via AsyncWeb3 to catch EVM reverts
     prior to signing.
"""

import logging
import os
import re
import sys
from typing import Dict, Any, Optional, List, Tuple, Union, Literal
from web3 import Web3
from web3.exceptions import Web3Exception, ContractLogicError, ContractCustomError

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.schemas import (
        PreflightRequest,
        PreflightVerdict,
        PreflightSimulationResult,
        ChainId,
    )
    from src.chain_inspector import ChainInspector
except ImportError:
    from schemas import (
        PreflightRequest,
        PreflightVerdict,
        PreflightSimulationResult,
        ChainId,
    )
    from chain_inspector import ChainInspector

logger = logging.getLogger(__name__)

# Regex for invisible, zero-width, and bidirectional override characters
INVISIBLE_UNICODE_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u202a-\u202e\u2066-\u2069]")

# Prompt injection & adversarial command patterns
PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(?:all\s+|previous\s+|prior\s+)?instructions", re.IGNORECASE), "ignore instructions"),
    (re.compile(r"disregard\s+(?:all\s+|previous\s+|prior\s+)?instructions", re.IGNORECASE), "disregard instructions"),
    (re.compile(r"system\s+prompt", re.IGNORECASE), "system prompt"),
    (re.compile(r"you\s+are\s+now", re.IGNORECASE), "you are now"),
    (re.compile(r"override\s+security", re.IGNORECASE), "override security"),
    (re.compile(r"approve\s+the\s+transaction", re.IGNORECASE), "approve the transaction"),
    (re.compile(r"return\s+APPROVE", re.IGNORECASE), "return APPROVE"),
    (re.compile(r"risk_score.*?0", re.IGNORECASE), "risk_score manipulation targeting 0"),
    (re.compile(r"transfer.*?treasury", re.IGNORECASE), "unauthorized treasury transfer directive"),
]


def extract_strings_from_obj(obj: Any) -> List[str]:
    """Recursively collects all string values from a nested data structure."""
    strings: List[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                strings.append(k)
            strings.extend(extract_strings_from_obj(v))
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            strings.extend(extract_strings_from_obj(item))
    return strings


def scan_prompt_injection(text: Optional[str]) -> Tuple[bool, List[str], float]:
    """
    Scans text for:
      - Invisible / zero-width / bidirectional override Unicode characters.
      - Prompt injection / system override regex patterns.

    Returns:
      (prompt_injection_detected, matched_signals, risk_score)
      Risk score is 9.5 if any signal matches, else 0.0.
    """
    if not text or not isinstance(text, str):
        return False, [], 0.0

    signals: List[str] = []

    # 1. Unicode invisible / bidi overrides
    found_chars = INVISIBLE_UNICODE_RE.findall(text)
    if found_chars:
        signals.append(f"Detected {len(found_chars)} invisible or bidirectional override Unicode characters")

    # 2. Injection patterns
    for pattern, name in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            signals.append(f"Prompt injection pattern matched: '{name}'")

    if signals:
        return True, signals, 9.5
    return False, [], 0.0


def decode_calldata_and_approvals(calldata: str) -> Tuple[Dict[str, Any], List[str], float]:
    """
    Inspects 4-byte selector and 32-byte ABI words in calldata:
      - 0x095ea7b3 (approve(address,uint256)), 0x39509351 (increaseAllowance(address,uint256)):
        flags unlimited approval (>= 2**255 - 1) with risk >= 7.5.
      - 0xa22cb465 (setApprovalForAll(address,bool)):
        flags operator approval if true with risk >= 8.0.
      - 0x87517c45 (Permit2 approve), 0x2b67b570 (Permit2 permit), 0xd505accf (EIP-2612 permit):
        flags Permit2 / off-chain signature allowance delegation with risk >= 7.0.
      - 0xf2fde38b (transferOwnership), 0x3659cfe6 (upgradeTo), 0x4f1ef286 (upgradeToAndCall):
        flags critical administrative / proxy upgrade action with risk >= 8.5.

    Returns:
      (decoded_action_dict, approval_risks_list, base_risk_score)
    """
    if not calldata or not isinstance(calldata, str):
        return {"selector": "0x", "signature": "native_transfer_or_empty", "args": {}}, [], 0.0

    raw = calldata.strip()
    if raw.startswith("0x") or raw.startswith("0X"):
        raw = raw[2:]

    if len(raw) < 8:
        return {"selector": "0x", "signature": "native_transfer_or_empty", "args": {}}, [], 0.0

    selector = "0x" + raw[:8].lower()
    payload = raw[8:]
    words = [payload[i : i + 64] for i in range(0, len(payload), 64)]

    def get_address(idx: int) -> Optional[str]:
        if idx < len(words) and len(words[idx]) >= 40:
            hex_addr = words[idx][-40:]
            try:
                return Web3.to_checksum_address("0x" + hex_addr)
            except Exception:
                return "0x" + hex_addr
        return None

    def get_uint(idx: int) -> int:
        if idx < len(words):
            try:
                return int(words[idx], 16)
            except ValueError:
                return 0
        return 0

    def get_bool(idx: int) -> bool:
        return get_uint(idx) != 0

    # 1. ERC-20 approve(address,uint256)
    if selector == "0x095ea7b3":
        spender = get_address(0)
        amount = get_uint(1)
        decoded = {
            "selector": selector,
            "signature": "approve(address,uint256)",
            "args": {"spender": spender, "amount": amount},
        }
        risks: List[str] = []
        risk_score = 0.0
        if amount >= (2**255 - 1):
            risks.append("Unlimited ERC-20 token approval (MAX_UINT256) detected")
            risk_score = 7.5
        return decoded, risks, risk_score

    # 2. ERC-20 increaseAllowance(address,uint256)
    if selector == "0x39509351":
        spender = get_address(0)
        amount = get_uint(1)
        decoded = {
            "selector": selector,
            "signature": "increaseAllowance(address,uint256)",
            "args": {"spender": spender, "amount": amount},
        }
        risks = []
        risk_score = 0.0
        if amount >= (2**255 - 1):
            risks.append("Unlimited ERC-20 token approval (MAX_UINT256) detected")
            risk_score = 7.5
        return decoded, risks, risk_score

    # 3. ERC-721 / ERC-1155 setApprovalForAll(address,bool)
    if selector == "0xa22cb465":
        operator = get_address(0)
        approved = get_bool(1)
        decoded = {
            "selector": selector,
            "signature": "setApprovalForAll(address,bool)",
            "args": {"operator": operator, "approved": approved},
        }
        risks = []
        risk_score = 0.0
        if approved:
            risks.append("Full collection operator approval (setApprovalForAll=true) detected")
            risk_score = 8.0
        return decoded, risks, risk_score

    # 4. Permit2 approve(address,address,uint160,uint48)
    if selector == "0x87517c45":
        token = get_address(0)
        spender = get_address(1)
        amount = get_uint(2)
        expiration = get_uint(3)
        decoded = {
            "selector": selector,
            "signature": "approve(address,address,uint160,uint48)",
            "args": {"token": token, "spender": spender, "amount": amount, "expiration": expiration},
        }
        risks = ["Permit2 off-chain signature allowance delegation detected"]
        risk_score = 7.0
        if amount >= (2**159 - 1) or amount >= (2**255 - 1):
            risks.append("Unlimited Permit2 token allowance (MAX_UINT) detected")
            risk_score = 7.5
        return decoded, risks, risk_score

    # 5. Permit2 permit(address,PermitSingle,bytes)
    if selector == "0x2b67b570":
        owner = get_address(0)
        decoded = {
            "selector": selector,
            "signature": "permit(address,PermitSingle,bytes)",
            "args": {"owner": owner},
        }
        risks = ["Permit2 off-chain signature allowance delegation detected"]
        return decoded, risks, 7.0

    # 6. EIP-2612 permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
    if selector == "0xd505accf":
        owner = get_address(0)
        spender = get_address(1)
        value = get_uint(2)
        deadline = get_uint(3)
        decoded = {
            "selector": selector,
            "signature": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            "args": {"owner": owner, "spender": spender, "value": value, "deadline": deadline},
        }
        risks = ["EIP-2612 off-chain signature permit delegation detected"]
        risk_score = 7.0
        if value >= (2**255 - 1):
            risks.append("Unlimited ERC-20 token approval (MAX_UINT256) detected")
            risk_score = 7.5
        return decoded, risks, risk_score

    # 7. transferOwnership(address)
    if selector == "0xf2fde38b":
        new_owner = get_address(0)
        decoded = {
            "selector": selector,
            "signature": "transferOwnership(address)",
            "args": {"newOwner": new_owner},
        }
        risks = ["Critical administrative action: transferOwnership detected"]
        return decoded, risks, 8.5

    # 8. upgradeTo(address)
    if selector == "0x3659cfe6":
        new_impl = get_address(0)
        decoded = {
            "selector": selector,
            "signature": "upgradeTo(address)",
            "args": {"newImplementation": new_impl},
        }
        risks = ["Critical proxy upgrade action (upgradeTo) detected"]
        return decoded, risks, 8.5

    # 9. upgradeToAndCall(address,bytes)
    if selector == "0x4f1ef286":
        new_impl = get_address(0)
        decoded = {
            "selector": selector,
            "signature": "upgradeToAndCall(address,bytes)",
            "args": {"newImplementation": new_impl},
        }
        risks = ["Critical proxy upgrade action (upgradeToAndCall) detected"]
        return decoded, risks, 8.5

    # 10. Standard transfer(address,uint256)
    if selector == "0xa9059cbb":
        to = get_address(0)
        amount = get_uint(1)
        decoded = {
            "selector": selector,
            "signature": "transfer(address,uint256)",
            "args": {"to": to, "amount": amount},
        }
        return decoded, [], 0.0

    # 11. Standard transferFrom(address,address,uint256)
    if selector == "0x23b872dd":
        sender = get_address(0)
        recipient = get_address(1)
        amount = get_uint(2)
        decoded = {
            "selector": selector,
            "signature": "transferFrom(address,address,uint256)",
            "args": {"from": sender, "to": recipient, "amount": amount},
        }
        return decoded, [], 0.0

    # Unknown or unhandled selector
    decoded = {
        "selector": selector,
        "signature": "unknown_selector",
        "args": {},
    }
    return decoded, [], 0.0


def inspect_eip712_typed_data(
    typed_data: Optional[Dict[str, Any]],
) -> Tuple[List[str], float]:
    """
    Safely inspects domain, primaryType, and message of EIP-712 typed data:
      - Detects PermitSingle, PermitBatch, PermitTransferFrom, Permit:
        checks details.amount or value for unlimited/huge allowance (>= 2**159 - 1 for uint160
        or >= 2**255 - 1 for uint256), spender/to, and excessive expiration/sigDeadline.
      - Detects Gnosis Safe SafeTx: if operation == 1 (DelegateCall), flags critical risk (>= 9.0).
      - Checks if domain.verifyingContract is missing when primaryType is a permit or transaction type.

    Returns:
      (findings_list, eip712_risk_score)
    """
    if not typed_data or not isinstance(typed_data, dict):
        return [], 0.0

    findings: List[str] = []
    risk_score = 0.0

    domain = typed_data.get("domain", {})
    primary_type = typed_data.get("primaryType", "")
    message = typed_data.get("message", {})
    types = typed_data.get("types", {})

    if not isinstance(domain, dict):
        domain = {}
    if not isinstance(message, dict):
        message = {}

    sensitive_types = {"Permit", "PermitSingle", "PermitBatch", "PermitTransferFrom", "SafeTx"}
    is_sensitive = (
        primary_type in sensitive_types
        or "permit" in primary_type.lower()
        or "safetx" in primary_type.lower()
    )

    # 1. Missing verifyingContract check
    verifying_contract = domain.get("verifyingContract")
    if is_sensitive and (
        not verifying_contract
        or verifying_contract == "0x"
        or verifying_contract == "0x0000000000000000000000000000000000000000"
    ):
        findings.append("Missing verifyingContract in EIP-712 domain for sensitive signing payload")
        risk_score = max(risk_score, 7.5)

    # 2. Gnosis Safe SafeTx: operation == 1 (DelegateCall)
    if primary_type == "SafeTx" or "SafeTx" in types:
        op = message.get("operation")
        if op == 1 or str(op).strip() == "1" or str(op).upper() == "DELEGATECALL":
            findings.append("Critical SafeTx DelegateCall (operation=1) detected in EIP-712 payload")
            risk_score = max(risk_score, 9.0)

    # 3. Permit amounts & expirations inspection
    def inspect_amount_and_expiration(amt_val: Any, exp_val: Any):
        nonlocal risk_score
        if amt_val is not None:
            try:
                amt_int = int(str(amt_val), 0)
                if amt_int >= (2**159 - 1) or amt_int >= (2**255 - 1):
                    findings.append(f"Unlimited/excessive allowance ({amt_int}) requested in EIP-712 permit payload")
                    risk_score = max(risk_score, 7.5)
            except (ValueError, TypeError):
                pass

        if exp_val is not None:
            try:
                exp_int = int(str(exp_val), 0)
                if exp_int >= (2**47 - 1) or exp_int > 2524608000:
                    findings.append(f"Excessive expiration timestamp ({exp_int}) detected in EIP-712 permit payload")
                    risk_score = max(risk_score, 7.0)
            except (ValueError, TypeError):
                pass

    if (
        primary_type in ("Permit", "PermitSingle", "PermitBatch", "PermitTransferFrom")
        or "permit" in primary_type.lower()
    ):
        details = message.get("details")
        if isinstance(details, dict):
            inspect_amount_and_expiration(details.get("amount"), details.get("expiration"))
        elif isinstance(details, list):
            for item in details:
                if isinstance(item, dict):
                    inspect_amount_and_expiration(item.get("amount"), item.get("expiration"))

        inspect_amount_and_expiration(
            message.get("amount") or message.get("value"),
            message.get("expiration") or message.get("sigDeadline") or message.get("deadline"),
        )

        if risk_score == 0.0:
            risk_score = 6.0
            findings.append(f"EIP-712 permit allowance delegation ({primary_type}) detected")

    return findings, risk_score


class PreflightFirewall:
    """
    Preflight Security Firewall for Web3 Transactions and Typed Data.
    Enforces deterministic zero-cost security verification:
      - Calldata decoding & approval risk detection
      - EIP-712 permit & SafeTx DelegateCall inspection
      - Indirect Prompt Injection (IPI) defense
      - AsyncWeb3 eth_call on-chain simulation
    """

    def __init__(self, rpc_url: Optional[Union[str, List[str]]] = None):
        self.rpc_url = rpc_url

    async def simulate_eth_call(
        self, req: PreflightRequest, target_addr: str
    ) -> PreflightSimulationResult:
        """
        Executes an on-chain eth_call simulation using AsyncWeb3.
        Distinguishes EVM reverts from infrastructure/network RPC errors with automatic failover.
        """
        tx_dict: Dict[str, Any] = {
            "to": target_addr,
            "data": req.calldata or "0x",
            "value": int(req.value_wei),
        }
        if req.from_address:
            tx_dict["from"] = req.from_address

        try:
            rpc_urls = ChainInspector.resolve_rpc_urls(int(req.chain_id), self.rpc_url)
        except Exception as exc:
            return PreflightSimulationResult(
                executed=False,
                success=None,
                rpc_error=f"Failed to resolve RPC URL for chain {req.chain_id}: {exc}",
            )

        last_rpc_error: Optional[Exception] = None

        for url in rpc_urls:
            try:
                w3 = ChainInspector._get_or_create_w3(int(req.chain_id), url)
                res = await w3.eth.call(tx_dict)
                hex_res = res.hex() if isinstance(res, (bytes, bytearray)) else str(res)
                if not hex_res.startswith("0x"):
                    hex_res = "0x" + hex_res
                return PreflightSimulationResult(
                    executed=True,
                    success=True,
                    return_data=hex_res,
                    revert_reason=None,
                    rpc_error=None,
                )
            except (ContractLogicError, ContractCustomError) as rev_exc:
                return PreflightSimulationResult(
                    executed=True,
                    success=False,
                    return_data=None,
                    revert_reason=str(rev_exc),
                    rpc_error=None,
                )
            except Exception as exc:
                msg = str(exc).lower()
                # Check for EVM revert indicators returned by RPC provider
                if any(k in msg for k in ("revert", "execution reverted", "vm exception", "out of gas", "invalid opcode")):
                    return PreflightSimulationResult(
                        executed=True,
                        success=False,
                        return_data=None,
                        revert_reason=str(exc),
                        rpc_error=None,
                    )
                # Network or infrastructure error: record and attempt fallback RPC
                last_rpc_error = exc
                continue

        return PreflightSimulationResult(
            executed=False,
            success=None,
            return_data=None,
            revert_reason=None,
            rpc_error=str(last_rpc_error) if last_rpc_error else "All RPC endpoints failed",
        )

    async def evaluate(self, req: PreflightRequest) -> PreflightVerdict:
        """
        Evaluates a PreflightRequest through the firewall pipeline:
          1. Decodes calldata & inspects ERC-20/Permit2/admin approvals.
          2. Inspects EIP-712 typed data (Permit / SafeTx DelegateCall).
          3. Scans untrusted text and EIP-712 payloads for indirect prompt injection.
          4. Simulates eth_call on-chain (if enabled and target address is provided).
          5. Applies deterministic security verdict policy (ALLOW, MANUAL_REVIEW, or BLOCK).
        """
        target_addr = req.to_address or req.target_address

        # 1. Calldata decoding & approval checks
        decoded_action, approval_risks, calldata_score = decode_calldata_and_approvals(req.calldata)

        # 2. EIP-712 typed data inspection
        eip712_findings, eip712_score = inspect_eip712_typed_data(req.eip712_typed_data)

        # 3. Indirect prompt injection scan
        ipi_detected = False
        ipi_signals: List[str] = []
        ipi_score = 0.0

        if req.untrusted_text:
            d_txt, s_txt, sc_txt = scan_prompt_injection(req.untrusted_text)
            if d_txt:
                ipi_detected = True
                ipi_signals.extend(s_txt)
                ipi_score = max(ipi_score, sc_txt)

        if req.eip712_typed_data:
            eip_strings = extract_strings_from_obj(req.eip712_typed_data)
            for s_val in eip_strings:
                d_eip, s_eip, sc_eip = scan_prompt_injection(s_val)
                if d_eip:
                    ipi_detected = True
                    ipi_signals.extend(s_eip)
                    ipi_score = max(ipi_score, sc_eip)

        # 4. On-chain simulation
        simulation = PreflightSimulationResult()
        sim_revert_score = 0.0

        if req.run_simulation and target_addr:
            try:
                simulation = await self.simulate_eth_call(req, target_addr)
                if simulation.executed and simulation.success is False:
                    sim_revert_score = 8.5
            except Exception as e:
                simulation = PreflightSimulationResult(executed=False, rpc_error=str(e))

        # 5. Combined risk score calculation
        risk_score = min(10.0, max(calldata_score, eip712_score, ipi_score, sim_revert_score))

        # 6. Flagged issues compilation
        flagged_issues: List[str] = []
        flagged_issues.extend(approval_risks)
        flagged_issues.extend(eip712_findings)
        if ipi_detected:
            flagged_issues.extend([f"Prompt injection signal: {sig}" for sig in ipi_signals])
        if simulation.executed and simulation.success is False:
            flagged_issues.append(f"Simulation reverted: {simulation.revert_reason or 'execution reverted'}")
        if simulation.rpc_error:
            flagged_issues.append(f"Simulation RPC error: {simulation.rpc_error}")

        # 7. Deterministic verdict policy
        if risk_score >= 8.0 or ipi_detected or (simulation.executed and simulation.success is False):
            verdict: Literal["ALLOW", "BLOCK", "MANUAL_REVIEW"] = "BLOCK"
        elif risk_score >= 5.0:
            verdict = "MANUAL_REVIEW"
        else:
            verdict = "ALLOW"

        # 8. Human-readable summary
        if verdict == "BLOCK":
            issues_summary = "; ".join(flagged_issues[:3]) if flagged_issues else "Risk threshold exceeded"
            summary = f"Preflight BLOCKED: Risk score {risk_score:.1f}/10. Reason(s): {issues_summary}."
        elif verdict == "MANUAL_REVIEW":
            issues_summary = "; ".join(flagged_issues[:3]) if flagged_issues else "Elevated risk parameters"
            summary = f"Preflight MANUAL_REVIEW: Risk score {risk_score:.1f}/10. Needs confirmation: {issues_summary}."
        else:
            summary = f"Preflight ALLOWED: Risk score {risk_score:.1f}/10. Transaction parameters validated successfully."

        return PreflightVerdict(
            verdict=verdict,
            risk_score=round(risk_score, 2),
            chain_id=int(req.chain_id),
            target_address=target_addr,
            decoded_action=decoded_action,
            approval_risks=approval_risks,
            eip712_findings=eip712_findings,
            prompt_injection_detected=ipi_detected,
            prompt_injection_signals=ipi_signals,
            simulation=simulation,
            flagged_issues=flagged_issues,
            summary=summary,
            llm_invoked=False,
            payment=None,
        )
