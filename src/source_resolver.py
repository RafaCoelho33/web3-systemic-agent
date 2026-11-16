"""
Proxy & Verified Source Resolver for Web3 Condition-Action Trigger Agent.

Provides automated resolution of smart contract source code and proxy implementation state:
1. EIP-1967 storage slot inspection (implementation, admin, and beacon slots).
2. On-chain probing for administrative owner() and paused() contract state.
3. Multi-provider verified source code retrieval (Sourcify API with zero API keys,
   and Etherscan v2 API fallback for multi-file standard JSON and single-file sources).
4. Automated 4-byte selector extraction from implementation bytecode.
5. Generation of high-risk security warnings (unverified source, upgradeable proxy, paused state).

Typical usage:
    resolver = ContractSourceResolver()
    audit_context = await resolver.resolve_full_audit_context(
        chain_id=8453,
        target_address="0x..."
    )
    print(audit_context["proxy_info"]["is_proxy"])
    print(audit_context["source_info"]["verified"])
    print(audit_context["security_warnings"])
"""

import asyncio
import json
import logging
import os
import re
import sys
from typing import Dict, Any, Optional, List, Tuple, Union

import httpx
from web3 import Web3, AsyncWeb3
from web3.exceptions import Web3Exception

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
for _p in (_ROOT_DIR, _SRC_DIR, _SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.chain_inspector import ChainInspector
except ImportError:
    from chain_inspector import ChainInspector

logger = logging.getLogger(__name__)

# Standard EIP-1967 storage slots
EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

# Standard 4-byte function selectors
SELECTOR_OWNER = "0x8da5cb5b"           # owner()
SELECTOR_PAUSED = "0x5c975abb"          # paused()
SELECTOR_IMPLEMENTATION = "0x5c60da1b"  # implementation()

# Maximum character budget for source code input into downstream LLM prompts
MAX_SOURCE_CHARS = 24000

# Canonical EVM dispatcher opcode pattern (PUSH4 <sel> EQ)
DISPATCHER_REGEX = re.compile(r"(?:63|8063|8263)([0-9a-fA-F]{8})14", re.IGNORECASE)

KNOWN_SELECTORS: Dict[str, str] = {
    # ERC20 / ERC721 Standard
    "0xa9059cbb": "transfer(address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x70a08231": "balanceOf(address)",
    "0x18160ddd": "totalSupply()",
    "0xdd62ed3e": "allowance(address,address)",
    # Ownership & Access Control
    "0x8da5cb5b": "owner()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x715018a6": "renounceOwnership()",
    # Minting & Burning
    "0x40c10f19": "mint(address,uint256)",
    "0xa0712d68": "mint(uint256)",
    "0x42966c68": "burn(uint256)",
    "0x79cc6790": "burnFrom(address,uint256)",
    # Upgradability & Proxies
    "0x3659cfe6": "upgradeTo(address)",
    "0x4f1f2732": "upgradeToAndCall(address,bytes)",
    "0x52d19004": "implementation()",
    "0x5c60da1b": "implementation()",
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


def _extract_address_from_word(raw_bytes_or_hex: Union[bytes, str]) -> Optional[str]:
    """
    Parses a 32-byte storage word or eth_call return value.
    If the last 20 bytes are non-zero and represent a valid EVM address,
    returns Web3.to_checksum_address("0x" + addr_hex). Otherwise returns None.
    """
    if raw_bytes_or_hex is None:
        return None

    if isinstance(raw_bytes_or_hex, (bytes, bytearray)):
        hex_str = raw_bytes_or_hex.hex()
    else:
        hex_str = str(raw_bytes_or_hex).strip()
        if hex_str.startswith(("0x", "0X")):
            hex_str = hex_str[2:]

    hex_str = hex_str.strip()
    if len(hex_str) < 40:
        return None

    addr_hex = hex_str[-40:]
    try:
        if int(addr_hex, 16) == 0:
            return None
        return Web3.to_checksum_address("0x" + addr_hex)
    except Exception:
        return None


def _sol_sort_key(item: Tuple[str, str]) -> Tuple[int, str]:
    """Sort key prioritizing primary contract code over libraries, interfaces, and mocks."""
    path, _ = item
    lower = path.lower()
    is_aux = (
        "/interfaces/" in lower
        or "/libraries/" in lower
        or "/interface/" in lower
        or "/library/" in lower
        or "/node_modules/" in lower
        or "/mock/" in lower
        or "/mocks/" in lower
        or os.path.basename(lower).startswith("i")
        or "interface" in lower
        or "library" in lower
    )
    return (1 if is_aux else 0, path)


def _format_and_truncate_sol_files(
    sol_files: List[Tuple[str, str]], max_chars: int = MAX_SOURCE_CHARS
) -> Tuple[str, bool]:
    """Formats multiple Solidity files with comment banners and truncates cleanly at max_chars."""
    formatted_parts: List[str] = []
    total_chars = 0
    truncated = False

    for path, content in sol_files:
        header = f"// File: {path}\n"
        body = content.strip()
        block = f"{header}{body}\n\n"

        if total_chars + len(block) > max_chars:
            remaining = max_chars - total_chars - len(header) - 30
            if remaining > 50:
                truncated_body = body[:remaining] + "\n// ... [TRUNCATED]"
                formatted_parts.append(f"{header}{truncated_body}\n\n")
            truncated = True
            break
        else:
            formatted_parts.append(block)
            total_chars += len(block)

    combined = "".join(formatted_parts).strip()
    if len(combined) > max_chars:
        combined = combined[:max_chars]
        truncated = True

    return combined, truncated


def _extract_contract_names(
    sol_files: List[Tuple[str, str]], initial_names: Optional[List[str]] = None
) -> List[str]:
    """Extracts contract, interface, and library names from Solidity files."""
    names: List[str] = []
    if initial_names:
        for n in initial_names:
            if n and n not in names:
                names.append(n)

    for path, content in sol_files:
        base = os.path.basename(path)
        if base.endswith(".sol"):
            base = base[:-4]
        if base and base not in names:
            names.append(base)
        for c in re.findall(r"\b(?:contract|interface|library)\s+([A-Za-z0-9_]+)\b", content):
            if c not in names:
                names.append(c)
    return names


def extract_selectors_from_bytecode(
    bytecode: Union[bytes, str],
    tx_input: Optional[Union[bytes, str]] = None,
) -> List[Dict[str, Any]]:
    """
    Extracts 4-byte function selectors from smart contract bytecode and deployment calldata.
    Identifies known signatures and flags privileged or high-risk capabilities.
    """
    if not bytecode:
        return []

    if isinstance(bytecode, bytes):
        bytecode_hex = bytecode.hex()
    else:
        bytecode_hex = bytecode[2:] if bytecode.startswith(("0x", "0X")) else bytecode

    found: Dict[str, Dict[str, Any]] = {}
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

    # 3. If tx_input is provided, inspect initialization calldata
    if tx_input:
        if isinstance(tx_input, bytes):
            input_hex = tx_input.hex()
        else:
            input_hex = tx_input[2:] if tx_input.startswith(("0x", "0X")) else tx_input
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


class ContractSourceResolver:
    """
    Resolves smart contract source code and proxy implementation state.
    Supports EIP-1967 proxy patterns (storage slot inspection), owner/paused state probing,
    and multi-provider verified source code retrieval (Sourcify and Etherscan v2 API).
    """

    def __init__(
        self,
        rpc_url: Optional[Union[str, List[str]]] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        timeout: float = 8.0,
    ):
        self.rpc_url = rpc_url
        self.http_client = http_client
        self.timeout = timeout

    async def _get_request(
        self, url: str, params: Optional[Dict[str, Any]] = None
    ) -> Optional[httpx.Response]:
        """Internal helper for performing async HTTP GET requests with fallback client management."""
        try:
            if self.http_client is not None:
                return await self.http_client.get(url, params=params, timeout=self.timeout)
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    return await client.get(url, params=params)
        except Exception as exc:
            logger.debug(f"HTTP GET request to {url} failed: {exc}")
            return None

    async def resolve_proxy_and_state(
        self, chain_id: int, target_address: str
    ) -> Dict[str, Any]:
        """
        Inspects on-chain storage slots and runtime state for proxy patterns, admin ownership,
        and paused status using AsyncWeb3.
        """
        checksum_addr = Web3.to_checksum_address(target_address)

        try:
            rpc_urls = ChainInspector.resolve_rpc_urls(chain_id, self.rpc_url)
        except Exception as exc:
            logger.warning(f"Failed to resolve RPC URLs for chain {chain_id}: {exc}")
            return {
                "target_address": checksum_addr,
                "chain_id": chain_id,
                "is_proxy": False,
                "implementation_address": None,
                "admin_address": None,
                "beacon_address": None,
                "owner_address": None,
                "is_paused": None,
                "effective_audit_address": checksum_addr,
                "implementation_bytecode_size": 0,
                "rpc_error": str(exc),
            }

        last_exc: Optional[Exception] = None
        for i, url in enumerate(rpc_urls):
            try:
                w3 = ChainInspector._get_or_create_w3(chain_id, url)

                # Concurrent storage slot reads for EIP-1967 pointers
                slots_res = await asyncio.gather(
                    w3.eth.get_storage_at(checksum_addr, EIP1967_IMPLEMENTATION_SLOT),
                    w3.eth.get_storage_at(checksum_addr, EIP1967_ADMIN_SLOT),
                    w3.eth.get_storage_at(checksum_addr, EIP1967_BEACON_SLOT),
                    return_exceptions=True,
                )

                # If all 3 slot reads failed with exceptions, treat as RPC network failure
                if all(isinstance(r, Exception) for r in slots_res):
                    raise slots_res[0]

                impl_raw, admin_raw, beacon_raw = slots_res
                impl_addr = (
                    _extract_address_from_word(impl_raw)
                    if not isinstance(impl_raw, Exception)
                    else None
                )
                admin_addr = (
                    _extract_address_from_word(admin_raw)
                    if not isinstance(admin_raw, Exception)
                    else None
                )
                beacon_addr = (
                    _extract_address_from_word(beacon_raw)
                    if not isinstance(beacon_raw, Exception)
                    else None
                )

                is_proxy = False
                if impl_addr:
                    is_proxy = True
                elif beacon_addr:
                    try:
                        beacon_call_res = await w3.eth.call({
                            "to": beacon_addr,
                            "data": SELECTOR_IMPLEMENTATION,
                        })
                        beacon_impl = _extract_address_from_word(beacon_call_res)
                        if beacon_impl:
                            impl_addr = beacon_impl
                            is_proxy = True
                    except Exception as b_exc:
                        logger.debug(
                            f"Calling implementation() on beacon {beacon_addr} failed: {b_exc}"
                        )

                # Probe owner() and paused() on target contract
                owner_addr: Optional[str] = None
                is_paused: Optional[bool] = None

                probe_res = await asyncio.gather(
                    w3.eth.call({"to": checksum_addr, "data": SELECTOR_OWNER}),
                    w3.eth.call({"to": checksum_addr, "data": SELECTOR_PAUSED}),
                    return_exceptions=True,
                )
                owner_raw, paused_raw = probe_res[0], probe_res[1]

                if not isinstance(owner_raw, Exception):
                    owner_addr = _extract_address_from_word(owner_raw)

                if not isinstance(paused_raw, Exception):
                    if isinstance(paused_raw, (bytes, bytearray)):
                        is_paused = bool(int.from_bytes(paused_raw, byteorder="big") != 0)
                    elif isinstance(paused_raw, str):
                        clean = paused_raw.strip()
                        if clean.startswith(("0x", "0X")):
                            clean = clean[2:]
                        if clean:
                            is_paused = bool(int(clean, 16) != 0)

                # If is_proxy and implementation_address, fetch runtime bytecode
                impl_code: Optional[bytes] = None
                if is_proxy and impl_addr:
                    try:
                        code_res = await w3.eth.get_code(impl_addr)
                        if isinstance(code_res, (bytes, bytearray)):
                            impl_code = bytes(code_res)
                        elif isinstance(code_res, str):
                            clean = code_res.strip()
                            if clean.startswith(("0x", "0X")):
                                clean = clean[2:]
                            impl_code = bytes.fromhex(clean) if clean else b""
                        if impl_code is not None:
                            ChainInspector._set_bytecode_cache(
                                f"{chain_id}:{impl_addr}", impl_code
                            )
                    except Exception as c_exc:
                        logger.warning(
                            f"Failed to fetch implementation bytecode for {impl_addr}: {c_exc}"
                        )

                return {
                    "target_address": checksum_addr,
                    "chain_id": chain_id,
                    "is_proxy": bool(is_proxy),
                    "implementation_address": impl_addr,
                    "admin_address": admin_addr,
                    "beacon_address": beacon_addr,
                    "owner_address": owner_addr,
                    "is_paused": is_paused,
                    "effective_audit_address": impl_addr or checksum_addr,
                    "implementation_bytecode_size": len(impl_code) if impl_code else 0,
                    "rpc_error": None,
                }

            except Exception as exc:
                logger.warning(
                    f"RPC call failed for URL {url} (index {i}, chain {chain_id}): {exc}"
                )
                last_exc = exc
                continue

        # All RPC endpoints failed
        return {
            "target_address": checksum_addr,
            "chain_id": chain_id,
            "is_proxy": False,
            "implementation_address": None,
            "admin_address": None,
            "beacon_address": None,
            "owner_address": None,
            "is_paused": None,
            "effective_audit_address": checksum_addr,
            "implementation_bytecode_size": 0,
            "rpc_error": str(last_exc) if last_exc else "All RPC URLs failed",
        }

    async def fetch_verified_source(
        self, chain_id: int, address: str
    ) -> Dict[str, Any]:
        """
        Retrieves verified Solidity source code using Sourcify (free, no API key) with
        fallback to Etherscan v2 API when API keys are configured.
        """
        checksum_addr = Web3.to_checksum_address(address)

        # ---------------------------------------------------------
        # Step 1: Sourcify API (Free, zero API key required)
        # ---------------------------------------------------------
        sourcify_url = f"https://sourcify.dev/server/files/any/{chain_id}/{checksum_addr}"
        resp = await self._get_request(sourcify_url)
        if resp is not None and resp.status_code == 200:
            try:
                data = resp.json()
                raw_files = data.get("files") if isinstance(data, dict) else (data if isinstance(data, list) else None)
                sol_files: List[Tuple[str, str]] = []

                if isinstance(raw_files, list):
                    for f in raw_files:
                        if isinstance(f, dict):
                            name = f.get("name") or f.get("path") or ""
                            content = f.get("content", "")
                            if (name.endswith(".sol") or ".sol" in name.lower()) and content:
                                sol_files.append((name, content))
                elif isinstance(raw_files, dict):
                    for path, f in raw_files.items():
                        if isinstance(f, dict):
                            content = f.get("content", "")
                        else:
                            content = str(f)
                        if (path.endswith(".sol") or ".sol" in path.lower()) and content:
                            sol_files.append((path, content))

                if sol_files:
                    sol_files.sort(key=_sol_sort_key)
                    contract_names = _extract_contract_names(sol_files)
                    combined_source, truncated = _format_and_truncate_sol_files(
                        sol_files, MAX_SOURCE_CHARS
                    )

                    return {
                        "verified": True,
                        "provider": "sourcify",
                        "match_status": data.get("status", "full") if isinstance(data, dict) else "full",
                        "address": checksum_addr,
                        "files_count": len(sol_files),
                        "contract_names": contract_names,
                        "source_code": combined_source,
                        "truncated": truncated,
                    }
            except Exception as exc:
                logger.debug(f"Failed to parse Sourcify response for {checksum_addr}: {exc}")

        # ---------------------------------------------------------
        # Step 2: Etherscan v2 API Fallback
        # ---------------------------------------------------------
        api_key = (
            os.getenv(f"ETHERSCAN_API_KEY_{chain_id}")
            or (os.getenv("BASESCAN_API_KEY") if chain_id in (8453, 84532) else None)
            or os.getenv("ETHERSCAN_API_KEY")
            or os.getenv("BASESCAN_API_KEY")
        )

        if api_key:
            etherscan_params = {
                "chainid": chain_id,
                "module": "contract",
                "action": "getsourcecode",
                "address": checksum_addr,
                "apikey": api_key,
            }
            eth_resp = await self._get_request(
                "https://api.etherscan.io/v2/api", params=etherscan_params
            )
            if eth_resp is not None and eth_resp.status_code == 200:
                try:
                    eth_data = eth_resp.json()
                    if eth_data.get("status") == "1" and eth_data.get("result"):
                        results = eth_data.get("result")
                        if isinstance(results, list) and len(results) > 0:
                            first_res = results[0]
                            raw_source = first_res.get("SourceCode", "").strip()
                            contract_name = first_res.get("ContractName", "").strip()

                            if raw_source and raw_source != "Contract source code not verified":
                                # Try parsing Standard JSON Input format (double or single braced)
                                parsed_json = None
                                if raw_source.startswith("{{") and raw_source.endswith("}}"):
                                    try:
                                        parsed_json = json.loads(raw_source[1:-1])
                                    except Exception:
                                        pass
                                elif raw_source.startswith("{") and raw_source.endswith("}"):
                                    try:
                                        parsed_json = json.loads(raw_source)
                                    except Exception:
                                        pass

                                if parsed_json and isinstance(parsed_json, dict):
                                    sources = parsed_json.get("sources", parsed_json)
                                    sol_files: List[Tuple[str, str]] = []
                                    if isinstance(sources, dict):
                                        for f_path, f_info in sources.items():
                                            if isinstance(f_info, dict):
                                                c = f_info.get("content", "")
                                            else:
                                                c = str(f_info)
                                            if (f_path.endswith(".sol") or ".sol" in f_path.lower()) and c:
                                                sol_files.append((f_path, c))

                                    if sol_files:
                                        sol_files.sort(key=_sol_sort_key)
                                        contract_names = _extract_contract_names(
                                            sol_files,
                                            initial_names=[contract_name] if contract_name else None,
                                        )
                                        combined_source, truncated = _format_and_truncate_sol_files(
                                            sol_files, MAX_SOURCE_CHARS
                                        )

                                        return {
                                            "verified": True,
                                            "provider": "etherscan_v2",
                                            "match_status": "full",
                                            "address": checksum_addr,
                                            "files_count": len(sol_files),
                                            "contract_names": contract_names,
                                            "source_code": combined_source,
                                            "truncated": truncated,
                                        }

                                # Single-file raw Solidity source
                                contract_names = [contract_name] if contract_name else []
                                for c_name in re.findall(
                                    r"\b(?:contract|interface|library)\s+([A-Za-z0-9_]+)\b",
                                    raw_source,
                                ):
                                    if c_name not in contract_names:
                                        contract_names.append(c_name)

                                truncated = False
                                if len(raw_source) > MAX_SOURCE_CHARS:
                                    combined_source = (
                                        raw_source[:MAX_SOURCE_CHARS] + "\n// ... [TRUNCATED]"
                                    )
                                    if len(combined_source) > MAX_SOURCE_CHARS:
                                        combined_source = combined_source[:MAX_SOURCE_CHARS]
                                    truncated = True
                                else:
                                    combined_source = raw_source

                                return {
                                    "verified": True,
                                    "provider": "etherscan_v2",
                                    "match_status": "full",
                                    "address": checksum_addr,
                                    "files_count": 1,
                                    "contract_names": contract_names,
                                    "source_code": combined_source,
                                    "truncated": truncated,
                                }
                except Exception as exc:
                    logger.debug(f"Failed to parse Etherscan response for {checksum_addr}: {exc}")

        # ---------------------------------------------------------
        # Step 3: Unverified Fallback
        # ---------------------------------------------------------
        return {
            "verified": False,
            "provider": None,
            "address": checksum_addr,
            "files_count": 0,
            "contract_names": [],
            "source_code": "",
            "truncated": False,
        }

    async def resolve_full_audit_context(
        self,
        chain_id: int,
        target_address: str,
        resolve_proxy: bool = True,
        fetch_source: bool = True,
    ) -> Dict[str, Any]:
        """
        Coordinates full audit context resolution: proxy status, storage state,
        verified source code, function selector extraction, and security warnings.
        """
        checksum_addr = Web3.to_checksum_address(target_address)

        if resolve_proxy:
            proxy_info = await self.resolve_proxy_and_state(chain_id, checksum_addr)
        else:
            proxy_info = {
                "target_address": checksum_addr,
                "chain_id": chain_id,
                "is_proxy": False,
                "implementation_address": None,
                "admin_address": None,
                "beacon_address": None,
                "owner_address": None,
                "is_paused": None,
                "effective_audit_address": checksum_addr,
                "implementation_bytecode_size": 0,
                "rpc_error": None,
            }

        effective_audit_address = (
            proxy_info.get("effective_audit_address") or checksum_addr
        )

        if fetch_source:
            source_info = await self.fetch_verified_source(
                chain_id, effective_audit_address
            )
            # If proxy and implementation source is not verified, check if proxy itself has source
            if (
                proxy_info.get("is_proxy")
                and not source_info.get("verified")
                and effective_audit_address != checksum_addr
            ):
                proxy_source = await self.fetch_verified_source(
                    chain_id, checksum_addr
                )
                if proxy_source.get("verified"):
                    source_info = proxy_source
        else:
            source_info = {
                "verified": False,
                "provider": None,
                "address": effective_audit_address,
                "files_count": 0,
                "contract_names": [],
                "source_code": "",
                "truncated": False,
            }

        # Extract 4-byte selectors from implementation bytecode (if proxy)
        effective_selectors: List[Dict[str, Any]] = []
        target_code: Optional[bytes] = None

        if proxy_info.get("is_proxy") and proxy_info.get("implementation_address"):
            impl_key = f"{chain_id}:{proxy_info['implementation_address']}"
            target_code = ChainInspector._bytecode_cache.get(impl_key)

        if not target_code:
            target_key = f"{chain_id}:{checksum_addr}"
            target_code = ChainInspector._bytecode_cache.get(target_key)

        if target_code:
            effective_selectors = extract_selectors_from_bytecode(target_code)

        security_warnings: List[str] = []
        if not source_info.get("verified"):
            security_warnings.append("Unverified contract source code")
        if proxy_info.get("is_proxy"):
            security_warnings.append("Upgradeable EIP-1967 proxy detected")
        if proxy_info.get("is_paused") is True:
            security_warnings.append("Contract is currently in paused state")
        if proxy_info.get("admin_address"):
            security_warnings.append(
                f"Proxy admin configured: {proxy_info['admin_address']}"
            )
        if proxy_info.get("beacon_address"):
            security_warnings.append(
                f"Beacon proxy detected: {proxy_info['beacon_address']}"
            )
        if source_info.get("truncated"):
            security_warnings.append(
                "Verified source code truncated to character limit"
            )
        if proxy_info.get("rpc_error"):
            security_warnings.append(
                f"RPC error during proxy/state resolution: {proxy_info['rpc_error']}"
            )

        return {
            "target_address": checksum_addr,
            "chain_id": chain_id,
            "effective_audit_address": effective_audit_address,
            "proxy_info": proxy_info,
            "source_info": source_info,
            "effective_selectors": effective_selectors,
            "security_warnings": security_warnings,
        }
