"""
Deterministic Chain Inspector Layer for Web3 Condition-Action Trigger Agent.
Interacts with EVM blockchains via AsyncWeb3 to evaluate on-chain conditions
(bytecode existence, native balance, calldata selectors) at zero LLM cost.
"""

import asyncio
import logging
import os
import sys
from typing import Dict, Any, Optional, List, Union
from web3 import AsyncWeb3, AsyncHTTPProvider, Web3
from web3.exceptions import Web3Exception

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.schemas import DeterministicCondition, DeterministicResult
except ImportError:
    from schemas import DeterministicCondition, DeterministicResult

logger = logging.getLogger(__name__)

BYTECODE_CACHE_MAX = 1024


class ChainInspector:
    """
    Deterministic Layer: Interacts with the EVM blockchain via AsyncWeb3.
    Filters out non-matching conditions at zero LLM token cost.
    """

    BYTECODE_CACHE_MAX = BYTECODE_CACHE_MAX

    DEFAULT_RPCS = {
        8453: "https://mainnet.base.org",
        84532: "https://sepolia.base.org",
        42161: "https://arb1.arbitrum.io/rpc",
    }

    KNOWN_SELECTORS = {
        "0xa9059cbb": "transfer(address,uint256)",
        "0x095ea7b3": "approve(address,uint256)",
        "0x23b872dd": "transferFrom(address,address,uint256)",
        "0xf2fde38b": "transferOwnership(address)",
        "0x3659cfe6": "upgradeTo(address)",
        "0x40c10f19": "mint(address,uint256)",
    }

    _bytecode_cache: Dict[str, bytes] = {}
    _web3_cache: Dict[str, Any] = {}

    @classmethod
    def _set_bytecode_cache(cls, key: str, code: bytes) -> None:
        if key in cls._bytecode_cache:
            cls._bytecode_cache[key] = code
            return
        if len(cls._bytecode_cache) >= cls.BYTECODE_CACHE_MAX:
            oldest_key = next(iter(cls._bytecode_cache))
            cls._bytecode_cache.pop(oldest_key, None)
        cls._bytecode_cache[key] = code

    @classmethod
    def clear_cache(cls) -> None:
        cls._bytecode_cache.clear()
        cls._web3_cache.clear()

    @property
    def bytecode_cache(self) -> Dict[str, bytes]:
        return self._bytecode_cache

    @classmethod
    def resolve_rpc_urls(
        cls, chain_id: int, rpc_url: Optional[Union[str, List[str]]] = None
    ) -> List[str]:
        if rpc_url is not None:
            if isinstance(rpc_url, str):
                urls = [u.strip() for u in rpc_url.split(",") if u.strip()]
            elif isinstance(rpc_url, (list, tuple)):
                urls = [str(u).strip() for u in rpc_url if str(u).strip()]
            else:
                urls = [str(rpc_url).strip()] if str(rpc_url).strip() else []
            if urls:
                return urls

        env_var = os.getenv(f"RPC_URL_{chain_id}")
        if env_var:
            urls = [u.strip() for u in env_var.split(",") if u.strip()]
            if urls:
                return urls

        default_rpc = cls.DEFAULT_RPCS.get(chain_id)
        if default_rpc:
            return [default_rpc]

        raise ValueError(f"No default RPC configured for chain_id {chain_id}")

    @classmethod
    def _get_or_create_w3(
        cls, chain_id: int, url: str, use_cache: bool = True
    ) -> AsyncWeb3:
        cache_key = f"{chain_id}:{url}"
        if use_cache and cache_key in cls._web3_cache:
            return cls._web3_cache[cache_key]
        w3_instance = AsyncWeb3(AsyncHTTPProvider(url))
        if use_cache:
            cls._web3_cache[cache_key] = w3_instance
        return w3_instance

    def __init__(
        self,
        chain_id: int,
        rpc_url: Optional[Union[str, List[str]]] = None,
        use_cache: bool = True,
    ):
        self.chain_id = chain_id
        self.use_cache = use_cache
        self.rpc_urls = self.resolve_rpc_urls(chain_id, rpc_url)
        self.w3 = self._get_or_create_w3(chain_id, self.rpc_urls[0], use_cache=use_cache)

    async def verify_connection(self) -> bool:
        try:
            return await self.w3.is_connected()
        except Web3Exception as exc:
            logger.error(f"RPC connection failed: {exc}")
            return False

    @staticmethod
    def inspect_calldata_selector(calldata: str) -> Dict[str, str]:
        if not calldata or calldata == "0x" or len(calldata) < 10:
            return {"selector": "0x", "signature": "native_transfer_or_empty"}
        selector = calldata[:10].lower()
        signature = ChainInspector.KNOWN_SELECTORS.get(selector, "unknown_selector")
        return {"selector": selector, "signature": signature}

    def _evaluate_post_rpc(
        self,
        condition: DeterministicCondition,
        context: Dict[str, Any],
        observed: Dict[str, Any],
    ) -> DeterministicResult:
        # Check transaction value passed in payload context
        tx_value_wei = int(context.get("tx_value_wei", 0))
        observed["tx_value_wei"] = tx_value_wei
        if not condition.check_native_balance and tx_value_wei < condition.min_value_wei:
            return DeterministicResult(
                passed=False,
                reason=f"Transaction value ({tx_value_wei} wei) is below threshold ({condition.min_value_wei} wei).",
                observed_data=observed,
                error=None,
            )

        # Inspect function selector if required
        calldata = context.get("calldata", "0x")
        selector_info = self.inspect_calldata_selector(calldata)
        observed["calldata_analysis"] = selector_info

        if condition.required_function_selectors:
            normalized_required = [s.lower() for s in condition.required_function_selectors]
            if selector_info["selector"] not in normalized_required:
                return DeterministicResult(
                    passed=False,
                    reason=f"Selector {selector_info['selector']} not in required list {normalized_required}.",
                    observed_data=observed,
                    error=None,
                )

        return DeterministicResult(
            passed=True,
            reason="All deterministic on-chain conditions satisfied.",
            observed_data=observed,
            error=None,
        )

    async def evaluate_deterministic(
        self, condition: DeterministicCondition, context: Dict[str, Any]
    ) -> DeterministicResult:
        target_addr = Web3.to_checksum_address(condition.target_address)
        cache_key = f"{self.chain_id}:{target_addr}"
        observed: Dict[str, Any] = {"target_address": target_addr}

        try:
            if not condition.check_native_balance and cache_key in self._bytecode_cache:
                code = self._bytecode_cache[cache_key]
                observed["is_contract"] = len(code) > 0
                observed["rpc_url_index"] = 0
                return self._evaluate_post_rpc(condition, context, observed)

            last_exc: Optional[Exception] = None
            for i, url in enumerate(self.rpc_urls):
                observed = {"target_address": target_addr}
                w3 = self._get_or_create_w3(self.chain_id, url, use_cache=self.use_cache)
                try:
                    if condition.check_native_balance:
                        results = await asyncio.gather(
                            w3.eth.get_code(target_addr),
                            w3.eth.get_balance(target_addr),
                            return_exceptions=True,
                        )
                        code_res, balance_res = results[0], results[1]

                        if isinstance(code_res, Exception):
                            raise code_res
                        if isinstance(balance_res, Exception):
                            raise balance_res

                        self._set_bytecode_cache(cache_key, code_res)
                        observed["is_contract"] = len(code_res) > 0
                        observed["native_balance_wei"] = balance_res
                        observed["native_balance_eth"] = float(w3.from_wei(balance_res, "ether"))

                        if balance_res < condition.min_value_wei:
                            observed["rpc_url_index"] = i
                            return DeterministicResult(
                                passed=False,
                                reason=f"Target balance ({balance_res} wei) is below threshold ({condition.min_value_wei} wei).",
                                observed_data=observed,
                                error=None,
                            )
                    else:
                        code = await w3.eth.get_code(target_addr)
                        self._set_bytecode_cache(cache_key, code)
                        observed["is_contract"] = len(code) > 0

                    observed["rpc_url_index"] = i
                    return self._evaluate_post_rpc(condition, context, observed)

                except Exception as exc:
                    logger.warning(
                        f"RPC call failed for URL {url} (index {i}, chain {self.chain_id}): {exc}"
                    )
                    last_exc = exc
                    continue

            logger.exception("All RPC URLs failed during deterministic evaluation")
            return DeterministicResult(
                passed=False,
                reason=f"RPC/Evaluation error: {str(last_exc)}",
                observed_data=observed,
                error=str(last_exc) if last_exc else "All RPC URLs failed",
            )

        except Exception as exc:
            logger.exception("Error during deterministic evaluation")
            return DeterministicResult(
                passed=False,
                reason=f"RPC/Evaluation error: {str(exc)}",
                observed_data=observed,
                error=str(exc),
            )
