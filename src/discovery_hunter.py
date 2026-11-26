"""
Active Multi-Channel Contract Hunter for Web3 Condition-Action Trigger Agent.

Continuously and autonomously discovers newly deployed contracts, newly minted DEX pools,
freshly listed tokens, and active DAO governance proposals across 5 zero-API-key, zero-gas
discovery channels:
    1. "base_blocks": Base Mainnet block contract deployments (scan_recent_blocks).
    2. "dex_pools": Aerodrome & Uniswap v3 PoolCreated events on Base (scan_pool_events).
    3. "geckoterminal_base": GeckoTerminal public New Pools API for Base.
    4. "dexscreener_base": DexScreener public Latest Token Profiles API filtered to Base.
    5. "snapshot_daos": Active Snapshot DAO governance proposals with on-chain targets.

Each discovered target is deduplicated via a bounded FIFO cache, triaged deterministically
on-chain at zero LLM cost (bytecode extraction, 4-byte selectors, honeypot signatures),
and escalated to Stage 2 semantic auditing only when high-risk indicators are present
(when require_high_risk_for_llm=True).

Usage Examples:
    import asyncio
    from src.discovery_hunter import ActiveContractHunter

    async def main():
        hunter = ActiveContractHunter()
        summary = await hunter.run_hunt_cycle(limit_per_channel=2, dry_run=True)
        print(summary["total_audited"], summary["high_risk_count"])

    asyncio.run(main())
"""

import asyncio
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

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
_ROOT_DIR = (
    os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
    if os.path.basename(_CURRENT_DIR) == "src"
    else _CURRENT_DIR
)
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

from web3 import AsyncHTTPProvider, AsyncWeb3, Web3

try:
    from src.chain_inspector import ChainInspector
    from src.engine import ConditionAgentEngine
    from src.governance_connector import (
        GovernanceAuditReport,
        GovernanceProposal,
        SnapshotGovernanceConnector,
        WebhookAlertDispatcher,
        get_curated_dao_proposals,
    )
    from src.schemas import (
        ChainId,
        ConditionRulePayload,
        DeterministicCondition,
        FinalAgentResponse,
        SemanticCondition,
    )
    from src.semantic_evaluator import MockSemanticEvaluator
    from src.storage import AgentStorage
except ImportError:
    from chain_inspector import ChainInspector
    from engine import ConditionAgentEngine
    from governance_connector import (
        GovernanceAuditReport,
        GovernanceProposal,
        SnapshotGovernanceConnector,
        WebhookAlertDispatcher,
        get_curated_dao_proposals,
    )
    from schemas import (
        ChainId,
        ConditionRulePayload,
        DeterministicCondition,
        FinalAgentResponse,
        SemanticCondition,
    )
    from semantic_evaluator import MockSemanticEvaluator
    from storage import AgentStorage

from scripts.block_contract_scanner import (
    audit_discovered_contracts,
    create_mock_w3 as create_mock_block_w3,
    extract_selectors_from_bytecode,
    is_high_risk_signature,
    scan_recent_blocks,
)
from scripts.dex_pool_monitor import (
    HONEYPOT_SELECTORS,
    analyze_bytecode_honeypot,
    audit_discovered_pools,
    get_curated_mock_pools,
    get_latest_block_number,
    scan_pool_events,
)

logger = logging.getLogger(__name__)

CHAIN_ID_BASE_MAINNET = 8453
DEFAULT_BASE_RPC = "https://mainnet.base.org"

GECKOTERMINAL_NEW_POOLS_URL = (
    "https://api.geckoterminal.com/api/v2/networks/base/new_pools"
)
GECKOTERMINAL_HEADERS = {"Accept": "application/json;version=20230302"}
DEXSCREENER_TOKEN_PROFILES_URL = (
    "https://api.dexscreener.com/token-profiles/latest/v1"
)

SUPPORTED_CHANNELS: Tuple[str, ...] = (
    "base_blocks",
    "dex_pools",
    "geckoterminal_base",
    "dexscreener_base",
    "snapshot_daos",
)

# Deterministic bytecode fixtures for offline dry-run simulations
_BENIGN_ERC20_BYTECODE = bytes.fromhex(
    "608060405234801561001057600080fd5b50"
    "8063a9059cbb1461003057"  # transfer(address,uint256)
    "8063095ea7b31461005057"  # approve(address,uint256)
    "806370a082311461007057"  # balanceOf(address)
    "600080fd"
)
_HONEYPOT_UPGRADEABLE_BYTECODE = bytes.fromhex(
    "608060405234801561001057600080fd5b50"
    "806340af12751461003057"  # setBlacklist(address,bool)
    "80631e3dd19f1461005057"  # setTax(uint256)
    "80633659cfe61461007057"  # upgradeTo(address)
    "8063f2fde38b1461009057"  # transferOwnership(address)
    "600080fd"
)


def _to_bytecode_bytes(bytecode: Any) -> bytes:
    """Normalizes hex string or bytes bytecode into raw bytes."""
    if not bytecode:
        return b""
    if isinstance(bytecode, (bytes, bytearray)):
        return bytes(bytecode)
    if isinstance(bytecode, str):
        cleaned = bytecode[2:] if bytecode.startswith("0x") else bytecode
        if not cleaned:
            return b""
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return b""
    return b""


def _extract_geckoterminal_token_address(item: Dict[str, Any]) -> Optional[str]:
    """Extracts and validates a checksummed Base token address from a GeckoTerminal pool item."""
    if not isinstance(item, dict):
        return None

    candidates: List[str] = []
    relationships = item.get("relationships")
    if isinstance(relationships, dict):
        base_token = relationships.get("base_token")
        if isinstance(base_token, dict):
            bt_data = base_token.get("data")
            if isinstance(bt_data, dict):
                bt_id = bt_data.get("id")
                if isinstance(bt_id, str):
                    candidates.append(bt_id[5:] if bt_id.startswith("base_") else bt_id)

    attrs = item.get("attributes")
    if isinstance(attrs, dict):
        for key in ("base_token_address", "address"):
            val = attrs.get(key)
            if isinstance(val, str):
                candidates.append(val)

    for raw in candidates:
        raw_clean = raw.strip()
        if Web3.is_address(raw_clean):
            return Web3.to_checksum_address(raw_clean)
    return None


class ActiveContractHunter:
    """
    Autonomous Multi-Channel Contract Hunter discovering real smart contracts,
    DEX tokens, and DAO governance payloads across 5 zero-cost channels.
    """

    def __init__(
        self,
        engine: Optional[ConditionAgentEngine] = None,
        storage: Optional[AgentStorage] = None,
        rpc_url: Optional[str] = None,
        http_client: Optional[Any] = None,
        require_high_risk_for_llm: bool = True,
        webhook_url: Optional[str] = None,
        public_api_url: Optional[str] = None,
        max_seen_cache: int = 2048,
    ):
        self.storage = storage if storage is not None else AgentStorage()
        self.engine = engine
        self.rpc_url = (
            rpc_url
            or os.getenv("RPC_URL_8453")
            or DEFAULT_BASE_RPC
        )
        self.http_client = http_client
        self.require_high_risk_for_llm = bool(require_high_risk_for_llm)
        self.webhook_url = (
            webhook_url
            or os.getenv("ALERT_WEBHOOK_URL")
            or os.getenv("WEBHOOK_URL")
            or ""
        ).strip() or None
        self.public_api_url = (
            public_api_url
            or os.getenv("PUBLIC_API_URL")
            or "https://web3-systemic-agent.onrender.com"
        ).rstrip("/")
        self.max_seen_cache = max(1, int(max_seen_cache))
        self._seen_targets: Dict[str, float] = {}

    def _is_seen(self, key: str) -> bool:
        return key in self._seen_targets

    def _mark_seen(self, key: str) -> None:
        if key in self._seen_targets:
            self._seen_targets[key] = time.time()
            return
        while len(self._seen_targets) >= self.max_seen_cache:
            oldest_key = next(iter(self._seen_targets))
            self._seen_targets.pop(oldest_key, None)
        self._seen_targets[key] = time.time()

    def _get_engine(self, dry_run: bool = False) -> ConditionAgentEngine:
        if dry_run:
            return ConditionAgentEngine(
                rpc_url=self.rpc_url,
                semantic_evaluator=MockSemanticEvaluator(),
                storage=self.storage,
            )
        if self.engine is None:
            self.engine = ConditionAgentEngine(
                rpc_url=self.rpc_url,
                storage=self.storage,
            )
        return self.engine

    async def _http_get_json(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Performs an async HTTP GET returning parsed JSON using injected or fresh httpx client."""
        if self.http_client is not None:
            resp = await self.http_client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()

        if httpx is None:
            raise RuntimeError("httpx is required for live HTTP discovery channels")

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()

    async def _fetch_base_bytecode(self, checksum_addr: str) -> bytes:
        """Resolves bytecode from ChainInspector cache or Base Mainnet RPC."""
        cache_key = f"{CHAIN_ID_BASE_MAINNET}:{checksum_addr}"
        if cache_key in ChainInspector._bytecode_cache:
            return ChainInspector._bytecode_cache[cache_key]

        inspector = ChainInspector(chain_id=CHAIN_ID_BASE_MAINNET, rpc_url=self.rpc_url)
        for url in inspector.rpc_urls:
            try:
                w3 = inspector._get_or_create_w3(
                    CHAIN_ID_BASE_MAINNET, url, use_cache=inspector.use_cache
                )
                code = await w3.eth.get_code(checksum_addr)
                code_bytes = _to_bytecode_bytes(code)
                ChainInspector._set_bytecode_cache(cache_key, code_bytes)
                return code_bytes
            except Exception as exc:
                logger.warning(f"RPC get_code failed for {checksum_addr} at {url}: {exc}")
        return b""

    def _build_token_rule_payload(
        self,
        checksum_addr: str,
        bytecode_bytes: bytes,
        analysis: Dict[str, Any],
        selectors: List[Dict[str, Any]],
        channel: str,
        source_prefix: str,
        label: str,
        extra_context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ConditionRulePayload, bool]:
        """Builds a ConditionRulePayload for a discovered token with risk-gated LLM escalation."""
        honeypot_flags: List[str] = list(analysis.get("honeypot_flags", []))
        is_honeypot = bool(analysis.get("is_honeypot", False))
        signatures = [s.get("signature", "") for s in selectors]
        high_risk_sigs = [sig for sig in signatures if is_high_risk_signature(sig)]
        has_risk_flags = bool(is_honeypot or honeypot_flags or high_risk_sigs)
        semantic_enabled = bool(has_risk_flags) if self.require_high_risk_for_llm else True

        matched_selector = "0x"
        matched_signature = "erc20_transfer"
        for s in selectors:
            sig = s.get("signature", "")
            if "transferOwnership" in sig or "upgradeTo" in sig:
                matched_selector = s["selector"]
                matched_signature = sig
                break
        if matched_selector == "0x":
            for s in selectors:
                if s.get("selector") in HONEYPOT_SELECTORS or is_high_risk_signature(s.get("signature", "")):
                    matched_selector = s["selector"]
                    matched_signature = s["signature"]
                    break
        if matched_selector == "0x" and selectors:
            matched_selector = selectors[0]["selector"]
            matched_signature = selectors[0]["signature"]

        threat_summary = (
            f"CRITICAL RISK INDICATORS: {', '.join(honeypot_flags + high_risk_sigs)}"
            if has_risk_flags
            else "Standard token bytecode without honeypot or privileged admin patterns."
        )

        prompt = (
            f"Audit newly discovered Base token {label} ({checksum_addr}) from channel {channel}. "
            f"Bytecode size: {len(bytecode_bytes)} bytes. "
            f"Honeypot flags: {', '.join(honeypot_flags) if honeypot_flags else 'None'}. "
            f"Privileged signatures: {', '.join(high_risk_sigs) if high_risk_sigs else 'None'}. "
            f"Evaluate blacklist traps, arbitrary transfer taxes, upgradeable proxy backdoors, and rugpull risk."
        )

        context_metadata: Dict[str, Any] = {
            "channel": channel,
            "target_token": checksum_addr,
            "token_label": label,
            "honeypot_flags": honeypot_flags,
            "is_honeypot_suspect": is_honeypot,
            "high_risk_signatures": high_risk_sigs,
            "selectors_found": [s.get("selector") for s in selectors],
            "signatures_found": signatures,
            "bytecode_length": len(bytecode_bytes),
            "calldata": matched_selector,
            "calldata_analysis": {
                "selector": matched_selector,
                "signature": matched_signature,
            },
            "proposal_title": f"{channel}: {label} ({checksum_addr})",
            "proposal_description": (
                f"Token discovered via {channel}. Address: {checksum_addr}. {threat_summary}"
            ),
        }
        if extra_context:
            context_metadata.update(extra_context)

        payload = ConditionRulePayload(
            rule_id=f"{source_prefix}-{checksum_addr.lower()[:12]}",
            chain_id=ChainId.BASE_MAINNET,
            deterministic=DeterministicCondition(
                target_address=checksum_addr,
                min_value_wei=0,
                required_function_selectors=None,
                check_native_balance=False,
            ),
            semantic=SemanticCondition(
                enabled=semantic_enabled,
                policy_prompt=prompt,
                risk_threshold=7.0,
            ),
            context_metadata=context_metadata,
        )
        return payload, is_honeypot

    async def _audit_discovered_token(
        self,
        token_address: str,
        channel: str,
        source: str,
        source_prefix: str,
        label: str,
        active_engine: ConditionAgentEngine,
        bytecode_override: Optional[bytes] = None,
        extra_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Executes deterministic triage and conditional Stage 2 audit for a discovered token."""
        if not Web3.is_address(token_address):
            return None
        checksum_addr = Web3.to_checksum_address(token_address)
        seen_key = checksum_addr.lower()
        if self._is_seen(seen_key):
            return None

        if bytecode_override is not None:
            bytecode_bytes = _to_bytecode_bytes(bytecode_override)
            ChainInspector._set_bytecode_cache(
                f"{CHAIN_ID_BASE_MAINNET}:{checksum_addr}", bytecode_bytes
            )
        else:
            bytecode_bytes = await self._fetch_base_bytecode(checksum_addr)

        if not bytecode_bytes or bytecode_bytes == b"\x00":
            return None

        self._mark_seen(seen_key)

        analysis = analyze_bytecode_honeypot(bytecode_bytes)
        selectors = extract_selectors_from_bytecode(bytecode_bytes)
        payload, is_honeypot = self._build_token_rule_payload(
            checksum_addr=checksum_addr,
            bytecode_bytes=bytecode_bytes,
            analysis=analysis,
            selectors=selectors,
            channel=channel,
            source_prefix=source_prefix,
            label=label,
            extra_context=extra_context,
        )

        try:
            response = await active_engine.process_rule(payload, source=source)
        except Exception as exc:
            logger.error(f"[{channel}] Audit failed for {checksum_addr}: {exc}")
            return None

        sem = response.semantic_Evaluation
        if is_honeypot:
            decision = "REJECT"
            risk_score = max(float(sem.risk_score) if sem else 9.0, 9.0)
        elif sem is not None:
            decision = sem.recommended_action
            risk_score = float(sem.risk_score)
        else:
            decision = "APPROVE" if response.deterministic_check.passed else "REJECT"
            risk_score = 0.0 if response.deterministic_check.passed else 10.0

        flags = list(analysis.get("honeypot_flags", []))
        for s in selectors:
            sig = s.get("signature", "")
            if is_high_risk_signature(sig) and sig not in flags:
                flags.append(sig)

        return {
            "channel": channel,
            "target": checksum_addr,
            "target_address": checksum_addr,
            "label": label,
            "risk_score": risk_score,
            "decision": decision,
            "llm_invoked": bool(response.llm_invoked),
            "flags": flags,
            "source": source,
            "rule_id": payload.rule_id,
            "response": response,
        }

    async def hunt_base_blocks(
        self,
        blocks: int = 2,
        limit: int = 2,
        w3: Optional[Any] = None,
        dry_run: bool = False,
        engine: Optional[ConditionAgentEngine] = None,
    ) -> List[Dict[str, Any]]:
        """Channel 1: Scans recent Base Mainnet blocks for new smart contract deployments."""
        if limit <= 0:
            return []

        active_engine = engine or self._get_engine(dry_run=dry_run)
        if w3 is not None:
            target_w3 = w3
        elif dry_run:
            target_w3 = create_mock_block_w3()
        else:
            target_w3 = AsyncWeb3(AsyncHTTPProvider(self.rpc_url))

        try:
            discovered = await scan_recent_blocks(
                w3=target_w3, num_blocks=blocks, limit=limit
            )
        except Exception as exc:
            logger.warning(f"[base_blocks] Failed to scan blocks: {exc}")
            return []

        unseen: List[Dict[str, Any]] = []
        for item in discovered:
            addr = item.get("contract_address")
            if not addr or not Web3.is_address(addr):
                continue
            chk = Web3.to_checksum_address(addr)
            if self._is_seen(chk.lower()):
                continue
            self._mark_seen(chk.lower())
            unseen.append(item)
            if len(unseen) >= limit:
                break

        if not unseen:
            return []

        audited = await audit_discovered_contracts(
            unseen,
            engine=active_engine,
            rpc_url=self.rpc_url,
            require_high_risk_for_llm=self.require_high_risk_for_llm,
        )

        results: List[Dict[str, Any]] = []
        for r in audited:
            resp: FinalAgentResponse = r["response"]
            addr = r["contract_address"]
            high_risk_sigs = [
                s["signature"]
                for s in r.get("selectors", [])
                if is_high_risk_signature(s.get("signature", ""))
            ]
            results.append({
                "channel": "base_blocks",
                "target": addr,
                "target_address": addr,
                "label": f"Block {r.get('block_number')} Deploy",
                "risk_score": float(r.get("risk_score", 0.0)),
                "decision": r.get("recommendation", "APPROVE"),
                "llm_invoked": bool(resp.llm_invoked),
                "flags": high_risk_sigs,
                "source": "block_scanner",
                "rule_id": resp.rule_id,
                "response": resp,
            })
        return results

    async def hunt_dex_pools(
        self,
        blocks: int = 20,
        limit: int = 2,
        w3: Optional[Any] = None,
        dry_run: bool = False,
        engine: Optional[ConditionAgentEngine] = None,
    ) -> List[Dict[str, Any]]:
        """Channel 2: Monitors Aerodrome & Uniswap v3 PoolCreated events on Base Mainnet."""
        if limit <= 0:
            return []

        active_engine = engine or self._get_engine(dry_run=dry_run)

        if dry_run and w3 is None:
            discovered = get_curated_mock_pools()
        else:
            target_w3 = w3 if w3 is not None else AsyncWeb3(AsyncHTTPProvider(self.rpc_url))
            try:
                latest_block = await get_latest_block_number(target_w3)
                from_block = max(0, latest_block - max(1, blocks) + 1)
                discovered = await scan_pool_events(
                    target_w3, from_block=from_block, to_block=latest_block, limit=max(limit * 2, limit)
                )
            except Exception as exc:
                logger.warning(f"[dex_pools] Failed to scan DEX pool events: {exc}")
                return []

        unseen: List[Dict[str, Any]] = []
        for item in discovered:
            tok = item.get("target_token")
            if not tok or not Web3.is_address(tok):
                continue
            chk = Web3.to_checksum_address(tok)
            if self._is_seen(chk.lower()):
                continue
            self._mark_seen(chk.lower())
            unseen.append(item)
            if len(unseen) >= limit:
                break

        if not unseen:
            return []

        audited = await audit_discovered_pools(
            unseen, engine=active_engine, rpc_url=self.rpc_url
        )

        results: List[Dict[str, Any]] = []
        for r in audited:
            resp: FinalAgentResponse = r["response"]
            tok = r["target_token"]
            results.append({
                "channel": "dex_pools",
                "target": tok,
                "target_address": tok,
                "label": f"{r.get('dex', 'DEX')} {r.get('pair', '')}".strip(),
                "risk_score": float(r.get("risk_score", 0.0)),
                "decision": r.get("decision", "APPROVE"),
                "llm_invoked": bool(resp.llm_invoked),
                "flags": list(r.get("honeypot_flags", [])),
                "source": "dex_pool_monitor",
                "rule_id": resp.rule_id,
                "response": resp,
            })
        return results

    async def hunt_geckoterminal_base(
        self,
        limit: int = 3,
        dry_run: bool = False,
        engine: Optional[ConditionAgentEngine] = None,
    ) -> List[Dict[str, Any]]:
        """Channel 3: Queries GeckoTerminal New Pools public API for newly listed Base tokens."""
        if limit <= 0:
            return []

        active_engine = engine or self._get_engine(dry_run=dry_run)

        if dry_run:
            synthetic_items = [
                {
                    "id": "base_0xaa11111111111111111111111111111111111111",
                    "attributes": {"name": "BASECLEAN / WETH", "address": "0xaa11111111111111111111111111111111111111"},
                    "relationships": {
                        "base_token": {"data": {"id": "base_0x9a11111111111111111111111111111111111111"}}
                    },
                    "_mock_bytecode": _BENIGN_ERC20_BYTECODE,
                },
                {
                    "id": "base_0xaa22222222222222222222222222222222222222",
                    "attributes": {"name": "RUGPEPE / USDC", "address": "0xaa22222222222222222222222222222222222222"},
                    "relationships": {
                        "base_token": {"data": {"id": "base_0x9a22222222222222222222222222222222222222"}}
                    },
                    "_mock_bytecode": _HONEYPOT_UPGRADEABLE_BYTECODE,
                },
            ]
            items = synthetic_items[:limit]
        else:
            try:
                payload = await self._http_get_json(
                    GECKOTERMINAL_NEW_POOLS_URL, headers=GECKOTERMINAL_HEADERS
                )
                items = payload.get("data", []) if isinstance(payload, dict) else []
            except Exception as exc:
                logger.warning(f"[geckoterminal_base] API fetch failed: {exc}")
                return []

        results: List[Dict[str, Any]] = []
        for item in items:
            if len(results) >= limit:
                break
            token_addr = _extract_geckoterminal_token_address(item)
            if not token_addr:
                continue

            attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
            pool_name = str(attrs.get("name") or f"Pool {token_addr[:10]}")
            pool_addr = str(attrs.get("address") or "")
            bytecode_override = item.get("_mock_bytecode") if dry_run else None

            audited = await self._audit_discovered_token(
                token_address=token_addr,
                channel="geckoterminal_base",
                source="hunter_geckoterminal",
                source_prefix="hunter-gt",
                label=pool_name,
                active_engine=active_engine,
                bytecode_override=bytecode_override,
                extra_context={"pool_address": pool_addr, "pool_name": pool_name},
            )
            if audited is not None:
                results.append(audited)

        return results

    async def hunt_dexscreener_base(
        self,
        limit: int = 3,
        dry_run: bool = False,
        engine: Optional[ConditionAgentEngine] = None,
    ) -> List[Dict[str, Any]]:
        """Channel 4: Queries DexScreener Latest Token Profiles filtered to Base chain."""
        if limit <= 0:
            return []

        active_engine = engine or self._get_engine(dry_run=dry_run)

        if dry_run:
            raw_items = [
                {
                    "chainId": "solana",
                    "tokenAddress": "So11111111111111111111111111111111111111112",
                    "description": "Filtered non-EVM chain item",
                },
                {
                    "chainId": "base",
                    "tokenAddress": "0x8b11111111111111111111111111111111111111",
                    "header": "SafeBaseToken",
                    "description": "Standard ERC-20 liquidity token on Base",
                    "_mock_bytecode": _BENIGN_ERC20_BYTECODE,
                },
                {
                    "chainId": "base",
                    "tokenAddress": "0x8b22222222222222222222222222222222222222",
                    "header": "HoneypotProxyToken",
                    "description": "Newly boosted Base token with hidden tax/upgrade",
                    "_mock_bytecode": _HONEYPOT_UPGRADEABLE_BYTECODE,
                },
            ]
        else:
            try:
                payload = await self._http_get_json(DEXSCREENER_TOKEN_PROFILES_URL)
                if isinstance(payload, list):
                    raw_items = payload
                elif isinstance(payload, dict):
                    raw_items = payload.get("profiles") or payload.get("data") or []
                else:
                    raw_items = []
            except Exception as exc:
                logger.warning(f"[dexscreener_base] API fetch failed: {exc}")
                return []

        results: List[Dict[str, Any]] = []
        for item in raw_items:
            if len(results) >= limit:
                break
            if not isinstance(item, dict):
                continue
            if str(item.get("chainId", "")).lower() != "base":
                continue

            token_addr = str(item.get("tokenAddress") or "").strip()
            if not Web3.is_address(token_addr):
                continue

            label = str(
                item.get("header")
                or item.get("symbol")
                or item.get("url")
                or f"DexScreener {token_addr[:10]}"
            )
            bytecode_override = item.get("_mock_bytecode") if dry_run else None

            audited = await self._audit_discovered_token(
                token_address=token_addr,
                channel="dexscreener_base",
                source="hunter_dexscreener",
                source_prefix="hunter-ds",
                label=label,
                active_engine=active_engine,
                bytecode_override=bytecode_override,
                extra_context={
                    "dexscreener_url": item.get("url"),
                    "profile_description": item.get("description"),
                },
            )
            if audited is not None:
                results.append(audited)

        return results

    async def hunt_snapshot_daos(
        self,
        limit: int = 2,
        dry_run: bool = False,
        engine: Optional[ConditionAgentEngine] = None,
    ) -> List[Dict[str, Any]]:
        """Channel 5: Fetches Snapshot DAO proposals with on-chain targets and audits them."""
        if limit <= 0:
            return []

        active_engine = engine or self._get_engine(dry_run=dry_run)
        connector = SnapshotGovernanceConnector(default_chain_id=ChainId.BASE_MAINNET)

        if dry_run:
            proposals = get_curated_dao_proposals(
                default_chain_id=ChainId.BASE_MAINNET, limit=max(limit, 3)
            )
        else:
            try:
                proposals = await connector.fetch_proposals(
                    limit=limit, use_curated_fallback=True
                )
            except Exception as exc:
                logger.warning(f"[snapshot_daos] Fetch failed: {exc}")
                return []

        results: List[Dict[str, Any]] = []
        for prop in proposals:
            if len(results) >= limit:
                break
            seen_key = f"snapshot:{prop.proposal_id.lower()}"
            if self._is_seen(seen_key):
                continue
            self._mark_seen(seen_key)

            if dry_run:
                chain_val = (
                    prop.chain_id.value
                    if hasattr(prop.chain_id, "value")
                    else int(prop.chain_id)
                )
                ChainInspector._set_bytecode_cache(
                    f"{chain_val}:{prop.target_address}", _BENIGN_ERC20_BYTECODE
                )

            payload = connector.proposal_to_rule_payload(prop)
            try:
                resp = await active_engine.process_rule(payload, source="hunter_snapshot")
            except Exception as exc:
                logger.error(f"[snapshot_daos] Audit failed for {prop.proposal_id}: {exc}")
                continue

            sem = resp.semantic_Evaluation
            decision = (
                sem.recommended_action
                if sem is not None
                else ("APPROVE" if resp.deterministic_check.passed else "REJECT")
            )
            risk_score = (
                float(sem.risk_score)
                if sem is not None
                else (0.0 if resp.deterministic_check.passed else 10.0)
            )
            flags = list(sem.flagged_issues) if sem else []

            results.append({
                "channel": "snapshot_daos",
                "target": f"{prop.space_id}:{prop.proposal_id}",
                "target_address": prop.target_address,
                "label": prop.title,
                "risk_score": risk_score,
                "decision": decision,
                "llm_invoked": bool(resp.llm_invoked),
                "flags": flags,
                "source": "hunter_snapshot",
                "rule_id": payload.rule_id,
                "response": resp,
                "proposal": prop,
            })

        return results

    async def _dispatch_high_risk_alerts(self, results: List[Dict[str, Any]]) -> int:
        """Safely dispatches webhook alerts for findings with risk_score >= 8.0 or decision == REJECT."""
        if not self.webhook_url:
            return 0

        high_risk_items = [
            r for r in results
            if float(r.get("risk_score", 0.0)) >= 8.0 or r.get("decision") == "REJECT"
        ]
        if not high_risk_items:
            return 0

        sent = 0
        try:
            dispatcher = WebhookAlertDispatcher(
                webhook_url=self.webhook_url,
                public_api_url=self.public_api_url,
                client=self.http_client,
            )
            for item in high_risk_items:
                resp = item.get("response")
                if not isinstance(resp, FinalAgentResponse):
                    continue
                target_addr = item.get("target_address") or "0x0000000000000000000000000000000000000000"
                if not Web3.is_address(str(target_addr)):
                    target_addr = "0x0000000000000000000000000000000000000000"
                proposal = item.get("proposal")
                if not isinstance(proposal, GovernanceProposal):
                    proposal = GovernanceProposal(
                        proposal_id=str(item.get("rule_id") or item.get("target")),
                        space_id=f"hunter:{item.get('channel', 'unknown')}",
                        title=str(item.get("label") or item.get("target")),
                        body=(
                            f"Autonomous discovery alert on channel {item.get('channel')}. "
                            f"Flags: {', '.join(item.get('flags', [])) or 'High risk detected'}."
                        ),
                        author="0x0000000000000000000000000000000000000000",
                        state="active",
                        created=int(time.time()),
                        target_address=Web3.to_checksum_address(target_addr),
                        calldata="0x",
                        tx_value_wei=0,
                        chain_id=ChainId.BASE_MAINNET,
                    )
                report = GovernanceAuditReport(
                    proposal=proposal,
                    rule_id=str(item.get("rule_id") or resp.rule_id),
                    agent_response=resp,
                    alert_level="CRITICAL",
                )
                if await dispatcher.dispatch_alert(report):
                    sent += 1
        except Exception as exc:
            logger.warning(f"Failed to dispatch high-risk webhook alert: {exc}")
        return sent

    async def run_hunt_cycle(
        self,
        channels: Optional[List[str]] = None,
        limit_per_channel: int = 2,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Orchestrates one complete discovery & audit cycle across the selected channels.
        Returns a structured summary dictionary with per-channel breakdowns and flat results.
        """
        selected = list(SUPPORTED_CHANNELS) if channels is None else list(channels)
        for ch in selected:
            if ch not in SUPPORTED_CHANNELS:
                raise ValueError(
                    f"Unsupported discovery channel '{ch}'. Supported: {', '.join(SUPPORTED_CHANNELS)}"
                )

        active_engine = self._get_engine(dry_run=dry_run)

        channel_runners = {
            "base_blocks": lambda: self.hunt_base_blocks(
                blocks=2, limit=limit_per_channel, dry_run=dry_run, engine=active_engine
            ),
            "dex_pools": lambda: self.hunt_dex_pools(
                blocks=20, limit=limit_per_channel, dry_run=dry_run, engine=active_engine
            ),
            "geckoterminal_base": lambda: self.hunt_geckoterminal_base(
                limit=limit_per_channel, dry_run=dry_run, engine=active_engine
            ),
            "dexscreener_base": lambda: self.hunt_dexscreener_base(
                limit=limit_per_channel, dry_run=dry_run, engine=active_engine
            ),
            "snapshot_daos": lambda: self.hunt_snapshot_daos(
                limit=limit_per_channel, dry_run=dry_run, engine=active_engine
            ),
        }

        async def _safe_run(channel_name: str) -> Tuple[str, List[Dict[str, Any]]]:
            try:
                items = await channel_runners[channel_name]()
                return channel_name, items
            except Exception as exc:
                logger.warning(f"[{channel_name}] Channel hunt failed: {exc}")
                return channel_name, []

        channel_outputs = await asyncio.gather(*(_safe_run(ch) for ch in selected))

        by_channel: Dict[str, Dict[str, Any]] = {}
        all_results: List[Dict[str, Any]] = []
        high_risk_count = 0

        for ch, ch_results in channel_outputs:
            ch_high = sum(
                1
                for r in ch_results
                if float(r.get("risk_score", 0.0)) >= 8.0 or r.get("decision") == "REJECT"
            )
            high_risk_count += ch_high
            by_channel[ch] = {
                "discovered": len(ch_results),
                "audited": len(ch_results),
                "high_risk": ch_high,
                "results": ch_results,
            }
            all_results.extend(ch_results)

        if self.webhook_url and high_risk_count > 0:
            await self._dispatch_high_risk_alerts(all_results)

        return {
            "total_discovered": len(all_results),
            "total_audited": len(all_results),
            "high_risk_count": high_risk_count,
            "by_channel": by_channel,
            "results": all_results,
        }
