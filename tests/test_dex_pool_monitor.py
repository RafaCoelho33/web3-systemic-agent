"""
Unit and mocked integration test suite for Engine 3: DEX Liquidity Pool Monitor & Honeypot Auditor
(scripts/dex_pool_monitor.py).

Validates:
1. PoolCreated event log scanning for Aerodrome Finance and Uniswap v3 on Base Mainnet.
2. Topic and data parameter decoding (token0, token1, pool address, stable, fee, tickSpacing).
3. Target token identification against canonical Base collateral (WETH, USDC, USDbC, cbBTC).
4. Static EVM bytecode honeypot and risk selector detection (blacklist, fee trap, trading pause, selfdestruct).
5. Two-stage deterministic and semantic risk evaluation pipeline via ConditionAgentEngine.
6. SQLite AgentStorage persistence with source="dex_pool_monitor".
7. Webhook alert formatting and dispatching.
8. ASCII table formatting.
9. Dry-run CLI execution with zero network dependency.
"""

import argparse
import asyncio
import os
import sys
import warnings
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from web3 import Web3
from web3.exceptions import Web3Exception

warnings.filterwarnings("ignore", category=ResourceWarning)
warnings.filterwarnings("ignore", category=pytest.PytestUnraisableExceptionWarning)

pytestmark = [
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]

# Ensure workspace paths are present in sys.path
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SCRIPTS_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scripts.dex_pool_monitor import (
    AERODROME_FACTORY_ADDRESS,
    AERODROME_POOL_CREATED_TOPIC0,
    BASE_TOKENS,
    CHAIN_ID_BASE_MAINNET,
    DEFAULT_BASE_RPC,
    HONEYPOT_SELECTORS,
    STANDARD_ERC20_SELECTORS,
    UNISWAP_V3_FACTORY_ADDRESS,
    UNISWAP_V3_POOL_CREATED_TOPIC0,
    DexSemanticEvaluator,
    DexWebhookAlertDispatcher,
    analyze_bytecode_honeypot,
    audit_discovered_pools,
    create_dex_pool_rule_payload,
    create_mock_w3,
    decode_address_from_topic,
    decode_aerodrome_pool_data,
    decode_univ3_pool_data,
    extract_selectors_from_bytecode,
    get_curated_mock_pools,
    identify_target_token,
    main,
    parse_args,
    print_dex_table,
    run_continuous_monitor,
    run_dex_monitor,
    scan_pool_events,
)
from src.engine import ConditionAgentEngine
from src.schemas import (
    ChainId,
    ConditionRulePayload,
    DeterministicResult,
    FinalAgentResponse,
    SemanticAuditResult,
)
from src.semantic_evaluator import MockSemanticEvaluator
from src.storage import AgentStorage


# ============================================================================
# 1. Mandatory Core Tests
# ============================================================================


@pytest.mark.asyncio
async def test_scan_pool_events_aerodrome():
    """
    Mandatory Test 1:
    Mocks Aerodrome PoolCreated event logs with token0 (WETH) and token1 (new token).
    Validates accurate token extraction, target token identification, pool address decoding,
    and bytecode retrieval without real network calls.
    """
    mock_w3 = MagicMock()
    mock_w3.is_connected = AsyncMock(return_value=True)

    weth_addr = "0x4200000000000000000000000000000000000006"
    new_token_addr = "0x1234567890123456789012345678901234567890"
    pool_addr = "0xAe99999999999999999999999999999999999999"
    tx_hash = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"

    # Aerodrome ABI encoding:
    # topics[0] = Topic0
    # topics[1] = token0 (WETH, padded to 32 bytes)
    # topics[2] = token1 (new token, padded to 32 bytes)
    # data = (bool stable: word 0, address pool: word 1, uint256 index: word 2)
    t0_padded = "0x" + "0" * 24 + weth_addr[2:].lower()
    t1_padded = "0x" + "0" * 24 + new_token_addr[2:].lower()

    stable_word = "0" * 63 + "1"  # stable = True
    pool_word = "0" * 24 + pool_addr[2:].lower()
    index_word = "0" * 64
    log_data = "0x" + stable_word + pool_word + index_word

    aero_log = {
        "address": AERODROME_FACTORY_ADDRESS,
        "topics": [AERODROME_POOL_CREATED_TOPIC0, t0_padded, t1_padded],
        "data": log_data,
        "blockNumber": 21050010,
        "transactionHash": tx_hash,
        "logIndex": 0,
    }

    async def mock_get_logs(filter_params):
        if filter_params.get("address").lower() == AERODROME_FACTORY_ADDRESS.lower():
            return [aero_log]
        return []

    mock_w3.eth.get_logs = AsyncMock(side_effect=mock_get_logs)
    mock_bytecode = bytes.fromhex("608060405234801561001057600080fd5b508063a9059cbb14")
    mock_w3.eth.get_code = AsyncMock(return_value=mock_bytecode)

    discovered = await scan_pool_events(mock_w3, from_block=21050000, to_block=21050020, limit=5)

    assert len(discovered) == 1
    p = discovered[0]
    assert p["dex"] == "Aerodrome"
    assert p["block_number"] == 21050010
    assert p["tx_hash"] == tx_hash
    assert p["token0"].lower() == weth_addr.lower()
    assert p["token1"].lower() == new_token_addr.lower()
    assert p["target_token"].lower() == new_token_addr.lower()
    assert p["base_token"].lower() == weth_addr.lower()
    assert p["pool_address"].lower() == pool_addr.lower()
    assert p["extra_meta"]["stable"] is True
    assert p["bytecode"] == mock_bytecode


@pytest.mark.asyncio
async def test_scan_pool_events_uniswap_v3():
    """
    Mandatory Test 2:
    Mocks Uniswap v3 PoolCreated event logs and validates topic decoding,
    fee/tickSpacing parameter extraction, target token vs base token identification.
    """
    mock_w3 = MagicMock()
    mock_w3.is_connected = AsyncMock(return_value=True)

    usdc_addr = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    target_token_addr = "0x9876543210987654321098765432109876543210"
    pool_addr = "0xBb88888888888888888888888888888888888888"
    tx_hash = "0x9999999999999999999999999999999999999999999999999999999999999999"

    # Uniswap v3:
    # topics[0] = Topic0
    # topics[1] = token0 (target_token, padded to 32 bytes)
    # topics[2] = token1 (USDC, padded to 32 bytes)
    # data = (uint24 fee: word 0, int24 tickSpacing: word 1, address pool: word 2)
    t0_padded = "0x" + "0" * 24 + target_token_addr[2:].lower()
    t1_padded = "0x" + "0" * 24 + usdc_addr[2:].lower()

    fee_word = hex(3000)[2:].zfill(64)
    tick_spacing_word = hex(60)[2:].zfill(64)
    pool_word = "0" * 24 + pool_addr[2:].lower()
    log_data = "0x" + fee_word + tick_spacing_word + pool_word

    uni_log = {
        "address": UNISWAP_V3_FACTORY_ADDRESS,
        "topics": [UNISWAP_V3_POOL_CREATED_TOPIC0, t0_padded, t1_padded],
        "data": log_data,
        "blockNumber": 21050050,
        "transactionHash": tx_hash,
        "logIndex": 1,
    }

    async def mock_get_logs(filter_params):
        if filter_params.get("address").lower() == UNISWAP_V3_FACTORY_ADDRESS.lower():
            return [uni_log]
        return []

    mock_w3.eth.get_logs = AsyncMock(side_effect=mock_get_logs)
    mock_bytecode = bytes.fromhex("608060405280631e3dd19f14")  # setTax selector
    mock_w3.eth.get_code = AsyncMock(return_value=mock_bytecode)

    discovered = await scan_pool_events(mock_w3, from_block=21050040, to_block=21050060, limit=5)

    assert len(discovered) == 1
    p = discovered[0]
    assert p["dex"] == "Uniswap v3"
    assert p["block_number"] == 21050050
    assert p["tx_hash"] == tx_hash
    assert p["token0"].lower() == target_token_addr.lower()
    assert p["token1"].lower() == usdc_addr.lower()
    assert p["target_token"].lower() == target_token_addr.lower()
    assert p["base_token"].lower() == usdc_addr.lower()
    assert p["pool_address"].lower() == pool_addr.lower()
    assert p["extra_meta"]["fee"] == 3000
    assert p["extra_meta"]["tick_spacing"] == 60
    assert p["bytecode"] == mock_bytecode


def test_target_token_detection_against_base_assets():
    """
    Mandatory Test 3:
    Validates that the monitor correctly identifies which of the two tokens is the unverified
    new asset to be audited and which is the canonical collateral (WETH, USDC, USDbC, cbBTC).
    """
    weth = "0x4200000000000000000000000000000000000006"
    usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    usdbc = "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"
    cbbtc = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"
    new_token_a = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    new_token_b = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

    # Case 1: token0 is WETH, token1 is new token -> target is token1
    target, base, pair = identify_target_token(weth, new_token_a)
    assert target.lower() == new_token_a.lower()
    assert base.lower() == weth.lower()
    assert "WETH" in pair

    # Case 2: token0 is new token, token1 is USDC -> target is token0
    target, base, pair = identify_target_token(new_token_a, usdc)
    assert target.lower() == new_token_a.lower()
    assert base.lower() == usdc.lower()
    assert "USDC" in pair

    # Case 3: token0 is cbBTC, token1 is new token -> target is token1
    target, base, pair = identify_target_token(cbbtc, new_token_b)
    assert target.lower() == new_token_b.lower()
    assert base.lower() == cbbtc.lower()
    assert "cbBTC" in pair

    # Case 4: token0 is new token, token1 is USDbC -> target is token0
    target, base, pair = identify_target_token(new_token_b, usdbc)
    assert target.lower() == new_token_b.lower()
    assert base.lower() == usdbc.lower()
    assert "USDbC" in pair

    # Case 5: Both tokens are canonical base assets (e.g., WETH / USDC)
    target, base, pair = identify_target_token(weth, usdc)
    assert target.lower() == usdc.lower()
    assert base.lower() == weth.lower()
    assert "WETH/USDC" in pair

    # Case 6: Both tokens are unverified new assets
    target, base, pair = identify_target_token(new_token_a, new_token_b)
    assert target.lower() == new_token_a.lower()
    assert base.lower() == new_token_b.lower()


def test_honeypot_signature_detection():
    """
    Mandatory Test 4:
    Validates detection of honeypot risk selectors across all critical categories:
    - Blacklist (0xf9f02b01, 0x40af1275)
    - Fee trap / Arbitrary tax (0x1e3dd19f, 0x4b7890ec, 0x8a92d475)
    - Trading pause / freeze (0x34468f9b, 0x4fbee1e3)
    - Destruction / drain (0x00f714ce, 0x41c0e1b5, opcode 0xff)
    - Clean standard ERC-20 token
    """
    # 1. Blacklist token bytecode
    bl_bytecode = bytes.fromhex("6080604052806340af127514610020578063f9f02b0114")
    bl_analysis = analyze_bytecode_honeypot(bl_bytecode)
    assert bl_analysis["is_honeypot"] is True
    assert bl_analysis["severity"] == "CRITICAL"
    assert "Blacklist" in bl_analysis["summary_display"]
    assert len(bl_analysis["categories"]["blacklist"]) >= 1

    # 2. Fee / 100% Tax trap bytecode
    tax_bytecode = bytes.fromhex("608060405280631e3dd19f146100205780634b7890ec14")
    tax_analysis = analyze_bytecode_honeypot(tax_bytecode)
    assert tax_analysis["is_honeypot"] is True
    assert "Arbitrary Tax" in tax_analysis["summary_display"]
    assert len(tax_analysis["categories"]["fee_tax"]) >= 1

    # 3. Trading pause / lockup bytecode
    pause_bytecode = bytes.fromhex("6080604052806334468f9b146100205780634fbee1e314")
    pause_analysis = analyze_bytecode_honeypot(pause_bytecode)
    assert pause_analysis["is_honeypot"] is True
    assert "Trading Pause" in pause_analysis["summary_display"]
    assert len(pause_analysis["categories"]["pause_trading"]) >= 1

    # 4. Selfdestruct opcode / kill bytecode
    kill_bytecode = bytes.fromhex("6080604052806341c0e1b51461002057ff")
    kill_analysis = analyze_bytecode_honeypot(kill_bytecode)
    assert kill_analysis["is_honeypot"] is True
    assert kill_analysis["severity"] == "CRITICAL"
    assert "Selfdestruct" in kill_analysis["summary_display"]
    assert len(kill_analysis["categories"]["destruct_drain"]) >= 1

    # 5. Clean Standard ERC-20 token bytecode (transfer, balanceOf, approve)
    clean_bytecode = bytes.fromhex("60806040528063a9059cbb1461002057806370a0823114610040578063095ea7b314")
    clean_analysis = analyze_bytecode_honeypot(clean_bytecode)
    assert clean_analysis["is_honeypot"] is False
    assert clean_analysis["severity"] == "CLEAN"
    assert clean_analysis["summary_display"] == "CLEAN"
    assert len(clean_analysis["honeypot_flags"]) == 0


@pytest.mark.asyncio
async def test_audit_pool_tokens_flow(tmp_path):
    """
    Mandatory Test 5:
    Validates complete two-stage audit execution through ConditionAgentEngine
    and persistence into SQLite AgentStorage.
    """
    db_file = str(tmp_path / "test_dex_audit_flow.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    evaluator = DexSemanticEvaluator()
    engine = ConditionAgentEngine(
        rpc_url=DEFAULT_BASE_RPC,
        semantic_evaluator=evaluator,
        storage=storage,
    )

    clean_target = Web3.to_checksum_address("0x1111111111111111111111111111111111111111")
    honeypot_target = Web3.to_checksum_address("0x2222222222222222222222222222222222222222")
    weth = Web3.to_checksum_address("0x4200000000000000000000000000000000000006")

    clean_code = bytes.fromhex("60806040528063a9059cbb1461002057806370a0823114")
    honeypot_code = bytes.fromhex("6080604052806340af1275146100205780631e3dd19f14")  # blacklist + tax

    pools = [
        {
            "dex": "Aerodrome",
            "block_number": 21050100,
            "tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "pool_address": Web3.to_checksum_address("0xAe11111111111111111111111111111111111111"),
            "token0": clean_target,
            "token1": weth,
            "target_token": clean_target,
            "base_token": weth,
            "pair_name": "CLEAN/WETH",
            "bytecode": clean_code,
            "extra_meta": {"stable": False},
        },
        {
            "dex": "Uniswap v3",
            "block_number": 21050105,
            "tx_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "pool_address": Web3.to_checksum_address("0xBb22222222222222222222222222222222222222"),
            "token0": honeypot_target,
            "token1": weth,
            "target_token": honeypot_target,
            "base_token": weth,
            "pair_name": "HONEY/WETH",
            "bytecode": honeypot_code,
            "extra_meta": {"fee": 3000, "tick_spacing": 60},
        },
    ]

    results = await audit_discovered_pools(pools, engine=engine)

    assert len(results) == 2

    # Clean pool verification
    clean_res = results[0]
    assert clean_res["target_token"] == clean_target
    assert clean_res["decision"] == "APPROVE"
    assert clean_res["risk_score"] < 7.0
    assert clean_res["risk_honeypot"] == "CLEAN"

    # Honeypot pool verification
    honey_res = results[1]
    assert honey_res["target_token"] == honeypot_target
    assert honey_res["decision"] == "REJECT"
    assert honey_res["risk_score"] >= 8.5
    assert "Blacklist" in honey_res["risk_honeypot"] or "Arbitrary Tax" in honey_res["risk_honeypot"]

    # Verify SQLite AgentStorage persistence
    records = await storage.get_evaluations(limit=10)
    assert len(records) >= 2
    rule_ids = [r["rule_id"] for r in records]
    assert clean_res["payload"].rule_id in rule_ids
    assert honey_res["payload"].rule_id in rule_ids
    assert any(r.get("source") == "dex_pool_monitor" for r in records)


def test_print_dex_scan_table(capsys):
    """
    Mandatory Test 6:
    Validates rendering of the formatted ASCII table in the terminal with expected columns.
    """
    results = [
        {
            "dex": "Aerodrome",
            "block_number": 21050100,
            "pair": "TEST/WETH",
            "target_token": "0x1111111111111111111111111111111111111111",
            "risk_honeypot": "CLEAN",
            "decision": "APPROVE",
            "risk_score": 2.0,
        },
        {
            "dex": "Uniswap v3",
            "block_number": 21050102,
            "pair": "SCAM/USDC",
            "target_token": "0x2222222222222222222222222222222222222222",
            "risk_honeypot": "Blacklist, Arbitrary Tax",
            "decision": "REJECT",
            "risk_score": 9.5,
        },
    ]

    print_dex_table(results)
    captured = capsys.readouterr().out

    assert "DEX" in captured
    assert "Bloco" in captured
    assert "Par / Pool" in captured
    assert "Token Alvo" in captured
    assert "Risco / Honeypot" in captured
    assert "Decisão" in captured
    assert "Score" in captured
    assert "Aerodrome" in captured
    assert "Uniswap v3" in captured
    assert "TEST/WETH" in captured
    assert "SCAM/USDC" in captured
    assert "APPROVE" in captured
    assert "REJECT" in captured

    # Test empty table handling
    print_dex_table([])
    captured_empty = capsys.readouterr().out
    assert "No DEX liquidity pool events detected" in captured_empty


def test_cli_dry_run_execution():
    """
    Mandatory Test 7:
    Executes main() in dry-run simulation mode and verifies clean zero-exit status.
    """
    test_args = [
        "dex_pool_monitor.py",
        "--dry-run",
        "--limit",
        "2",
        "--blocks",
        "50",
    ]
    with patch.object(sys, "argv", test_args):
        # main() should run without raising SystemExit(non-zero) or Unhandled Exception
        try:
            main()
        except SystemExit as exc:
            assert exc.code in (0, None)


# ============================================================================
# 2. Complementary Unit & Edge Case Tests
# ============================================================================


def test_decode_address_from_topic_variations():
    """Validates topic address decoding across hex strings, raw bytes, and casing."""
    raw_addr = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    checksummed = Web3.to_checksum_address(raw_addr)

    # 1. 32-byte hex string with 0x prefix
    topic_hex = "0x" + "0" * 24 + raw_addr[2:].lower()
    assert decode_address_from_topic(topic_hex) == checksummed

    # 2. 32-byte hex string without 0x prefix
    assert decode_address_from_topic(topic_hex[2:]) == checksummed

    # 3. 32 bytes binary
    topic_bytes = bytes.fromhex(topic_hex[2:])
    assert decode_address_from_topic(topic_bytes) == checksummed


def test_decode_aerodrome_pool_data_edge_cases():
    """Validates Aerodrome data decoding for stable pool, volatile pool, and short buffer."""
    pool_addr = Web3.to_checksum_address("0xae11111111111111111111111111111111111111")
    pool_padded = "0" * 24 + pool_addr[2:].lower()

    # Stable = True
    data_stable = "0x" + "0" * 63 + "1" + pool_padded + "0" * 64
    addr, stable = decode_aerodrome_pool_data(data_stable)
    assert addr == pool_addr
    assert stable is True

    # Stable = False
    data_volatile = "0x" + "0" * 64 + pool_padded + "0" * 64
    addr, stable = decode_aerodrome_pool_data(data_volatile)
    assert addr == pool_addr
    assert stable is False

    # Short data fallback
    addr_short, stable_short = decode_aerodrome_pool_data("0x1234")
    assert addr_short == "0x0000000000000000000000000000000000000000"
    assert stable_short is False


def test_decode_univ3_pool_data_edge_cases():
    """Validates Uniswap v3 fee, tickSpacing (including negative values), and short buffer."""
    pool_addr = Web3.to_checksum_address("0xbb22222222222222222222222222222222222222")
    pool_padded = "0" * 24 + pool_addr[2:].lower()

    fee = 10000
    fee_hex = hex(fee)[2:].zfill(64)

    # Positive tick spacing = 200
    tick_pos = 200
    tick_hex_pos = hex(tick_pos)[2:].zfill(64)
    data_pos = "0x" + fee_hex + tick_hex_pos + pool_padded

    p_addr, p_fee, p_tick = decode_univ3_pool_data(data_pos)
    assert p_addr == pool_addr
    assert p_fee == 10000
    assert p_tick == 200

    # Negative tick spacing = -60
    tick_neg = -60
    tick_bytes_neg = (tick_neg).to_bytes(32, byteorder="big", signed=True)
    data_neg = "0x" + fee_hex + tick_bytes_neg.hex() + pool_padded

    p_addr2, p_fee2, p_tick2 = decode_univ3_pool_data(data_neg)
    assert p_addr2 == pool_addr
    assert p_fee2 == 10000
    assert p_tick2 == -60

    # Short data fallback
    p_short, f_short, t_short = decode_univ3_pool_data("0x")
    assert p_short == "0x0000000000000000000000000000000000000000"
    assert f_short == 3000
    assert t_short == 60


def test_extract_selectors_from_bytecode_dispatcher_and_direct():
    """Validates selector extraction from both standard PUSH4 dispatchers and known signatures."""
    # Bytecode with EVM dispatcher pattern: PUSH4 0xa9059cbb EQ
    dispatcher_code = "608060405234801561001057600080fd5b508063a9059cbb1461002057806370a0823114"
    selectors = extract_selectors_from_bytecode(dispatcher_code)

    sel_hexes = [s["selector"] for s in selectors]
    assert "0xa9059cbb" in sel_hexes
    assert "0x70a08231" in sel_hexes

    # Known signature mapping
    sig_map = {s["selector"]: s["signature"] for s in selectors}
    assert sig_map["0xa9059cbb"] == "transfer(address,uint256)"
    assert sig_map["0x70a08231"] == "balanceOf(address)"


@pytest.mark.asyncio
async def test_dex_webhook_alert_dispatcher():
    """Validates webhook alert payload construction and HTTP dispatch behavior."""
    dispatcher = DexWebhookAlertDispatcher(webhook_url="https://example.com/webhook")

    sample_res = {
        "dex": "Aerodrome",
        "pair": "SCAM/WETH",
        "pool_address": "0x1234567890123456789012345678901234567890",
        "target_token": "0x9999999999999999999999999999999999999999",
        "risk_honeypot": "Blacklist, Arbitrary Tax",
        "decision": "REJECT",
        "risk_score": 9.8,
        "block_number": 21050099,
    }

    payload = dispatcher.format_alert_payload(sample_res)
    assert "🚨 **DEX LIQUIDITY POOL SECURITY AUDIT [REJECT]** 🚨" in payload["content"]
    assert len(payload["embeds"]) == 1
    assert payload["embeds"][0]["color"] == 0xFF0000

    # Test HTTP dispatch with mock client
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.post = AsyncMock(return_value=mock_post_resp)
        mock_client_cls.return_value = mock_client

        success = await dispatcher.dispatch_alert(sample_res)
        assert success is True
        mock_client.post.assert_called_once()

    # Test when webhook_url is None
    dispatcher_none = DexWebhookAlertDispatcher(webhook_url=None)
    assert await dispatcher_none.dispatch_alert(sample_res) is False


@pytest.mark.asyncio
async def test_scan_pool_events_edge_cases():
    """Validates boundary handling when from_block > to_block, limit <= 0, or RPC errors."""
    mock_w3 = MagicMock()

    # Inverted block range
    assert await scan_pool_events(mock_w3, from_block=100, to_block=50) == []

    # Limit <= 0
    assert await scan_pool_events(mock_w3, from_block=50, to_block=100, limit=0) == []

    # RPC Exception handling
    mock_w3.eth.get_logs = AsyncMock(side_effect=Web3Exception("RPC node unavailable"))
    res = await scan_pool_events(mock_w3, from_block=100, to_block=105, limit=5)
    assert res == []


def test_create_dex_pool_rule_payload_structure():
    """Validates schema conformance and metadata structure of create_dex_pool_rule_payload."""
    pool_item = {
        "dex": "Aerodrome",
        "block_number": 21050100,
        "tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "pool_address": "0xae11111111111111111111111111111111111111",
        "target_token": "0x1234567890123456789012345678901234567890",
        "base_token": "0x4200000000000000000000000000000000000006",
        "pair_name": "TEST/WETH",
        "bytecode": b"\x60\x80\x60\x40",
    }
    analysis = {
        "selectors": [{"selector": "0x40af1275", "signature": "setBlacklist(address,bool)"}],
        "honeypot_flags": ["Blacklist: setBlacklist(address,bool) (0x40af1275)"],
        "is_honeypot": True,
        "summary_display": "Blacklist",
    }

    payload = create_dex_pool_rule_payload(pool_item, analysis)

    assert isinstance(payload, ConditionRulePayload)
    assert payload.chain_id == ChainId.BASE_MAINNET
    assert payload.deterministic.target_address == Web3.to_checksum_address(pool_item["target_token"])
    assert payload.semantic.enabled is True
    assert payload.semantic.risk_threshold == 7.0
    assert payload.context_metadata["dex"] == "Aerodrome"
    assert payload.context_metadata["is_honeypot_suspect"] is True


def test_curated_mock_pools_structure():
    """Validates the 5 synthetic mock pool profiles in get_curated_mock_pools()."""
    pools = get_curated_mock_pools()
    assert len(pools) == 5

    dexes = {p["dex"] for p in pools}
    assert "Aerodrome" in dexes
    assert "Uniswap v3" in dexes

    for p in pools:
        assert Web3.is_checksum_address(p["pool_address"])
        assert Web3.is_checksum_address(p["token0"])
        assert Web3.is_checksum_address(p["token1"])
        assert Web3.is_checksum_address(p["target_token"])
        assert Web3.is_checksum_address(p["base_token"])
        assert isinstance(p["bytecode"], bytes)
        assert len(p["bytecode"]) > 0


@pytest.mark.asyncio
async def test_create_mock_w3_simulation():
    """Validates that create_mock_w3 provides functional mock eth_getLogs and eth_getCode."""
    mock_w3 = create_mock_w3()
    assert await mock_w3.is_connected() is True
    assert await mock_w3.eth.block_number > 21050100

    # Query Aerodrome logs
    aero_logs = await mock_w3.eth.get_logs({
        "address": AERODROME_FACTORY_ADDRESS,
        "topics": [AERODROME_POOL_CREATED_TOPIC0],
    })
    assert len(aero_logs) == 2  # 2 Aerodrome pools in curated set

    # Query Uniswap v3 logs
    uni_logs = await mock_w3.eth.get_logs({
        "address": UNISWAP_V3_FACTORY_ADDRESS,
        "topics": [UNISWAP_V3_POOL_CREATED_TOPIC0],
    })
    assert len(uni_logs) == 3  # 3 Uniswap v3 pools in curated set

    # Query bytecode for curated token
    code = await mock_w3.eth.get_code("0x1111111111111111111111111111111111111111")
    assert len(code) > 0


@pytest.mark.asyncio
async def test_run_dex_monitor_dry_run_flow(tmp_path):
    """Validates run_dex_monitor execution in dry-run mode with isolated SQLite DB."""
    db_file = str(tmp_path / "test_run_dry_run.db")
    args = argparse.Namespace(
        dry_run=True,
        limit=3,
        blocks=100,
        db_path=db_file,
        rpc_url=DEFAULT_BASE_RPC,
        webhook_url=None,
    )

    results = await run_dex_monitor(args)
    assert len(results) == 3
    for r in results:
        assert r["dex"] in ("Aerodrome", "Uniswap v3")
        assert r["decision"] in ("APPROVE", "REJECT", "MANUAL_REVIEW")


@pytest.mark.asyncio
async def test_run_dex_monitor_live_mocked_flow(tmp_path):
    """Validates run_dex_monitor execution through the live RPC branch using a mock web3 instance."""
    db_file = str(tmp_path / "test_run_live.db")
    mock_w3 = create_mock_w3()

    args = argparse.Namespace(
        dry_run=False,
        limit=2,
        blocks=50,
        db_path=db_file,
        rpc_url="https://mainnet.base.org",
        webhook_url=None,
    )

    with patch("scripts.dex_pool_monitor.AsyncWeb3", return_value=mock_w3):
        results = await run_dex_monitor(args)
        assert len(results) == 2


@pytest.mark.asyncio
async def test_run_continuous_monitor_cancelled():
    """Validates that run_continuous_monitor exits cleanly when CancelledError is raised."""
    args = argparse.Namespace(
        poll_interval=0,
        blocks=10,
        rpc_url=DEFAULT_BASE_RPC,
        dry_run=True,
    )

    mock_w3 = MagicMock()
    mock_w3.eth.block_number = AsyncMock(side_effect=asyncio.CancelledError)

    with patch("scripts.dex_pool_monitor.AsyncWeb3", return_value=mock_w3):
        # Should catch CancelledError and terminate gracefully
        await run_continuous_monitor(args)


def test_parse_args_defaults_and_overrides():
    """Validates argument parsing defaults and custom CLI options."""
    # Defaults
    args = parse_args([])
    assert args.blocks == 100
    assert args.limit == 5
    assert args.continuous is False
    assert args.poll_interval == 15
    assert args.dry_run is False
    assert args.rpc_url is None
    assert args.webhook_url is None

    # Custom flags
    custom = parse_args([
        "--blocks", "250",
        "--limit", "10",
        "--continuous",
        "--poll-interval", "30",
        "--dry-run",
        "--rpc-url", "https://custom.base.org",
        "--webhook-url", "https://discord.com/webhook",
        "--db-path", "data/custom.db",
    ])
    assert custom.blocks == 250
    assert custom.limit == 10
    assert custom.continuous is True
    assert custom.poll_interval == 30
    assert custom.dry_run is True
    assert custom.rpc_url == "https://custom.base.org"
    assert custom.webhook_url == "https://discord.com/webhook"
    assert custom.db_path == "data/custom.db"


@pytest.mark.asyncio
async def test_audit_discovered_pools_resilience_to_engine_error(tmp_path):
    """Validates that audit_discovered_pools skips a failing pool and continues auditing others."""
    db_file = str(tmp_path / "test_resilience.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    mock_engine = MagicMock(spec=ConditionAgentEngine)
    mock_engine.storage = storage

    # First call fails, second succeeds
    clean_target = Web3.to_checksum_address("0x1111111111111111111111111111111111111111")
    weth = Web3.to_checksum_address("0x4200000000000000000000000000000000000006")

    response_success = FinalAgentResponse(
        rule_id="dex-pool-0x11111111",
        chain_id=ChainId.BASE_MAINNET.value,
        deterministic_check=DeterministicResult(
            passed=True, reason="ok", observed_data={}
        ),
        llm_invoked=True,
        semantic_Evaluation=SemanticAuditResult(
            conditions_met=True,
            risk_score=2.0,
            flagged_issues=[],
            summary="Clean",
            recommended_action="APPROVE",
        ),
    )

    mock_engine.process_rule = AsyncMock(
        side_effect=[Exception("RPC connection timeout"), response_success]
    )

    pools = [
        {
            "dex": "Aerodrome",
            "block_number": 100,
            "tx_hash": "0x1",
            "pool_address": "0xae11111111111111111111111111111111111111",
            "token0": clean_target,
            "token1": weth,
            "target_token": clean_target,
            "base_token": weth,
            "pair_name": "FAIL/WETH",
            "bytecode": b"\x60",
            "extra_meta": {},
        },
        {
            "dex": "Aerodrome",
            "block_number": 101,
            "tx_hash": "0x2",
            "pool_address": "0xae22222222222222222222222222222222222222",
            "token0": clean_target,
            "token1": weth,
            "target_token": clean_target,
            "base_token": weth,
            "pair_name": "PASS/WETH",
            "bytecode": b"\x60",
            "extra_meta": {},
        },
    ]

    results = await audit_discovered_pools(pools, engine=mock_engine)

    assert len(results) == 1
    assert results[0]["pair"] == "PASS/WETH"
