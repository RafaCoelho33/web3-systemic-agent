"""
Unit and mocked integration test suite for Engine 1: On-Chain Block Scanner (scripts/block_contract_scanner.py).

Validates smart contract deployment detection (tx.to is None), bytecode and selector extraction,
deterministic and semantic risk evaluation pipeline via ConditionAgentEngine, table formatting,
and dry-run CLI execution with zero real network dependency.
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from web3.exceptions import Web3Exception

# Ensure repo root, scripts, and src directories are accessible
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SCRIPTS_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scripts.block_contract_scanner import (
    CHAIN_ID_BASE_MAINNET,
    DEFAULT_BASE_RPC,
    KNOWN_SELECTORS,
    audit_discovered_contracts,
    create_deployment_rule_payload,
    create_mock_w3,
    extract_selectors_from_bytecode,
    is_high_risk_signature,
    main,
    parse_args,
    print_scan_table,
    run_continuous_scanner,
    run_scanner,
    scan_recent_blocks,
)
from src.engine import ConditionAgentEngine
from src.schemas import (
    ChainId,
    ConditionRulePayload,
    FinalAgentResponse,
)
from src.semantic_evaluator import MockSemanticEvaluator
from src.storage import AgentStorage


# ============================================================================
# 1. Mandatory Core Tests
# ============================================================================


@pytest.mark.asyncio
async def test_scan_recent_blocks_detects_contract_creation():
    """
    Mandatory Test 1:
    Mocks a block containing a transaction with to=None and a receipt with contractAddress.
    Validates correct contract extraction, metadata parsing, and block traversal.
    """
    mock_w3 = MagicMock()
    mock_w3.eth.block_number = AsyncMock(return_value=100)

    contract_addr = "0x1111111111111111111111111111111111111111"
    tx_hash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

    mock_tx = {
        "hash": tx_hash,
        "from": "0xDeployer000000000000000000000000000000001",
        "to": None,  # EVM contract deployment marker
        "input": "0x6080604052348015",
    }
    mock_block = {
        "number": 100,
        "transactions": [mock_tx],
    }
    mock_receipt = {
        "contractAddress": contract_addr,
        "status": 1,
    }
    mock_bytecode = bytes.fromhex("608060405234801561001057600080fd5b508063f2fde38b14")

    mock_w3.eth.get_block = AsyncMock(return_value=mock_block)
    mock_w3.eth.get_transaction_receipt = AsyncMock(return_value=mock_receipt)
    mock_w3.eth.get_code = AsyncMock(return_value=mock_bytecode)

    discovered = await scan_recent_blocks(mock_w3, num_blocks=1, limit=5)

    assert len(discovered) == 1
    item = discovered[0]
    assert item["block_number"] == 100
    assert item["tx_hash"] == tx_hash
    assert item["contract_address"].lower() == contract_addr.lower()
    assert item["deployer"] == "0xDeployer000000000000000000000000000000001"
    assert item["bytecode"] == mock_bytecode
    assert item["tx_input"] == "0x6080604052348015"


@pytest.mark.asyncio
async def test_scan_recent_blocks_ignores_standard_transfers():
    """
    Mandatory Test 2:
    Mocks standard EOA-to-EOA or call transactions (to != None) and validates that
    they are filtered out and not treated as contract creations.
    """
    mock_w3 = MagicMock()
    mock_w3.eth.block_number = AsyncMock(return_value=100)

    mock_tx_standard = {
        "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "from": "0xSender0000000000000000000000000000000001",
        "to": "0xReceiver000000000000000000000000000000002",  # Not None
        "input": "0x",
    }
    mock_block = {
        "number": 100,
        "transactions": [mock_tx_standard],
    }

    mock_w3.eth.get_block = AsyncMock(return_value=mock_block)
    mock_w3.eth.get_transaction_receipt = AsyncMock()
    mock_w3.eth.get_code = AsyncMock()

    discovered = await scan_recent_blocks(mock_w3, num_blocks=1, limit=5)

    assert len(discovered) == 0
    # Must never query receipts or bytecode for standard non-deployment transactions
    mock_w3.eth.get_transaction_receipt.assert_not_called()
    mock_w3.eth.get_code.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("empty_code", ["0x", "0x0", b"", b"\x00", None])
async def test_scan_recent_blocks_with_empty_bytecode_skipped(empty_code):
    """
    Mandatory Test 3:
    Mocks contract creation whose deployed bytecode returns empty/zero.
    Validates that such transactions are safely skipped.
    """
    mock_w3 = MagicMock()
    mock_w3.eth.block_number = AsyncMock(return_value=100)

    mock_tx = {
        "hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "from": "0xDeployer000000000000000000000000000000001",
        "to": None,
        "input": "0x60806040",
    }
    mock_block = {
        "number": 100,
        "transactions": [mock_tx],
    }
    mock_receipt = {
        "contractAddress": "0x2222222222222222222222222222222222222222",
        "status": 1,
    }

    mock_w3.eth.get_block = AsyncMock(return_value=mock_block)
    mock_w3.eth.get_transaction_receipt = AsyncMock(return_value=mock_receipt)
    mock_w3.eth.get_code = AsyncMock(return_value=empty_code)

    discovered = await scan_recent_blocks(mock_w3, num_blocks=1, limit=5)

    assert len(discovered) == 0


@pytest.mark.asyncio
async def test_scan_and_audit_flow_with_engine(tmp_path):
    """
    Mandatory Test 4:
    Validates that a discovered contract is evaluated through ConditionAgentEngine,
    producing a FinalAgentResponse and persisting evaluation records in AgentStorage.
    """
    db_file = str(tmp_path / "test_scanner_audit.db")
    storage = AgentStorage(db_path=db_file)
    evaluator = MockSemanticEvaluator()
    engine = ConditionAgentEngine(
        rpc_url=DEFAULT_BASE_RPC,
        semantic_evaluator=evaluator,
        storage=storage,
    )

    contract_address = "0x4444444444444444444444444444444444444444"
    bytecode = bytes.fromhex(
        "608060405234801561001057600080fd5b50"
        "8063f2fde38b1461003057"  # transferOwnership
        "806340c10f191461005057"  # mint
        "600080fd"
    )
    discovered = [
        {
            "block_number": 23419500,
            "tx_hash": "0xaaa4444444444444444444444444444444444444444444444444444444444444",
            "contract_address": contract_address,
            "deployer": "0xDeployer000000000000000000000000000000001",
            "bytecode": bytecode,
            "tx_input": "0x60806040",
        }
    ]

    results = await audit_discovered_contracts(discovered, engine)

    assert len(results) == 1
    r = results[0]
    assert r["block_number"] == 23419500
    assert r["contract_address"] == contract_address
    assert isinstance(r["response"], FinalAgentResponse)
    assert r["response"].deterministic_check.passed is True
    assert r["recommendation"] in ("APPROVE", "REJECT", "MANUAL_REVIEW")
    assert isinstance(r["risk_score"], float)

    # Validate function selectors extracted
    selector_hexes = [s["selector"] for s in r["selectors"]]
    assert "0xf2fde38b" in selector_hexes
    assert "0x40c10f19" in selector_hexes

    # Validate persistence to SQLite AgentStorage
    records = await storage.get_evaluations(rule_id=r["payload"].rule_id)
    assert len(records) >= 1
    assert records[0]["rule_id"] == r["payload"].rule_id
    assert records[0]["source"] == "block_scanner"
    assert records[0]["stage1_passed"] == 1


def test_print_scan_table_output(capsys):
    """
    Mandatory Test 5:
    Validates that print_scan_table renders a properly formatted ASCII table
    with headers for Bloco, Tx Hash, Endereço do Contrato, Seletores, Recomendação, Score de Risco.
    """
    results = [
        {
            "block_number": 23419500,
            "tx_hash": "0xaaa1111111111111111111111111111111111111111111111111111111111111",
            "contract_address": "0x1111111111111111111111111111111111111111",
            "selectors": [
                {"selector": "0xf2fde38b", "signature": "transferOwnership(address)", "known": True},
                {"selector": "0x83197ef0", "signature": "destroy(address)", "known": True},
            ],
            "recommendation": "REJECT",
            "risk_score": 9.5,
        },
        {
            "block_number": 23419501,
            "tx_hash": "0xbbb2222222222222222222222222222222222222222222222222222222222222",
            "contract_address": "0x2222222222222222222222222222222222222222",
            "selectors": [
                {"selector": "0xa9059cbb", "signature": "transfer(address,uint256)", "known": True},
            ],
            "recommendation": "APPROVE",
            "risk_score": 1.0,
        },
    ]

    print_scan_table(results)
    captured = capsys.readouterr().out

    # Header presence
    assert "Bloco" in captured
    assert "Tx Hash" in captured
    assert "Endereço do Contrato" in captured
    assert "Seletores Encontrados" in captured
    assert "Recomendação" in captured
    assert "Score de Risco" in captured

    # Value presence
    assert "23419500" in captured
    assert "0x1111111111111111111111111111111111111111" in captured
    assert "transferOwnership" in captured
    assert "REJECT" in captured
    assert "9.5" in captured
    assert "23419501" in captured
    assert "APPROVE" in captured
    assert "1.0" in captured

    # Test empty results formatting branch
    print_scan_table([])
    empty_captured = capsys.readouterr().out
    assert "Nenhum contrato detectado" in empty_captured


def test_cli_dry_run_execution(monkeypatch, tmp_path):
    """
    Mandatory Test 6:
    Executes main() with the --dry-run CLI argument, validating that it finishes
    with code 0 without making external network calls or raising unhandled exceptions.
    """
    db_file = str(tmp_path / "cli_dry_run.db")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "block_contract_scanner.py",
            "--dry-run",
            "--blocks",
            "2",
            "--limit",
            "3",
        ],
    )

    with patch("scripts.block_contract_scanner.AgentStorage") as mock_storage_cls:
        test_storage = AgentStorage(db_path=db_file)
        mock_storage_cls.return_value = test_storage

        # main() must execute cleanly with zero exit code / no uncaught exception
        main()

        assert os.path.exists(db_file)


# ============================================================================
# 2. Auxiliary Edge-Case and Resiliency Tests
# ============================================================================


@pytest.mark.asyncio
async def test_scan_recent_blocks_respects_limit():
    """Validates that scan_recent_blocks stops immediately when the limit is reached."""
    mock_w3 = MagicMock()
    mock_w3.eth.block_number = AsyncMock(return_value=200)

    txs = [
        {"hash": f"0x{i:064x}", "from": "0xDeployer", "to": None, "input": "0x6080"}
        for i in range(1, 6)
    ]
    mock_block = {"number": 200, "transactions": txs}

    mock_w3.eth.get_block = AsyncMock(return_value=mock_block)
    mock_w3.eth.get_transaction_receipt = AsyncMock(
        side_effect=lambda h: {"contractAddress": f"0x{int(str(h), 16):040x}", "status": 1}
    )
    mock_w3.eth.get_code = AsyncMock(return_value=b"\x60\x80\x60\x40")

    # Request limit of 2 when 5 are available in the block
    discovered = await scan_recent_blocks(mock_w3, num_blocks=1, limit=2)

    assert len(discovered) == 2


@pytest.mark.asyncio
async def test_scan_recent_blocks_handles_receipt_exception():
    """Validates that receipt retrieval failures are caught gracefully without breaking the loop."""
    mock_w3 = MagicMock()
    mock_w3.eth.block_number = AsyncMock(return_value=100)

    mock_tx_failing = {"hash": "0xfail", "from": "0xDeployer", "to": None, "input": "0x6080"}
    mock_tx_success = {"hash": "0xsucc", "from": "0xDeployer", "to": None, "input": "0x6080"}

    mock_block = {"number": 100, "transactions": [mock_tx_failing, mock_tx_success]}
    mock_w3.eth.get_block = AsyncMock(return_value=mock_block)

    async def _receipt_side_effect(tx_h):
        if tx_h == "0xfail":
            raise Web3Exception("RPC timeout fetching receipt")
        return {"contractAddress": "0x5555555555555555555555555555555555555555", "status": 1}

    mock_w3.eth.get_transaction_receipt = AsyncMock(side_effect=_receipt_side_effect)
    mock_w3.eth.get_code = AsyncMock(return_value=b"\x60\x80\x60\x40")

    discovered = await scan_recent_blocks(mock_w3, num_blocks=1, limit=5)

    assert len(discovered) == 1
    assert discovered[0]["tx_hash"] == "0xsucc"


@pytest.mark.asyncio
async def test_scan_recent_blocks_handles_get_block_exception():
    """Validates that block retrieval errors do not abort the entire multi-block scan."""
    mock_w3 = MagicMock()
    mock_w3.eth.block_number = AsyncMock(return_value=101)

    async def _block_side_effect(b_num, full_transactions=True):
        if b_num == 101:
            raise Web3Exception("Block 101 not yet propagated")
        return {
            "number": 100,
            "transactions": [
                {"hash": "0x100a", "from": "0xDeployer", "to": None, "input": "0x6080"}
            ],
        }

    mock_w3.eth.get_block = AsyncMock(side_effect=_block_side_effect)
    mock_w3.eth.get_transaction_receipt = AsyncMock(
        return_value={"contractAddress": "0x6666666666666666666666666666666666666666", "status": 1}
    )
    mock_w3.eth.get_code = AsyncMock(return_value=b"\x60\x80\x60\x40")

    discovered = await scan_recent_blocks(mock_w3, num_blocks=2, limit=5)

    assert len(discovered) == 1
    assert discovered[0]["block_number"] == 100


@pytest.mark.asyncio
async def test_scan_recent_blocks_zero_or_negative_inputs():
    """Validates that non-positive limits or block counts return an empty list immediately."""
    mock_w3 = MagicMock()
    assert await scan_recent_blocks(mock_w3, num_blocks=0) == []
    assert await scan_recent_blocks(mock_w3, num_blocks=5, limit=0) == []
    assert await scan_recent_blocks(mock_w3, num_blocks=-1, limit=-1) == []


def test_extract_selectors_from_bytecode():
    """Validates selector extraction from direct bytecode, EVM dispatchers, and init calldata."""
    # 1. Direct bytecode containing transferOwnership (0xf2fde38b) and destroy (0x83197ef0)
    bytecode_hex = "60806040528063f2fde38b1461002057806383197ef01461004057"
    selectors = extract_selectors_from_bytecode(bytecode_hex)
    sel_map = {s["selector"]: s["signature"] for s in selectors}

    assert "0xf2fde38b" in sel_map
    assert sel_map["0xf2fde38b"] == "transferOwnership(address)"
    assert "0x83197ef0" in sel_map
    assert sel_map["0x83197ef0"] == "destroy(address)"

    # 2. Extract from deployment initialization calldata (tx_input)
    init_input = "0x60806040a9059cbb000000"  # Contains transfer (0xa9059cbb)
    selectors_with_input = extract_selectors_from_bytecode("0x60806040", tx_input=init_input)
    sel_input_map = {s["selector"]: s["signature"] for s in selectors_with_input}
    assert "0xa9059cbb" in sel_input_map
    assert sel_input_map["0xa9059cbb"] == "transfer(address,uint256)"


def test_is_high_risk_signature():
    """Validates classification of high-risk function signatures."""
    assert is_high_risk_signature("transferOwnership(address)") is True
    assert is_high_risk_signature("destroy(address)") is True
    assert is_high_risk_signature("selfdestruct()") is True
    assert is_high_risk_signature("kill()") is True
    assert is_high_risk_signature("mint(address,uint256)") is True
    assert is_high_risk_signature("pause()") is True
    assert is_high_risk_signature("upgradeTo(address)") is True

    # Standard benign methods
    assert is_high_risk_signature("transfer(address,uint256)") is False
    assert is_high_risk_signature("approve(address,uint256)") is False
    assert is_high_risk_signature("balanceOf(address)") is False


def test_create_deployment_rule_payload():
    """Validates ConditionRulePayload generation with proper checksums and metadata."""
    selectors = [
        {"selector": "0xf2fde38b", "signature": "transferOwnership(address)", "known": True},
        {"selector": "0x40c10f19", "signature": "mint(address,uint256)", "known": True},
    ]
    raw_addr = "0x7777777777777777777777777777777777777777"
    payload = create_deployment_rule_payload(
        contract_address=raw_addr,
        tx_hash="0xhash123",
        block_number=123456,
        deployer="0xDeployer123",
        selectors=selectors,
        bytecode_length=512,
    )

    assert isinstance(payload, ConditionRulePayload)
    assert payload.chain_id == ChainId.BASE_MAINNET
    assert payload.deterministic.target_address == "0x7777777777777777777777777777777777777777"
    assert payload.deterministic.min_value_wei == 0
    assert payload.semantic.enabled is True
    assert payload.context_metadata["contract_address"] == "0x7777777777777777777777777777777777777777"
    assert "0xf2fde38b" in payload.context_metadata["selectors_found"]
    assert "CRITICAL" in payload.context_metadata["proposal_description"]


@pytest.mark.asyncio
async def test_create_mock_w3():
    """Validates that create_mock_w3 simulates Base Mainnet blocks and code queries correctly."""
    mock_w3 = create_mock_w3()
    assert await mock_w3.is_connected() is True

    block_num = await mock_w3.eth.block_number
    assert block_num == 23419501

    block = await mock_w3.eth.get_block(23419500)
    assert len(block["transactions"]) == 2

    receipt = await mock_w3.eth.get_transaction_receipt(
        "0xaaa1111111111111111111111111111111111111111111111111111111111111"
    )
    assert receipt["contractAddress"] == "0x1111111111111111111111111111111111111111"

    code = await mock_w3.eth.get_code("0x1111111111111111111111111111111111111111")
    assert len(code) > 0


@pytest.mark.asyncio
async def test_run_scanner_dry_run_returns_audited_results(tmp_path):
    """Validates end-to-end execution of run_scanner in dry_run mode."""
    db_file = str(tmp_path / "dry_run_test.db")
    storage = AgentStorage(db_path=db_file)

    results = await run_scanner(
        blocks=2,
        limit=5,
        dry_run=True,
        storage=storage,
    )

    assert len(results) > 0
    for r in results:
        assert r["block_number"] in (23419500, 23419501)
        assert r["contract_address"].startswith("0x")
        assert r["recommendation"] in ("APPROVE", "REJECT", "MANUAL_REVIEW")
        assert isinstance(r["response"], FinalAgentResponse)

    # Confirm evaluations were persisted
    persisted = await storage.get_evaluations(rule_id=results[0]["payload"].rule_id)
    assert len(persisted) >= 1


@pytest.mark.asyncio
async def test_run_continuous_scanner_single_iteration():
    """Validates that continuous mode executes cleanly and exits when max_iterations is reached."""
    mock_w3 = create_mock_w3()
    storage = AgentStorage(db_path=":memory:")
    evaluator = MockSemanticEvaluator()
    engine = ConditionAgentEngine(
        rpc_url=DEFAULT_BASE_RPC,
        semantic_evaluator=evaluator,
        storage=storage,
    )

    # Should run exactly 1 iteration and return cleanly without infinite loop
    await run_continuous_scanner(
        w3=mock_w3,
        engine=engine,
        limit=2,
        poll_interval=0.01,
        max_iterations=1,
    )


def test_parse_args_options():
    """Validates CLI argument parsing defaults and overrides."""
    args_default = parse_args([])
    assert args_default.blocks == 5
    assert args_default.limit == 10
    assert args_default.dry_run is False
    assert args_default.continuous is False
    assert args_default.rpc_url is None

    args_custom = parse_args(
        ["--blocks", "20", "--limit", "3", "--dry-run", "--continuous", "--rpc-url", "https://custom.rpc"]
    )
    assert args_custom.blocks == 20
    assert args_custom.limit == 3
    assert args_custom.dry_run is True
    assert args_custom.continuous is True
    assert args_custom.rpc_url == "https://custom.rpc"


# ============================================================================
# Stage 1 LLM Gatekeeping & High Risk Filtering Tests
# ============================================================================


def test_create_deployment_rule_payload_require_high_risk_for_llm():
    """
    Validates Stage 1 LLM gatekeeping:
    - When selectors only contains benign ERC-20 selectors (transfer, approve, balanceOf)
      and require_high_risk_for_llm=True, verify payload.semantic.enabled is False.
    - When selectors contains transferOwnership(address) and require_high_risk_for_llm=True,
      verify payload.semantic.enabled is True.
    """
    benign_selectors = [
        {"selector": "0xa9059cbb", "signature": "transfer(address,uint256)"},
        {"selector": "0x095ea7b3", "signature": "approve(address,uint256)"},
        {"selector": "0x70a08231", "signature": "balanceOf(address)"},
    ]

    payload_benign = create_deployment_rule_payload(
        contract_address="0x1111111111111111111111111111111111111111",
        tx_hash="0x" + "11" * 32,
        block_number=1000,
        deployer="0x2222222222222222222222222222222222222222",
        selectors=benign_selectors,
        bytecode_length=200,
        require_high_risk_for_llm=True,
    )
    assert payload_benign.semantic.enabled is False

    high_risk_selectors = [
        {"selector": "0xa9059cbb", "signature": "transfer(address,uint256)"},
        {"selector": "0xf2fde38b", "signature": "transferOwnership(address)"},
    ]
    payload_high_risk = create_deployment_rule_payload(
        contract_address="0x1111111111111111111111111111111111111111",
        tx_hash="0x" + "22" * 32,
        block_number=1001,
        deployer="0x2222222222222222222222222222222222222222",
        selectors=high_risk_selectors,
        bytecode_length=350,
        require_high_risk_for_llm=True,
    )
    assert payload_high_risk.semantic.enabled is True


@pytest.mark.asyncio
async def test_audit_discovered_contracts_skips_llm_for_benign_when_high_risk_required(tmp_path):
    """
    Validates that audit_discovered_contracts skips LLM evaluation (llm_invoked=False)
    for benign contracts when require_high_risk_for_llm=True, recommends APPROVE,
    and produces exactly 1 storage record without duplicate writes.
    """
    db_file = str(tmp_path / "benign_audit.db")
    storage = AgentStorage(db_path=db_file)
    evaluator = MockSemanticEvaluator()
    engine = ConditionAgentEngine(
        rpc_url=DEFAULT_BASE_RPC,
        semantic_evaluator=evaluator,
        storage=storage,
    )

    # Benign bytecode containing only the transfer selector (0xa9059cbb)
    benign_bytecode = bytes.fromhex("608060405234801561001057600080fd5b508063a9059cbb14")
    contract_addr = "0x3333333333333333333333333333333333333333"

    discovered = [
        {
            "block_number": 23419500,
            "tx_hash": "0x" + "33" * 32,
            "contract_address": contract_addr,
            "deployer": "0x4444444444444444444444444444444444444444",
            "bytecode": benign_bytecode,
            "tx_input": "0x",
        }
    ]

    results = await audit_discovered_contracts(
        contracts=discovered,
        engine=engine,
        require_high_risk_for_llm=True,
    )

    assert len(results) == 1
    resp = results[0]["response"]
    assert isinstance(resp, FinalAgentResponse)
    assert resp.llm_invoked is False
    assert results[0]["recommendation"] == "APPROVE"

    persisted = await storage.get_evaluations(rule_id=results[0]["payload"].rule_id)
    assert len(persisted) == 1

