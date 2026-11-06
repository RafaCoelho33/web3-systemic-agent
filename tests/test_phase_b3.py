"""
Comprehensive Unit & Edge-Case Test Suite for Phase B3 (x402 Protocol Integration - A2A).
Tests every section of the Phase B3 Specification Contract:
1. requirements.txt contains x402 and preserves existing dependencies.
2. Schemas: PaymentReceipt validation & FinalAgentResponse.payment optional field.
3. Storage: SQLite payments ledger (record_payment, is_payment_settled, get_payments, get_summary_metrics).
4. x402 Module: constants, X402Config env overrides, usdc_to_atomic, parse_x402_header, MockX402Facilitator, build_402_response.
5. FastAPI Integration:
   - Free Mode (X402_ENABLED=false): /evaluate, /rules/enqueue, /rules/evaluate-batch work free without payment header.
   - Paid Mode (X402_ENABLED=true):
     * Free routes accessible without payment header (/health, /rules/validate, /metrics/summary, /logs/errors, /jobs/{id}, /payments).
     * /health includes x402_enabled, x402_network, price_per_eval_usdc.
     * Paid routes missing payment header return HTTP 402 with X-PAYMENT-REQUIRED and exact maxAmountRequired.
     * Request schema validation (422) and oversized batch (422) take precedence BEFORE charging.
     * Insufficient payment amounts return HTTP 402 without settling.
     * Valid payments settle once, attach receipt with tx_hash, set X-PAYMENT-RESPONSE header, and persist in SQLite.
     * Base64 encoded headers and PAYMENT-SIGNATURE header support.
     * Replay attack prevention: reusing same payment_id returns HTTP 402 and never settles twice.
     * Settlement failure handling: returns HTTP 402, logs error to storage, does not persist payment.
     * CRITICAL No-Charge-on-Error Rule: Stage 1 RPC failures or unhandled engine exceptions return HTTP 503
       with payment_settled: False, log error, and NEVER call facilitator.settle (0 charges).
     * Diagnostics endpoint GET /payments with filtering and limits.
     * CORS headers include x402 headers.
6. Report CLI: format_report_text includes total_payments_settled, total_revenue_usdc, and net_profit_usd.
"""

import asyncio
import base64
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from web3 import Web3

# -----------------------------------------------------------------------------
# Module Setup & Path Resolution (matching project conventions)
# -----------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(ROOT_DIR) in ("src", "tests"):
    ROOT_DIR = os.path.abspath(os.path.join(ROOT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")

for p in (ROOT_DIR, SRC_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import src.schemas as schemas_module
    import src.storage as storage_module
    import src.x402_payment as x402_module
    import src.api as api_module
    import src.report as report_module

    sys.modules.setdefault("schemas", schemas_module)
    sys.modules.setdefault("storage", storage_module)
    sys.modules.setdefault("x402_payment", x402_module)
    sys.modules.setdefault("api", api_module)
    sys.modules.setdefault("report", report_module)
except ImportError:
    import schemas as schemas_module
    import storage as storage_module
    import x402_payment as x402_module
    import api as api_module
    import report as report_module

    sys.modules.setdefault("src.schemas", schemas_module)
    sys.modules.setdefault("src.storage", storage_module)
    sys.modules.setdefault("src.x402_payment", x402_module)
    sys.modules.setdefault("src.api", api_module)
    sys.modules.setdefault("src.report", report_module)

from schemas import (
    ChainId,
    DeterministicCondition,
    SemanticCondition,
    ConditionRulePayload,
    DeterministicResult,
    FinalAgentResponse,
    PaymentReceipt,
)
from storage import AgentStorage
from x402_payment import (
    DEFAULT_X402_PRICE_USDC,
    DEFAULT_X402_NETWORK,
    DEFAULT_PAY_TO_ADDRESS,
    DEFAULT_FACILITATOR_URL,
    BASE_SEPOLIA_USDC,
    BASE_MAINNET_USDC,
    USDC_DECIMALS,
    X402Config,
    MockX402Facilitator,
    usdc_to_atomic,
    parse_x402_header,
    build_402_response,
)
from api import create_app
from report import format_report_text


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def clean_x402_env(monkeypatch):
    """Guarantees x402 and API key environment variables are clean between tests."""
    vars_to_clean = [
        "X402_ENABLED",
        "X402_PRICE_EVALUATE",
        "X402_NETWORK",
        "PAY_TO_ADDRESS",
        "FACILITATOR_URL",
        "X402_ASSET",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
    ]
    for var in vars_to_clean:
        monkeypatch.delenv(var, raising=False)
    yield
    for var in vars_to_clean:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def base_payload() -> ConditionRulePayload:
    return ConditionRulePayload(
        rule_id="b3-test-rule-001",
        chain_id=ChainId.BASE_SEPOLIA,
        deterministic=DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            min_value_wei=1000000000000000000,
            required_function_selectors=["0xf2fde38b"],
            check_native_balance=False,
        ),
        semantic=SemanticCondition(
            enabled=True,
            policy_prompt="Audit DAO administrative operations.",
            risk_threshold=7.0,
        ),
        context_metadata={
            "tx_value_wei": 2000000000000000000,
            "calldata": "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "proposal_description": "Administrative update for review.",
        },
    )


@pytest.fixture
def sample_payment_receipt() -> PaymentReceipt:
    return PaymentReceipt(
        payment_id="pay-test-receipt-001",
        payer_address="0x4200000000000000000000000000000000000006",
        pay_to_address="0x0000000000000000000000000000000000000001",
        amount_usdc=0.01,
        amount_atomic=10000,
        network="eip155:84532",
        asset="USDC",
        tx_hash="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        endpoint="/evaluate",
        settled_at="2026-11-04T12:00:00Z",
    )


def make_valid_payment_header(
    payment_id: str = "pay-001",
    payer_address: str = "0x4200000000000000000000000000000000000006",
    amount_atomic: int = 10000,
    network: str = "eip155:84532",
    signature: str = "0x" + "aa" * 65,
    as_base64: bool = False,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    payload = {
        "payment_id": payment_id,
        "payer_address": payer_address,
        "amount_atomic": amount_atomic,
        "network": network,
        "signature": signature,
    }
    if extra:
        payload.update(extra)
    raw_json = json.dumps(payload)
    if as_base64:
        return base64.b64encode(raw_json.encode()).decode()
    return raw_json


# =============================================================================
# 1. Requirements Contract Tests
# =============================================================================
class TestSection1Requirements:
    def test_requirements_contains_x402(self):
        """Contract 1: requirements.txt must list x402>=2.0.0 (or equivalent)."""
        req_path = Path(ROOT_DIR) / "requirements.txt"
        assert req_path.exists(), f"requirements.txt not found at {req_path}"
        lines = [line.strip() for line in req_path.read_text(encoding="utf-8").splitlines()]
        x402_lines = [l for l in lines if l and not l.startswith("#") and "x402" in l.lower()]
        assert len(x402_lines) >= 1, "Missing x402 dependency in requirements.txt"
        assert any("x402" in l for l in x402_lines)

    def test_requirements_preserves_existing_dependencies(self):
        """Contract 1: requirements.txt preserves runtime deps, requirements-dev.txt contains test deps and references requirements.txt."""
        req_path = Path(ROOT_DIR) / "requirements.txt"
        assert req_path.exists()
        content = req_path.read_text(encoding="utf-8").lower()
        for expected in ["web3", "pydantic", "fastapi", "uvicorn", "httpx", "aiosqlite"]:
            assert expected in content, f"Pre-existing runtime dependency '{expected}' was removed from requirements.txt"

        dev_req_path = Path(ROOT_DIR) / "requirements-dev.txt"
        assert dev_req_path.exists(), "requirements-dev.txt not found"
        dev_content = dev_req_path.read_text(encoding="utf-8").lower()
        assert "-r requirements.txt" in dev_content, "requirements-dev.txt must reference -r requirements.txt"
        for dev_expected in ["pytest", "pytest-asyncio"]:
            assert dev_expected in dev_content, f"Dev dependency '{dev_expected}' missing from requirements-dev.txt"


# =============================================================================
# 2. Schemas Contract Tests
# =============================================================================
class TestSection2Schemas:
    def test_payment_receipt_valid_instantiation(self):
        """Contract 2: PaymentReceipt validates all required fields correctly."""
        receipt = PaymentReceipt(
            payment_id="pay-valid-001",
            payer_address="0x4200000000000000000000000000000000000006",
            pay_to_address="0x0000000000000000000000000000000000000001",
            amount_usdc=0.01,
            amount_atomic=10000,
            tx_hash="0x" + "ff" * 32,
            endpoint="/evaluate",
            settled_at="2026-11-04T12:00:00Z",
        )
        assert receipt.payment_id == "pay-valid-001"
        assert receipt.payer_address == "0x4200000000000000000000000000000000000006"
        assert receipt.amount_usdc == 0.01
        assert receipt.amount_atomic == 10000
        assert receipt.network == "eip155:84532"  # default
        assert receipt.asset == "USDC"  # default
        assert receipt.tx_hash == "0x" + "ff" * 32
        assert receipt.endpoint == "/evaluate"

    def test_payment_receipt_defaults(self):
        """Contract 2: PaymentReceipt network and asset fields have standard defaults."""
        receipt = PaymentReceipt(
            payment_id="pay-defaults",
            payer_address="0x4200000000000000000000000000000000000006",
            pay_to_address="0x0000000000000000000000000000000000000001",
            amount_usdc=0.02,
            amount_atomic=20000,
            tx_hash="0x" + "01" * 32,
            endpoint="/rules/enqueue",
            settled_at="2026-11-04T12:00:00Z",
        )
        assert receipt.network == "eip155:84532"
        assert receipt.asset == "USDC"

    def test_payment_receipt_amount_validation(self):
        """Contract 2: PaymentReceipt rejects negative amounts for amount_usdc and amount_atomic."""
        # Negative amount_usdc
        with pytest.raises(ValidationError):
            PaymentReceipt(
                payment_id="pay-neg-1",
                payer_address="0x4200000000000000000000000000000000000006",
                pay_to_address="0x0000000000000000000000000000000000000001",
                amount_usdc=-0.01,
                amount_atomic=10000,
                tx_hash="0x" + "02" * 32,
                endpoint="/evaluate",
                settled_at="2026-11-04T12:00:00Z",
            )
        # Negative amount_atomic
        with pytest.raises(ValidationError):
            PaymentReceipt(
                payment_id="pay-neg-2",
                payer_address="0x4200000000000000000000000000000000000006",
                pay_to_address="0x0000000000000000000000000000000000000001",
                amount_usdc=0.01,
                amount_atomic=-5,
                tx_hash="0x" + "02" * 32,
                endpoint="/evaluate",
                settled_at="2026-11-04T12:00:00Z",
            )

    def test_payment_receipt_missing_required_fields(self):
        """Contract 2: PaymentReceipt fails validation if required fields are missing."""
        # Missing tx_hash
        with pytest.raises(ValidationError):
            PaymentReceipt(
                payment_id="pay-missing-tx",
                payer_address="0x4200000000000000000000000000000000000006",
                pay_to_address="0x0000000000000000000000000000000000000001",
                amount_usdc=0.01,
                amount_atomic=10000,
                endpoint="/evaluate",
                settled_at="2026-11-04T12:00:00Z",
            )
        # Missing payer_address
        with pytest.raises(ValidationError):
            PaymentReceipt(
                payment_id="pay-missing-payer",
                pay_to_address="0x0000000000000000000000000000000000000001",
                amount_usdc=0.01,
                amount_atomic=10000,
                tx_hash="0x" + "03" * 32,
                endpoint="/evaluate",
                settled_at="2026-11-04T12:00:00Z",
            )

    def test_final_agent_response_payment_field_default_none(self):
        """Contract 2: FinalAgentResponse.payment defaults to None for backward compatibility."""
        resp = FinalAgentResponse(
            rule_id="r1",
            chain_id=84532,
            deterministic_check=DeterministicResult(passed=True, reason="ok"),
            llm_invoked=False,
        )
        assert resp.payment is None
        assert "payment" in FinalAgentResponse.model_fields

    def test_final_agent_response_payment_field_with_receipt(self, sample_payment_receipt):
        """Contract 2: FinalAgentResponse correctly holds a PaymentReceipt."""
        resp = FinalAgentResponse(
            rule_id="r1",
            chain_id=84532,
            deterministic_check=DeterministicResult(passed=True, reason="ok"),
            llm_invoked=False,
            payment=sample_payment_receipt,
        )
        assert resp.payment is not None
        assert resp.payment.payment_id == sample_payment_receipt.payment_id
        assert resp.payment.amount_usdc == 0.01

    def test_final_agent_response_serialization_with_and_without_payment(self, sample_payment_receipt):
        """Contract 2: FinalAgentResponse serializes to JSON / dict cleanly with or without payment."""
        resp_no_pay = FinalAgentResponse(
            rule_id="r-no-pay",
            chain_id=84532,
            deterministic_check=DeterministicResult(passed=False, reason="halt"),
            llm_invoked=False,
        )
        dumped_no_pay = resp_no_pay.model_dump()
        assert dumped_no_pay["payment"] is None

        resp_with_pay = FinalAgentResponse(
            rule_id="r-with-pay",
            chain_id=84532,
            deterministic_check=DeterministicResult(passed=True, reason="ok"),
            llm_invoked=False,
            payment=sample_payment_receipt,
        )
        dumped_with_pay = resp_with_pay.model_dump()
        assert dumped_with_pay["payment"]["payment_id"] == sample_payment_receipt.payment_id
        assert dumped_with_pay["payment"]["tx_hash"] == sample_payment_receipt.tx_hash
        json_str = resp_with_pay.model_dump_json()
        assert sample_payment_receipt.payment_id in json_str


# =============================================================================
# 3. SQLite Storage Contract Tests (AgentStorage)
# =============================================================================
class TestSection3StoragePayments:
    @pytest.mark.asyncio
    async def test_storage_initialize_creates_payments_table_and_indexes(self, tmp_path):
        """Contract 3: AgentStorage.initialize creates the payments table and its indexes."""
        db_file = tmp_path / "test_init.db"
        storage = AgentStorage(db_path=str(db_file))
        await storage.initialize()

        import aiosqlite
        async with aiosqlite.connect(str(db_file)) as db:
            cursor = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='payments'"
            )
            table = await cursor.fetchone()
            assert table is not None, "Table 'payments' was not created"

            cursor = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_payments_%'"
            )
            indexes = [row[0] for row in await cursor.fetchall()]
            assert "idx_payments_payer" in indexes
            assert "idx_payments_created_at" in indexes

    @pytest.mark.asyncio
    async def test_storage_record_payment_and_idempotency(self, tmp_path, sample_payment_receipt):
        """Contract 3: record_payment persists payment receipt, returns row id, and handles duplicate payment_id safely."""
        db_file = tmp_path / "test_rec.db"
        storage = AgentStorage(db_path=str(db_file))
        await storage.initialize()

        # First record
        row_id = await storage.record_payment(sample_payment_receipt)
        assert row_id is not None
        assert row_id > 0

        # Idempotency / duplicate check: recording duplicate payment_id returns None, never crashes
        dup_result = await storage.record_payment(sample_payment_receipt)
        assert dup_result is None

        # Verify only 1 row exists
        payments = await storage.get_payments(limit=10)
        assert len(payments) == 1
        assert payments[0]["payment_id"] == sample_payment_receipt.payment_id
        assert payments[0]["amount_usdc"] == sample_payment_receipt.amount_usdc
        assert payments[0]["amount_atomic"] == sample_payment_receipt.amount_atomic
        assert payments[0]["status"] == "SETTLED"

    @pytest.mark.asyncio
    async def test_storage_record_payment_optional_rule_and_job_id(self, tmp_path, sample_payment_receipt):
        """Contract 3: record_payment properly stores optional rule_id and job_id."""
        db_file = tmp_path / "test_opt.db"
        storage = AgentStorage(db_path=str(db_file))
        await storage.initialize()

        row_id = await storage.record_payment(
            sample_payment_receipt,
            rule_id="test-rule-xyz",
            job_id="job-12345",
            status="SETTLED",
        )
        assert row_id is not None
        payments = await storage.get_payments(limit=1)
        assert payments[0]["rule_id"] == "test-rule-xyz"
        assert payments[0]["job_id"] == "job-12345"

    @pytest.mark.asyncio
    async def test_storage_is_payment_settled(self, tmp_path, sample_payment_receipt):
        """Contract 3: is_payment_settled correctly detects unsettled and settled payments."""
        db_file = tmp_path / "test_settled.db"
        storage = AgentStorage(db_path=str(db_file))
        await storage.initialize()

        # Before insertion
        settled_before = await storage.is_payment_settled(sample_payment_receipt.payment_id)
        assert settled_before is False

        # After insertion
        await storage.record_payment(sample_payment_receipt)
        settled_after = await storage.is_payment_settled(sample_payment_receipt.payment_id)
        assert settled_after is True

    @pytest.mark.asyncio
    async def test_storage_get_payments_ordering_and_limit(self, tmp_path):
        """Contract 3: get_payments returns records ordered by id DESC and respects limit."""
        db_file = tmp_path / "test_order.db"
        storage = AgentStorage(db_path=str(db_file))
        await storage.initialize()

        for i in range(1, 6):
            receipt = PaymentReceipt(
                payment_id=f"pay-seq-{i}",
                payer_address="0x4200000000000000000000000000000000000006",
                pay_to_address="0x0000000000000000000000000000000000000001",
                amount_usdc=0.01 * i,
                amount_atomic=10000 * i,
                tx_hash=f"0x{i:064x}",
                endpoint="/evaluate",
                settled_at=f"2026-11-04T12:0{i}:00Z",
            )
            await storage.record_payment(receipt)

        # Limit 3
        payments = await storage.get_payments(limit=3)
        assert len(payments) == 3
        # Ordering check: highest id first
        assert payments[0]["payment_id"] == "pay-seq-5"
        assert payments[1]["payment_id"] == "pay-seq-4"
        assert payments[2]["payment_id"] == "pay-seq-3"

    @pytest.mark.asyncio
    async def test_storage_get_payments_filter_by_payer(self, tmp_path):
        """Contract 3: get_payments filters by payer_address accurately."""
        db_file = tmp_path / "test_filter.db"
        storage = AgentStorage(db_path=str(db_file))
        await storage.initialize()

        payer_a = "0x4200000000000000000000000000000000000006"
        payer_b = "0x1111111111111111111111111111111111111111"

        r_a = PaymentReceipt(
            payment_id="pay-payer-a",
            payer_address=payer_a,
            pay_to_address="0x0000000000000000000000000000000000000001",
            amount_usdc=0.01,
            amount_atomic=10000,
            tx_hash="0x" + "a1" * 32,
            endpoint="/evaluate",
            settled_at="2026-11-04T12:00:00Z",
        )
        r_b = PaymentReceipt(
            payment_id="pay-payer-b",
            payer_address=payer_b,
            pay_to_address="0x0000000000000000000000000000000000000001",
            amount_usdc=0.05,
            amount_atomic=50000,
            tx_hash="0x" + "b1" * 32,
            endpoint="/evaluate",
            settled_at="2026-11-04T12:01:00Z",
        )
        await storage.record_payment(r_a)
        await storage.record_payment(r_b)

        # Filter by payer_a
        res_a = await storage.get_payments(payer_address=payer_a)
        assert len(res_a) == 1
        assert res_a[0]["payment_id"] == "pay-payer-a"

        # Filter by payer_b
        res_b = await storage.get_payments(payer_address=payer_b)
        assert len(res_b) == 1
        assert res_b[0]["payment_id"] == "pay-payer-b"

        # Filter by non-existent payer
        res_none = await storage.get_payments(payer_address="0x9999999999999999999999999999999999999999")
        assert len(res_none) == 0

    @pytest.mark.asyncio
    async def test_storage_get_summary_metrics_with_zero_payments(self, tmp_path):
        """Contract 3: get_summary_metrics returns 0 payment metrics when table is empty."""
        db_file = tmp_path / "test_sum_zero.db"
        storage = AgentStorage(db_path=str(db_file))
        await storage.initialize()

        metrics = await storage.get_summary_metrics(target_price_usd=0.01)
        assert "total_payments_settled" in metrics
        assert "total_revenue_usdc" in metrics
        assert "net_profit_usd" in metrics
        assert metrics["total_payments_settled"] == 0
        assert metrics["total_revenue_usdc"] == 0.0
        assert metrics["net_profit_usd"] == round(0.0 - metrics["total_cost_usd"], 6)

    @pytest.mark.asyncio
    async def test_storage_get_summary_metrics_with_settled_payments(self, tmp_path):
        """Contract 3: get_summary_metrics aggregates total_revenue_usdc, total_payments_settled, and net_profit_usd."""
        db_file = tmp_path / "test_sum_settled.db"
        storage = AgentStorage(db_path=str(db_file))
        await storage.initialize()

        # Record 2 payments: 0.01 and 0.025 USDC
        p1 = PaymentReceipt(
            payment_id="pay-metric-1",
            payer_address="0x4200000000000000000000000000000000000006",
            pay_to_address="0x0000000000000000000000000000000000000001",
            amount_usdc=0.01,
            amount_atomic=10000,
            tx_hash="0x" + "11" * 32,
            endpoint="/evaluate",
            settled_at="2026-11-04T12:00:00Z",
        )
        p2 = PaymentReceipt(
            payment_id="pay-metric-2",
            payer_address="0x4200000000000000000000000000000000000006",
            pay_to_address="0x0000000000000000000000000000000000000001",
            amount_usdc=0.025,
            amount_atomic=25000,
            tx_hash="0x" + "22" * 32,
            endpoint="/rules/evaluate-batch",
            settled_at="2026-11-04T12:01:00Z",
        )
        await storage.record_payment(p1)
        await storage.record_payment(p2)

        metrics = await storage.get_summary_metrics(target_price_usd=0.01)
        assert metrics["total_payments_settled"] == 2
        assert metrics["total_revenue_usdc"] == 0.035
        expected_profit = round(0.035 - metrics["total_cost_usd"], 6)
        assert metrics["net_profit_usd"] == expected_profit

        # Verify all existing summary metrics keys are preserved
        for key in [
            "total_evaluations",
            "stage1_halted_count",
            "stage1_filter_rate_pct",
            "llm_invoked_count",
            "total_input_tokens",
            "total_output_tokens",
            "total_cost_usd",
            "avg_cost_per_eval_usd",
            "max_cost_usd",
            "p95_cost_usd",
            "price_covers_max_cost",
            "total_errors",
        ]:
            assert key in metrics, f"Existing summary key '{key}' was lost"

    @pytest.mark.asyncio
    async def test_storage_record_payment_resilience_on_closed_db(self, sample_payment_receipt):
        """Contract 3: record_payment and get_payments safely return None/[] if database is unwritable or fails."""
        bad_storage = AgentStorage(db_path="Z:\\impossible_path_not_existing\\agent.db")
        result = await bad_storage.record_payment(sample_payment_receipt)
        assert result is None  # Never raises unhandled exception

        payments = await bad_storage.get_payments()
        assert payments == []

        is_settled = await bad_storage.is_payment_settled("any-id")
        assert is_settled is False


# =============================================================================
# 4. x402 Payment Module Contract Tests (src/x402_payment.py)
# =============================================================================
class TestSection4X402Module:
    def test_x402_constants(self):
        """Contract 4: Validates standard x402 protocol constants."""
        assert DEFAULT_X402_PRICE_USDC == 0.01
        assert DEFAULT_X402_NETWORK == "eip155:84532"
        assert DEFAULT_PAY_TO_ADDRESS == "0x0000000000000000000000000000000000000001"
        assert DEFAULT_FACILITATOR_URL == "https://x402.org/facilitator"
        assert BASE_SEPOLIA_USDC == "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
        assert BASE_MAINNET_USDC == "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        assert USDC_DECIMALS == 6

    def test_x402_config_defaults(self):
        """Contract 4: X402Config default values conform to contract."""
        cfg = X402Config()
        assert cfg.enabled is False
        assert cfg.price_per_eval_usdc == 0.01
        assert cfg.network == "eip155:84532"
        assert cfg.pay_to_address == Web3.to_checksum_address(DEFAULT_PAY_TO_ADDRESS)
        assert cfg.facilitator_url == DEFAULT_FACILITATOR_URL
        assert cfg.asset == "USDC"

    def test_x402_config_env_overrides(self, monkeypatch):
        """Contract 4: X402Config respects environment variables."""
        monkeypatch.setenv("X402_ENABLED", "true")
        monkeypatch.setenv("X402_PRICE_EVALUATE", "0.05")
        monkeypatch.setenv("X402_NETWORK", "eip155:8453")
        monkeypatch.setenv("PAY_TO_ADDRESS", "0x4200000000000000000000000000000000000006")
        monkeypatch.setenv("FACILITATOR_URL", "https://custom-facilitator.org/api")
        monkeypatch.setenv("X402_ASSET", "USDC.e")

        cfg = X402Config()
        assert cfg.enabled is True
        assert cfg.price_per_eval_usdc == 0.05
        assert cfg.network == "eip155:8453"
        assert cfg.pay_to_address == "0x4200000000000000000000000000000000000006"
        assert cfg.facilitator_url == "https://custom-facilitator.org/api"
        assert cfg.asset == "USDC.e"

        # Test boolean truthy/falsy parsing
        for val in ["1", "yes", "True", "TRUE"]:
            monkeypatch.setenv("X402_ENABLED", val)
            assert X402Config().enabled is True

        for val in ["0", "no", "false", "FALSE"]:
            monkeypatch.setenv("X402_ENABLED", val)
            assert X402Config().enabled is False

    def test_x402_config_pay_to_address_eip55_normalization(self):
        """Contract 4: PAY_TO_ADDRESS is normalized via Web3.to_checksum_address."""
        raw_lowercase = "0x4200000000000000000000000000000000000006".lower()
        cfg = X402Config(pay_to_address=raw_lowercase)
        assert cfg.pay_to_address == "0x4200000000000000000000000000000000000006"

    def test_usdc_to_atomic(self):
        """Contract 4: usdc_to_atomic converts USDC decimal float to 6-decimal atomic units."""
        assert usdc_to_atomic(0.01) == 10000
        assert usdc_to_atomic(1.0) == 1000000
        assert usdc_to_atomic(0.000001) == 1
        assert usdc_to_atomic(0.0) == 0
        assert usdc_to_atomic(0.03) == 30000

    def test_parse_x402_header_raw_json(self):
        """Contract 4: parse_x402_header handles raw JSON string and normalizes payer_address."""
        raw = json.dumps({
            "payment_id": "pay-raw-01",
            "payer_address": "0x4200000000000000000000000000000000000006".lower(),
            "amount_atomic": 10000,
            "signature": "0x" + "bb" * 65,
        })
        parsed = parse_x402_header(raw)
        assert parsed["payment_id"] == "pay-raw-01"
        assert parsed["payer_address"] == "0x4200000000000000000000000000000000000006"
        assert parsed["amount_atomic"] == 10000
        assert parsed["signature"] == "0x" + "bb" * 65

    def test_parse_x402_header_base64_encoded(self):
        """Contract 4: parse_x402_header handles base64-encoded JSON header."""
        raw = json.dumps({
            "payment_id": "pay-b64-01",
            "payer_address": "0x4200000000000000000000000000000000000006",
            "amount_atomic": 15000,
            "signature": "0x" + "cc" * 65,
        })
        b64 = base64.b64encode(raw.encode()).decode()
        parsed = parse_x402_header(b64)
        assert parsed["payment_id"] == "pay-b64-01"
        assert parsed["amount_atomic"] == 15000

    def test_parse_x402_header_field_aliases(self):
        """Contract 4: parse_x402_header accommodates field aliases (nonce, payer, amount_usdc)."""
        # Using nonce, payer, and amount_usdc
        raw = json.dumps({
            "nonce": "pay-alias-01",
            "payer": "0x4200000000000000000000000000000000000006",
            "amount_usdc": 0.02,
            "signature": "0x1234",
        })
        parsed = parse_x402_header(raw)
        assert parsed["payment_id"] == "pay-alias-01"
        assert parsed["payer_address"] == "0x4200000000000000000000000000000000000006"
        assert parsed["amount_atomic"] == 20000

    def test_parse_x402_header_rejections(self):
        """Contract 4: parse_x402_header raises ValueError for missing payment_id or invalid payer."""
        # Missing payment_id / nonce
        with pytest.raises(ValueError, match="Missing payment_id or nonce"):
            parse_x402_header(json.dumps({
                "payer_address": "0x4200000000000000000000000000000000000006",
                "amount_atomic": 10000,
                "signature": "0x12",
            }))

        # Invalid payer address
        with pytest.raises(ValueError):
            parse_x402_header(json.dumps({
                "payment_id": "p-1",
                "payer_address": "not-an-evm-address",
                "amount_atomic": 10000,
                "signature": "0x12",
            }))

        # Malformed non-JSON / corrupt base64
        with pytest.raises(ValueError):
            parse_x402_header("!!!NOT_VALID_JSON_OR_BASE64@@@")

    @pytest.mark.asyncio
    async def test_mock_facilitator_verify_success(self):
        """Contract 4: MockX402Facilitator.verify returns valid=True for clean payment."""
        fac = MockX402Facilitator()
        cfg = X402Config()
        payment_data = {
            "payment_id": "pay-fac-01",
            "payer_address": "0x4200000000000000000000000000000000000006",
            "amount_atomic": 10000,
            "signature": "0x" + "ab" * 65,
            "network": "eip155:84532",
        }
        res = await fac.verify(payment_data, required_atomic=10000, config=cfg)
        assert res.valid is True

    @pytest.mark.asyncio
    async def test_mock_facilitator_verify_invalid_signature(self):
        """Contract 4: MockX402Facilitator rejects invalid, empty, or '0xinvalid' signatures."""
        fac = MockX402Facilitator()
        cfg = X402Config()

        for bad_sig in ["invalid", "0xinvalid", ""]:
            data = {
                "payment_id": "pay-fac-sig",
                "payer_address": "0x4200000000000000000000000000000000000006",
                "amount_atomic": 10000,
                "signature": bad_sig,
            }
            res = await fac.verify(data, required_atomic=10000, config=cfg)
            assert res.valid is False

    @pytest.mark.asyncio
    async def test_mock_facilitator_verify_insufficient_amount(self):
        """Contract 4: MockX402Facilitator rejects amounts lower than required_atomic."""
        fac = MockX402Facilitator()
        cfg = X402Config()
        data = {
            "payment_id": "pay-fac-low",
            "payer_address": "0x4200000000000000000000000000000000000006",
            "amount_atomic": 5000,  # 0.005 USDC
            "signature": "0x" + "11" * 65,
        }
        res = await fac.verify(data, required_atomic=10000, config=cfg)
        assert res.valid is False
        assert "Insufficient" in res.reason

    @pytest.mark.asyncio
    async def test_mock_facilitator_verify_network_mismatch(self):
        """Contract 4: MockX402Facilitator rejects network mismatches."""
        fac = MockX402Facilitator()
        cfg = X402Config(network="eip155:84532")
        data = {
            "payment_id": "pay-net-mismatch",
            "payer_address": "0x4200000000000000000000000000000000000006",
            "amount_atomic": 10000,
            "signature": "0x" + "22" * 65,
            "network": "eip155:1",  # Ethereum Mainnet instead of Base Sepolia
        }
        res = await fac.verify(data, required_atomic=10000, config=cfg)
        assert res.valid is False
        assert "Network mismatch" in res.reason

    @pytest.mark.asyncio
    async def test_mock_facilitator_settle_deterministic_hash(self):
        """Contract 4: MockX402Facilitator.settle increments settle_calls and returns deterministic tx_hash."""
        fac = MockX402Facilitator()
        cfg = X402Config()
        payment_id = "test-settle-001"
        data = {"payment_id": payment_id, "amount_atomic": 10000}

        assert fac.settle_calls == 0
        res = await fac.settle(data, required_atomic=10000, config=cfg)
        assert fac.settle_calls == 1
        assert res.settled is True
        expected_hash = "0x" + hashlib.sha256(payment_id.encode()).hexdigest()
        assert res.tx_hash == expected_hash

    @pytest.mark.asyncio
    async def test_mock_facilitator_settle_simulated_error(self):
        """Contract 4: MockX402Facilitator handles simulate_settle_error gracefully."""
        fac = MockX402Facilitator()
        cfg = X402Config()
        data = {
            "payment_id": "test-err-001",
            "amount_atomic": 10000,
            "simulate_settle_error": True,
        }
        res = await fac.settle(data, required_atomic=10000, config=cfg)
        assert res.settled is False
        assert "Simulated facilitator settlement error" in res.error

    def test_build_402_response_structure_and_headers(self):
        """Contract 4: build_402_response outputs compliant HTTP 402 with X-PAYMENT-REQUIRED and base64 Payment-Required header."""
        cfg = X402Config()
        resp = build_402_response(cfg, "/evaluate", 0.01, reason="Payment Required")
        assert resp.status_code == 402
        assert resp.headers.get("X-PAYMENT-REQUIRED") == "true"
        pr_header = resp.headers.get("Payment-Required")
        assert pr_header is not None
        body = json.loads(resp.body.decode())
        assert json.loads(base64.b64decode(pr_header).decode("utf-8")) == body
        assert body["x402Version"] == 2
        assert body["error"] == "PaymentRequired"
        assert body["message"] == "Payment Required"
        assert len(body["accepts"]) == 1
        acc = body["accepts"][0]
        assert acc["scheme"] == "exact"
        assert acc["network"] == cfg.network
        assert acc["maxAmountRequired"] == "10000"
        assert acc["amount_usdc"] == 0.01
        assert acc["asset"] in ("USDC", cfg.usdc_contract_address)
        assert acc["payTo"] == cfg.pay_to_address
        assert acc["resource"] == "/evaluate" or (isinstance(acc["resource"], dict) and acc["resource"]["url"].endswith("/evaluate"))


# =============================================================================
# 5. FastAPI Free Mode Contract Tests (X402_ENABLED=false)
# =============================================================================
class TestSection5FastAPIFreeMode:
    def test_free_mode_default_config_evaluate_no_header(self, base_payload, tmp_path):
        """Contract 5: When x402 is disabled (default), POST /evaluate works without payment header."""
        storage = AgentStorage(db_path=str(tmp_path / "free_eval.db"))
        mock_engine = AsyncMock()
        mock_engine.process_rule = AsyncMock(
            return_value=FinalAgentResponse(
                rule_id=base_payload.rule_id,
                chain_id=base_payload.chain_id.value,
                deterministic_check=DeterministicResult(passed=True, reason="ok"),
                llm_invoked=False,
            )
        )

        app = create_app(engine=mock_engine, storage=storage)
        client = TestClient(app)

        resp = client.post("/evaluate", json=base_payload.model_dump(mode="json"))
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == base_payload.rule_id
        assert data["payment"] is None

    def test_free_mode_enqueue_no_header(self, base_payload, tmp_path):
        """Contract 5: When x402 is disabled, POST /rules/enqueue works free."""
        storage = AgentStorage(db_path=str(tmp_path / "free_enq.db"))
        app = create_app(storage=storage)
        client = TestClient(app)

        resp = client.post("/rules/enqueue", json=base_payload.model_dump(mode="json"))
        assert resp.status_code == 202
        assert "job_id" in resp.json()

    def test_free_mode_batch_evaluate_no_header(self, base_payload, tmp_path):
        """Contract 5: When x402 is disabled, POST /rules/evaluate-batch works free."""
        storage = AgentStorage(db_path=str(tmp_path / "free_batch.db"))
        mock_engine = AsyncMock()
        mock_engine.process_rules_batch = AsyncMock(
            return_value=[
                FinalAgentResponse(
                    rule_id=base_payload.rule_id,
                    chain_id=base_payload.chain_id.value,
                    deterministic_check=DeterministicResult(passed=True, reason="ok"),
                    llm_invoked=False,
                )
            ]
        )

        app = create_app(engine=mock_engine, storage=storage)
        client = TestClient(app)

        batch = [base_payload.model_dump(mode="json")]
        resp = client.post("/rules/evaluate-batch", json=batch)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["payment"] is None


# =============================================================================
# 5. FastAPI Paid Mode Contract Tests (X402_ENABLED=true)
# =============================================================================
class TestSection5FastAPIPaidMode:
    @pytest.fixture
    def paid_app_setup(self, tmp_path):
        """Fixture setting up an app in paid mode with MockX402Facilitator and real SQLite storage."""
        db_path = str(tmp_path / "paid_test.db")
        storage = AgentStorage(db_path=db_path)
        asyncio.run(storage.initialize())

        x402_config = X402Config(enabled=True, price_per_eval_usdc=0.01)
        facilitator = MockX402Facilitator()

        mock_evaluator = MagicMock()
        mock_evaluator.model_name = "mock-model"
        mock_evaluator.model = "mock-model"

        mock_engine = AsyncMock()
        mock_engine.semantic_evaluator = mock_evaluator

        def _make_response(rule_id, error=None):
            return FinalAgentResponse(
                rule_id=rule_id,
                chain_id=84532,
                deterministic_check=DeterministicResult(
                    passed=(error is None),
                    reason="Stage 1 match" if error is None else "Stage 1 RPC error",
                    error=error,
                ),
                llm_invoked=False,
            )

        async def _fake_process_rule(payload, source="evaluate"):
            return _make_response(payload.rule_id)

        async def _fake_process_batch(payloads):
            return [_make_response(p.rule_id) for p in payloads]

        mock_engine.process_rule = AsyncMock(side_effect=_fake_process_rule)
        mock_engine.process_rules_batch = AsyncMock(side_effect=_fake_process_batch)

        app = create_app(
            engine=mock_engine,
            storage=storage,
            x402_config=x402_config,
            facilitator=facilitator,
        )
        client = TestClient(app)
        return app, client, storage, facilitator, mock_engine

    def test_health_check_reports_x402_status_and_free_access(self, paid_app_setup):
        """Contract 5: GET /health returns HTTP 200 without payment and includes x402 status."""
        _, client, _, _, _ = paid_app_setup
        # Default simple health check returns 200 without payment
        simple_resp = client.get("/health")
        assert simple_resp.status_code == 200
        assert simple_resp.json() == {"status": "ok"}

        # Full health check includes detailed x402 status
        resp = client.get("/health?full=true")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("x402_enabled") is True
        assert data.get("x402_network") == "eip155:84532"
        assert data.get("price_per_eval_usdc") == 0.01

    def test_free_routes_accessible_without_payment(self, paid_app_setup, base_payload):
        """Contract 5: Free routes remain accessible (200) without X-PAYMENT header in paid mode."""
        _, client, _, _, _ = paid_app_setup

        # /rules/validate
        r1 = client.post("/rules/validate", json=base_payload.model_dump(mode="json"))
        assert r1.status_code == 200

        # /metrics/summary
        r2 = client.get("/metrics/summary")
        assert r2.status_code == 200

        # /logs/errors
        r3 = client.get("/logs/errors")
        assert r3.status_code == 200

        # /jobs/{id}
        r4 = client.get("/jobs/non-existent-id")
        assert r4.status_code == 404  # Not 402!

        # /payments
        r5 = client.get("/payments")
        assert r5.status_code == 200

    def test_paid_routes_missing_header_return_402(self, paid_app_setup, base_payload):
        """Contract 5: Paid routes without X-PAYMENT header return HTTP 402 with X-PAYMENT-REQUIRED and base64 Payment-Required."""
        _, client, _, facilitator, _ = paid_app_setup

        # POST /evaluate
        resp = client.post("/evaluate", json=base_payload.model_dump(mode="json"))
        assert resp.status_code == 402
        assert resp.headers.get("X-PAYMENT-REQUIRED") == "true"
        pr_header = resp.headers.get("Payment-Required")
        assert pr_header is not None
        assert json.loads(base64.b64decode(pr_header).decode("utf-8")) == resp.json()
        body = resp.json()
        assert body["error"] == "PaymentRequired"
        assert body["accepts"][0]["maxAmountRequired"] == "10000"
        assert facilitator.settle_calls == 0

        # POST /rules/enqueue
        resp_enq = client.post("/rules/enqueue", json=base_payload.model_dump(mode="json"))
        assert resp_enq.status_code == 402
        assert resp_enq.headers.get("X-PAYMENT-REQUIRED") == "true"
        pr_enq = resp_enq.headers.get("Payment-Required")
        assert pr_enq is not None
        assert json.loads(base64.b64decode(pr_enq).decode("utf-8")) == resp_enq.json()
        assert resp_enq.json()["accepts"][0]["maxAmountRequired"] == "10000"
        assert facilitator.settle_calls == 0

    def test_paid_routes_evaluate_batch_accepts_scaled_amount(self, paid_app_setup, base_payload):
        """Contract 5: POST /rules/evaluate-batch scales maxAmountRequired with batch size."""
        _, client, _, facilitator, _ = paid_app_setup
        batch_3 = [base_payload.model_dump(mode="json") for _ in range(3)]

        resp = client.post("/rules/evaluate-batch", json=batch_3)
        assert resp.status_code == 402
        assert resp.headers.get("X-PAYMENT-REQUIRED") == "true"
        pr_header = resp.headers.get("Payment-Required")
        assert pr_header is not None
        assert json.loads(base64.b64decode(pr_header).decode("utf-8")) == resp.json()
        body = resp.json()
        # 3 items * 10000 = 30000 atomic
        assert body["accepts"][0]["maxAmountRequired"] == "30000"
        assert body["accepts"][0]["amount_usdc"] == 0.03
        assert facilitator.settle_calls == 0

    def test_empty_batch_returns_empty_without_charge(self, paid_app_setup):
        """Contract 5: POST /rules/evaluate-batch with empty list returns [] without charging."""
        _, client, _, facilitator, _ = paid_app_setup
        resp = client.post("/rules/evaluate-batch", json=[])
        assert resp.status_code == 200
        assert resp.json() == []
        assert facilitator.settle_calls == 0

    def test_validation_422_before_charge_for_single_and_batch(self, paid_app_setup, base_payload):
        """Contract 5: Malformed payload or oversized batch returns HTTP 422 BEFORE payment settlement."""
        _, client, _, facilitator, _ = paid_app_setup
        header_val = make_valid_payment_header(payment_id="pay-422-test")

        # 1. Malformed payload on /evaluate
        resp1 = client.post(
            "/evaluate",
            json={"bad": "payload", "missing_required": True},
            headers={"X-PAYMENT": header_val},
        )
        assert resp1.status_code == 422
        assert facilitator.settle_calls == 0

        # 2. Oversized batch on /rules/evaluate-batch (e.g. > max batch items)
        oversized = [base_payload.model_dump(mode="json") for _ in range(55)]
        resp2 = client.post(
            "/rules/evaluate-batch",
            json=oversized,
            headers={"X-PAYMENT": make_valid_payment_header(amount_atomic=550000)},
        )
        assert resp2.status_code == 422
        assert facilitator.settle_calls == 0

    def test_insufficient_payment_amount_returns_402_no_settle(self, paid_app_setup, base_payload):
        """Contract 5: Payments offering less than required atomic amount return HTTP 402."""
        _, client, _, facilitator, _ = paid_app_setup

        # Single eval requires 10000, offer 5000
        low_header = make_valid_payment_header(amount_atomic=5000)
        resp = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": low_header},
        )
        assert resp.status_code == 402
        assert facilitator.settle_calls == 0
        assert "Insufficient" in resp.json().get("message", "")

        # Batch of 2 requires 20000, offer 10000
        batch_2 = [base_payload.model_dump(mode="json") for _ in range(2)]
        resp_b = client.post(
            "/rules/evaluate-batch",
            json=batch_2,
            headers={"X-PAYMENT": make_valid_payment_header(amount_atomic=10000)},
        )
        assert resp_b.status_code == 402
        assert facilitator.settle_calls == 0

    def test_malformed_payment_header_returns_402_no_settle(self, paid_app_setup, base_payload):
        """Contract 5: Malformed payment headers, bad addresses, or bad signatures return HTTP 402."""
        _, client, _, facilitator, _ = paid_app_setup

        # Garbage header
        r1 = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": "NOT_JSON_OR_BASE64"},
        )
        assert r1.status_code == 402
        assert facilitator.settle_calls == 0

        # Invalid signature "0xinvalid"
        bad_sig_header = make_valid_payment_header(signature="0xinvalid")
        r2 = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": bad_sig_header},
        )
        assert r2.status_code == 402
        assert facilitator.settle_calls == 0

    def test_successful_payment_on_evaluate(self, paid_app_setup, base_payload):
        """Contract 5: Valid payment on /evaluate settles once, attaches receipt, sets headers, records to SQLite."""
        _, client, storage, facilitator, _ = paid_app_setup
        payment_id = "pay-success-eval-001"
        header_val = make_valid_payment_header(payment_id=payment_id, amount_atomic=10000)

        resp = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": header_val},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert facilitator.settle_calls == 1

        # Receipt attached to response
        assert data.get("payment") is not None
        receipt = data["payment"]
        assert receipt["payment_id"] == payment_id
        assert receipt["amount_usdc"] == 0.01
        assert receipt["amount_atomic"] == 10000
        assert receipt["tx_hash"].startswith("0x")

        # Response header set
        assert "X-PAYMENT-RESPONSE" in resp.headers

        # Persisted in SQLite ledger
        async def _check_db():
            assert await storage.is_payment_settled(payment_id)
            records = await storage.get_payments(limit=10)
            assert len(records) == 1
            assert records[0]["payment_id"] == payment_id
        asyncio.run(_check_db())

    def test_successful_payment_on_enqueue(self, paid_app_setup, base_payload):
        """Contract 5: Valid payment on /rules/enqueue settles, returns 202 with receipt, records to SQLite."""
        _, client, storage, facilitator, _ = paid_app_setup
        payment_id = "pay-success-enq-001"
        header_val = make_valid_payment_header(payment_id=payment_id, amount_atomic=10000)

        resp = client.post(
            "/rules/enqueue",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": header_val},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert facilitator.settle_calls == 1
        assert "payment" in data
        assert data["payment"]["payment_id"] == payment_id

        async def _check():
            assert await storage.is_payment_settled(payment_id)
        asyncio.run(_check())

    def test_successful_payment_on_batch_evaluate(self, paid_app_setup, base_payload):
        """Contract 5: Valid payment on /rules/evaluate-batch settles once for batch and attaches receipt."""
        _, client, storage, facilitator, _ = paid_app_setup
        payment_id = "pay-success-batch-001"
        # 2 rules = 20000 atomic units
        header_val = make_valid_payment_header(payment_id=payment_id, amount_atomic=20000)
        batch = [base_payload.model_dump(mode="json") for _ in range(2)]

        resp = client.post(
            "/rules/evaluate-batch",
            json=batch,
            headers={"X-PAYMENT": header_val},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert facilitator.settle_calls == 1
        assert len(data) == 2
        for item in data:
            assert item.get("payment") is not None
            assert item["payment"]["payment_id"] == payment_id

    def test_base64_and_payment_signature_header_support(self, paid_app_setup, base_payload):
        """Contract 5: Supports base64 encoding and PAYMENT-SIGNATURE alternative header name."""
        _, client, _, facilitator, _ = paid_app_setup

        # Base64 in X-PAYMENT
        b64_header = make_valid_payment_header(payment_id="pay-b64-test", as_base64=True)
        resp1 = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": b64_header},
        )
        assert resp1.status_code == 200
        assert facilitator.settle_calls == 1

        # PAYMENT-SIGNATURE header
        raw_header = make_valid_payment_header(payment_id="pay-sig-header-test")
        resp2 = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"PAYMENT-SIGNATURE": raw_header},
        )
        assert resp2.status_code == 200
        assert facilitator.settle_calls == 2

    def test_replay_attack_prevention(self, paid_app_setup, base_payload):
        """Contract 5: Reusing the same payment_id returns HTTP 402 (replay detected) and does NOT settle twice."""
        _, client, _, facilitator, _ = paid_app_setup
        payment_id = "pay-replay-attack-001"
        header_val = make_valid_payment_header(payment_id=payment_id)

        # First request succeeds
        r1 = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": header_val},
        )
        assert r1.status_code == 200
        assert facilitator.settle_calls == 1

        # Second request with SAME payment_id is rejected
        r2 = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": header_val},
        )
        assert r2.status_code == 402
        assert "replay" in r2.json().get("message", "").lower()
        # Facilitator settle must NOT have been called a second time!
        assert facilitator.settle_calls == 1

    def test_settlement_failure_returns_402_and_logs_error(self, paid_app_setup, base_payload):
        """Contract 5: When facilitator.settle fails, API returns HTTP 402 and logs error without saving payment."""
        _, client, storage, facilitator, _ = paid_app_setup
        payment_id = "pay-simulated-settle-fail"
        header_val = make_valid_payment_header(
            payment_id=payment_id,
            extra={"simulate_settle_error": True},
        )

        resp = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": header_val},
        )
        assert resp.status_code == 402

        # Verify not recorded in payments
        async def _check():
            assert not await storage.is_payment_settled(payment_id)
            # Verify logged to error_log
            errors = await storage.get_errors(stage="payment")
            assert len(errors) >= 1
            assert any(payment_id in str(e) or "settle" in str(e).lower() for e in errors)
        asyncio.run(_check())

    # -------------------------------------------------------------------------
    # CRITICAL No-Charge-on-Error Rule Tests
    # -------------------------------------------------------------------------
    def test_critical_no_charge_on_stage1_rpc_error(self, paid_app_setup, base_payload):
        """Contract 5 (CRITICAL): When Stage 1 RPC fails, API returns HTTP 503 and NEVER calls facilitator.settle."""
        _, client, storage, facilitator, mock_engine = paid_app_setup

        # Mock engine returns Stage 1 deterministic check failure with error
        mock_engine.process_rule = AsyncMock(
            return_value=FinalAgentResponse(
                rule_id=base_payload.rule_id,
                chain_id=84532,
                deterministic_check=DeterministicResult(
                    passed=False,
                    reason="Stage 1 RPC network failure",
                    error="RPCConnectionError: All fallback endpoints unreachable",
                ),
                llm_invoked=False,
            )
        )

        payment_id = "pay-rpc-fail-no-charge"
        header_val = make_valid_payment_header(payment_id=payment_id)

        resp = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": header_val},
        )

        # Must return HTTP 503 Service Unavailable
        assert resp.status_code == 503
        data = resp.json()
        assert data.get("payment_settled") is False

        # Facilitator.settle was NEVER called!
        assert facilitator.settle_calls == 0

        # SQLite ledger has 0 payment records
        async def _check():
            assert not await storage.is_payment_settled(payment_id)
            payments = await storage.get_payments()
            assert len(payments) == 0
            # Error was logged
            errors = await storage.get_errors()
            assert any("ServiceUnavailableNoCharge" in str(e.get("error_type", "")) for e in errors)
        asyncio.run(_check())

    def test_critical_no_charge_on_engine_unhandled_exception(self, paid_app_setup, base_payload):
        """Contract 5 (CRITICAL): When engine raises unhandled exception, API returns HTTP 503 and NEVER settles."""
        _, client, storage, facilitator, mock_engine = paid_app_setup
        mock_engine.process_rule = AsyncMock(side_effect=RuntimeError("Fatal database/engine crash"))

        payment_id = "pay-crash-no-charge"
        header_val = make_valid_payment_header(payment_id=payment_id)

        resp = client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": header_val},
        )

        assert resp.status_code == 503
        data = resp.json()
        assert data.get("payment_settled") is False

        # NEVER charged
        assert facilitator.settle_calls == 0

        async def _check():
            assert not await storage.is_payment_settled(payment_id)
            payments = await storage.get_payments()
            assert len(payments) == 0
        asyncio.run(_check())

    def test_critical_no_charge_on_batch_partial_rpc_error(self, paid_app_setup, base_payload):
        """Contract 5 (CRITICAL): If any item in evaluate-batch encounters an RPC error, return 503 and NO charge."""
        _, client, storage, facilitator, mock_engine = paid_app_setup

        # Batch where 2nd item has an RPC error
        mock_engine.process_rules_batch = AsyncMock(
            return_value=[
                FinalAgentResponse(
                    rule_id="r1",
                    chain_id=84532,
                    deterministic_check=DeterministicResult(passed=True, reason="ok"),
                    llm_invoked=False,
                ),
                FinalAgentResponse(
                    rule_id="r2",
                    chain_id=84532,
                    deterministic_check=DeterministicResult(
                        passed=False,
                        reason="RPC error",
                        error="Web3RPCException: eth_getCode failed",
                    ),
                    llm_invoked=False,
                ),
            ]
        )

        payment_id = "pay-batch-err-no-charge"
        header_val = make_valid_payment_header(payment_id=payment_id, amount_atomic=20000)
        batch = [base_payload.model_dump(mode="json") for _ in range(2)]

        resp = client.post(
            "/rules/evaluate-batch",
            json=batch,
            headers={"X-PAYMENT": header_val},
        )

        assert resp.status_code == 503
        data = resp.json()
        assert data.get("payment_settled") is False
        assert facilitator.settle_calls == 0

        async def _check():
            assert not await storage.is_payment_settled(payment_id)
        asyncio.run(_check())

    def test_diagnostics_payments_endpoint_filtering_and_limits(self, paid_app_setup, base_payload):
        """Contract 5: GET /payments lists settled payments with limit and payer_address filtering."""
        _, client, _, _, _ = paid_app_setup

        payer_1 = "0x4200000000000000000000000000000000000006"
        payer_2 = "0x1111111111111111111111111111111111111111"

        client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": make_valid_payment_header(payment_id="pay-diag-1", payer_address=payer_1)},
        )
        client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": make_valid_payment_header(payment_id="pay-diag-2", payer_address=payer_2)},
        )

        # GET /payments all
        r_all = client.get("/payments?limit=10")
        assert r_all.status_code == 200
        assert len(r_all.json()) == 2

        # GET /payments limit=1
        r_lim = client.get("/payments?limit=1")
        assert r_lim.status_code == 200
        assert len(r_lim.json()) == 1

        # GET /payments filtered by payer_1
        r_p1 = client.get(f"/payments?payer_address={payer_1}")
        assert r_p1.status_code == 200
        assert len(r_p1.json()) == 1
        assert r_p1.json()[0]["payment_id"] == "pay-diag-1"

    def test_cors_headers_expose_payment_headers(self, paid_app_setup):
        """Contract 5: CORS configuration exposes x402 headers to browser and client agents."""
        app, _, _, _, _ = paid_app_setup
        cors_middlewares = [
            m for m in getattr(app, "user_middleware", [])
            if "CORSMiddleware" in str(m) or getattr(m, "cls", None).__name__ == "CORSMiddleware"
        ]
        assert len(cors_middlewares) >= 1
        kwargs = cors_middlewares[0].kwargs
        expose_headers = [h.upper() for h in kwargs.get("expose_headers", [])]
        assert any("X-PAYMENT-REQUIRED" in h for h in expose_headers)
        assert any("X-PAYMENT-RESPONSE" in h for h in expose_headers)


# =============================================================================
# 6. Report Module Contract Tests (src/report.py)
# =============================================================================
class TestSection6ReportModule:
    def test_format_report_text_includes_payment_and_profit_metrics(self):
        """Contract 6: format_report_text displays total_payments_settled, total_revenue_usdc, and net_profit_usd."""
        metrics = {
            "total_evaluations": 100,
            "stage1_halted_count": 80,
            "stage1_filter_rate_pct": 80.0,
            "llm_invoked_count": 20,
            "total_input_tokens": 15000,
            "total_output_tokens": 3000,
            "total_cost_usd": 0.0075,
            "avg_cost_per_eval_usd": 0.000075,
            "avg_cost_per_llm_call_usd": 0.000375,
            "p95_cost_usd": 0.00045,
            "max_cost_usd": 0.0005,
            "target_price_usd": 0.01,
            "price_covers_max_cost": True,
            "total_errors": 0,
            "errors_by_stage": {},
            # New Phase B3 keys
            "total_payments_settled": 85,
            "total_revenue_usdc": 0.85,
            "net_profit_usd": 0.8425,
        }
        report_text = format_report_text(metrics)
        assert "Total Payments Settled" in report_text or "payments settled" in report_text.lower()
        assert "0.85" in report_text
        assert "0.8425" in report_text

    def test_format_report_text_fallback_when_payment_metrics_absent(self):
        """Contract 6: format_report_text handles missing Phase B3 metrics without error (backward compatibility)."""
        metrics = {
            "total_evaluations": 10,
            "stage1_halted_count": 5,
            "stage1_filter_rate_pct": 50.0,
            "llm_invoked_count": 5,
            "total_input_tokens": 2000,
            "total_output_tokens": 500,
            "total_cost_usd": 0.001,
        }
        report_text = format_report_text(metrics)
        assert "Operational Report" in report_text
