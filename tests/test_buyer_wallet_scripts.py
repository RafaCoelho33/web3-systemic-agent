"""
Unit and edge-case test suite for Phase B4 Web3 Live Integration utility scripts:
- scripts/setup_buyer_wallet.py
- scripts/send_live_usdc.py (Gasless EIP-3009 Settlement via x402 Facilitator)
"""

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from eth_account import Account

# Ensure scripts and src directories are accessible
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
for _p in (_ROOT_DIR, _SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scripts.setup_buyer_wallet import (
    load_or_create_buyer_wallet,
    inspect_buyer_balances,
    USDC_CONTRACT_ADDRESS,
)
from scripts.send_live_usdc import (
    load_buyer_wallet,
    send_live_usdc,
    record_settled_payment,
    TRANSFER_AMOUNT_UNITS,
)


class TestBuyerWalletSetup:
    """Test suite for setup_buyer_wallet.py."""

    def test_creates_new_wallet_when_missing(self):
        """Generates a valid EVM account when no file exists."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_wallet_file = os.path.join(tmp_dir, ".buyer_wallet.json")
            wallet_info = load_or_create_buyer_wallet(temp_wallet_file)

            assert wallet_info["created"] is True
            assert os.path.exists(temp_wallet_file)
            assert wallet_info["address"].startswith("0x")
            assert len(wallet_info["address"]) == 42
            assert wallet_info["private_key"].startswith("0x")

            # Verify persisted JSON
            with open(temp_wallet_file, "r", encoding="utf-8") as f:
                saved_data = json.load(f)
            assert saved_data["address"] == wallet_info["address"]
            assert saved_data["private_key"] == wallet_info["private_key"]

            # Keypair cryptographic conformance
            reconstructed = Account.from_key(saved_data["private_key"])
            assert reconstructed.address.lower() == wallet_info["address"].lower()

    def test_loads_existing_wallet(self):
        """Re-uses existing wallet credentials when file already exists."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_wallet_file = os.path.join(tmp_dir, ".buyer_wallet.json")
            created_wallet = load_or_create_buyer_wallet(temp_wallet_file)

            # Second call should load existing without regenerating
            loaded_wallet = load_or_create_buyer_wallet(temp_wallet_file)
            assert loaded_wallet["created"] is False
            assert loaded_wallet["address"] == created_wallet["address"]
            assert loaded_wallet["private_key"] == created_wallet["private_key"]

    @patch("scripts.setup_buyer_wallet.Web3")
    def test_inspect_balances_success(self, mock_web3_cls):
        """Queries on-chain ETH and USDC balances accurately with mocked Web3."""
        mock_w3 = MagicMock()
        mock_web3_cls.return_value = mock_w3
        mock_web3_cls.to_checksum_address.side_effect = lambda addr: addr

        mock_w3.is_connected.return_value = True
        mock_w3.eth.chain_id = 84532
        mock_w3.eth.block_number = 54321
        mock_w3.eth.get_balance.return_value = 50_000_000_000_000_000  # 0.05 ETH
        mock_w3.from_wei.return_value = "0.05"

        mock_contract = MagicMock()
        mock_contract.functions.balanceOf.return_value.call.return_value = 50_000  # 0.05 USDC
        mock_w3.eth.contract.return_value = mock_contract

        result = inspect_buyer_balances("0x1111111111111111111111111111111111111111")
        assert result["connected"] is True
        assert result["chain_id"] == 84532
        assert result["eth_balance"] == 0.05
        assert result["usdc_units"] == 50_000
        assert result["usdc_balance"] == 0.05

    @patch("scripts.setup_buyer_wallet.Web3")
    def test_inspect_balances_rpc_failure(self, mock_web3_cls):
        """Handles RPC connection failure gracefully."""
        mock_w3 = MagicMock()
        mock_web3_cls.return_value = mock_w3
        mock_w3.is_connected.return_value = False

        result = inspect_buyer_balances("0x1111111111111111111111111111111111111111")
        assert result["connected"] is False
        assert "Failed to connect" in result["error"]


class TestSendLiveUSDC:
    """Test suite for send_live_usdc.py (Gasless EIP-3009 Settlement)."""

    def test_load_buyer_wallet_missing_file_returns_none(self):
        """Returns None if wallet file does not exist."""
        result = load_buyer_wallet("/non/existent/path/.buyer_wallet.json")
        assert result is None

    def test_load_buyer_wallet_valid_file(self):
        """Loads Account successfully from valid JSON."""
        account = Account.create()
        with tempfile.TemporaryDirectory() as tmp_dir:
            wallet_path = os.path.join(tmp_dir, ".buyer_wallet.json")
            with open(wallet_path, "w", encoding="utf-8") as f:
                json.dump({"address": account.address, "private_key": account.key.hex()}, f)

            loaded = load_buyer_wallet(wallet_path)
            assert loaded is not None
            assert loaded.address.lower() == account.address.lower()

    @patch("scripts.send_live_usdc.load_buyer_wallet", return_value=None)
    def test_send_live_usdc_aborts_without_wallet(self, mock_load):
        """Aborts cleanly if buyer wallet is not found."""
        assert send_live_usdc() is False

    @patch("scripts.send_live_usdc.x402ClientSync")
    @patch("scripts.send_live_usdc.x402ResourceServerSync")
    @patch("scripts.send_live_usdc.Web3")
    @patch("scripts.send_live_usdc.load_buyer_wallet")
    def test_send_live_usdc_aborts_on_insufficient_funds(
        self, mock_load_wallet, mock_web3_cls, mock_srv_cls, mock_cli_cls
    ):
        """Aborts cleanly with detailed diagnostics when facilitator returns invalid."""
        test_account = Account.create()
        mock_load_wallet.return_value = test_account

        mock_w3 = MagicMock()
        mock_web3_cls.return_value = mock_w3
        mock_web3_cls.to_checksum_address.side_effect = lambda addr: addr
        mock_w3.is_connected.return_value = True
        mock_w3.eth.get_balance.return_value = 0
        mock_w3.from_wei.return_value = "0.0"

        mock_contract = MagicMock()
        mock_contract.functions.balanceOf.return_value.call.return_value = 0
        mock_w3.eth.contract.return_value = mock_contract

        mock_srv = MagicMock()
        mock_srv_cls.return_value = mock_srv
        mock_req = MagicMock()
        mock_srv.build_payment_requirements.return_value = [mock_req]

        mock_cli = MagicMock()
        mock_cli_cls.return_value = mock_cli
        mock_cli.create_payment_payload.return_value = MagicMock()

        mock_verify_resp = MagicMock()
        mock_verify_resp.verify.is_valid = False
        mock_verify_resp.verify.invalid_reason = "invalid_exact_evm_insufficient_balance"
        mock_verify_resp.verify.invalid_message = "ERC20: transfer amount exceeds balance"
        mock_srv.verify_payment.return_value = mock_verify_resp

        success = send_live_usdc()
        assert success is False
        mock_srv.verify_payment.assert_called_once()
        mock_srv.settle_payment.assert_not_called()

    @patch("scripts.send_live_usdc.record_settled_payment")
    @patch("scripts.send_live_usdc.x402ClientSync")
    @patch("scripts.send_live_usdc.x402ResourceServerSync")
    @patch("scripts.send_live_usdc.Web3")
    @patch("scripts.send_live_usdc.load_buyer_wallet")
    def test_send_live_usdc_builds_and_broadcasts_transaction(
        self, mock_load_wallet, mock_web3_cls, mock_srv_cls, mock_cli_cls, mock_record
    ):
        """Builds EIP-3009 payload, verifies via facilitator, and settles gasless on-chain."""
        test_account = Account.create()
        mock_load_wallet.return_value = test_account

        mock_w3 = MagicMock()
        mock_web3_cls.return_value = mock_w3
        mock_web3_cls.to_checksum_address.side_effect = lambda addr: addr
        mock_w3.is_connected.return_value = True
        mock_w3.eth.get_balance.return_value = 0  # 0 ETH needed for Gasless EIP-3009!
        mock_w3.from_wei.return_value = "0.0"

        mock_contract = MagicMock()
        mock_contract.functions.balanceOf.return_value.call.return_value = 50_000
        mock_w3.eth.contract.return_value = mock_contract

        mock_srv = MagicMock()
        mock_srv_cls.return_value = mock_srv
        mock_req = MagicMock()
        mock_srv.build_payment_requirements.return_value = [mock_req]

        mock_cli = MagicMock()
        mock_cli_cls.return_value = mock_cli
        mock_payload = MagicMock()
        mock_payload.model_dump.return_value = {
            "payload": {
                "authorization": {
                    "nonce": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                }
            }
        }
        mock_cli.create_payment_payload.return_value = mock_payload

        # Mock successful verification response
        mock_verify_resp = MagicMock()
        mock_verify_resp.verify.is_valid = True
        mock_srv.verify_payment.return_value = mock_verify_resp

        # Mock successful settlement response
        fake_tx = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        mock_settle_resp = MagicMock()
        mock_settle_resp.success = True
        mock_settle_resp.transaction = fake_tx
        mock_srv.settle_payment.return_value = mock_settle_resp
        mock_record.return_value = True

        success = send_live_usdc()
        assert success is True
        mock_srv.verify_payment.assert_called_once()
        mock_srv.settle_payment.assert_called_once()
        mock_record.assert_called_once()

    @patch("scripts.send_live_usdc.x402ResourceServerSync")
    @patch("scripts.send_live_usdc.Web3")
    @patch("scripts.send_live_usdc.load_buyer_wallet")
    def test_send_live_usdc_settlement_failure(self, mock_load_wallet, mock_web3_cls, mock_srv_cls):
        """Handles on-chain settlement failure from facilitator gracefully."""
        test_account = Account.create()
        mock_load_wallet.return_value = test_account

        mock_w3 = MagicMock()
        mock_web3_cls.return_value = mock_w3
        mock_web3_cls.to_checksum_address.side_effect = lambda addr: addr
        mock_w3.is_connected.return_value = True

        mock_srv = MagicMock()
        mock_srv_cls.return_value = mock_srv
        mock_req = MagicMock()
        mock_srv.build_payment_requirements.return_value = [mock_req]

        mock_verify_resp = MagicMock()
        mock_verify_resp.verify.is_valid = True
        mock_srv.verify_payment.return_value = mock_verify_resp

        mock_settle_resp = MagicMock()
        mock_settle_resp.success = False
        mock_settle_resp.error_reason = "settlement_reverted"
        mock_settle_resp.error_message = "Execution reverted by on-chain contract"
        mock_srv.settle_payment.return_value = mock_settle_resp

        success = send_live_usdc()
        assert success is False

    @patch("scripts.send_live_usdc.x402ResourceServerSync")
    @patch("scripts.send_live_usdc.Web3")
    @patch("scripts.send_live_usdc.load_buyer_wallet")
    def test_send_live_usdc_facilitator_exception(self, mock_load_wallet, mock_web3_cls, mock_srv_cls):
        """Catches network or facilitator exceptions cleanly without crashing."""
        test_account = Account.create()
        mock_load_wallet.return_value = test_account

        mock_w3 = MagicMock()
        mock_web3_cls.return_value = mock_w3
        mock_web3_cls.to_checksum_address.side_effect = lambda addr: addr
        mock_w3.is_connected.return_value = True

        mock_srv = MagicMock()
        mock_srv_cls.side_effect = RuntimeError("Connection timed out to facilitator")

        success = send_live_usdc()
        assert success is False

    def test_record_settled_payment_persists_to_sqlite(self):
        """Verifies record_settled_payment properly stores a PaymentReceipt into SQLite."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_db = os.path.join(tmp_dir, "test_ledger.db")
            recorded = record_settled_payment(
                payment_id="0x999999999999",
                payer_address="0x4EbC7529d8c948ed1245A8106F2834969dbCec2b",
                pay_to_address="0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63",
                amount_usdc=0.01,
                amount_atomic=10000,
                tx_hash="0xtesttxhash123",
                db_path=test_db,
            )
            assert recorded is True
            assert os.path.exists(test_db)


class TestClientAgentX402Session:
    """Regression test suite for scripts/client_agent_x402.py session timeouts and failover."""

    @pytest.mark.asyncio
    async def test_setup_client_session_live_timeout_gte_30s(self):
        """Verifies live server client session returns httpx.AsyncClient with timeout >= 30.0s."""
        from unittest.mock import AsyncMock, patch
        import httpx
        from scripts.client_agent_x402 import setup_client_session

        mock_resp = MagicMock(status_code=200)
        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            client, is_live, app = await setup_client_session("http://127.0.0.1:8000")
            try:
                assert is_live is True
                assert app is None
                assert client.timeout.read is not None
                assert client.timeout.read >= 30.0
            finally:
                await client.aclose()

    @pytest.mark.asyncio
    async def test_setup_client_session_fallback_timeout_gte_30s(self):
        """Verifies in-process fallback client session returns httpx.AsyncClient with timeout >= 30.0s."""
        from scripts.client_agent_x402 import setup_client_session

        client, is_live, app = await setup_client_session("http://127.0.0.1:9999")
        try:
            assert is_live is False
            assert app is not None
            assert client.timeout.read is not None
            assert client.timeout.read >= 30.0
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_gemini_semantic_evaluator_503_failover(self):
        """Verifies GeminiSemanticEvaluator retries with failover model on 503 UNAVAILABLE."""
        from src.semantic_evaluator import GeminiSemanticEvaluator, SemanticAuditResult

        calls = []

        class FakeAioModels:
            async def generate_content(self, model, contents, config):
                calls.append(model)
                if len(calls) == 1:
                    raise RuntimeError("503 Service UNAVAILABLE: High demand")
                return SemanticAuditResult(
                    conditions_met=True,
                    risk_score=1.0,
                    summary="Passes after failover",
                    recommended_action="APPROVE",
                    flagged_issues=[],
                )

        class FakeAio:
            def __init__(self):
                self.models = FakeAioModels()

        class FakeGenAIClient:
            def __init__(self):
                self.aio = FakeAio()

        fake_client = FakeGenAIClient()
        evaluator = GeminiSemanticEvaluator(
            api_key="test-key",
            client=fake_client,
            model="gemini-2.5-flash",
            fallback_to_mock=False,
        )

        from src.schemas import SemanticCondition

        cond = SemanticCondition(policy_prompt="Test policy", risk_threshold=0.5)
        res = await evaluator.evaluate(cond, {"tx": "0x123"}, {})
        assert res.recommended_action == "APPROVE"
        assert res.model == "gemini-3.5-flash-lite"
        assert calls == ["gemini-2.5-flash", "gemini-3.5-flash-lite"]

