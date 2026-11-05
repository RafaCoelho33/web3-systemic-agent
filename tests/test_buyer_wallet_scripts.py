"""
Unit and edge-case test suite for Phase B4 Web3 Live Integration utility scripts:
- scripts/setup_buyer_wallet.py
- scripts/client_agent_x402.py
"""

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, AsyncMock, patch

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

    def test_load_persistent_buyer_wallet_from_existing_file(self):
        """Loads Account successfully from scripts/.buyer_wallet.json when present."""
        from scripts.client_agent_x402 import load_persistent_buyer_wallet

        test_account = Account.create()
        with tempfile.TemporaryDirectory() as tmp_dir:
            wallet_path = os.path.join(tmp_dir, ".buyer_wallet.json")
            with open(wallet_path, "w", encoding="utf-8") as f:
                json.dump({"address": test_account.address, "private_key": test_account.key.hex()}, f)

            with patch("scripts.client_agent_x402._CURRENT_DIR", tmp_dir):
                loaded = load_persistent_buyer_wallet()
                assert loaded is not None
                assert loaded.address.lower() == test_account.address.lower()

    def test_load_persistent_buyer_wallet_generates_transient_when_missing(self):
        """Generates a transient Account keypair when wallet file is absent."""
        from scripts.client_agent_x402 import load_persistent_buyer_wallet

        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("scripts.client_agent_x402._CURRENT_DIR", tmp_dir):
                transient = load_persistent_buyer_wallet()
                assert transient is not None
                assert transient.address.startswith("0x")
                assert len(transient.address) == 42

    def test_load_persistent_buyer_wallet_handles_corrupt_file(self):
        """Gracefully falls back to transient Account if .buyer_wallet.json is corrupted."""
        from scripts.client_agent_x402 import load_persistent_buyer_wallet

        with tempfile.TemporaryDirectory() as tmp_dir:
            wallet_path = os.path.join(tmp_dir, ".buyer_wallet.json")
            with open(wallet_path, "w", encoding="utf-8") as f:
                f.write("NOT_VALID_JSON{{{")

            with patch("scripts.client_agent_x402._CURRENT_DIR", tmp_dir):
                fallback = load_persistent_buyer_wallet()
                assert fallback is not None
                assert fallback.address.startswith("0x")

    @pytest.mark.asyncio
    async def test_setup_client_session_force_in_process(self):
        """Verifies force_in_process=True initializes in-process app directly without network probing."""
        import httpx
        from scripts.client_agent_x402 import setup_client_session

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_probe_get:
            client, is_live, app = await setup_client_session("http://127.0.0.1:8000", force_in_process=True)
            try:
                assert is_live is False
                assert app is not None
                mock_probe_get.assert_not_called()
                assert client.timeout.read is not None
                assert client.timeout.read >= 30.0
            finally:
                await client.aclose()

    def test_fetch_live_contract_transaction_success(self):
        """Scans mocked blocks and extracts authentic smart contract transaction with calldata."""
        from web3 import Web3 as RealWeb3
        from scripts.client_agent_x402 import fetch_live_contract_transaction

        with patch("scripts.client_agent_x402.Web3") as mock_w3_cls:
            mock_w3 = MagicMock()
            mock_w3_cls.return_value = mock_w3
            mock_w3_cls.HTTPProvider = MagicMock()
            mock_w3_cls.to_checksum_address.side_effect = RealWeb3.to_checksum_address
            mock_w3.is_connected.return_value = True
            mock_w3.eth.block_number = 100

            # 4 Transactions to test filtering
            # Tx 1: contract creation (to=None) -> skipped
            tx1 = {"to": None, "input": "0x"}
            # Tx 2: empty calldata -> skipped
            tx2 = {"to": "0x1111111111111111111111111111111111111111", "input": "0x"}
            # Tx 3: EOA transfer with code b"" -> skipped
            tx3 = {"to": "0x2222222222222222222222222222222222222222", "input": "0xa9059cbb00000000"}
            # Tx 4: Contract call with code b"\x60\x80" -> match!
            tx4 = {
                "to": "0x4200000000000000000000000000000000000006",
                "from": "0x3333333333333333333333333333333333333333",
                "input": "0xa9059cbb0000000000000000",
                "value": 500,
                "hash": bytes.fromhex("ab" * 32),
            }

            mock_block = MagicMock()
            mock_block.transactions = [tx1, tx2, tx3, tx4]
            mock_w3.eth.get_block.return_value = mock_block

            def mock_get_code(addr):
                if "2222" in str(addr):
                    return b""
                return b"\x60\x80"

            mock_w3.eth.get_code.side_effect = mock_get_code

            result = fetch_live_contract_transaction()
            assert result is not None
            assert result["selector"] == "0xa9059cbb"
            assert result["value_wei"] == 500
            assert result["block_number"] == 100
            assert result["tx_hash"] == "0x" + "ab" * 32
            assert result["target_address"] == "0x4200000000000000000000000000000000000006"
            assert result["from_address"] == "0x3333333333333333333333333333333333333333"
            assert result["calldata"] == "0xa9059cbb0000000000000000"

    def test_fetch_live_contract_transaction_rpc_offline_returns_none(self):
        """Returns None gracefully when candidate Web3 RPC endpoints are unreachable."""
        from scripts.client_agent_x402 import fetch_live_contract_transaction

        with patch("scripts.client_agent_x402.Web3") as mock_w3_cls:
            mock_w3 = MagicMock()
            mock_w3_cls.return_value = mock_w3
            mock_w3_cls.HTTPProvider = MagicMock()
            mock_w3.is_connected.return_value = False

            result = fetch_live_contract_transaction()
            assert result is None


class TestEIP3009APIIntegration:
    """
    Comprehensive test suite for EIP-3009 gasless micropayment integration:
    - create_eip3009_payment_header v2 envelopes, base64 encoding, and SDK guard
    - parse_x402_header pure envelope extraction without convenience fields
    - HTTPX402Facilitator synchronous EIP-3009 verification and settlement paths
    - FastAPI POST /evaluate end-to-end payment gatekeeping, verification, settlement, and persistence
    - build_402_response EIP-712 domain metadata verification
    """

    def test_create_eip3009_payment_header_valid_v2_envelope(self):
        """Generates a valid EIP-3009 v2 JSON header with authorization, signature, and accepted fields."""
        from src.x402_payment import create_eip3009_payment_header

        buyer_account = Account.create()
        pay_to = "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"
        amount_atomic = 10000

        header_json = create_eip3009_payment_header(
            account=buyer_account,
            pay_to_address=pay_to,
            amount_atomic=amount_atomic,
            network="eip155:84532",
        )
        data = json.loads(header_json)

        assert data["x402Version"] == 2
        assert "payload" in data
        assert "authorization" in data["payload"]
        assert "signature" in data["payload"]
        assert data["payload"]["signature"].startswith("0x")

        auth = data["payload"]["authorization"]
        for required_field in ("from", "to", "value", "validAfter", "validBefore", "nonce"):
            assert required_field in auth
        assert auth["from"].lower() == buyer_account.address.lower()
        assert auth["to"].lower() == pay_to.lower()
        assert int(auth["value"]) == amount_atomic
        assert auth["nonce"].startswith("0x")

        assert "accepted" in data
        assert data["accepted"]["network"] == "eip155:84532"
        assert int(data["accepted"]["amount"]) == amount_atomic

        # Top-level convenience fields
        assert data["payment_id"] == auth["nonce"]
        assert data["payer_address"].lower() == buyer_account.address.lower()
        assert data["amount_atomic"] == amount_atomic
        assert data["amount_usdc"] == 0.01
        assert data["network"] == "eip155:84532"
        assert data["signature"] == data["payload"]["signature"]

    def test_create_eip3009_payment_header_base64_roundtrip(self):
        """Base64-encoded EIP-3009 header round-trips cleanly through parse_x402_header."""
        from src.x402_payment import create_eip3009_payment_header, parse_x402_header

        buyer_account = Account.create()
        pay_to = "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"
        amount_atomic = 25000

        b64_header = create_eip3009_payment_header(
            account=buyer_account,
            pay_to_address=pay_to,
            amount_atomic=amount_atomic,
            network="eip155:84532",
            as_base64=True,
        )

        assert not b64_header.strip().startswith("{")

        parsed = parse_x402_header(b64_header)
        assert parsed["amount_atomic"] == 25000
        assert parsed["amount_usdc"] == 0.025
        assert parsed["payer_address"].lower() == buyer_account.address.lower()
        assert parsed["network"] == "eip155:84532"
        assert parsed["signature"].startswith("0x")
        assert parsed["payment_id"].startswith("0x")
        assert "payload" in parsed
        assert "accepted" in parsed
        assert parsed["payload"]["authorization"]["to"].lower() == pay_to.lower()

    def test_create_eip3009_payment_header_raises_without_sdk(self):
        """Raises RuntimeError if HAS_X402_SDK is False."""
        from src.x402_payment import create_eip3009_payment_header

        buyer_account = Account.create()
        pay_to = "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"

        with patch("src.x402_payment.HAS_X402_SDK", False):
            with pytest.raises(RuntimeError, match="x402 SDK is required"):
                create_eip3009_payment_header(
                    account=buyer_account,
                    pay_to_address=pay_to,
                    amount_atomic=10000,
                )

    def test_parse_x402_header_pure_v2_envelope(self):
        """Extracts all required fields from a pure v2 envelope with zero top-level convenience fields."""
        from src.x402_payment import parse_x402_header

        pure_v2_envelope = {
            "x402Version": 2,
            "payload": {
                "signature": "0x1234",
                "authorization": {
                    "from": "0x4200000000000000000000000000000000000006",
                    "to": "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63",
                    "value": "15000",
                    "validAfter": "0",
                    "validBefore": "9999999999",
                    "nonce": "0xabc123",
                },
            },
            "accepted": {
                "scheme": "exact",
                "network": "eip155:84532",
                "amount": "15000",
            },
        }

        json_str = json.dumps(pure_v2_envelope)
        parsed = parse_x402_header(json_str)

        assert parsed["payment_id"] == "0xabc123"
        assert parsed["payer_address"] == "0x4200000000000000000000000000000000000006"
        assert parsed["amount_atomic"] == 15000
        assert parsed["amount_usdc"] == 0.015
        assert parsed["signature"] == "0x1234"
        assert parsed["network"] == "eip155:84532"
        assert parsed["payload"] == pure_v2_envelope["payload"]
        assert parsed["accepted"] == pure_v2_envelope["accepted"]
        assert parsed["x402Version"] == 2

    @pytest.mark.asyncio
    async def test_httpx402_facilitator_rejects_insufficient_amount_without_remote_call(self):
        """Rejects insufficient payment amount without invoking remote facilitator."""
        from src.x402_payment import HTTPX402Facilitator, X402Config

        facilitator = HTTPX402Facilitator(facilitator_url="https://x402.org/facilitator")
        cfg = X402Config(enabled=True, network="eip155:84532")
        payment_data = {
            "payment_id": "0xnonce1",
            "payer_address": "0x4200000000000000000000000000000000000006",
            "amount_atomic": 5000,
            "amount_usdc": 0.005,
            "signature": "0x1234",
            "network": "eip155:84532",
            "payload": {
                "signature": "0x1234",
                "authorization": {
                    "from": "0x4200000000000000000000000000000000000006",
                    "to": cfg.pay_to_address,
                    "value": "5000",
                    "nonce": "0xnonce1",
                },
            },
        }

        with patch("src.x402_payment.x402ResourceServerSync") as mock_srv_cls, \
             patch.object(facilitator, "_verify_eip3009_sync") as mock_sync:
            res = await facilitator.verify(payment_data, required_atomic=10000, config=cfg)
            assert res.valid is False
            assert "Insufficient payment amount" in res.reason
            mock_srv_cls.assert_not_called()
            mock_sync.assert_not_called()

    @pytest.mark.asyncio
    async def test_httpx402_facilitator_rejects_network_mismatch_without_remote_call(self):
        """Rejects CAIP-2 network mismatch without invoking remote facilitator."""
        from src.x402_payment import HTTPX402Facilitator, X402Config

        facilitator = HTTPX402Facilitator(facilitator_url="https://x402.org/facilitator")
        cfg = X402Config(enabled=True, network="eip155:84532")
        payment_data = {
            "payment_id": "0xnonce2",
            "payer_address": "0x4200000000000000000000000000000000000006",
            "amount_atomic": 10000,
            "amount_usdc": 0.01,
            "signature": "0x1234",
            "network": "eip155:1",  # Mismatched network (Ethereum Mainnet vs Base Sepolia)
            "payload": {
                "signature": "0x1234",
                "authorization": {
                    "from": "0x4200000000000000000000000000000000000006",
                    "to": cfg.pay_to_address,
                    "value": "10000",
                    "nonce": "0xnonce2",
                },
            },
        }

        with patch("src.x402_payment.x402ResourceServerSync") as mock_srv_cls, \
             patch.object(facilitator, "_verify_eip3009_sync") as mock_sync:
            res = await facilitator.verify(payment_data, required_atomic=10000, config=cfg)
            assert res.valid is False
            assert "Network mismatch" in res.reason
            mock_srv_cls.assert_not_called()
            mock_sync.assert_not_called()

    @pytest.mark.asyncio
    async def test_httpx402_facilitator_verify_success_mocked(self):
        """Verifies facilitator.verify returns valid=True when x402ResourceServerSync returns is_valid=True."""
        from src.x402_payment import HTTPX402Facilitator, X402Config, create_eip3009_payment_header, parse_x402_header

        buyer_account = Account.create()
        cfg = X402Config(enabled=True, network="eip155:84532")
        raw_header = create_eip3009_payment_header(buyer_account, cfg.pay_to_address, 10000, network=cfg.network)
        payment_data = parse_x402_header(raw_header)

        facilitator = HTTPX402Facilitator(facilitator_url="https://x402.org/facilitator")

        with patch("src.x402_payment.x402ResourceServerSync") as mock_srv_cls:
            mock_srv = MagicMock()
            mock_srv_cls.return_value = mock_srv
            mock_resp = MagicMock(spec=["verify"])
            mock_resp.verify = MagicMock(spec=["is_valid"])
            mock_resp.verify.is_valid = True
            mock_srv.verify_payment.return_value = mock_resp

            res = await facilitator.verify(payment_data, required_atomic=10000, config=cfg)
            assert res.valid is True
            assert res.reason is None
            assert res.amount_atomic == 10000
            assert res.payer_address.lower() == buyer_account.address.lower()
            mock_srv.verify_payment.assert_called_once()

    @pytest.mark.asyncio
    async def test_httpx402_facilitator_verify_failure_mocked(self):
        """Verifies facilitator.verify returns valid=False with reason when is_valid=False."""
        from src.x402_payment import HTTPX402Facilitator, X402Config, create_eip3009_payment_header, parse_x402_header

        buyer_account = Account.create()
        cfg = X402Config(enabled=True, network="eip155:84532")
        raw_header = create_eip3009_payment_header(buyer_account, cfg.pay_to_address, 10000, network=cfg.network)
        payment_data = parse_x402_header(raw_header)

        facilitator = HTTPX402Facilitator(facilitator_url="https://x402.org/facilitator")

        with patch("src.x402_payment.x402ResourceServerSync") as mock_srv_cls:
            mock_srv = MagicMock()
            mock_srv_cls.return_value = mock_srv
            mock_resp = MagicMock(spec=["verify"])
            mock_resp.verify = MagicMock(spec=["is_valid", "invalid_reason", "invalid_message"])
            mock_resp.verify.is_valid = False
            mock_resp.verify.invalid_reason = "invalid_exact_evm_signature"
            mock_resp.verify.invalid_message = "Cryptographic signature validation failed"
            mock_srv.verify_payment.return_value = mock_resp

            res = await facilitator.verify(payment_data, required_atomic=10000, config=cfg)
            assert res.valid is False
            assert "invalid_exact_evm_signature" in res.reason
            assert "Cryptographic signature validation failed" in res.reason
            mock_srv.verify_payment.assert_called_once()

    @pytest.mark.asyncio
    async def test_httpx402_facilitator_settle_success_mocked(self):
        """Verifies facilitator.settle returns settled=True and tx_hash on success."""
        from src.x402_payment import HTTPX402Facilitator, X402Config, create_eip3009_payment_header, parse_x402_header

        buyer_account = Account.create()
        cfg = X402Config(enabled=True, network="eip155:84532")
        raw_header = create_eip3009_payment_header(buyer_account, cfg.pay_to_address, 10000, network=cfg.network)
        payment_data = parse_x402_header(raw_header)

        facilitator = HTTPX402Facilitator(facilitator_url="https://x402.org/facilitator")
        fake_tx = "0x" + "c" * 64

        with patch("src.x402_payment.x402ResourceServerSync") as mock_srv_cls:
            mock_srv = MagicMock()
            mock_srv_cls.return_value = mock_srv
            mock_resp = MagicMock(spec=["success", "transaction"])
            mock_resp.success = True
            mock_resp.transaction = fake_tx
            mock_srv.settle_payment.return_value = mock_resp

            res = await facilitator.settle(payment_data, required_atomic=10000, config=cfg)
            assert res.settled is True
            assert res.tx_hash == fake_tx
            assert res.error is None
            mock_srv.settle_payment.assert_called_once()

    @pytest.mark.asyncio
    async def test_httpx402_facilitator_settle_failure_mocked(self):
        """Verifies facilitator.settle returns settled=False with error message when success=False."""
        from src.x402_payment import HTTPX402Facilitator, X402Config, create_eip3009_payment_header, parse_x402_header

        buyer_account = Account.create()
        cfg = X402Config(enabled=True, network="eip155:84532")
        raw_header = create_eip3009_payment_header(buyer_account, cfg.pay_to_address, 10000, network=cfg.network)
        payment_data = parse_x402_header(raw_header)

        facilitator = HTTPX402Facilitator(facilitator_url="https://x402.org/facilitator")

        with patch("src.x402_payment.x402ResourceServerSync") as mock_srv_cls:
            mock_srv = MagicMock()
            mock_srv_cls.return_value = mock_srv
            mock_resp = MagicMock(spec=["success", "error_reason", "error_message"])
            mock_resp.success = False
            mock_resp.error_reason = "settlement_reverted"
            mock_resp.error_message = "ERC20: transfer amount exceeds balance"
            mock_srv.settle_payment.return_value = mock_resp

            res = await facilitator.settle(payment_data, required_atomic=10000, config=cfg)
            assert res.settled is False
            assert "settlement_reverted" in res.error
            assert "ERC20: transfer amount exceeds balance" in res.error

    @pytest.mark.asyncio
    async def test_httpx402_facilitator_settle_exception_handling(self):
        """Verifies facilitator.settle catches network/facilitator exceptions cleanly without crashing."""
        from src.x402_payment import HTTPX402Facilitator, X402Config, create_eip3009_payment_header, parse_x402_header

        buyer_account = Account.create()
        cfg = X402Config(enabled=True, network="eip155:84532")
        raw_header = create_eip3009_payment_header(buyer_account, cfg.pay_to_address, 10000, network=cfg.network)
        payment_data = parse_x402_header(raw_header)

        facilitator = HTTPX402Facilitator(facilitator_url="https://x402.org/facilitator")

        with patch("src.x402_payment.x402ResourceServerSync") as mock_srv_cls:
            mock_srv = MagicMock()
            mock_srv_cls.return_value = mock_srv
            mock_srv.settle_payment.side_effect = ConnectionResetError("Facilitator connection dropped")

            res = await facilitator.settle(payment_data, required_atomic=10000, config=cfg)
            assert res.settled is False
            assert "Facilitator settlement error" in res.error
            assert "Facilitator connection dropped" in res.error

    @pytest.mark.asyncio
    async def test_fastapi_evaluate_e2e_with_eip3009_header_and_httpx402_facilitator(self):
        """End-to-End FastAPI POST /evaluate flow with EIP-3009 signed header, verification, settlement, and persistence."""
        import httpx
        from src.api import create_app
        from src.storage import AgentStorage
        from src.schemas import FinalAgentResponse, DeterministicResult
        from src.x402_payment import (
            create_eip3009_payment_header,
            X402Config,
            HTTPX402Facilitator,
            VerificationResult,
            SettlementResult,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "test_e2e.db")
            storage = AgentStorage(db_path=db_path)
            await storage.initialize()

            buyer_account = Account.create()
            fake_tx_hash = "0x" + "e" * 64

            mock_engine = MagicMock()
            mock_engine.storage = storage
            mock_det_result = DeterministicResult(
                passed=True,
                reason="All deterministic conditions satisfied",
                observed_data={},
                error=None,
            )
            fake_agent_resp = FinalAgentResponse(
                rule_id="eip3009-rule-e2e",
                chain_id=84532,
                deterministic_check=mock_det_result,
                llm_invoked=False,
            )
            mock_engine.process_rule = AsyncMock(return_value=fake_agent_resp)

            cfg = X402Config(
                enabled=True,
                use_live_facilitator=True,
                network="eip155:84532",
                price_per_eval_usdc=0.01,
            )
            facilitator = HTTPX402Facilitator(facilitator_url="https://x402.org/facilitator")

            def mock_verify_sync(*args, **kwargs):
                return VerificationResult(
                    valid=True,
                    payment_id=kwargs.get("payment_id", "0xdefault"),
                    payer_address=kwargs.get("payer_address", buyer_account.address),
                    amount_atomic=kwargs.get("amount_atomic", 10000),
                    amount_usdc=kwargs.get("amount_usdc", 0.01),
                )

            def mock_settle_sync(*args, **kwargs):
                return SettlementResult(settled=True, tx_hash=fake_tx_hash)

            facilitator._verify_eip3009_sync = mock_verify_sync
            facilitator._settle_eip3009_sync = mock_settle_sync

            app = create_app(
                engine=mock_engine,
                storage=storage,
                x402_config=cfg,
                facilitator=facilitator,
            )

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                raw_header = create_eip3009_payment_header(
                    account=buyer_account,
                    pay_to_address=cfg.pay_to_address,
                    amount_atomic=10000,
                    network=cfg.network,
                )

                rule_payload = {
                    "rule_id": "eip3009-rule-e2e",
                    "chain_id": 84532,
                    "deterministic": {
                        "target_address": "0x4200000000000000000000000000000000000006",
                        "required_function_selectors": [],
                        "min_value_wei": 0,
                    },
                    "semantic": {
                        "enabled": False,
                        "policy_prompt": "No semantic evaluation needed",
                    },
                }

                # 1. Unauthenticated request returns HTTP 402 Payment Required
                resp_402 = await client.post("/evaluate", json=rule_payload)
                assert resp_402.status_code == 402

                # 2. Authenticated request with valid EIP-3009 header returns HTTP 200 OK
                resp_200 = await client.post(
                    "/evaluate",
                    json=rule_payload,
                    headers={"x-payment": raw_header},
                )
                assert resp_200.status_code == 200
                data = resp_200.json()
                assert data["payment"] is not None
                assert data["payment"]["tx_hash"] == fake_tx_hash
                assert data["payment"]["amount_atomic"] == 10000

                # 3. GET /payments verifies ledger persistence
                p_resp = await client.get("/payments")
                assert p_resp.status_code == 200
                payments = p_resp.json()
                assert len(payments) == 1
                assert payments[0]["tx_hash"] == fake_tx_hash
                assert payments[0]["payment_id"] == data["payment"]["payment_id"]
                assert payments[0]["payer_address"].lower() == buyer_account.address.lower()

                # 4. Replay attempt returns HTTP 402 with replay detected
                replay_resp = await client.post(
                    "/evaluate",
                    json=rule_payload,
                    headers={"x-payment": raw_header},
                )
                assert replay_resp.status_code == 402
                assert "replay detected" in replay_resp.json()["message"].lower()

    def test_build_402_response_eip712_domain_metadata(self):
        """Verifies build_402_response contains usdcAddress and EIP-712 extra domain metadata."""
        from src.x402_payment import build_402_response, X402Config

        cfg = X402Config(
            enabled=True,
            network="eip155:84532",
            pay_to_address="0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63",
        )
        response = build_402_response(cfg, "/evaluate", 0.01)

        assert response.status_code == 402
        body = json.loads(response.body)

        assert "accepts" in body
        assert len(body["accepts"]) == 1
        accept_entry = body["accepts"][0]

        assert accept_entry["scheme"] == "exact"
        assert accept_entry["network"] == "eip155:84532"
        assert accept_entry["usdcAddress"] == cfg.usdc_contract_address
        assert accept_entry["extra"] == {"name": "USDC", "version": "2"}
        assert accept_entry["maxAmountRequired"] == "10000"


