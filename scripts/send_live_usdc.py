"""
Utility Script: Send Live Gasless USDC Micropayments on Base Sepolia.

Demonstrates Gasless EIP-3009 Settlement via the live x402 Public Facilitator (https://x402.org/facilitator)
using the official x402 SDK (x402ClientSync, x402ResourceServerSync, ResourceConfig,
HTTPFacilitatorClientSync, FacilitatorConfig, ExactEvmClientScheme, ExactEvmServerScheme).

With EIP-3009 transferWithAuthorization via https://x402.org/facilitator:
- The Buyer Wallet ONLY needs USDC (from Circle Faucet https://faucet.circle.com/).
- The Buyer Wallet does NOT need any Base Sepolia ETH for gas (the x402 facilitator pays gas on-chain).
- The payment payload is cryptographically signed using EIP-712 / EIP-3009 transferWithAuthorization.
- The x402 facilitator verifies the signature and simulates execution on Base Sepolia contract.
- Upon valid settlement, the on-chain transaction hash is recorded into AgentStorage (data/agent.db).
"""

import asyncio
from datetime import datetime, timezone
import json
import os
import sys
from typing import Dict, Any, Optional

# Ensure UTF-8 output across standard streams
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Configure root directory and environment
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from eth_account import Account
from web3 import Web3

from x402 import (
    x402ClientSync,
    x402ResourceServerSync,
    ResourceConfig,
    FacilitatorConfig,
)
from x402.http import HTTPFacilitatorClientSync
from x402.mechanisms.evm.exact import (
    ExactEvmClientScheme,
    ExactEvmServerScheme,
)

# Base Sepolia Configuration Constants
DEFAULT_RPC = "https://sepolia.base.org"
BASE_SEPOLIA_CHAIN_ID = 84532
BASE_SEPOLIA_NETWORK = "eip155:84532"
USDC_CONTRACT_ADDRESS = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
DEFAULT_PAY_TO = "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"
DEFAULT_FACILITATOR_URL = "https://x402.org/facilitator"
WALLET_FILE = os.path.join(_CURRENT_DIR, ".buyer_wallet.json")
TRANSFER_AMOUNT_UNITS = 10_000  # 0.01 USDC (6 decimals)

# Minimal ERC-20 ABI for balanceOf
USDC_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    }
]


def load_env_if_present() -> None:
    """Loads root .env variables if present without polluting during test import."""
    try:
        import dotenv
        env_path = os.path.join(_ROOT_DIR, ".env")
        if os.path.exists(env_path):
            dotenv.load_dotenv(env_path, override=False)
    except Exception:
        pass


def load_buyer_wallet(wallet_path: str = WALLET_FILE) -> Optional[Account]:
    """Loads the buyer Account instance from the persistent JSON file."""
    if not os.path.exists(wallet_path):
        return None
    try:
        with open(wallet_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        private_key = data.get("private_key")
        if not private_key:
            return None
        return Account.from_key(private_key)
    except Exception as e:
        print(f"[!] Error loading wallet from {wallet_path}: {e}")
        return None


def record_settled_payment(
    payment_id: str,
    payer_address: str,
    pay_to_address: str,
    amount_usdc: float,
    amount_atomic: int,
    tx_hash: str,
    db_path: Optional[str] = None,
) -> bool:
    """Records an on-chain settled payment receipt into AgentStorage SQLite ledger."""
    try:
        try:
            from src.schemas import PaymentReceipt
            from src.storage import AgentStorage
        except ImportError:
            from schemas import PaymentReceipt
            from storage import AgentStorage

        storage = AgentStorage(db_path=db_path) if db_path else AgentStorage()
        receipt = PaymentReceipt(
            payment_id=payment_id,
            payer_address=payer_address,
            pay_to_address=pay_to_address,
            amount_usdc=amount_usdc,
            amount_atomic=amount_atomic,
            network=BASE_SEPOLIA_NETWORK,
            asset="USDC",
            tx_hash=tx_hash,
            endpoint="/api/v1/evaluate",
            settled_at=datetime.now(timezone.utc).isoformat(),
        )

        async def _save():
            await storage.initialize()
            return await storage.record_payment(receipt)

        res = asyncio.run(_save())
        return res is not None
    except Exception as exc:
        print(f"[!] Warning: Could not record payment in AgentStorage: {exc}")
        return False


def send_live_usdc(
    amount_units: int = TRANSFER_AMOUNT_UNITS,
    recipient_address: Optional[str] = None,
    rpc_url: Optional[str] = None,
    facilitator_url: Optional[str] = None,
    wallet_path: str = WALLET_FILE,
    db_path: Optional[str] = None,
) -> bool:
    """
    Executes a Gasless EIP-3009 payment via the live x402 Public Facilitator.

    Lifecycle:
    1. Loads persistent buyer wallet from `scripts/.buyer_wallet.json`.
    2. Resolves merchant pay_to address from .env (fallback: DEFAULT_PAY_TO).
    3. Checks buyer's on-chain USDC balance on Base Sepolia.
    4. Connects to live x402 facilitator (https://x402.org/facilitator) and builds EIP-3009 payment payload.
    5. Calls srv.verify_payment(payload, reqs[0]).
       - If invalid, prints detailed simulated execution error and Circle faucet instructions.
       - If valid, settles on-chain with srv.settle_payment, prints explorer URLs, and stores receipt in agent.db.

    Returns:
        bool: True if payment successfully settled on-chain, False otherwise.
    """
    width = 78
    print("=" * width)
    print(" Web3 Gasless USDC Payment Dispatcher (x402 EIP-3009 Settlement)")
    print("=" * width)

    # 1. Load Persistent Buyer Wallet
    account = load_buyer_wallet(wallet_path)
    if not account:
        print("[!] Error: Buyer wallet keypair not found.")
        print(f"    Expected path: {wallet_path}")
        print("    Please run `python scripts/setup_buyer_wallet.py` first to generate it.")
        print("=" * width)
        return False

    buyer_address = Web3.to_checksum_address(account.address)

    # 2. Resolve Destination Address
    raw_pay_to = recipient_address or os.getenv("PAY_TO_ADDRESS", DEFAULT_PAY_TO)
    pay_to = Web3.to_checksum_address(raw_pay_to)
    price_usdc = round(amount_units / 1_000_000.0, 6)

    print(f"[*] Buyer Address:        {buyer_address}")
    print(f"[*] Pay-To Address:       {pay_to}")
    print(f"[*] Settlement Scheme:    EIP-3009 Gasless Authorization (ExactEvm)")
    print(f"[*] Transfer Amount:      {price_usdc:.4f} USDC ({amount_units} atomic units)")
    print("-" * width)

    # 3. Check On-Chain Balances on Base Sepolia
    effective_rpc = rpc_url or os.getenv("BASE_SEPOLIA_RPC", DEFAULT_RPC)
    try:
        w3 = Web3(Web3.HTTPProvider(effective_rpc))
        if w3.is_connected():
            eth_balance_wei = w3.eth.get_balance(buyer_address)
            eth_balance = float(w3.from_wei(eth_balance_wei, "ether"))

            usdc_contract = w3.eth.contract(
                address=Web3.to_checksum_address(USDC_CONTRACT_ADDRESS),
                abi=USDC_ABI,
            )
            usdc_balance_units = usdc_contract.functions.balanceOf(buyer_address).call()
            usdc_balance = usdc_balance_units / 1_000_000.0

            print(f"[*] Current Buyer Balances:")
            print(f"    - ETH (Gas): {eth_balance:.6f} ETH (0 ETH needed for Gasless EIP-3009!)")
            print(f"    - USDC:      {usdc_balance:.4f} USDC ({usdc_balance_units} atomic units)")
        else:
            print(f"[!] Warning: Could not connect to RPC ({effective_rpc}). Proceeding with facilitator...")
    except Exception as exc:
        print(f"[!] Balance query notice ({exc}). Proceeding with facilitator...")

    print("-" * width)

    # 4. Demonstrate Live Call to x402 Facilitator
    target_fac_url = facilitator_url or os.getenv("FACILITATOR_URL", DEFAULT_FACILITATOR_URL)
    print(f"[*] Connecting to x402 Facilitator: {target_fac_url}...")

    try:
        # Initialize Facilitator Client & Resource Server
        fac = HTTPFacilitatorClientSync(FacilitatorConfig(url=target_fac_url))
        srv = x402ResourceServerSync(fac)
        srv.register(BASE_SEPOLIA_NETWORK, ExactEvmServerScheme())
        srv.initialize()

        # Build Payment Requirements for Base Sepolia USDC
        reqs = srv.build_payment_requirements(
            ResourceConfig(
                scheme="exact",
                network=BASE_SEPOLIA_NETWORK,
                pay_to=pay_to,
                price=price_usdc,
            )
        )
        if not reqs:
            print("[!] Error: No payment requirements generated.")
            print("=" * width)
            return False

        # Initialize Buyer x402 Client with Buyer Keypair
        cli = x402ClientSync()
        cli.register(BASE_SEPOLIA_NETWORK, ExactEvmClientScheme(account))

        # Create Signed EIP-3009 Payment Payload
        print("[*] Generating EIP-712 / EIP-3009 authorization signature...")
        payment_required_resp = srv.create_payment_required_response(reqs)
        payload = cli.create_payment_payload(payment_required_resp)

        # Verify Payment with Facilitator
        print(f"[*] Dispatching verify request to {target_fac_url}/verify...")
        v = srv.verify_payment(payload, reqs[0])

        if not v.verify.is_valid:
            invalid_reason = getattr(v.verify, "invalid_reason", "unknown")
            invalid_message = getattr(v.verify, "invalid_message", "Payment verification rejected")
            print("-" * width)
            print("[!] Facilitator Verification Response: INVALID")
            print(f"    - Invalid Reason: {invalid_reason}")
            print()
            print(f"    - Simulated Execution Trace:")
            for line in str(invalid_message).strip().splitlines():
                print(f"      {line}")
            print()
            print("[*] Facilitator verified EIP-3009 signature and simulated `transferWithAuthorization`")
            print(f"    on Base Sepolia contract: {USDC_CONTRACT_ADDRESS}.")
            print("-" * width)
            print(">>> 1-STEP FUNDING ACTION REQUIRED (NO ETH GAS NEEDED!): <<<")
            print(" 1. Visit Circle Faucet: https://faucet.circle.com/")
            print(" 2. Select 'Base Sepolia' -> 'USDC'")
            print(f" 3. Paste Buyer Address: {buyer_address}")
            print(" 4. Click 'Send 10 USDC' (NO ETH gas needed; x402 facilitator pays gas!)")
            print(" 5. Then re-run: python scripts/send_live_usdc.py")
            print("=" * width)
            return False

        # If Valid, Settle Payment On-Chain
        print("-" * width)
        print("[+] Facilitator Verification Succeeded! Broadcasting on-chain settlement...")
        s = srv.settle_payment(payload, reqs[0])

        settle_success = getattr(s, "success", False)
        if not settle_success and hasattr(s, "settle"):
            settle_success = getattr(s.settle, "success", False)

        if not settle_success:
            err_reason = getattr(s, "error_reason", "unknown")
            err_msg = getattr(s, "error_message", "Unknown error")
            print(f"[!] Settlement failed on facilitator: {err_reason} - {err_msg}")
            print("=" * width)
            return False

        # Extract transaction hash supporting both direct and nested settle attributes
        tx_hash = (
            getattr(s, "transaction", None)
            or (getattr(s.settle, "transaction", None) if hasattr(s, "settle") else None)
        )
        print(f"[+] LIVE ON-CHAIN TX HASH: {tx_hash}")
        print(f"[+] VERIFY ON BASESCAN:   https://sepolia.basescan.org/tx/{tx_hash}")
        print(f"[+] MERCHANT WALLET:      https://sepolia.basescan.org/address/{pay_to}#tokentxns")

        # Extract payment nonce / id from payload authorization
        payment_id = None
        try:
            payload_dict = payload.model_dump()
            payment_id = payload_dict.get("payload", {}).get("authorization", {}).get("nonce")
        except Exception:
            pass
        if not payment_id:
            payment_id = f"0x{os.urandom(32).hex()}"

        # Record receipt into AgentStorage
        recorded = record_settled_payment(
            payment_id=payment_id,
            payer_address=buyer_address,
            pay_to_address=pay_to,
            amount_usdc=price_usdc,
            amount_atomic=amount_units,
            tx_hash=tx_hash,
            db_path=db_path,
        )
        if recorded:
            print(f"[+] Settlement receipt recorded in AgentStorage (data/agent.db)")
            print(f"    Verify telemetry with: python -m src.report")

        print("=" * width)
        return True

    except Exception as exc:
        print(f"[!] Error interacting with x402 facilitator: {exc}")
        print("=" * width)
        return False


def main() -> None:
    """CLI Entry point for send_live_usdc."""
    load_env_if_present()
    success = send_live_usdc()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
