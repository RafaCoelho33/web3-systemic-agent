"""
Utility Script: Setup & Inspect Persistent Buyer Wallet for Base Sepolia.

Generates or loads a persistent buyer testnet keypair stored in
`scripts/.buyer_wallet.json`, connects to the Base Sepolia testnet,
queries both ETH and native USDC balances, and provides funding instructions
for the Circle USDC Faucet and Base Sepolia ETH faucets.
"""

import json
import os
import sys
from typing import Dict, Any

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

# Base Sepolia Configuration Constants
DEFAULT_RPC = "https://sepolia.base.org"
BASE_SEPOLIA_CHAIN_ID = 84532
USDC_CONTRACT_ADDRESS = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
WALLET_FILE = os.path.join(_CURRENT_DIR, ".buyer_wallet.json")

# Minimal ERC-20 ABI for querying balanceOf
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


def load_or_create_buyer_wallet(wallet_path: str = WALLET_FILE) -> Dict[str, str]:
    """
    Loads an existing buyer keypair from wallet_path or generates a new one.

    Returns:
        dict: Containing 'address' (checksummed) and 'private_key' (hex string).
    """
    if os.path.exists(wallet_path):
        try:
            with open(wallet_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            address = data.get("address")
            private_key = data.get("private_key")
            if address and private_key:
                # Validate keypair consistency
                account = Account.from_key(private_key)
                checksum_address = Web3.to_checksum_address(account.address)
                return {
                    "address": checksum_address,
                    "private_key": private_key,
                    "created": False,
                }
        except Exception as e:
            print(f"[!] Warning reading existing wallet file ({e}). Generating new wallet.")

    # Generate new keypair
    account = Account.create()
    raw_key = account.key.hex()
    private_key = raw_key if raw_key.startswith("0x") else f"0x{raw_key}"
    wallet_data = {
        "address": Web3.to_checksum_address(account.address),
        "private_key": private_key,
    }

    with open(wallet_path, "w", encoding="utf-8") as f:
        json.dump(wallet_data, f, indent=2)

    wallet_data["created"] = True
    return wallet_data


def inspect_buyer_balances(address: str, rpc_url: str = None) -> Dict[str, Any]:
    """
    Connects to Base Sepolia RPC and retrieves ETH and native USDC balances.

    Args:
        address: EVM address to inspect.
        rpc_url: Optional RPC endpoint; defaults to BASE_SEPOLIA_RPC env or DEFAULT_RPC.

    Returns:
        dict: Balances and network status.
    """
    effective_rpc = rpc_url or os.getenv("BASE_SEPOLIA_RPC", DEFAULT_RPC)
    w3 = Web3(Web3.HTTPProvider(effective_rpc))
    if not w3.is_connected():
        return {
            "connected": False,
            "error": f"Failed to connect to Base Sepolia RPC at {effective_rpc}",
        }

    checksum_addr = Web3.to_checksum_address(address)
    usdc_addr = Web3.to_checksum_address(USDC_CONTRACT_ADDRESS)

    # 1. Inspect ETH Balance
    eth_balance_wei = w3.eth.get_balance(checksum_addr)
    eth_balance = float(w3.from_wei(eth_balance_wei, "ether"))

    # 2. Inspect USDC Balance (6 decimals)
    contract = w3.eth.contract(address=usdc_addr, abi=USDC_ABI)
    usdc_units = contract.functions.balanceOf(checksum_addr).call()
    usdc_balance = usdc_units / 1_000_000.0

    return {
        "connected": True,
        "chain_id": w3.eth.chain_id,
        "block_number": w3.eth.block_number,
        "eth_balance_wei": eth_balance_wei,
        "eth_balance": eth_balance,
        "usdc_units": usdc_units,
        "usdc_balance": usdc_balance,
    }


def main() -> None:
    """Main execution flow for buyer wallet setup and inspection."""
    load_env_if_present()
    rpc_url = os.getenv("BASE_SEPOLIA_RPC", DEFAULT_RPC)

    width = 74
    print("=" * width)
    print(" Web3 Buyer Agent Wallet Setup & Inspection (Base Sepolia)")
    print("=" * width)

    wallet_info = load_or_create_buyer_wallet()
    address = wallet_info["address"]
    was_created = wallet_info.get("created", False)

    if was_created:
        print(f"[+] Created new buyer wallet keypair.")
    else:
        print(f"[*] Loaded existing buyer wallet keypair.")

    print(f"    File:    {WALLET_FILE}")
    print(f"    Address: {address}")
    print("-" * width)

    print(f"[*] Connecting to Base Sepolia RPC ({rpc_url})...")
    status = inspect_buyer_balances(address, rpc_url=rpc_url)

    if not status.get("connected"):
        print(f"[!] Error: {status.get('error')}")
        return

    print(f"[+] Connected to Base Sepolia (Chain ID: {status['chain_id']}, Block: {status['block_number']})")
    print(f"    - ETH Balance:  {status['eth_balance']:.6f} ETH ({status['eth_balance_wei']} wei)")
    print(f"    - USDC Balance: {status['usdc_balance']:.4f} USDC ({status['usdc_units']} atomic units)")
    print("-" * width)

    print("Funding Instructions for Circle Faucet & Gas:")
    print(" 1. Circle USDC Faucet (Free Base Sepolia USDC):")
    print("    URL:     https://faucet.circle.com/")
    print("    Network: Select 'Base Sepolia'")
    print("    Token:   Select 'USDC'")
    print(f"    Address: {address}")
    print()
    print(" 2. Base Sepolia Gas Faucets (Free Testnet ETH for transaction fees):")
    print("    - Chainlink: https://faucets.chain.link/base-sepolia")
    print("    - Alchemy:   https://www.alchemy.com/faucets/base-sepolia")
    print("    - Superchain:https://superchainfaucet.com/base-sepolia")
    print("=" * width)


if __name__ == "__main__":
    main()
