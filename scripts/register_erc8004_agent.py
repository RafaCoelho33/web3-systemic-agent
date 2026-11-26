"""
ERC-8004 ("Trustless Agents") On-Chain Identity Manifest & Calldata Generator.

Generates, validates, and ABI-encodes the ERC-8004 registration manifest
(`https://eips.ethereum.org/EIPS/eip-8004#registration-v1`) for indexing the
Web3 Systemic Agent on Base Mainnet (`8004scan.io` / `8004agents.ai`), including
A2A, MCP streamable-http, x402 discovery, and REST security endpoints.

Also encodes the manifest as a self-contained `data:application/json;base64,...`
`agentURI` and generates the exact ABI calldata (`0xf2c298be` = `register(string)`)
ready for submission to an ERC-8004 Identity Registry contract.

Usage Examples:
    # 1. Dry-run generation, validation, and calldata inspection:
    python scripts/register_erc8004_agent.py --dry-run

    # 2. Custom public URL and payout wallet saved to JSON file:
    python scripts/register_erc8004_agent.py \\
        --public-url https://web3-systemic-agent.onrender.com \\
        --pay-to 0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63 \\
        --output erc8004-registration.json
"""

import argparse
import base64
import json
import os
import sys
from typing import Any, Dict, List, Optional

from web3 import Web3

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

DEFAULT_PUBLIC_URL = "https://web3-systemic-agent.onrender.com"
DEFAULT_PAY_TO_ADDRESS = "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"
ERC8004_TYPE_URI = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"
REGISTER_SELECTOR = "0xf2c298be"  # keccak256("register(string)")[:4]


def build_erc8004_registration_json(
    public_url: str,
    pay_to_address: str,
    version: str = "1.0.2",
) -> Dict[str, Any]:
    """
    Builds a canonical ERC-8004 ("Trustless Agents") registration JSON manifest
    describing the agent's A2A, MCP, x402, and REST endpoints on Base Mainnet.
    """
    base_url = str(public_url or "").strip().rstrip("/")
    if not base_url.startswith(("https://", "http://")):
        raise ValueError(f"Invalid public_url '{public_url}': must start with http:// or https://")

    if not pay_to_address or not Web3.is_address(pay_to_address):
        raise ValueError(f"Invalid pay_to_address '{pay_to_address}': expected valid EVM address")
    checksum_pay_to = Web3.to_checksum_address(pay_to_address)

    return {
        "type": ERC8004_TYPE_URI,
        "name": "Web3 Systemic Agent",
        "description": (
            "Autonomous Web3 Security & Governance Auditor with a Two-Stage Hybrid Pipeline "
            "(deterministic on-chain bytecode/proxy/preflight gatekeeping + Gemini LLM semantic "
            "audits) monetized via gasless x402 EIP-3009 USDC micropayments on Base."
        ),
        "version": str(version),
        "image": f"{base_url}/icon.svg",
        "active": True,
        "endpoints": [
            {
                "name": "A2A",
                "endpoint": f"{base_url}/.well-known/agent-card.json",
                "version": "0.3.0",
            },
            {
                "name": "MCP",
                "endpoint": f"{base_url}/mcp",
                "transport": "streamable-http",
                "version": "2024-11-05",
            },
            {
                "name": "x402",
                "endpoint": f"{base_url}/.well-known/x402",
                "version": "2.0",
            },
            {
                "name": "REST-token-check",
                "endpoint": f"{base_url}/token/check",
                "methods": ["GET", "POST"],
                "price_usdc": "0.005",
            },
            {
                "name": "REST-preflight",
                "endpoint": f"{base_url}/preflight",
                "methods": ["GET", "POST"],
                "price_usdc": "0.01",
            },
            {
                "name": "REST-audit",
                "endpoint": f"{base_url}/audit",
                "methods": ["GET", "POST"],
                "price_usdc": "0.015",
            },
            {
                "name": "REST-evaluate",
                "endpoint": f"{base_url}/evaluate",
                "methods": ["GET", "POST"],
                "price_usdc": "0.015",
            },
            {
                "name": "REST-audit-deep",
                "endpoint": f"{base_url}/audit/deep",
                "methods": ["GET", "POST"],
                "price_usdc": "0.25",
            },
            {
                "name": "REST-feed-recent",
                "endpoint": f"{base_url}/feed/recent",
                "methods": ["GET"],
                "price_usdc": "0",
            },
        ],
        "registrations": [],
        "supportedTrust": ["reputation"],
        "x402Support": True,
        "paymentWallet": checksum_pay_to,
    }


def validate_erc8004_registration_json(reg_json: Dict[str, Any]) -> None:
    """Validates required ERC-8004 registration fields, endpoint URLs, and payout wallet."""
    required_keys = (
        "type",
        "name",
        "description",
        "image",
        "endpoints",
        "registrations",
        "supportedTrust",
        "x402Support",
        "paymentWallet",
    )
    for key in required_keys:
        if key not in reg_json:
            raise ValueError(f"Missing required ERC-8004 field: '{key}'")

    if reg_json["type"] != ERC8004_TYPE_URI:
        raise ValueError(f"Unexpected ERC-8004 type: {reg_json['type']}")
    if not isinstance(reg_json["endpoints"], list) or len(reg_json["endpoints"]) < 3:
        raise ValueError("ERC-8004 'endpoints' must be a non-empty list of endpoint definitions")
    if not isinstance(reg_json["registrations"], list):
        raise ValueError("ERC-8004 'registrations' must be a list")
    if not isinstance(reg_json["supportedTrust"], list) or not reg_json["supportedTrust"]:
        raise ValueError("ERC-8004 'supportedTrust' must be a non-empty list")
    if not isinstance(reg_json["x402Support"], bool):
        raise ValueError("ERC-8004 'x402Support' must be a boolean")

    wallet = reg_json["paymentWallet"]
    if not isinstance(wallet, str) or not Web3.is_address(wallet):
        raise ValueError(f"Invalid ERC-8004 paymentWallet: {wallet}")
    if wallet != Web3.to_checksum_address(wallet):
        raise ValueError("ERC-8004 paymentWallet must be EIP-55 checksummed")

    endpoint_urls = [str(ep.get("endpoint", "")) for ep in reg_json["endpoints"] if isinstance(ep, dict)]
    required_suffixes = (
        "/.well-known/agent-card.json",
        "/mcp",
        "/.well-known/x402",
        "/token/check",
        "/preflight",
        "/audit",
        "/evaluate",
        "/audit/deep",
        "/feed/recent",
    )
    for suffix in required_suffixes:
        if not any(url.endswith(suffix) for url in endpoint_urls):
            raise ValueError(f"Missing required endpoint ending with '{suffix}'")


def encode_agent_uri_data(reg_json: Dict[str, Any]) -> str:
    """
    Encodes the ERC-8004 registration JSON as a `data:application/json;base64,...` URI
    ready to pass into `register(string agentURI)`.
    """
    compact_json = json.dumps(reg_json, separators=(",", ":"), ensure_ascii=False)
    b64_bytes = base64.b64encode(compact_json.encode("utf-8"))
    return f"data:application/json;base64,{b64_bytes.decode('ascii')}"


def encode_register_calldata(agent_uri: str) -> str:
    """
    ABI-encodes `register(string agentURI)` using selector `0xf2c298be`
    (`keccak256("register(string)")[:4]`).
    """
    uri_bytes = agent_uri.encode("utf-8")
    offset_word = (32).to_bytes(32, "big")
    length_word = len(uri_bytes).to_bytes(32, "big")
    pad_len = (32 - (len(uri_bytes) % 32)) % 32
    padded_uri = uri_bytes + (b"\x00" * pad_len)
    payload_bytes = offset_word + length_word + padded_uri
    return f"{REGISTER_SELECTOR}{payload_bytes.hex()}"


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses CLI arguments for scripts/register_erc8004_agent.py."""
    parser = argparse.ArgumentParser(
        description="Generate and validate ERC-8004 Trustless Agent registration manifest & calldata."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Generate, validate, and print ERC-8004 manifest summary without broadcasting on-chain",
    )
    parser.add_argument(
        "--public-url",
        type=str,
        default=os.getenv("PUBLIC_API_URL") or DEFAULT_PUBLIC_URL,
        help=f"Public agent HTTPS base URL (default: {DEFAULT_PUBLIC_URL})",
    )
    parser.add_argument(
        "--pay-to",
        type=str,
        default=os.getenv("PAY_TO_ADDRESS") or DEFAULT_PAY_TO_ADDRESS,
        help=f"Agent x402 recipient wallet address (default: {DEFAULT_PAY_TO_ADDRESS})",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="1.0.2",
        help="Agent semantic version string (default: 1.0.2)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional output file path to write the formatted ERC-8004 JSON manifest",
    )
    return parser.parse_args(args)


def main() -> int:
    """CLI entrypoint."""
    args = parse_args()
    reg_json = build_erc8004_registration_json(
        public_url=args.public_url,
        pay_to_address=args.pay_to,
        version=args.version,
    )
    validate_erc8004_registration_json(reg_json)

    agent_uri = encode_agent_uri_data(reg_json)
    calldata = encode_register_calldata(agent_uri)

    print("=" * 72)
    print("Web3 Systemic Agent: ERC-8004 Registration Manifest")
    print("=" * 72)
    print(f"[*] Mode          : {'DRY-RUN (Validation & Encoding)' if args.dry_run else 'GENERATE'}")
    print(f"[*] Type          : {reg_json['type']}")
    print(f"[*] Name          : {reg_json['name']} (v{reg_json['version']})")
    print(f"[*] Public URL    : {args.public_url.rstrip('/')}")
    print(f"[*] Payment Wallet: {reg_json['paymentWallet']}")
    print(f"[*] x402 Support  : {reg_json['x402Support']} | Trust: {', '.join(reg_json['supportedTrust'])}")
    print(f"[*] Endpoints     : {len(reg_json['endpoints'])} registered")
    for ep in reg_json["endpoints"]:
        print(f"    - {ep['name']:18s} -> {ep['endpoint']}")
    print(f"[*] agentURI len  : {len(agent_uri)} chars (data:application/json;base64,...)")
    print(f"[*] Calldata sel  : {REGISTER_SELECTOR} (register(string))")
    print(f"[*] Calldata hex  : {calldata[:74]}... ({len(calldata)} chars)")

    if args.output:
        out_dir = os.path.dirname(os.path.abspath(args.output))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(reg_json, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"[*] Saved ERC-8004 manifest JSON to: {args.output}")

    print("[*] ERC-8004 validation PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
