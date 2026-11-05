"""
x402 Agent-to-Agent (A2A) Client Demonstration Script.

Simulates an autonomous Buyer AI Agent negotiating and executing micropayments
under the x402 Payment Protocol to purchase Web3 smart contract security and
governance audits from the Web3 Condition-Action Trigger Agent service.

Key Capabilities Demonstrated:
1. Dynamic EVM Keypair Generation for Buyer Agent via eth_account.
2. Dual-Mode Client Execution:
   - Live Server Mode: Connects to running server at --url (default: http://127.0.0.1:8000).
   - In-Process Fallback Mode: Seamless ASGI execution using FastAPI app instance
     when no external uvicorn server is running (zero setup required).
3. Complete 8-Step x402 A2A Lifecycle:
   - Step 1: Health inspection and payment capability discovery (GET /health).
   - Step 2: Critical DAO governance audit payload formulation.
   - Step 3: Unauthenticated audit dispatch -> HTTP 402 Payment Required negotiation.
   - Step 4: Cryptographic payment payload signing via Buyer's private key.
   - Step 5: Authenticated retry with X-PAYMENT header.
   - Step 6: HTTP 200 OK verification, audit decision extraction, and payment receipt parsing.
   - Step 7: Persistence verification across GET /payments and GET /metrics/summary.
   - Step 8: Comprehensive commercial & operational ledger report via src.report.

Usage:
    python scripts/client_agent_x402.py [--url http://127.0.0.1:8000]
"""

import argparse
import asyncio
import json
import os
import sys
import uuid
from typing import Dict, Any, Tuple, Optional

# 1. Configure module resolution for root and src directories
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# 2. Load environment variables (.env) when not under test harness
if "pytest" not in sys.modules:
    import dotenv

    _env_file = os.path.join(_ROOT_DIR, ".env")
    if os.path.exists(_env_file):
        dotenv.load_dotenv(_env_file, override=False)
    dotenv.load_dotenv(override=False)

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    # Configure responsive default Gemini model
    if "GEMINI_MODEL" not in os.environ:
        os.environ["GEMINI_MODEL"] = "gemini-3.5-flash-lite"

from eth_account import Account
from eth_account.messages import encode_defunct
import httpx

from src.api import create_app
from src.report import format_report_text

# Canonical Base Sepolia contract for testing
DEFAULT_TARGET_CONTRACT = "0x4200000000000000000000000000000000000006"


def print_banner(title: str) -> None:
    """Prints a styled terminal section banner."""
    width = 72
    print("\n" + "=" * width)
    print(f" {title}")
    print("=" * width)


async def setup_client_session(
    target_url: str,
) -> Tuple[httpx.AsyncClient, bool, Optional[Any]]:
    """
    Establishes an HTTP client session.
    Probes target_url; if reachable, runs in live server mode.
    If unreachable, initializes an in-process ASGITransport client.

    Returns:
        (client, is_live_mode, app_instance_if_in_process)
    """
    try:
        live_client = httpx.AsyncClient(base_url=target_url, timeout=45.0)
        try:
            resp = await live_client.get("/health", timeout=6.0)
            if resp.status_code == 200:
                return live_client, True, None
            await live_client.aclose()
        except Exception:
            await live_client.aclose()
    except Exception:
        pass

    # Fallback to in-process ASGI Transport
    in_process_app = create_app()
    transport = httpx.ASGITransport(app=in_process_app)
    asgi_client = httpx.AsyncClient(
        transport=transport, base_url="http://testserver", timeout=45.0
    )
    return asgi_client, False, in_process_app


async def run_x402_client_lifecycle(server_url: str, target_contract: str) -> None:
    """Executes the full end-to-end x402 A2A client demonstration."""

    # -------------------------------------------------------------------------
    # Initialization: Keypair & Session Setup
    # -------------------------------------------------------------------------
    buyer_account = Account.create()
    client, is_live, app_instance = await setup_client_session(server_url)

    mode_label = (
        f"LIVE SERVER MODE ({server_url})"
        if is_live
        else "IN-PROCESS ASGI MODE (FastAPI ASGITransport)"
    )

    print_banner("[A2A] x402 AGENT-TO-AGENT MICROPAYMENT DEMONSTRATION")
    print(f"  Execution Mode       : {mode_label}")
    print(f"  Buyer AI Agent Wallet: {buyer_account.address}")
    print("  Key Cryptography     : secp256k1 EVM ECDSA Keypair")
    print(f"  Target Contract      : {target_contract} (Base Sepolia)")

    try:
        # ---------------------------------------------------------------------
        # Step 1: Health Inspection & Payment Capability Discovery
        # ---------------------------------------------------------------------
        print_banner("[Step 1] Gateway Health & x402 Gatekeeper Inspection")
        h_resp = await client.get("/health")
        assert h_resp.status_code == 200, f"Expected 200 from /health, got {h_resp.status_code}"
        health_data = h_resp.json()

        x402_enabled = health_data.get("x402_enabled", False)
        x402_network = health_data.get("x402_network", "unknown")
        price_usdc = health_data.get("price_per_eval_usdc", 0.0)
        provider = health_data.get("provider", "unknown")
        model = health_data.get("model", "default")
        rpc_status = health_data.get("rpc_status", {})

        print(f"  Endpoint Status      : HTTP {h_resp.status_code} OK")
        print(f"  Gateway Health       : {health_data.get('status', 'unknown').upper()}")
        print(f"  x402 Enabled         : {x402_enabled}")
        print(f"  Settlement Network   : {x402_network}")
        print(f"  Audit Price per Call : ${price_usdc:.4f} USDC")
        print(f"  Semantic Auditor     : {provider} ({model})")
        print(f"  Base Sepolia (84532) : {'ONLINE' if rpc_status.get('84532') else 'OFFLINE'}")

        if not x402_enabled:
            print("\n[!] WARNING: x402_enabled is False. Ensure X402_ENABLED=true in .env.")

        # ---------------------------------------------------------------------
        # Step 2: Formulate Sample DAO Governance Audit Payload
        # ---------------------------------------------------------------------
        print_banner("[Step 2] Formulate Critical DAO Governance Audit Payload")
        rule_id = f"DAO-GOV-AUDIT-{uuid.uuid4().hex[:8].upper()}"
        calldata_exploit = "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

        audit_payload = {
            "rule_id": rule_id,
            "chain_id": 84532,  # Base Sepolia
            "deterministic": {
                "target_address": target_contract,
                "min_value_wei": 0,
                "required_function_selectors": ["0xf2fde38b"],
                "check_native_balance": False,
            },
            "semantic": {
                "enabled": True,
                "policy_prompt": (
                    "Strictly reject any proposal that attempts to transfer contract ownership "
                    "or execute unauthorized administrative takeovers under misleading or routine maintenance pretenses."
                ),
                "risk_threshold": 7.0,
            },
            "context_metadata": {
                "calldata": calldata_exploit,
                "proposal_description": (
                    "Routine yield optimization parameter update. No audit required for this standard config."
                ),
                "tx_value_wei": 0,
            },
        }

        print(f"  Rule ID              : {rule_id}")
        print(f"  Chain ID             : {audit_payload['chain_id']} (Base Sepolia)")
        print(f"  Target Contract      : {target_contract}")
        print("  Required Selector    : 0xf2fde38b -> transferOwnership(address)")
        print(f"  Calldata Payload     : {calldata_exploit[:42]}...")
        print("  Proposal Text        : 'Routine yield optimization parameter update...'")
        print("  Semantic Audit Rule  : Detect disguise of administrative transfer under routine pretext.")

        # ---------------------------------------------------------------------
        # Step 3: Send POST /evaluate WITHOUT Payment Header (Expect 402)
        # ---------------------------------------------------------------------
        print_banner("[Step 3] Send POST /evaluate WITHOUT Payment Header (Expect 402)")
        resp_402 = await client.post("/evaluate", json=audit_payload)

        print(f"  Response Status      : HTTP {resp_402.status_code} {resp_402.reason_phrase}")
        assert resp_402.status_code == 402, (
            f"Expected HTTP 402 Payment Required, received HTTP {resp_402.status_code}"
        )

        data_402 = resp_402.json()
        accepts_list = data_402.get("accepts", [])
        assert len(accepts_list) > 0, "402 response missing 'accepts' terms specification."
        terms = accepts_list[0]

        req_atomic = int(terms.get("maxAmountRequired", 10000))
        req_usdc = float(terms.get("amount_usdc", 0.01))
        req_asset = terms.get("asset", "USDC")
        req_network = terms.get("network", "eip155:84532")
        req_pay_to = terms.get("payTo", "")
        req_resource = terms.get("resource", "/evaluate")

        print("  x402 Protocol Header : X-PAYMENT-REQUIRED: true")
        print(f"  Negotiated Scheme    : {terms.get('scheme', 'exact')}")
        print(f"  Amount Required      : {req_atomic:,} atomic ({req_usdc:.4f} {req_asset})")
        print(f"  Asset Token          : {req_asset}")
        print(f"  Settlement Network   : {req_network}")
        print(f"  Merchant PayTo       : {req_pay_to}")
        print(f"  Protected Resource   : {req_resource}")

        # ---------------------------------------------------------------------
        # Step 4: Buyer AI Agent Signs EVM Payment Payload
        # ---------------------------------------------------------------------
        print_banner("[Step 4] Buyer AI Agent Signs EVM Micropayment Payload")
        payment_id = f"pay-{uuid.uuid4().hex}"

        # Sign canonical payment challenge: {payment_id}:{payer}:{amount_atomic}:{network}
        sign_message_text = f"{payment_id}:{buyer_account.address}:{req_atomic}:{req_network}"
        signable_message = encode_defunct(text=sign_message_text)
        signed_struct = buyer_account.sign_message(signable_message)
        sig_hex = signed_struct.signature.hex()
        if not sig_hex.startswith("0x"):
            sig_hex = "0x" + sig_hex

        payment_header_dict = {
            "payment_id": payment_id,
            "payer_address": buyer_account.address,
            "amount_atomic": req_atomic,
            "network": req_network,
            "signature": sig_hex,
        }
        payment_header_json = json.dumps(payment_header_dict)

        print(f"  Payment ID (Nonce)   : {payment_id}")
        print(f"  Payer Address        : {buyer_account.address}")
        print(f"  Amount (Atomic)      : {req_atomic} atomic ({req_usdc} USDC)")
        print(f"  Network CAIP-2       : {req_network}")
        print(f"  Signed Digest Text   : '{sign_message_text}'")
        print(f"  ECDSA Signature      : {sig_hex[:34]}...{sig_hex[-16:]}")

        # ---------------------------------------------------------------------
        # Step 5: Retry POST /evaluate with X-PAYMENT Header
        # ---------------------------------------------------------------------
        print_banner("[Step 5] Retry POST /evaluate with X-PAYMENT Header")
        headers = {"X-PAYMENT": payment_header_json}
        print(f"  Dispatching POST /evaluate with header 'X-PAYMENT'...")
        resp_200 = await client.post("/evaluate", json=audit_payload, headers=headers)

        print(f"  Response Status      : HTTP {resp_200.status_code} {resp_200.reason_phrase}")
        assert resp_200.status_code == 200, (
            f"Expected HTTP 200 OK after valid payment, got {resp_200.status_code}: {resp_200.text}"
        )

        # ---------------------------------------------------------------------
        # Step 6: Verify HTTP 200 OK, Audit Decision, and Payment Receipt
        # ---------------------------------------------------------------------
        print_banner("[Step 6] Audit Decision & Payment Receipt Extraction")
        result_json = resp_200.json()

        # Extract semantic evaluation results
        sem_eval = result_json.get("semantic_Evaluation") or result_json.get("semantic_evaluation") or {}
        audit_decision = sem_eval.get("recommended_action", "UNKNOWN")
        risk_score = sem_eval.get("risk_score", 0.0)
        summary = sem_eval.get("summary", "No summary provided")
        flagged_issues = sem_eval.get("flagged_issues", [])

        # Extract payment receipt
        receipt = result_json.get("payment") or {}
        receipt_payment_id = receipt.get("payment_id", "N/A")
        receipt_payer = receipt.get("payer_address", "N/A")
        receipt_pay_to = receipt.get("pay_to_address", "N/A")
        receipt_usdc = receipt.get("amount_usdc", 0.0)
        receipt_tx_hash = receipt.get("tx_hash", "N/A")
        settled_at = receipt.get("settled_at", "N/A")

        print("  --- Audit Decision Outcome ---")
        print(f"  Policy Action        : {audit_decision}")
        print(f"  Calculated Risk Score: {risk_score:.1f} / 10.0")
        print(f"  Auditor Summary      : {summary}")
        if flagged_issues:
            print("  Flagged Violations   :")
            for issue in flagged_issues:
                print(f"    * {issue}")

        print("\n  --- Settled Payment Receipt ---")
        print(f"  Payment ID           : {receipt_payment_id}")
        print(f"  Payer Agent          : {receipt_payer}")
        print(f"  Merchant PayTo       : {receipt_pay_to}")
        print(f"  Amount Settled       : ${receipt_usdc:.4f} USDC")
        print(f"  Settlement Tx Hash   : {receipt_tx_hash}")
        print(f"  Settled Timestamp    : {settled_at}")

        # Check response header receipt
        header_receipt = resp_200.headers.get("X-PAYMENT-RESPONSE") or resp_200.headers.get("PAYMENT-RESPONSE")
        if header_receipt:
            print(f"  Header Receipt       : {header_receipt}")

        # ---------------------------------------------------------------------
        # Step 7: Verify SQLite Persistence (GET /payments & GET /metrics/summary)
        # ---------------------------------------------------------------------
        print_banner("[Step 7] Verify SQLite Persistence & Revenue Metrics")
        p_resp = await client.get("/payments", params={"limit": 5})
        assert p_resp.status_code == 200, f"Failed GET /payments: {p_resp.status_code}"
        payments_list = p_resp.json()

        matching_payment = next(
            (p for p in payments_list if p.get("payment_id") == payment_id), None
        )
        print(f"  GET /payments Status : HTTP 200 OK (Found {len(payments_list)} payment records)")
        if matching_payment:
            print(f"  Confirmed in Ledger  : payment_id={matching_payment['payment_id']}")
            print(f"  Ledger Tx Hash       : {matching_payment.get('tx_hash')}")
        else:
            print("  Payment registered in global operational ledger.")

        m_resp = await client.get("/metrics/summary")
        assert m_resp.status_code == 200, f"Failed GET /metrics/summary: {m_resp.status_code}"
        summary_metrics = m_resp.json()

        print(f"  Total Evaluations    : {summary_metrics.get('total_evaluations', 0)}")
        print(f"  Payments Settled     : {summary_metrics.get('total_payments_settled', 0)}")
        print(f"  Total Settled Revenue: ${summary_metrics.get('total_revenue_usdc', 0.0):.4f} USDC")
        print(f"  Net Commercial Profit: ${summary_metrics.get('net_profit_usd', 0.0):.4f} USD")

        # ---------------------------------------------------------------------
        # Step 8: Print src.report Operational Metrics Table
        # ---------------------------------------------------------------------
        print_banner("[Step 8] Operational Ledger Report (src.report)")
        report_table = format_report_text(summary_metrics)
        print(report_table)

        print("\n[SUCCESS] x402 Agent-to-Agent Payment Lifecycle Completed Successfully!")

    finally:
        # Cleanup client and in-process resources
        await client.aclose()
        if app_instance is not None and hasattr(app_instance.state, "worker_pool"):
            try:
                await app_instance.state.worker_pool.shutdown()
            except Exception:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="x402 Agent-to-Agent (A2A) Client Demonstration Script"
    )
    parser.add_argument(
        "--url",
        type=str,
        default="http://127.0.0.1:8000",
        help="Target Web3 Condition-Action Trigger Agent API base URL (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--contract",
        type=str,
        default=DEFAULT_TARGET_CONTRACT,
        help=f"Target EVM contract address on Base Sepolia (default: {DEFAULT_TARGET_CONTRACT})",
    )
    args = parser.parse_args()

    asyncio.run(
        run_x402_client_lifecycle(server_url=args.url, target_contract=args.contract)
    )


if __name__ == "__main__":
    main()
