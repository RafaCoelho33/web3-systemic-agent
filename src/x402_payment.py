"""
x402 Protocol Integration and Payment Gatekeeper Module.

Provides micropayment gatekeeping for Agent-to-Agent (A2A) and machine-to-machine
interactions using the x402 payment protocol, supporting Base Sepolia and Base Mainnet
USDC settlement with local mock simulation and HTTP facilitator adapters.

Usage:
    from src.x402_payment import (
        X402Config,
        MockX402Facilitator,
        HTTPX402Facilitator,
        get_x402_facilitator,
        NETWORK_PROFILES,
        get_network_profile,
        parse_x402_header,
        create_eip3009_payment_header,
        build_402_response,
        usdc_to_atomic,
    )

    config = X402Config(enabled=True, price_per_eval_usdc=0.01)
    facilitator = MockX402Facilitator()
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import sys
from typing import Dict, Any, Optional, Union
import httpx
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from web3 import Web3

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.schemas import PaymentReceipt
except ImportError:
    from schemas import PaymentReceipt

try:
    from x402 import (
        x402ClientSync,
        x402ResourceServerSync,
        ResourceConfig,
        FacilitatorConfig,
        PaymentRequirements,
        PaymentRequired,
        PaymentPayload,
    )
    from x402.http import HTTPFacilitatorClientSync
    from x402.mechanisms.evm.exact import (
        ExactEvmClientScheme,
        ExactEvmServerScheme,
    )
    HAS_X402_SDK = True
except ImportError:
    HAS_X402_SDK = False

logger = logging.getLogger(__name__)

# Protocol Constants
USDC_DECIMALS: int = 6
DEFAULT_X402_PRICE_USDC: float = 0.01
DEFAULT_X402_NETWORK: str = "eip155:84532"  # Base Sepolia
DEFAULT_PAY_TO_ADDRESS: str = "0x0000000000000000000000000000000000000001"
DEFAULT_FACILITATOR_URL: str = "https://x402.org/facilitator"
BASE_SEPOLIA_USDC: str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
BASE_MAINNET_USDC: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
ARBITRUM_ONE_USDC: str = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"

NETWORK_PROFILES: Dict[str, Dict[str, Any]] = {
    "eip155:84532": {
        "chain_id": 84532,
        "name": "Base Sepolia",
        "is_testnet": True,
        "usdc_address": BASE_SEPOLIA_USDC,
        "default_rpc": "https://sepolia.base.org",
    },
    "eip155:8453": {
        "chain_id": 8453,
        "name": "Base Mainnet",
        "is_testnet": False,
        "usdc_address": BASE_MAINNET_USDC,
        "default_rpc": "https://mainnet.base.org",
    },
    "eip155:42161": {
        "chain_id": 42161,
        "name": "Arbitrum One",
        "is_testnet": False,
        "usdc_address": ARBITRUM_ONE_USDC,
        "default_rpc": "https://arb1.arbitrum.io/rpc",
    },
}


def get_network_profile(network: str) -> Dict[str, Any]:
    """
    Looks up CAIP-2 network identifier in NETWORK_PROFILES.
    Raises ValueError if unsupported. Returns a copy of the profile dictionary.
    """
    key = str(network or "").strip()
    if key not in NETWORK_PROFILES:
        raise ValueError(f"Unsupported CAIP-2 network: {network}")
    return dict(NETWORK_PROFILES[key])


def usdc_to_atomic(amount_usdc: float) -> int:
    """Converts a floating-point USDC amount into integer atomic units (6 decimals)."""
    return int(round(amount_usdc * (10 ** USDC_DECIMALS)))


def atomic_to_usdc(amount_atomic: int) -> float:
    """Converts atomic USDC units into a floating-point amount rounded to 6 decimal places."""
    return round(amount_atomic / (10 ** USDC_DECIMALS), USDC_DECIMALS)


class X402Config(BaseModel):
    """
    Configuration for x402 payment gatekeeper, resolved from environment variables or explicit kwargs.
    """
    enabled: bool = Field(default=False, description="Whether x402 payment gatekeeper is active")
    price_per_eval_usdc: float = Field(default=DEFAULT_X402_PRICE_USDC, ge=0.0, description="Price per evaluation in USDC")
    network: str = Field(default=DEFAULT_X402_NETWORK, description="CAIP-2 network identifier")
    pay_to_address: str = Field(default=DEFAULT_PAY_TO_ADDRESS, description="Recipient EVM address")
    facilitator_url: str = Field(default=DEFAULT_FACILITATOR_URL, description="Facilitator service URL")
    asset: str = Field(default="USDC", description="Token symbol or contract address")
    use_live_facilitator: bool = Field(default=False, description="Whether to route micropayments to a live HTTP facilitator")

    def __init__(self, **data: Any):
        if "enabled" not in data:
            env_val = os.getenv("X402_ENABLED", "false").strip().lower()
            data["enabled"] = env_val in ("true", "1", "yes")
        if "price_per_eval_usdc" not in data:
            env_val = os.getenv("X402_PRICE_EVALUATE")
            if env_val:
                try:
                    data["price_per_eval_usdc"] = float(env_val)
                except (ValueError, TypeError):
                    pass
        if "network" not in data:
            data["network"] = os.getenv("X402_NETWORK", DEFAULT_X402_NETWORK)
        if "pay_to_address" not in data:
            data["pay_to_address"] = os.getenv("PAY_TO_ADDRESS", DEFAULT_PAY_TO_ADDRESS)
        if "facilitator_url" not in data:
            data["facilitator_url"] = os.getenv("FACILITATOR_URL", DEFAULT_FACILITATOR_URL)
        if "asset" not in data:
            data["asset"] = os.getenv("X402_ASSET", "USDC")
        if "use_live_facilitator" not in data:
            env_live = os.getenv("X402_USE_LIVE_FACILITATOR", "false").strip().lower()
            data["use_live_facilitator"] = env_live in ("true", "1", "yes")

        raw_addr = data.get("pay_to_address", DEFAULT_PAY_TO_ADDRESS)
        if Web3.is_address(raw_addr):
            data["pay_to_address"] = Web3.to_checksum_address(raw_addr)

        super().__init__(**data)

    @field_validator("pay_to_address")
    @classmethod
    def normalize_pay_to(cls, v: str) -> str:
        if Web3.is_address(v):
            return Web3.to_checksum_address(v)
        return v

    @property
    def chain_id(self) -> int:
        """Returns numeric EVM chain ID resolved from network CAIP-2 profile or string."""
        if self.network in NETWORK_PROFILES:
            return int(NETWORK_PROFILES[self.network]["chain_id"])
        if self.network.startswith("eip155:"):
            try:
                return int(self.network.split(":")[1])
            except (ValueError, IndexError):
                pass
        return 84532

    @property
    def usdc_contract_address(self) -> str:
        """Returns active USDC contract address for the configured network."""
        if self.network in NETWORK_PROFILES:
            return str(NETWORK_PROFILES[self.network]["usdc_address"])
        return BASE_SEPOLIA_USDC

    @property
    def is_testnet(self) -> bool:
        """Returns whether the active network profile is a testnet."""
        if self.network in NETWORK_PROFILES:
            return bool(NETWORK_PROFILES[self.network]["is_testnet"])
        return True


def parse_x402_header(header_value: Optional[str], default_network: Optional[str] = DEFAULT_X402_NETWORK) -> Dict[str, Any]:
    """
    Parses an X-PAYMENT or PAYMENT-SIGNATURE header containing raw JSON or base64-encoded JSON.
    Supports both legacy flat headers and nested x402 v2 EIP-3009 payload envelopes.
    Normalizes aliases and validates required fields: payment_id, payer_address, amount_atomic, and signature.
    """
    if not header_value or not isinstance(header_value, str) or not header_value.strip():
        raise ValueError("Missing or empty payment header")

    clean_val = header_value.strip()
    data = None

    if clean_val.startswith("{"):
        try:
            data = json.loads(clean_val)
        except Exception:
            pass

    if data is None:
        try:
            missing_padding = len(clean_val) % 4
            padded = clean_val + ("=" * (4 - missing_padding) if missing_padding else "")
            decoded = base64.b64decode(padded).decode("utf-8")
            data = json.loads(decoded)
        except Exception as exc:
            raise ValueError(f"Invalid payment header: {exc}")

    if not isinstance(data, dict):
        raise ValueError("Payment header must encode a JSON object")

    payload_dict = data.get("payload") if isinstance(data.get("payload"), dict) else {}
    auth_dict = payload_dict.get("authorization") if isinstance(payload_dict.get("authorization"), dict) else {}
    accepted_dict = data.get("accepted") if isinstance(data.get("accepted"), dict) else {}

    payment_id = data.get("payment_id") or data.get("nonce") or data.get("id") or auth_dict.get("nonce")
    if not payment_id or not str(payment_id).strip():
        raise ValueError("Missing payment_id or nonce")
    payment_id = str(payment_id).strip()

    payer = data.get("payer_address") or data.get("payer") or data.get("from") or auth_dict.get("from")
    if not payer or not isinstance(payer, str) or not Web3.is_address(payer):
        raise ValueError(f"Invalid or missing payer address: {payer}")
    payer_address = Web3.to_checksum_address(payer)

    signature = data.get("signature") or payload_dict.get("signature")
    if not signature or not isinstance(signature, str) or not signature.strip():
        raise ValueError("Missing signature in payment header")
    signature = signature.strip()

    amount_atomic = data.get("amount_atomic")
    if amount_atomic is None:
        amount_atomic = data.get("value")
    if amount_atomic is None:
        amount_atomic = data.get("amount")
    if amount_atomic is None:
        amount_atomic = auth_dict.get("value")
    if amount_atomic is None:
        amount_atomic = accepted_dict.get("amount")

    if amount_atomic is None and "amount_usdc" in data:
        amount_atomic = usdc_to_atomic(float(data["amount_usdc"]))

    if amount_atomic is None:
        raise ValueError("Missing payment amount")

    try:
        if isinstance(amount_atomic, str) and amount_atomic.startswith("0x"):
            amount_atomic = int(amount_atomic, 16)
        else:
            amount_atomic = int(amount_atomic)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid amount_atomic: {amount_atomic}")

    if amount_atomic < 0:
        raise ValueError("Payment amount cannot be negative")

    amount_usdc = float(data.get("amount_usdc", amount_atomic / (10 ** USDC_DECIMALS)))
    network = data.get("network") or accepted_dict.get("network") or default_network

    result = {
        "payment_id": payment_id,
        "payer_address": payer_address,
        "amount_atomic": amount_atomic,
        "amount_usdc": amount_usdc,
        "signature": signature,
        "network": network,
    }

    # Pass through additional context fields (e.g. simulate_settle_error, payload, accepted, x402Version)
    for k, v in data.items():
        if k not in result:
            result[k] = v

    return result


def create_eip3009_payment_header(
    account: Any,
    pay_to_address: str,
    amount_atomic: int,
    network: str = DEFAULT_X402_NETWORK,
    usdc_address: Optional[str] = None,
    as_base64: bool = False,
) -> str:
    """
    Constructs an EIP-712 / EIP-3009 transferWithAuthorization signed payment header dictionary
    using the official x402 SDK (ExactEvmClientScheme) in < 5ms without requiring network calls.
    Returns JSON string (or Base64-encoded JSON if as_base64=True).
    """
    if not HAS_X402_SDK:
        raise RuntimeError("x402 SDK is required to create EIP-3009 payment headers")

    checksum_pay_to = Web3.to_checksum_address(pay_to_address)
    token_address = usdc_address
    if not token_address:
        try:
            profile = get_network_profile(network)
            token_address = profile["usdc_address"]
        except Exception:
            token_address = BASE_SEPOLIA_USDC
    checksum_token = Web3.to_checksum_address(token_address)

    cli = x402ClientSync()
    cli.register(network, ExactEvmClientScheme(account))

    req = PaymentRequirements(
        scheme="exact",
        network=network,
        asset=checksum_token,
        amount=str(amount_atomic),
        pay_to=checksum_pay_to,
        max_timeout_seconds=300,
        extra={"name": "USDC", "version": "2"},
    )
    payment_required = PaymentRequired(x402_version=2, accepts=[req])
    payload_obj = cli.create_payment_payload(payment_required)
    payload_dict = payload_obj.model_dump()

    auth = payload_dict.get("payload", {}).get("authorization", {})
    sig = payload_dict.get("payload", {}).get("signature", "")
    payment_id = auth.get("nonce", "")
    payer_address = Web3.to_checksum_address(auth.get("from", getattr(account, "address", "")))
    amount = int(auth.get("value", amount_atomic))
    amount_usdc = atomic_to_usdc(amount)

    header_dict = {
        "x402Version": payload_dict.get("x402Version", 2),
        "payment_id": payment_id,
        "payer_address": payer_address,
        "amount_atomic": amount,
        "amount_usdc": amount_usdc,
        "network": network,
        "signature": sig,
        "payload": payload_dict.get("payload"),
        "accepted": payload_dict.get("accepted"),
    }
    if payload_dict.get("extensions") is not None:
        header_dict["extensions"] = payload_dict["extensions"]

    json_str = json.dumps(header_dict)
    if as_base64:
        return base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
    return json_str


class VerificationResult(BaseModel):
    valid: bool
    reason: Optional[str] = None
    payment_id: str
    payer_address: str
    amount_atomic: int
    amount_usdc: float


class SettlementResult(BaseModel):
    settled: bool
    tx_hash: Optional[str] = None
    error: Optional[str] = None


class MockX402Facilitator:
    """
    In-memory mock facilitator for unit tests and local development.
    Tracks verify and settle calls and generates deterministic transaction hashes.
    """

    def __init__(self):
        self.verify_calls: int = 0
        self.settle_calls: int = 0

    async def verify(
        self,
        payment_data: Dict[str, Any],
        required_atomic: int,
        config: X402Config,
    ) -> VerificationResult:
        self.verify_calls += 1
        payment_id = str(payment_data.get("payment_id", ""))
        payer_address = str(payment_data.get("payer_address", ""))
        amount_atomic = int(payment_data.get("amount_atomic", 0))
        amount_usdc = float(payment_data.get("amount_usdc", amount_atomic / (10 ** USDC_DECIMALS)))
        sig = str(payment_data.get("signature", "")).strip()

        if not sig or sig.lower() in ("invalid", "0xinvalid"):
            return VerificationResult(
                valid=False,
                reason="Invalid signature",
                payment_id=payment_id,
                payer_address=payer_address,
                amount_atomic=amount_atomic,
                amount_usdc=amount_usdc,
            )

        if amount_atomic < required_atomic:
            return VerificationResult(
                valid=False,
                reason=f"Insufficient payment amount: {amount_atomic} < {required_atomic}",
                payment_id=payment_id,
                payer_address=payer_address,
                amount_atomic=amount_atomic,
                amount_usdc=amount_usdc,
            )

        net = payment_data.get("network")
        if net and net != config.network:
            return VerificationResult(
                valid=False,
                reason="Network mismatch",
                payment_id=payment_id,
                payer_address=payer_address,
                amount_atomic=amount_atomic,
                amount_usdc=amount_usdc,
            )

        return VerificationResult(
            valid=True,
            reason=None,
            payment_id=payment_id,
            payer_address=payer_address,
            amount_atomic=amount_atomic,
            amount_usdc=amount_usdc,
        )

    async def settle(
        self,
        payment_data: Dict[str, Any],
        required_atomic: int,
        config: X402Config,
    ) -> SettlementResult:
        self.settle_calls += 1
        if payment_data.get("simulate_settle_error"):
            return SettlementResult(
                settled=False,
                error="Simulated facilitator settlement error",
            )
        payment_id = str(payment_data.get("payment_id", ""))
        tx_hash = "0x" + hashlib.sha256(payment_id.encode("utf-8")).hexdigest()
        return SettlementResult(
            settled=True,
            tx_hash=tx_hash,
        )


class HTTPX402Facilitator:
    """
    Production-grade HTTP facilitator adapter communicating with a remote x402 facilitator node.
    Supports both standard HTTP REST facilitator endpoints and EIP-3009 on-chain settlement via x402 SDK.
    """

    def __init__(
        self,
        facilitator_url: Optional[str] = None,
        timeout: float = 10.0,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.facilitator_url = facilitator_url
        self.timeout = timeout
        self.client = client

    def _verify_eip3009_sync(
        self,
        payload_obj: Any,
        req: Any,
        facilitator_url: str,
        network: str,
        payment_id: str,
        payer_address: str,
        amount_atomic: int,
        amount_usdc: float,
    ) -> VerificationResult:
        try:
            fac = HTTPFacilitatorClientSync(FacilitatorConfig(url=facilitator_url))
            srv = x402ResourceServerSync(fac)
            srv.register(network, ExactEvmServerScheme())
            srv.initialize()

            v = srv.verify_payment(payload_obj, req)
            is_valid = getattr(v, "is_valid", False)
            if hasattr(v, "verify") and hasattr(v.verify, "is_valid"):
                is_valid = bool(v.verify.is_valid)

            if is_valid:
                return VerificationResult(
                    valid=True,
                    reason=None,
                    payment_id=payment_id,
                    payer_address=payer_address,
                    amount_atomic=amount_atomic,
                    amount_usdc=amount_usdc,
                )
            else:
                invalid_reason = (
                    getattr(v, "invalid_reason", None)
                    or (getattr(v.verify, "invalid_reason", None) if hasattr(v, "verify") else None)
                    or "Payment verification rejected"
                )
                invalid_msg = (
                    getattr(v, "invalid_message", None)
                    or (getattr(v.verify, "invalid_message", None) if hasattr(v, "verify") else None)
                )
                reason_str = f"{invalid_reason}: {invalid_msg}" if invalid_msg else str(invalid_reason)
                return VerificationResult(
                    valid=False,
                    reason=reason_str,
                    payment_id=payment_id,
                    payer_address=payer_address,
                    amount_atomic=amount_atomic,
                    amount_usdc=amount_usdc,
                )
        except Exception as exc:
            return VerificationResult(
                valid=False,
                reason=f"Facilitator verification connection error: {str(exc)}",
                payment_id=payment_id,
                payer_address=payer_address,
                amount_atomic=amount_atomic,
                amount_usdc=amount_usdc,
            )

    def _settle_eip3009_sync(
        self,
        payload_obj: Any,
        req: Any,
        facilitator_url: str,
        network: str,
    ) -> SettlementResult:
        try:
            fac = HTTPFacilitatorClientSync(FacilitatorConfig(url=facilitator_url))
            srv = x402ResourceServerSync(fac)
            srv.register(network, ExactEvmServerScheme())
            srv.initialize()

            s = srv.settle_payment(payload_obj, req)
            settle_success = getattr(s, "success", False)
            if not settle_success and hasattr(s, "settle"):
                settle_success = getattr(s.settle, "success", False)

            if not settle_success:
                err_reason = getattr(s, "error_reason", "unknown")
                err_msg = getattr(s, "error_message", "Unknown settlement error")
                return SettlementResult(
                    settled=False,
                    error=f"{err_reason}: {err_msg}",
                )

            tx_hash = (
                getattr(s, "transaction", None)
                or (getattr(s.settle, "transaction", None) if hasattr(s, "settle") else None)
            )
            return SettlementResult(
                settled=True,
                tx_hash=tx_hash,
            )
        except Exception as exc:
            return SettlementResult(
                settled=False,
                error=f"Facilitator settlement error: {str(exc)}",
            )

    async def verify(
        self,
        payment_data: Dict[str, Any],
        required_atomic: int,
        config: X402Config,
    ) -> VerificationResult:
        payment_id = str(payment_data.get("payment_id", ""))
        payer_address = str(payment_data.get("payer_address", ""))
        amount_atomic = int(payment_data.get("amount_atomic", 0))
        amount_usdc = float(payment_data.get("amount_usdc", amount_atomic / (10 ** USDC_DECIMALS)))

        is_eip3009 = (
            self.client is None
            and HAS_X402_SDK
            and isinstance(payment_data.get("payload"), dict)
            and "authorization" in payment_data["payload"]
        )

        if is_eip3009:
            if amount_atomic < required_atomic:
                return VerificationResult(
                    valid=False,
                    reason=f"Insufficient payment amount: {amount_atomic} < {required_atomic}",
                    payment_id=payment_id,
                    payer_address=payer_address,
                    amount_atomic=amount_atomic,
                    amount_usdc=amount_usdc,
                )

            net = payment_data.get("network")
            if net and net != config.network:
                return VerificationResult(
                    valid=False,
                    reason="Network mismatch",
                    payment_id=payment_id,
                    payer_address=payer_address,
                    amount_atomic=amount_atomic,
                    amount_usdc=amount_usdc,
                )

            base_url = (self.facilitator_url or config.facilitator_url).rstrip("/")
            accepted_data = payment_data.get("accepted")
            if isinstance(accepted_data, dict):
                req = PaymentRequirements.model_validate(accepted_data)
            else:
                req = PaymentRequirements(
                    scheme="exact",
                    network=config.network,
                    asset=config.usdc_contract_address,
                    amount=str(amount_atomic),
                    pay_to=config.pay_to_address,
                    max_timeout_seconds=300,
                    extra={"name": "USDC", "version": "2"},
                )

            payload_dict = {
                "x402Version": payment_data.get("x402Version", 2),
                "payload": payment_data["payload"],
            }
            if isinstance(accepted_data, dict):
                payload_dict["accepted"] = accepted_data
            else:
                payload_dict["accepted"] = req.model_dump(by_alias=True)

            payload_obj = PaymentPayload.model_validate(payload_dict)

            return await asyncio.to_thread(
                self._verify_eip3009_sync,
                payload_obj=payload_obj,
                req=req,
                facilitator_url=base_url,
                network=config.network,
                payment_id=payment_id,
                payer_address=payer_address,
                amount_atomic=amount_atomic,
                amount_usdc=amount_usdc,
            )

        base_url = (self.facilitator_url or config.facilitator_url).rstrip("/")
        url = f"{base_url}/verify"
        payload = {
            "payment_data": payment_data,
            "required_atomic": required_atomic,
            "network": config.network,
        }
        try:
            if self.client is not None:
                resp = await self.client.post(url, json=payload, timeout=self.timeout)
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return VerificationResult(**data)
            else:
                return VerificationResult(
                    valid=False,
                    reason=f"Facilitator verification returned status {resp.status_code}: {resp.text}",
                    payment_id=payment_id,
                    payer_address=payer_address,
                    amount_atomic=amount_atomic,
                    amount_usdc=amount_usdc,
                )
        except Exception as exc:
            return VerificationResult(
                valid=False,
                reason=f"Facilitator verification connection error: {str(exc)}",
                payment_id=payment_id,
                payer_address=payer_address,
                amount_atomic=amount_atomic,
                amount_usdc=amount_usdc,
            )

    async def settle(
        self,
        payment_data: Dict[str, Any],
        required_atomic: int,
        config: X402Config,
    ) -> SettlementResult:
        is_eip3009 = (
            self.client is None
            and HAS_X402_SDK
            and isinstance(payment_data.get("payload"), dict)
            and "authorization" in payment_data["payload"]
        )

        if is_eip3009:
            base_url = (self.facilitator_url or config.facilitator_url).rstrip("/")
            accepted_data = payment_data.get("accepted")
            if isinstance(accepted_data, dict):
                req = PaymentRequirements.model_validate(accepted_data)
            else:
                amount_atomic = int(payment_data.get("amount_atomic", required_atomic))
                req = PaymentRequirements(
                    scheme="exact",
                    network=config.network,
                    asset=config.usdc_contract_address,
                    amount=str(amount_atomic),
                    pay_to=config.pay_to_address,
                    max_timeout_seconds=300,
                    extra={"name": "USDC", "version": "2"},
                )

            payload_dict = {
                "x402Version": payment_data.get("x402Version", 2),
                "payload": payment_data["payload"],
            }
            if isinstance(accepted_data, dict):
                payload_dict["accepted"] = accepted_data
            else:
                payload_dict["accepted"] = req.model_dump(by_alias=True)

            payload_obj = PaymentPayload.model_validate(payload_dict)

            return await asyncio.to_thread(
                self._settle_eip3009_sync,
                payload_obj=payload_obj,
                req=req,
                facilitator_url=base_url,
                network=config.network,
            )

        base_url = (self.facilitator_url or config.facilitator_url).rstrip("/")
        url = f"{base_url}/settle"
        payload = {
            "payment_data": payment_data,
            "required_atomic": required_atomic,
            "network": config.network,
        }
        try:
            if self.client is not None:
                resp = await self.client.post(url, json=payload, timeout=self.timeout)
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return SettlementResult(**data)
            else:
                return SettlementResult(
                    settled=False,
                    error=f"Facilitator settlement returned status {resp.status_code}: {resp.text}",
                )
        except Exception as exc:
            return SettlementResult(
                settled=False,
                error=f"Facilitator settlement connection error: {str(exc)}",
            )


def get_x402_facilitator(
    config: Optional[X402Config] = None,
) -> Union[HTTPX402Facilitator, MockX402Facilitator]:
    """
    Returns an appropriate x402 facilitator instance based on config.
    Returns HTTPX402Facilitator if config.use_live_facilitator is True,
    otherwise MockX402Facilitator.
    """
    cfg = config or X402Config()
    if cfg.use_live_facilitator:
        return HTTPX402Facilitator(facilitator_url=cfg.facilitator_url)
    return MockX402Facilitator()


def build_402_response(
    config: X402Config,
    endpoint: str,
    required_usdc: float,
    reason: str = "Payment Required",
) -> JSONResponse:
    """
    Constructs a compliant HTTP 402 Payment Required response containing x402 payment scheme metadata.
    """
    required_atomic = usdc_to_atomic(required_usdc)
    body = {
        "x402Version": 1,
        "error": "PaymentRequired",
        "message": reason,
        "accepts": [
            {
                "scheme": "exact",
                "network": config.network,
                "maxAmountRequired": str(required_atomic),
                "amount_usdc": round(required_usdc, 6),
                "asset": config.asset,
                "usdcAddress": config.usdc_contract_address,
                "payTo": config.pay_to_address,
                "resource": endpoint,
                "description": f"Web3 Security & Governance Audit for {endpoint}",
                "extra": {"name": "USDC", "version": "2"},
            }
        ],
    }
    return JSONResponse(
        status_code=402,
        content=body,
        headers={"X-PAYMENT-REQUIRED": "true"},
    )
