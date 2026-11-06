"""
Autonomous Test Suite for x402 Bazaar Auto-Discovery and Coinbase Developer Platform (CDP) Validator.
Validates 100% compliance with Coinbase CDP indexer crawler requirements (https://api.cdp.coinbase.com/platform/v2/x402/validate).

Core Specifications Covered:
1. GET /evaluate returns HTTP 402 with full Bazaar auto-discovery metadata and Payment-Required headers.
2. POST /evaluate empty probe ({}) without payment header returns HTTP 402 (Payment Required), NOT 422.
3. POST /evaluate with payment header and invalid body returns HTTP 422 (preserves schema validation gate).
4. build_402_response & build_bazaar_discovery_extension conform strictly to CDP Bazaar schema:
   - accepts[0]["amount"] is an atomic string (e.g., "10000" or "50000").
   - accepts[0]["asset"] is a valid checksummed EVM address (USDC contract address).
   - accepts[0]["maxTimeoutSeconds"] == 300.
   - extensions["bazaar"]["info"]["input"]["method"] == "POST".
   - extensions["bazaar"]["info"]["input"]["type"] == "http".
   - extensions["bazaar"]["schema"] declares input and output specifications.
5. Exact 24-check CDP Validator Preflight Simulation against live /evaluate responses:
   - 100% required checks pass.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
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

    sys.modules.setdefault("schemas", schemas_module)
    sys.modules.setdefault("storage", storage_module)
    sys.modules.setdefault("x402_payment", x402_module)
    sys.modules.setdefault("api", api_module)
except ImportError:
    import schemas as schemas_module
    import storage as storage_module
    import x402_payment as x402_module
    import api as api_module

    sys.modules.setdefault("src.schemas", schemas_module)
    sys.modules.setdefault("src.storage", storage_module)
    sys.modules.setdefault("src.x402_payment", x402_module)
    sys.modules.setdefault("src.api", api_module)

from schemas import (
    ChainId,
    ConditionRulePayload,
    DeterministicCondition,
    DeterministicResult,
    FinalAgentResponse,
    PaymentReceipt,
    SemanticCondition,
)
from storage import AgentStorage
from x402_payment import (
    DEFAULT_X402_NETWORK,
    HAS_X402_SDK,
    MockX402Facilitator,
    X402Config,
    build_402_response,
    build_bazaar_discovery_extension,
    usdc_to_atomic,
)
from api import create_app


# -----------------------------------------------------------------------------
# Pytest Fixtures
# -----------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def clean_x402_env(monkeypatch):
    """Guarantees x402 and API key environment variables are isolated between tests."""
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
        "PUBLIC_EVALUATE_ONLY",
    ]
    for var in vars_to_clean:
        monkeypatch.delenv(var, raising=False)
    yield
    for var in vars_to_clean:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def temp_storage(tmp_path: Path) -> AgentStorage:
    """Provides an isolated SQLite AgentStorage instance."""
    db_file = tmp_path / "test_cdp_validator.db"
    return AgentStorage(db_path=str(db_file))


@pytest.fixture
def x402_config() -> X402Config:
    """Default active x402 configuration."""
    return X402Config(
        enabled=True,
        price_per_eval_usdc=0.01,
        network=DEFAULT_X402_NETWORK,
    )


@pytest.fixture
def mock_engine(base_payload: ConditionRulePayload) -> AsyncMock:
    """Mock ConditionAgentEngine returning successful FinalAgentResponse."""
    engine = AsyncMock()
    engine.process_rule = AsyncMock(
        return_value=FinalAgentResponse(
            rule_id=base_payload.rule_id,
            chain_id=base_payload.chain_id.value,
            deterministic_check=DeterministicResult(passed=True, reason="Mock deterministic check passed"),
            llm_invoked=False,
        )
    )
    return engine


@pytest.fixture
def base_payload() -> ConditionRulePayload:
    """Valid condition rule payload conforming to schemas.py."""
    return ConditionRulePayload(
        rule_id="cdp-test-rule-001",
        chain_id=ChainId.BASE_SEPOLIA,
        deterministic=DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            min_value_wei=1000000000000000000,
            required_function_selectors=["0xf2fde38b"],
            check_native_balance=False,
        ),
        semantic=SemanticCondition(
            enabled=True,
            policy_prompt="Audit transaction calldata and governance proposal for security risks",
            risk_threshold=7.0,
        ),
        context_metadata={
            "tx_value_wei": 2000000000000000000,
            "calldata": "0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "proposal_description": "DAO Governance parameter update audit.",
        },
    )


@pytest.fixture
def test_client(temp_storage: AgentStorage, x402_config: X402Config, mock_engine: AsyncMock) -> TestClient:
    """FastAPI TestClient with active x402 payment gate, mock engine, and isolated storage."""
    facilitator = MockX402Facilitator()
    app = create_app(
        engine=mock_engine,
        storage=temp_storage,
        x402_config=x402_config,
        facilitator=facilitator,
    )
    return TestClient(app)


# -----------------------------------------------------------------------------
# CDP Validator 24-Check Preflight Simulation Engine
# -----------------------------------------------------------------------------
def simulate_cdp_validator(
    response: Any,
    url: str = "/evaluate",
) -> Dict[str, Any]:
    """
    Simulates the exact 24 verification checks executed by the Coinbase Developer Platform (CDP)
    x402 validator indexer (https://api.cdp.coinbase.com/platform/v2/x402/validate).

    Returns a structured dictionary detailing individual check status, total checks executed (24),
    and whether all required checks passed.
    """
    # 1. Extract status code, headers, and body
    if hasattr(response, "status_code"):
        status_code = response.status_code
        headers = {k.lower(): str(v) for k, v in response.headers.items()}
        try:
            body = response.json()
        except Exception:
            body = None
    elif isinstance(response, dict):
        status_code = 402
        headers = {
            "content-type": "application/json",
            "x-payment-required": "true",
            "payment-required": "true",
        }
        body = response
    else:
        raise ValueError(f"Unsupported response type for simulation: {type(response)}")

    checks: List[Dict[str, Any]] = []

    def add_check(
        check_id: int,
        name: str,
        category: str,
        severity: str,
        passed: bool,
        details: str,
    ):
        checks.append({
            "id": check_id,
            "name": name,
            "category": category,
            "severity": severity,
            "passed": bool(passed),
            "details": details,
        })

    # --- Category 1: HTTP Transport & Response Protocol (Checks 1-4) ---
    # Check 1: URL validation
    is_valid_url = bool(url and isinstance(url, str) and (url.startswith("/") or url.startswith("http://") or url.startswith("https://")))
    add_check(
        1, "url_format_valid", "transport", "required",
        is_valid_url,
        f"Endpoint URL: '{url}'" if is_valid_url else "Endpoint URL must be a valid path or HTTP(S) URL",
    )

    # Check 2: HTTP Status 402 Payment Required
    is_402 = (status_code == 402)
    add_check(
        2, "http_status_is_402", "transport", "required",
        is_402,
        f"Status code is {status_code}" if is_402 else f"Expected HTTP status 402 Payment Required, got {status_code}",
    )

    # Check 3: Content-Type is JSON
    content_type = headers.get("content-type", "")
    is_json = "application/json" in content_type or isinstance(body, dict)
    add_check(
        3, "content_type_is_json", "transport", "required",
        is_json,
        f"Content-Type: '{content_type}'" if is_json else f"Content-Type must be application/json, got '{content_type}'",
    )

    # Check 4: Payment Required Header
    has_payment_header = (
        headers.get("payment-required", "").lower() == "true"
        or headers.get("x-payment-required", "").lower() == "true"
    )
    add_check(
        4, "payment_required_header_present", "transport", "required",
        has_payment_header,
        "Header 'Payment-Required' or 'X-PAYMENT-REQUIRED' is 'true'" if has_payment_header else "Missing Payment-Required or X-PAYMENT-REQUIRED header",
    )

    # --- Category 2: Top-Level x402 Protocol Payload (Checks 5-9) ---
    # Check 5: Body is JSON dictionary
    is_dict = isinstance(body, dict)
    add_check(
        5, "body_is_json_dict", "x402_protocol", "required",
        is_dict,
        "Response body successfully parsed as JSON object" if is_dict else "Response body is not a JSON object",
    )

    # Check 6: x402Version field
    version_val = body.get("x402Version") if is_dict else None
    has_valid_version = isinstance(version_val, int) and version_val >= 1
    add_check(
        6, "x402_version_valid", "x402_protocol", "required",
        has_valid_version,
        f"x402Version: {version_val}" if has_valid_version else f"x402Version must be integer >= 1, got {version_val}",
    )

    # Check 7: Error discriminator field
    error_val = body.get("error") if is_dict else None
    has_error_field = bool(error_val and isinstance(error_val, str))
    add_check(
        7, "error_field_present", "x402_protocol", "required",
        has_error_field,
        f"Error discriminator: '{error_val}'" if has_error_field else "Missing 'error' field in response body",
    )

    # Check 8: Accepts array present
    has_accepts = is_dict and "accepts" in body and isinstance(body["accepts"], list)
    add_check(
        8, "has_accepts_array", "x402_protocol", "required",
        has_accepts,
        "'accepts' list present in body" if has_accepts else "Missing 'accepts' array in response body",
    )

    # Check 9: Accepts contains at least one scheme option
    accepts_list = body.get("accepts", []) if is_dict and isinstance(body.get("accepts"), list) else []
    accepts_non_empty = len(accepts_list) >= 1
    add_check(
        9, "accepts_is_non_empty_list", "x402_protocol", "required",
        accepts_non_empty,
        f"'accepts' contains {len(accepts_list)} payment option(s)" if accepts_non_empty else "'accepts' array is empty",
    )

    # --- Category 3: Accepts Specification Shape & Contract Requirements (Checks 10-18) ---
    first_accept = accepts_list[0] if accepts_non_empty and isinstance(accepts_list[0], dict) else {}

    # Check 10: accepts[0] is dictionary
    accept_is_dict = bool(accepts_non_empty and isinstance(accepts_list[0], dict))
    add_check(
        10, "accepts_0_is_dict", "accepts", "required",
        accept_is_dict,
        "accepts[0] is a valid dictionary" if accept_is_dict else "accepts[0] is not a dictionary",
    )

    # Check 11: accepts[0].scheme == "exact"
    scheme_val = first_accept.get("scheme")
    scheme_exact = (scheme_val == "exact")
    add_check(
        11, "accepts_0_scheme_exact", "accepts", "required",
        scheme_exact,
        f"Scheme: '{scheme_val}'" if scheme_exact else f"Scheme must be 'exact', got '{scheme_val}'",
    )

    # Check 12: accepts[0].network is CAIP-2 identifier
    network_val = first_accept.get("network", "")
    network_caip2 = bool(isinstance(network_val, str) and network_val.startswith("eip155:"))
    add_check(
        12, "accepts_0_network_caip2", "accepts", "required",
        network_caip2,
        f"CAIP-2 Network: '{network_val}'" if network_caip2 else f"Network must be CAIP-2 format (e.g., 'eip155:8453'), got '{network_val}'",
    )

    # Check 13: accepts[0].asset is checksummed EVM address
    asset_val = first_accept.get("asset", "")
    asset_valid_checksum = bool(
        isinstance(asset_val, str)
        and asset_val.startswith("0x")
        and len(asset_val) == 42
        and Web3.is_checksum_address(asset_val)
    )
    add_check(
        13, "accepts_0_asset_checksummed", "accepts", "required",
        asset_valid_checksum,
        f"Asset address: {asset_val} (checksum validated)" if asset_valid_checksum else f"Asset must be checksummed EVM address, got '{asset_val}'",
    )

    # Check 14: accepts[0].amount exists and is an atomic string
    amount_val = first_accept.get("amount")
    amount_valid = bool(
        isinstance(amount_val, str)
        and amount_val.isdigit()
        and int(amount_val) > 0
    )
    add_check(
        14, "accepts_0_amount_atomic_str", "accepts", "required",
        amount_valid,
        f"Atomic amount: '{amount_val}'" if amount_valid else f"Amount must be positive atomic string, got '{amount_val}'",
    )

    # Check 15: accepts[0].maxAmountRequired exists and matches atomic
    max_amount_val = first_accept.get("maxAmountRequired")
    max_amount_valid = bool(
        isinstance(max_amount_val, str)
        and max_amount_val.isdigit()
        and int(max_amount_val) > 0
    )
    add_check(
        15, "accepts_0_max_amount_required", "accepts", "required",
        max_amount_valid,
        f"maxAmountRequired: '{max_amount_val}'" if max_amount_valid else f"maxAmountRequired missing or invalid, got '{max_amount_val}'",
    )

    # Check 16: accepts[0].payTo is checksummed EVM address
    pay_to_val = first_accept.get("payTo", "")
    pay_to_valid = bool(
        isinstance(pay_to_val, str)
        and pay_to_val.startswith("0x")
        and len(pay_to_val) == 42
        and Web3.is_checksum_address(pay_to_val)
    )
    add_check(
        16, "accepts_0_pay_to_checksummed", "accepts", "required",
        pay_to_valid,
        f"payTo address: {pay_to_val} (checksum validated)" if pay_to_valid else f"payTo must be checksummed EVM address, got '{pay_to_val}'",
    )

    # Check 17: accepts[0].maxTimeoutSeconds == 300
    timeout_val = first_accept.get("maxTimeoutSeconds")
    timeout_valid = bool(isinstance(timeout_val, int) and timeout_val == 300)
    add_check(
        17, "accepts_0_max_timeout_seconds", "accepts", "required",
        timeout_valid,
        f"maxTimeoutSeconds: {timeout_val}" if timeout_valid else f"maxTimeoutSeconds must equal 300, got {timeout_val}",
    )

    # Check 18: accepts[0].resource matches endpoint
    resource_val = first_accept.get("resource", "")
    resource_valid = bool(
        isinstance(resource_val, str)
        and (resource_val == url or url.endswith(resource_val))
    )
    add_check(
        18, "accepts_0_resource_declared", "accepts", "required",
        resource_valid,
        f"Resource declared: '{resource_val}' matches '{url}'" if resource_valid else f"Resource '{resource_val}' does not match endpoint '{url}'",
    )

    # --- Category 4: Bazaar Auto-Discovery Extension (Checks 19-24) ---
    extensions_dict = body.get("extensions") if is_dict and isinstance(body.get("extensions"), dict) else {}

    # Check 19: extensions dictionary present
    has_extensions = bool(is_dict and "extensions" in body and isinstance(body["extensions"], dict))
    add_check(
        19, "has_extensions_dict", "bazaar", "required",
        has_extensions,
        "'extensions' dictionary present in response" if has_extensions else "Missing 'extensions' dictionary in response body",
    )

    # Check 20: bazaar extension present
    bazaar_ext = extensions_dict.get("bazaar") if isinstance(extensions_dict.get("bazaar"), dict) else {}
    has_bazaar = bool(has_extensions and "bazaar" in extensions_dict and isinstance(extensions_dict["bazaar"], dict))
    add_check(
        20, "has_bazaar_extension", "bazaar", "required",
        has_bazaar,
        "'extensions.bazaar' extension dictionary present" if has_bazaar else "Missing 'bazaar' auto-discovery extension in 'extensions'",
    )

    # Check 21: bazaar.info.input is dictionary
    bazaar_info = bazaar_ext.get("info") if isinstance(bazaar_ext.get("info"), dict) else {}
    bazaar_input = bazaar_info.get("input") if isinstance(bazaar_info.get("input"), dict) else {}
    has_bazaar_input = bool(has_bazaar and isinstance(bazaar_info.get("input"), dict))
    add_check(
        21, "bazaar_info_input_present", "bazaar", "required",
        has_bazaar_input,
        "'bazaar.info.input' object present" if has_bazaar_input else "Missing 'bazaar.info.input' dictionary",
    )

    # Check 22: bazaar.info.input.type == "http"
    input_type = bazaar_input.get("type")
    input_type_http = (input_type == "http")
    add_check(
        22, "bazaar_info_input_type_http", "bazaar", "required",
        input_type_http,
        f"bazaar.info.input.type: '{input_type}'" if input_type_http else f"Expected bazaar.info.input.type == 'http', got '{input_type}'",
    )

    # Check 23: bazaar.info.input.method == "POST"
    input_method = bazaar_input.get("method")
    input_method_post = (input_method == "POST")
    add_check(
        23, "bazaar_info_input_method_post", "bazaar", "required",
        input_method_post,
        f"bazaar.info.input.method: '{input_method}'" if input_method_post else f"Expected bazaar.info.input.method == 'POST', got '{input_method}'",
    )

    # Check 24: bazaar.schema declares input and output specifications
    bazaar_schema = bazaar_ext.get("schema") if isinstance(bazaar_ext.get("schema"), dict) else {}
    has_input_schema = (
        isinstance(bazaar_schema, dict)
        and (
            isinstance(bazaar_schema.get("input"), dict)
            or (
                isinstance(bazaar_schema.get("properties"), dict)
                and isinstance(bazaar_schema["properties"].get("input"), dict)
            )
        )
    )
    has_output_schema = (
        isinstance(bazaar_schema, dict)
        and (
            isinstance(bazaar_schema.get("output"), dict)
            or (
                isinstance(bazaar_schema.get("properties"), dict)
                and isinstance(bazaar_schema["properties"].get("output"), dict)
            )
        )
    )
    bazaar_schema_valid = bool(has_input_schema and has_output_schema)
    add_check(
        24, "bazaar_schema_input_output", "bazaar", "required",
        bazaar_schema_valid,
        "bazaar.schema declares both 'input' and 'output' JSON schema definitions" if bazaar_schema_valid else "bazaar.schema must contain both 'input' and 'output' schemas",
    )

    total_checks = len(checks)
    passed_checks = sum(1 for c in checks if c["passed"])
    failed_checks = sum(1 for c in checks if not c["passed"])
    required_passed = sum(1 for c in checks if c["passed"] and c["severity"] == "required")
    required_failed = sum(1 for c in checks if not c["passed"] and c["severity"] == "required")
    is_valid = (required_failed == 0 and total_checks == 24)

    return {
        "url": url,
        "valid": is_valid,
        "total_checks": total_checks,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "required_passed": required_passed,
        "required_failed": required_failed,
        "checks": checks,
    }


# =============================================================================
# Core Test Matrix: x402 Bazaar and Coinbase CDP Indexer Conformance
# =============================================================================
class TestX402BazaarCDPConformance:
    """
    Test suite verifying strict conformance to Coinbase Developer Platform (CDP)
    Bazaar crawler and indexer standards for agent discovery.
    """

    def test_get_evaluate_returns_402_with_bazaar_metadata(
        self, test_client: TestClient, x402_config: X402Config
    ):
        """
        Requirement 2.a:
        - Sends GET /evaluate with x402 active.
        - Asserts status_code == 402.
        - Asserts header X-PAYMENT-REQUIRED or Payment-Required is present.
        - Asserts body JSON has 'accepts' and 'extensions.bazaar'.
        """
        resp = test_client.get("/evaluate")
        assert resp.status_code == 402, f"Expected 402, got {resp.status_code}: {resp.text}"

        # Header assertion
        assert (
            resp.headers.get("Payment-Required") == "true"
            or resp.headers.get("X-PAYMENT-REQUIRED") == "true"
        ), "Response must include Payment-Required or X-PAYMENT-REQUIRED header"

        # Body JSON assertions
        body = resp.json()
        assert "accepts" in body, "Response body must contain 'accepts' list"
        assert isinstance(body["accepts"], list) and len(body["accepts"]) >= 1
        assert "extensions" in body, "Response body must contain 'extensions' dictionary"
        assert "bazaar" in body["extensions"], "Response body must declare 'bazaar' extension"

        bazaar_ext = body["extensions"]["bazaar"]
        assert "info" in bazaar_ext, "Expected 'info' in bazaar extension"
        assert "schema" in bazaar_ext, "Expected 'schema' in bazaar extension"
        assert bazaar_ext["info"]["input"]["method"] == "POST"
        assert bazaar_ext["info"]["input"]["type"] == "http"

    def test_post_evaluate_empty_probe_returns_402_not_422(
        self, test_client: TestClient
    ):
        """
        Requirement 2.b:
        - Sends POST /evaluate with json={} and WITHOUT payment header.
        - Asserts returns status_code == 402 (and NOT 422!).
        - Asserts body contains payment requirements ('accepts').
        """
        resp = test_client.post("/evaluate", json={})
        assert resp.status_code == 402, f"CDP empty probe must return 402, got {resp.status_code}: {resp.text}"

        # Must not be 422 Unprocessable Entity
        assert resp.status_code != 422, "CDP crawler empty probe must not trigger 422 schema validation error"

        # Headers and payload
        assert (
            resp.headers.get("Payment-Required") == "true"
            or resp.headers.get("X-PAYMENT-REQUIRED") == "true"
        )
        body = resp.json()
        assert "accepts" in body
        assert len(body["accepts"]) > 0
        assert body["accepts"][0]["scheme"] == "exact"
        assert "amount" in body["accepts"][0]

    def test_post_evaluate_with_payment_and_invalid_body_returns_422(
        self, test_client: TestClient
    ):
        """
        Requirement 2.c:
        - Sends POST /evaluate with json={"bad": "payload"} and WITH payment header.
        - Asserts returns status_code == 422 (guaranteeing schema validation is intact
          when payment intent is present).
        """
        mock_payment_header = json.dumps({
            "payment_id": "probe-test-pay-001",
            "payer_address": "0x4200000000000000000000000000000000000006",
            "amount_atomic": 10000,
            "network": "eip155:84532",
            "signature": "0x" + "11" * 65,
        })

        resp = test_client.post(
            "/evaluate",
            json={"bad": "payload"},
            headers={"X-PAYMENT": mock_payment_header},
        )
        assert resp.status_code == 422, (
            f"Expected HTTP 422 when payment header is provided with invalid schema, got {resp.status_code}"
        )
        body = resp.json()
        assert "detail" in body or "error" in body

    def test_bazaar_accepts_and_input_method_schema_structure(
        self, x402_config: X402Config
    ):
        """
        Requirement 2.d:
        - Inspects return value of build_402_response and build_bazaar_discovery_extension.
        - Asserts accepts[0]["amount"] exists and is an atomic string (e.g. "10000" or "50000").
        - Asserts accepts[0]["asset"] is a checksummed EVM address (USDC contract address).
        - Asserts accepts[0]["maxTimeoutSeconds"] == 300.
        - Asserts extensions["bazaar"]["info"]["input"]["method"] == "POST".
        - Asserts extensions["bazaar"]["info"]["input"]["type"] == "http".
        - Asserts extensions["bazaar"]["schema"] has input and output.
        """
        resp_402 = build_402_response(x402_config, "/evaluate", 0.05)
        assert resp_402.status_code == 402
        body = json.loads(resp_402.body)

        # 1. accepts[0] validations
        accepts = body["accepts"]
        assert isinstance(accepts, list) and len(accepts) >= 1
        acc = accepts[0]

        # amount is atomic string
        assert "amount" in acc, "Missing 'amount' key in accepts[0]"
        assert isinstance(acc["amount"], str), "accepts[0]['amount'] must be a string"
        assert acc["amount"] == "50000", f"Expected atomic '50000', got {acc['amount']}"
        assert acc["amount"].isdigit() and int(acc["amount"]) > 0

        # asset is EVM checksummed address
        assert "asset" in acc, "Missing 'asset' key in accepts[0]"
        assert Web3.is_checksum_address(acc["asset"]), f"Asset address '{acc['asset']}' is not checksummed"
        assert acc["asset"] == x402_config.usdc_contract_address

        # maxTimeoutSeconds == 300
        assert "maxTimeoutSeconds" in acc, "Missing 'maxTimeoutSeconds' in accepts[0]"
        assert acc["maxTimeoutSeconds"] == 300, f"Expected 300, got {acc['maxTimeoutSeconds']}"

        # 2. extensions.bazaar validations
        bazaar = body["extensions"]["bazaar"]
        assert bazaar["info"]["input"]["method"] == "POST", "Expected bazaar.info.input.method == 'POST'"
        assert bazaar["info"]["input"]["type"] == "http", "Expected bazaar.info.input.type == 'http'"

        schema = bazaar["schema"]
        # Schema must declare both input and output (either direct or under properties)
        has_input = "input" in schema or ("properties" in schema and "input" in schema["properties"])
        has_output = "output" in schema or ("properties" in schema and "output" in schema["properties"])
        assert has_input, "Expected 'input' specification in bazaar.schema"
        assert has_output, "Expected 'output' specification in bazaar.schema"

        # Also inspect standalone build_bazaar_discovery_extension
        ext = build_bazaar_discovery_extension("/evaluate")
        assert "bazaar" in ext
        assert ext["bazaar"]["info"]["input"]["method"] == "POST"
        assert ext["bazaar"]["info"]["input"]["type"] == "http"

    def test_cdp_validator_preflight_simulation(
        self, test_client: TestClient
    ):
        """
        Requirement 2.e:
        - Simulates the exact 24 checks executed by https://api.cdp.coinbase.com/platform/v2/x402/validate.
        - Executes simulation against live GET /evaluate response.
        - Asserts that 100% of required checks pass with zero failures.
        """
        response = test_client.get("/evaluate")
        assert response.status_code == 402

        sim_result = simulate_cdp_validator(response, url="/evaluate")

        # Validate check count and structure
        assert sim_result["total_checks"] == 24, f"Expected exactly 24 checks, got {sim_result['total_checks']}"
        assert sim_result["passed_checks"] == 24, (
            f"Failed checks: {[c for c in sim_result['checks'] if not c['passed']]}"
        )
        assert sim_result["failed_checks"] == 0
        assert sim_result["required_failed"] == 0
        assert sim_result["required_passed"] == 24
        assert sim_result["valid"] is True

        # Verify each category of checks
        transport_checks = [c for c in sim_result["checks"] if c["category"] == "transport"]
        protocol_checks = [c for c in sim_result["checks"] if c["category"] == "x402_protocol"]
        accepts_checks = [c for c in sim_result["checks"] if c["category"] == "accepts"]
        bazaar_checks = [c for c in sim_result["checks"] if c["category"] == "bazaar"]

        assert len(transport_checks) == 4, f"Expected 4 transport checks, got {len(transport_checks)}"
        assert len(protocol_checks) == 5, f"Expected 5 protocol checks, got {len(protocol_checks)}"
        assert len(accepts_checks) == 9, f"Expected 9 accepts checks, got {len(accepts_checks)}"
        assert len(bazaar_checks) == 6, f"Expected 6 bazaar checks, got {len(bazaar_checks)}"

    def test_cdp_validator_preflight_simulation_on_post_empty_probe(
        self, test_client: TestClient
    ):
        """
        Validates that the 24 CDP preflight checks pass cleanly when executed against
        an unauthenticated POST empty probe (CDP crawler interrogation behavior).
        """
        response = test_client.post("/evaluate", json={})
        assert response.status_code == 402

        sim_result = simulate_cdp_validator(response, url="/evaluate")
        assert sim_result["total_checks"] == 24
        assert sim_result["required_failed"] == 0
        assert sim_result["valid"] is True

    def test_cdp_validator_simulation_detects_all_anomalies(self):
        """
        Validates the simulation harness itself: ensures that deliberate violations of
        the 24 checks are accurately identified and flagged by simulate_cdp_validator.
        """
        # Baseline valid payload
        cfg = X402Config(enabled=True)
        valid_resp = build_402_response(cfg, "/evaluate", 0.01)
        valid_body = json.loads(valid_resp.body)

        # Baseline must pass 24/24
        res = simulate_cdp_validator(valid_body, url="/evaluate")
        assert res["total_checks"] == 24
        assert res["required_failed"] == 0

        # Anomaly 1: Status 200 instead of 402
        class Mock200Response:
            status_code = 200
            headers = {"content-type": "application/json", "Payment-Required": "true"}
            def json(self): return valid_body

        res_200 = simulate_cdp_validator(Mock200Response(), url="/evaluate")
        assert res_200["valid"] is False
        assert any(c["name"] == "http_status_is_402" and not c["passed"] for c in res_200["checks"])

        # Anomaly 2: Missing Payment-Required header
        class MockNoHeaderResponse:
            status_code = 402
            headers = {"content-type": "application/json"}
            def json(self): return valid_body

        res_no_hdr = simulate_cdp_validator(MockNoHeaderResponse(), url="/evaluate")
        assert res_no_hdr["valid"] is False
        assert any(c["name"] == "payment_required_header_present" and not c["passed"] for c in res_no_hdr["checks"])

        # Anomaly 3: Invalid asset address (non-checksum / lowercase)
        bad_asset_body = json.loads(json.dumps(valid_body))
        bad_asset_body["accepts"][0]["asset"] = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"  # all lower
        res_bad_asset = simulate_cdp_validator(bad_asset_body, url="/evaluate")
        assert any(c["name"] == "accepts_0_asset_checksummed" and not c["passed"] for c in res_bad_asset["checks"])

        # Anomaly 4: Missing bazaar input method POST
        bad_method_body = json.loads(json.dumps(valid_body))
        bad_method_body["extensions"]["bazaar"]["info"]["input"]["method"] = "GET"
        res_bad_method = simulate_cdp_validator(bad_method_body, url="/evaluate")
        assert any(c["name"] == "bazaar_info_input_method_post" and not c["passed"] for c in res_bad_method["checks"])

        # Anomaly 5: Missing atomic amount
        bad_amount_body = json.loads(json.dumps(valid_body))
        del bad_amount_body["accepts"][0]["amount"]
        res_bad_amount = simulate_cdp_validator(bad_amount_body, url="/evaluate")
        assert any(c["name"] == "accepts_0_amount_atomic_str" and not c["passed"] for c in res_bad_amount["checks"])

    def test_bazaar_fallback_fidelity_without_x402_sdk(self, monkeypatch):
        """
        Validates that when HAS_X402_SDK is False, the fallback builder returns
        an identical schema and method structure.
        """
        import src.x402_payment as x402_mod

        monkeypatch.setattr(x402_mod, "HAS_X402_SDK", False)
        fallback_ext = x402_mod.build_bazaar_discovery_extension("/evaluate")

        assert "bazaar" in fallback_ext
        bazaar = fallback_ext["bazaar"]
        assert bazaar["info"]["input"]["method"] == "POST"
        assert bazaar["info"]["input"]["type"] == "http"
        assert bazaar["info"]["input"]["bodyType"] == "json"
        assert "input" in bazaar["schema"]
        assert "output" in bazaar["schema"]
        assert bazaar["schema"]["input"]["title"] == "ConditionRulePayload"
        assert bazaar["schema"]["output"]["title"] == "FinalAgentResponse"

    def test_x402_disabled_mode_allows_execution_without_payment(
        self, temp_storage: AgentStorage, mock_engine: AsyncMock, base_payload: ConditionRulePayload
    ):
        """
        Validates that when x402 is disabled (X402_ENABLED=false), requests are not
        gated by 402 and execute directly.
        """
        cfg_disabled = X402Config(enabled=False)
        app = create_app(
            engine=mock_engine,
            storage=temp_storage,
            x402_config=cfg_disabled,
        )
        client = TestClient(app)

        # POST /evaluate with valid payload succeeds without payment header
        resp = client.post("/evaluate", json=base_payload.model_dump(mode="json"))
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == base_payload.rule_id
        assert data["payment"] is None

    def test_post_evaluate_valid_payment_settles_and_attaches_receipt(
        self, test_client: TestClient, base_payload: ConditionRulePayload, x402_config: X402Config
    ):
        """
        End-to-end integration: Valid payment header + valid body executes successfully,
        returns HTTP 200, attaches PaymentReceipt with transaction hash, and sets X-PAYMENT-RESPONSE.
        """
        payment_header_dict = {
            "payment_id": "test-valid-cdp-001",
            "payer_address": "0x4200000000000000000000000000000000000006",
            "amount_atomic": usdc_to_atomic(x402_config.price_per_eval_usdc),
            "network": x402_config.network,
            "signature": "0x" + "bb" * 65,
        }

        resp = test_client.post(
            "/evaluate",
            json=base_payload.model_dump(mode="json"),
            headers={"X-PAYMENT": json.dumps(payment_header_dict)},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()

        # Payment receipt must be present in response
        assert data.get("payment") is not None
        receipt = data["payment"]
        assert receipt["payment_id"] == "test-valid-cdp-001"
        assert receipt["amount_atomic"] == payment_header_dict["amount_atomic"]
        assert receipt["tx_hash"].startswith("0x")
        assert resp.headers.get("X-PAYMENT-RESPONSE") is not None
