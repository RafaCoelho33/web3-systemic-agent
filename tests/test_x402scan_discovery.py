"""
Comprehensive x402scan Discovery & Registration Compliance Test Suite.

Usage:
    pytest tests/test_x402scan_discovery.py -v

Covers all 5 compliance rules from `erro_fix.txt` and `https://www.x402scan.com/discovery/spec.md`:
1. Top-Level OpenAPI Discovery Metadata (`TestX402ScanOpenAPITopLevel`):
   - OpenAPI 3.x metadata, `info.x-guidance`, `info.contact.email` (param & env var),
     absence of `components.securitySchemes.x402` (so paid routes are never
     misclassified as `apiKey+paid`), and suppression of parameterless GET discovery
     stubs (`/evaluate`, `/audit/deep`) from `/openapi.json` while keeping runtime
     HTTP 402 active.
2. Strict Operation Classification (`TestX402ScanOperationClassification`):
   - Every operation in `/openapi.json` (`public_evaluate_only=True`) is strictly
     classified as either FREE (`security: []`, no `x-payment-info`) or PAID
     (omits `security`, `"402"` response, `x-payment-info` with exact USD pricing
     and `protocols: [{"x402": {}}]`), with zero unclassified operations.
3. Required Query Parameters & Input/Output Schemas (`TestX402ScanSchemasAndRequiredParams`):
   - Required query params (`address` on `GET /token/check` & `GET /audit`,
     `to_address` on `GET /preflight`), non-empty `requestBody` schemas on all POST
     routes, non-empty `200`/`202` response schemas on all routes, and required target
     fields on `QuickAuditRequest`, `DeepAuditRequest`, `TokenCheckRequest`, `PreflightRequest`.
4. Pre-Validation Paywall, Crawl Simulation & Burst Rate-Limit Resilience (`TestX402ScanFullCrawlSimulation`):
   - Unpaid minimal/empty probes (`GET` without params, `POST` with `{}`, plus
     `GET /rules/evaluate-batch`) return HTTP 402 with valid base64 `Payment-Required`
     x402 v2 headers (`scheme == "exact"`, integer atomic `amount`, `bazaar` extension).
   - Batch edge cases (`[]` -> 200 `[]`, 3 items -> 402 `"45000"`, valid `X-PAYMENT` +
     `{"bad": 1}` -> 422 with `facilitator.settle_calls == 0`).
   - 120-request high-burst crawl simulation under `rate_limit_per_minute=None` yields
     zero `429` responses, while explicit `rate_limit_per_minute=2` still enforces `429`
     on `/` and `/health`.
"""

import base64
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest
from fastapi.testclient import TestClient

# -----------------------------------------------------------------------------
# Module Setup & Path Resolution (matching project conventions)
# -----------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(ROOT_DIR) in ("src", "tests"):
    ROOT_DIR = os.path.abspath(os.path.join(ROOT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")

for _path in (ROOT_DIR, SRC_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from src.api import create_app
from src.engine import ConditionAgentEngine
from src.schemas import (
    ChainId,
    ConditionRulePayload,
    DeterministicCondition,
    SemanticCondition,
)
from src.semantic_evaluator import MockSemanticEvaluator
from src.storage import AgentStorage
from src.x402_payment import MockX402Facilitator, X402Config


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

EXPECTED_FREE_OPERATIONS: Set[Tuple[str, str]] = {
    ("GET", "/"),
    ("GET", "/feed/recent"),
    ("GET", "/report/{chain_id}/{address}/card.svg"),
    ("GET", "/report/{chain_id}/{address}"),
    ("GET", "/mcp"),
    ("POST", "/mcp"),
    ("GET", "/health"),
    ("POST", "/rules/validate"),
    ("GET", "/jobs/{job_id}"),
}

EXPECTED_PAID_OPERATIONS: Set[Tuple[str, str]] = {
    ("POST", "/evaluate"),
    ("GET", "/audit"),
    ("POST", "/audit"),
    ("GET", "/preflight"),
    ("POST", "/preflight"),
    ("POST", "/audit/deep"),
    ("GET", "/token/check"),
    ("POST", "/token/check"),
    ("POST", "/rules/evaluate-batch"),
    ("POST", "/rules/enqueue"),
}

EXPECTED_FIXED_PRICES: Dict[Tuple[str, str], str] = {
    ("GET", "/token/check"): "0.005000",
    ("POST", "/token/check"): "0.005000",
    ("GET", "/preflight"): "0.010000",
    ("POST", "/preflight"): "0.010000",
    ("GET", "/audit"): "0.015000",
    ("POST", "/audit"): "0.015000",
    ("POST", "/evaluate"): "0.015000",
    ("POST", "/rules/enqueue"): "0.015000",
    ("POST", "/audit/deep"): "0.250000",
}

EXPECTED_ATOMIC_AMOUNTS: Dict[Tuple[str, str], str] = {
    ("GET", "/token/check"): "5000",
    ("POST", "/token/check"): "5000",
    ("GET", "/preflight"): "10000",
    ("POST", "/preflight"): "10000",
    ("GET", "/audit"): "15000",
    ("POST", "/audit"): "15000",
    ("POST", "/evaluate"): "15000",
    ("POST", "/rules/enqueue"): "15000",
    ("POST", "/rules/evaluate-batch"): "15000",
    ("GET", "/rules/evaluate-batch"): "15000",
    ("POST", "/audit/deep"): "250000",
}


# -----------------------------------------------------------------------------
# Shared Fixtures & Helpers
# -----------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch):
    """Isolate x402, discovery, and rate-limit environment variables between tests."""
    env_vars = [
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
        "CONTACT_EMAIL",
        "RATE_LIMIT_PER_MINUTE",
        "ADMIN_API_KEY",
        "PUBLIC_API_URL",
        "ENABLE_BACKGROUND_SCANNER",
        "RENDER",
    ]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)
    yield
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def temp_storage(tmp_path: Path) -> AgentStorage:
    """Provide an isolated SQLite AgentStorage instance per test."""
    return AgentStorage(db_path=str(tmp_path / "x402scan_discovery.db"))


@pytest.fixture
def base_rule_dict() -> Dict[str, Any]:
    """Build a valid serialized ConditionRulePayload dictionary."""
    payload = ConditionRulePayload(
        rule_id="x402scan-batch-rule-001",
        chain_id=ChainId.BASE_MAINNET,
        deterministic=DeterministicCondition(
            target_address="0x4200000000000000000000000000000000000006",
            min_value_wei=0,
            required_function_selectors=["0xa9059cbb"],
            check_native_balance=False,
        ),
        semantic=SemanticCondition(
            enabled=False,
            policy_prompt="Inspect transfer calldata for unexpected admin hooks.",
            risk_threshold=7.0,
        ),
        context_metadata={
            "tx_value_wei": 0,
            "calldata": "0xa9059cbb" + "0" * 128,
            "proposal_description": "Standard ERC20 transfer probe.",
        },
    )
    return payload.model_dump(mode="json")


def _build_app(
    storage: AgentStorage,
    *,
    facilitator: Optional[MockX402Facilitator] = None,
    x402_config: Optional[X402Config] = None,
    public_evaluate_only: bool = True,
    rate_limit_per_minute: Optional[int] = 0,
    contact_email: Optional[str] = None,
):
    """Helper to instantiate FastAPI app with deterministic offline dependencies."""
    engine = ConditionAgentEngine(
        semantic_evaluator=MockSemanticEvaluator(),
        storage=storage,
    )
    kwargs: Dict[str, Any] = {
        "engine": engine,
        "storage": storage,
        "x402_config": x402_config or X402Config(enabled=True),
        "facilitator": facilitator or MockX402Facilitator(),
        "public_evaluate_only": public_evaluate_only,
        "enable_background_scanner": False,
        "rate_limit_per_minute": rate_limit_per_minute,
    }
    if contact_email is not None:
        kwargs["contact_email"] = contact_email
    return create_app(**kwargs)


def _decode_payment_required_header(resp) -> Dict[str, Any]:
    """Decode and validate the base64 `Payment-Required` HTTP response header."""
    raw_header = resp.headers.get("Payment-Required") or resp.headers.get("payment-required")
    assert raw_header, "Missing Payment-Required header on HTTP 402 response"
    decoded_bytes = base64.b64decode(raw_header)
    decoded = json.loads(decoded_bytes.decode("utf-8"))
    assert isinstance(decoded, dict), "Decoded Payment-Required payload must be a JSON object"
    return decoded


def _make_payment_header(
    payment_id: str,
    network: str,
    amount_atomic: int = 50000,
) -> str:
    """Create a mock X-PAYMENT JSON header accepted by MockX402Facilitator."""
    return json.dumps(
        {
            "payment_id": payment_id,
            "payer_address": "0x4200000000000000000000000000000000000006",
            "amount_atomic": amount_atomic,
            "network": network,
            "signature": "0x" + "11" * 65,
        }
    )


def _assert_non_empty_schema(
    schema: Any,
    components_schemas: Dict[str, Any],
    context: str,
) -> None:
    """Assert an OpenAPI schema (inline or $ref) is defined and non-empty (never {})."""
    assert isinstance(schema, dict) and len(schema) > 0, f"{context}: schema must be a non-empty dict, got {schema!r}"

    if "$ref" in schema:
        ref = schema["$ref"]
        assert isinstance(ref, str) and ref.startswith("#/components/schemas/"), (
            f"{context}: unexpected $ref format {ref!r}"
        )
        schema_name = ref.split("/")[-1]
        assert schema_name in components_schemas, f"{context}: missing component schema {schema_name!r}"
        resolved = components_schemas[schema_name]
        assert isinstance(resolved, dict) and len(resolved) > 0, (
            f"{context}: referenced schema {schema_name!r} is empty"
        )
        has_structure = bool(
            resolved.get("properties")
            or resolved.get("type")
            or resolved.get("anyOf")
            or resolved.get("oneOf")
            or resolved.get("allOf")
        )
        assert has_structure, f"{context}: referenced schema {schema_name!r} has no type/properties"
        return

    if schema.get("type") == "array":
        items = schema.get("items")
        _assert_non_empty_schema(items, components_schemas, f"{context}.items")
        return

    has_structure = bool(
        schema.get("properties")
        or schema.get("type")
        or schema.get("anyOf")
        or schema.get("oneOf")
        or schema.get("allOf")
        or schema.get("additionalProperties")
    )
    assert has_structure, f"{context}: inline schema lacks structural definition: {schema!r}"


# =============================================================================
# 1. Top-Level OpenAPI Discovery Metadata
# =============================================================================
class TestX402ScanOpenAPITopLevel:
    """Validates top-level /openapi.json metadata, securitySchemes, and GET stub suppression."""

    def test_openapi_top_level_metadata_contact_param_and_security_scheme(
        self, temp_storage: AgentStorage
    ):
        app = _build_app(
            temp_storage,
            contact_email="x402-alerts@example.com",
        )
        with TestClient(app) as client:
            resp = client.get("/openapi.json")
            assert resp.status_code == 200
            spec = resp.json()

            assert isinstance(spec.get("openapi"), str)
            assert spec["openapi"].startswith("3.")

            info = spec.get("info", {})
            assert isinstance(info.get("title"), str) and info["title"].strip()
            assert isinstance(info.get("version"), str) and info["version"].strip()

            guidance = info.get("x-guidance", "")
            assert isinstance(guidance, str) and len(guidance.strip()) > 0
            assert "x402" in guidance.lower()
            assert "endpoint" in guidance.lower()

            assert info.get("contact", {}).get("email") == "x402-alerts@example.com"

            sec_schemes = spec.get("components", {}).get("securitySchemes", {})
            assert "x402" not in sec_schemes

    def test_openapi_contact_email_from_env_var(
        self, temp_storage: AgentStorage, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("CONTACT_EMAIL", "x402-alerts@example.com")
        app = _build_app(temp_storage)
        with TestClient(app) as client:
            resp = client.get("/openapi.json")
            assert resp.status_code == 200
            spec = resp.json()
            assert spec.get("info", {}).get("contact", {}).get("email") == "x402-alerts@example.com"

    def test_discovery_only_get_stubs_excluded_from_openapi_but_return_402_at_runtime(
        self, temp_storage: AgentStorage
    ):
        app = _build_app(temp_storage)
        with TestClient(app) as client:
            spec = client.get("/openapi.json").json()
            paths = spec.get("paths", {})

            assert "/evaluate" in paths
            assert "get" not in paths["/evaluate"]
            assert "post" in paths["/evaluate"]

            assert "/audit/deep" in paths
            assert "get" not in paths["/audit/deep"]
            assert "post" in paths["/audit/deep"]

            # Runtime discovery stubs MUST still return HTTP 402
            for stub_path, expected_atomic in (("/evaluate", "15000"), ("/audit/deep", "250000")):
                runtime_resp = client.get(stub_path)
                assert runtime_resp.status_code == 402
                pr = _decode_payment_required_header(runtime_resp)
                assert pr.get("x402Version") == 2
                assert pr["accepts"][0]["scheme"] == "exact"
                assert pr["accepts"][0]["amount"] == expected_atomic


# =============================================================================
# 2. Strict Classification of Every Operation in /openapi.json
# =============================================================================
class TestX402ScanOperationClassification:
    """Validates every operation in /openapi.json is strictly FREE or PAID with exact pricing."""

    def test_all_openapi_operations_strictly_classified(self, temp_storage: AgentStorage):
        app = _build_app(temp_storage, public_evaluate_only=True)
        with TestClient(app) as client:
            resp = client.get("/openapi.json")
            assert resp.status_code == 200
            spec = resp.json()

            seen_operations: Set[Tuple[str, str]] = set()
            paths = spec.get("paths", {})

            for path, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                for method_lower, op in path_item.items():
                    if method_lower.lower() not in HTTP_METHODS:
                        continue
                    method = method_lower.upper()
                    key = (method, path)
                    seen_operations.add(key)

                    if key in EXPECTED_FREE_OPERATIONS:
                        assert op.get("security") == [], (
                            f"Free operation {key} must declare security == [], got {op.get('security')!r}"
                        )
                        assert "x-payment-info" not in op, (
                            f"Free operation {key} must not include x-payment-info"
                        )
                    elif key in EXPECTED_PAID_OPERATIONS:
                        assert "security" not in op, (
                            f"Paid operation {key} must omit 'security' for pure x402 classification, got {op.get('security')!r}"
                        )
                        assert "402" in op.get("responses", {}), (
                            f"Paid operation {key} must document a 402 response"
                        )
                        assert "x-payment-info" in op, (
                            f"Paid operation {key} must include x-payment-info"
                        )
                        pay_info = op["x-payment-info"]
                        assert pay_info.get("protocols") == [{"x402": {}}], (
                            f"Paid operation {key} protocols mismatch: {pay_info!r}"
                        )
                        price = pay_info.get("price", {})
                        assert price.get("currency") == "USD", (
                            f"Paid operation {key} currency must be USD: {price!r}"
                        )

                        if key == ("POST", "/rules/evaluate-batch"):
                            assert price.get("mode") == "dynamic"
                            assert price.get("min") == "0.015000"
                            assert price.get("max") == "0.750000"
                        else:
                            assert price.get("mode") == "fixed"
                            assert price.get("amount") == EXPECTED_FIXED_PRICES[key], (
                                f"Paid operation {key} expected amount {EXPECTED_FIXED_PRICES[key]!r}, got {price.get('amount')!r}"
                            )
                    else:
                        pytest.fail(f"Unclassified operation found in /openapi.json: {key}")

            missing_ops = (EXPECTED_FREE_OPERATIONS | EXPECTED_PAID_OPERATIONS) - seen_operations
            assert not missing_ops, f"Expected operations missing from /openapi.json: {sorted(missing_ops)}"
            assert seen_operations == (EXPECTED_FREE_OPERATIONS | EXPECTED_PAID_OPERATIONS)


# =============================================================================
# 3. Required Query Params & Complete Input/Output Schemas
# =============================================================================
class TestX402ScanSchemasAndRequiredParams:
    """Validates Rules #3 & #4: required query params and complete request/response schemas."""

    def test_required_query_parameters_on_get_paid_endpoints(self, temp_storage: AgentStorage):
        app = _build_app(temp_storage, public_evaluate_only=True)
        with TestClient(app) as client:
            spec = client.get("/openapi.json").json()
            paths = spec.get("paths", {})

            expected_required_query = {
                "/token/check": "address",
                "/audit": "address",
                "/preflight": "to_address",
            }

            for path, required_param_name in expected_required_query.items():
                op = paths[path]["get"]
                params = op.get("parameters", [])
                matching = [
                    p
                    for p in params
                    if p.get("in") == "query" and p.get("name") == required_param_name
                ]
                assert len(matching) == 1, (
                    f"GET {path} missing query parameter {required_param_name!r}: {params!r}"
                )
                assert matching[0].get("required") is True, (
                    f"GET {path} query parameter {required_param_name!r} must have required=True"
                )

    def test_every_post_has_request_schema_and_every_op_has_success_response_schema(
        self, temp_storage: AgentStorage
    ):
        app = _build_app(temp_storage, public_evaluate_only=True)
        with TestClient(app) as client:
            spec = client.get("/openapi.json").json()
            paths = spec.get("paths", {})
            components_schemas = spec.get("components", {}).get("schemas", {})

            expected_post_paths = {
                "/mcp",
                "/audit",
                "/preflight",
                "/audit/deep",
                "/token/check",
                "/evaluate",
                "/rules/enqueue",
                "/rules/evaluate-batch",
                "/rules/validate",
            }
            seen_post_paths: Set[str] = set()

            for path, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                for method_lower, op in path_item.items():
                    if method_lower.lower() not in HTTP_METHODS:
                        continue

                    # Rule #4a: Every POST operation has a non-empty requestBody schema
                    if method_lower.lower() == "post":
                        seen_post_paths.add(path)
                        req_body = op.get("requestBody", {})
                        assert isinstance(req_body, dict) and req_body, (
                            f"POST {path} missing requestBody"
                        )
                        content = req_body.get("content", {})
                        assert "application/json" in content, (
                            f"POST {path} requestBody missing application/json media type"
                        )
                        req_schema = content["application/json"].get("schema")
                        _assert_non_empty_schema(
                            req_schema,
                            components_schemas,
                            f"POST {path} requestBody",
                        )

                    # Rule #4b: Every operation has a non-empty 200 or 202 response schema
                    responses = op.get("responses", {})
                    success_code = "200" if "200" in responses else ("202" if "202" in responses else None)
                    assert success_code is not None, (
                        f"{method_lower.upper()} {path} missing 200 or 202 response"
                    )
                    resp_obj = responses[success_code]
                    resp_content = resp_obj.get("content", {})
                    assert isinstance(resp_content, dict) and len(resp_content) > 0, (
                        f"{method_lower.upper()} {path} {success_code} response missing content"
                    )
                    for media_type, media_obj in resp_content.items():
                        _assert_non_empty_schema(
                            media_obj.get("schema"),
                            components_schemas,
                            f"{method_lower.upper()} {path} {success_code} [{media_type}]",
                        )

            assert expected_post_paths.issubset(seen_post_paths), (
                f"Missing POST operations in OpenAPI: {sorted(expected_post_paths - seen_post_paths)}"
            )

    def test_component_request_schemas_declare_primary_target_required(
        self, temp_storage: AgentStorage
    ):
        app = _build_app(temp_storage, public_evaluate_only=True)
        with TestClient(app) as client:
            spec = client.get("/openapi.json").json()
            schemas = spec.get("components", {}).get("schemas", {})

            expected_primary_fields = {
                "QuickAuditRequest": "target_address",
                "DeepAuditRequest": "target_address",
                "TokenCheckRequest": "address",
                "PreflightRequest": "to_address",
            }
            for schema_name, required_field in expected_primary_fields.items():
                assert schema_name in schemas, f"{schema_name} missing from components.schemas"
                schema_obj = schemas[schema_name]
                required_list = schema_obj.get("required", [])
                assert required_field in required_list, (
                    f"{schema_name} must list {required_field!r} in required, got {required_list!r}"
                )


# =============================================================================
# 4. Pre-Validation Paywall, Full Crawl Simulation & Burst Rate-Limit Resilience
# =============================================================================
class TestX402ScanFullCrawlSimulation:
    """Simulates automated x402scan & CDP probing, batch edge cases, and high-burst crawls."""

    def test_unpaid_empty_probes_on_all_paid_routes_return_402_with_bazaar_v2_headers(
        self, temp_storage: AgentStorage
    ):
        facilitator = MockX402Facilitator()
        app = _build_app(temp_storage, facilitator=facilitator, public_evaluate_only=True)

        with TestClient(app) as client:
            spec = client.get("/openapi.json").json()
            paid_from_spec: List[Tuple[str, str]] = []
            for path, path_item in spec.get("paths", {}).items():
                if not isinstance(path_item, dict):
                    continue
                for method_lower, op in path_item.items():
                    if method_lower.lower() not in HTTP_METHODS:
                        continue
                    if "x-payment-info" in op and "security" not in op:
                        paid_from_spec.append((method_lower.upper(), path))

            assert set(paid_from_spec) == EXPECTED_PAID_OPERATIONS

            # Include GET /rules/evaluate-batch discovery probe explicitly
            probes = list(paid_from_spec) + [("GET", "/rules/evaluate-batch")]

            for method, path in probes:
                if method == "GET":
                    resp = client.get(path)
                elif method == "POST":
                    resp = client.post(path, json={})
                else:
                    pytest.fail(f"Unexpected HTTP method {method} for paid probe {path}")

                assert resp.status_code == 402, (
                    f"Unpaid empty probe {method} {path} returned {resp.status_code} instead of 402: {resp.text}"
                )

                pr = _decode_payment_required_header(resp)
                assert pr.get("x402Version") == 2, f"{method} {path}: expected x402Version==2"
                accepts = pr.get("accepts", [])
                assert isinstance(accepts, list) and len(accepts) >= 1, f"{method} {path}: empty accepts"
                first_accept = accepts[0]
                assert first_accept.get("scheme") == "exact", f"{method} {path}: scheme != exact"

                amount = first_accept.get("amount")
                assert isinstance(amount, str) and amount.isdigit(), (
                    f"{method} {path}: amount must be integer atomic string, got {amount!r}"
                )
                assert "." not in amount
                assert amount == EXPECTED_ATOMIC_AMOUNTS[(method, path)], (
                    f"{method} {path}: expected atomic amount {EXPECTED_ATOMIC_AMOUNTS[(method, path)]!r}, got {amount!r}"
                )

                extensions = pr.get("extensions", {})
                assert "bazaar" in extensions, f"{method} {path}: missing 'bazaar' in extensions"

            assert facilitator.settle_calls == 0

    def test_batch_and_enqueue_edge_cases_preserved(
        self, temp_storage: AgentStorage, base_rule_dict: Dict[str, Any]
    ):
        facilitator = MockX402Facilitator()
        x402_cfg = X402Config(enabled=True)
        app = _build_app(
            temp_storage,
            facilitator=facilitator,
            x402_config=x402_cfg,
            public_evaluate_only=True,
        )

        with TestClient(app) as client:
            # 1. Empty array batch returns 200 [] without charging
            empty_resp = client.post("/rules/evaluate-batch", json=[])
            assert empty_resp.status_code == 200
            assert empty_resp.json() == []
            assert facilitator.settle_calls == 0

            # 2. 3-item batch without payment returns 402 with amount == "45000" (3 * 15000)
            batch_3 = [dict(base_rule_dict, rule_id=f"batch-item-{i}") for i in range(3)]
            batch_402 = client.post("/rules/evaluate-batch", json=batch_3)
            assert batch_402.status_code == 402
            pr_batch = _decode_payment_required_header(batch_402)
            assert pr_batch["accepts"][0]["amount"] == "45000"
            assert batch_402.json()["accepts"][0]["amount"] == "45000"
            assert facilitator.settle_calls == 0

            # 3. Malformed body {"bad": 1} WITH valid X-PAYMENT returns 422 and never settles
            for idx, route in enumerate(("/rules/enqueue", "/rules/evaluate-batch")):
                pay_hdr = _make_payment_header(
                    payment_id=f"x402scan-invalid-body-{idx}",
                    network=x402_cfg.network,
                    amount_atomic=50000,
                )
                malformed_resp = client.post(
                    route,
                    json={"bad": 1},
                    headers={"X-PAYMENT": pay_hdr},
                )
                assert malformed_resp.status_code == 422, (
                    f"Expected 422 for {route} with valid X-PAYMENT and malformed body, got {malformed_resp.status_code}"
                )
                assert facilitator.settle_calls == 0

    def test_high_burst_crawler_simulation_under_default_rate_limit_zero_429s(
        self, temp_storage: AgentStorage, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("X402_ENABLED", "true")
        app = _build_app(
            temp_storage,
            x402_config=X402Config(enabled=True),
            public_evaluate_only=True,
            rate_limit_per_minute=None,
        )

        discovery_targets: List[Tuple[str, str, int]] = [
            ("GET", "/openapi.json", 200),
            ("GET", "/.well-known/x402", 200),
            ("GET", "/.well-known/agent.json", 200),
        ]
        paid_targets: List[Tuple[str, str, int]] = [
            (method, path, 402) for method, path in sorted(EXPECTED_PAID_OPERATIONS)
        ]
        crawl_sequence = discovery_targets + paid_targets

        # Execute 120 consecutive requests from the exact same IP
        same_ip_headers = {"CF-Connecting-IP": "198.51.100.200"}
        observed_statuses: List[Tuple[int, str, str, int]] = []

        with TestClient(app) as client:
            for idx in range(120):
                method, path, expected_status = crawl_sequence[idx % len(crawl_sequence)]
                if method == "GET":
                    resp = client.get(path, headers=same_ip_headers)
                else:
                    resp = client.post(path, json={}, headers=same_ip_headers)
                observed_statuses.append((idx, method, path, resp.status_code))
                assert resp.status_code != 429, (
                    f"Request #{idx} ({method} {path}) unexpectedly hit HTTP 429 rate limit"
                )
                assert resp.status_code == expected_status, (
                    f"Request #{idx} ({method} {path}) returned {resp.status_code}, expected {expected_status}"
                )

        assert len(observed_statuses) == 120
        assert all(code != 429 for _, _, _, code in observed_statuses)

    def test_explicit_rate_limit_per_minute_2_still_enforces_429_on_third_request(
        self, temp_storage: AgentStorage
    ):
        app = _build_app(
            temp_storage,
            public_evaluate_only=True,
            rate_limit_per_minute=2,
        )
        with TestClient(app) as client:
            for ip_suffix, endpoint in (("10", "/"), ("11", "/health")):
                headers = {"CF-Connecting-IP": f"203.0.113.{ip_suffix}"}
                assert client.get(endpoint, headers=headers).status_code == 200
                assert client.get(endpoint, headers=headers).status_code == 200
                third = client.get(endpoint, headers=headers)
                assert third.status_code == 429, (
                    f"Expected 429 on 3rd request to {endpoint} with rate_limit_per_minute=2, got {third.status_code}"
                )
