"""
Wave 3 Growth, Active Discovery & Public Distribution Suite
(tests/test_wave3_growth_and_hunter.py)

Covers all Wave 3 deliverables deterministically with zero live network calls
and zero warnings:
1. ActiveContractHunter (`src/discovery_hunter.py`):
   - `run_hunt_cycle(dry_run=True)` across all 5 channels (`base_blocks`,
     `dex_pools`, `geckoterminal_base`, `dexscreener_base`, `snapshot_daos`),
     persisting to temporary `AgentStorage`, gating LLM via
     `require_high_risk_for_llm=True`, and returning valid counts.
   - `hunt_geckoterminal_base` with mocked `http_client` & `ChainInspector`:
     EIP-55 extraction from `base_0x...`, auditing, and `_seen_targets`
     deduplication on subsequent calls.
   - `hunt_dexscreener_base` with mocked `http_client` & `ChainInspector`:
     filtering out non-EVM chains (`solana`), validating EVM addresses on
     `base`, auditing, and deduplicating across calls.
   - Optional webhook alert dispatch on `risk_score >= 8.0` / `REJECT` plus
     exception isolation when webhook POST fails.
2. CLI Scripts:
   - `scripts/active_contract_hunter.py` (`--dry-run --once`, subprocess +
     direct `run_hunter`, exit code 0 and ASCII table rendering).
   - `scripts/register_erc8004_agent.py` (`build_erc8004_registration_json`,
     `validate_erc8004_registration_json`, `encode_agent_uri_data`,
     `encode_register_calldata`, plus `--dry-run` and `--output <tmp_file>`).
3. Landing Page + Live Playground (`GET /` Content Negotiation in `src/api.py`):
   - Default `Accept: */*`, `Accept: application/json`, and `?format=json`
     return JSON `ServiceDiscoveryResponse` (`version == "1.0.2"`,
     `feed_recent` & `report_template` in `endpoints`).
   - `Accept: text/html,application/xhtml+xml` and `GET /?format=html` return
     `200 text/html` containing `check_token_honeypot`, `/feed/recent`, `uvx`,
     `Cursor`, and `x-content-type-options: nosniff`.
4. Public Feed (`GET`/`HEAD /feed/recent`) & Shareable Reports
   (`/report/{chain_id}/{address}` + `/card.svg`):
   - Public accessibility (`200`, NOT `403`) under `public_evaluate_only=True`
     without any admin key.
   - Populated `AgentStorage` items returned with `target_address`,
     `report_url`, `token_check_x402_url`, `deep_audit_x402_url`, `source`
     filtering, and `limit` clamping.
   - `422` validation on invalid EVM address for `/report/...` and `/card.svg`.
   - SVG OpenGraph card (`image/svg+xml`, `<svg`, `1200`, `630`,
     `Cache-Control: public, max-age=300`).
   - Report JSON default vs HTML OpenGraph (`og:image` -> `/card.svg`,
     `twitter:card`) when `Accept: text/html` or `?format=html`.
"""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from web3 import Web3

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
for _p in (_ROOT_DIR, _SRC_DIR, _SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scripts.active_contract_hunter import parse_args as hunter_parse_args, run_hunter
from scripts.register_erc8004_agent import (
    ERC8004_TYPE_URI,
    REGISTER_SELECTOR,
    build_erc8004_registration_json,
    encode_agent_uri_data,
    encode_register_calldata,
    validate_erc8004_registration_json,
)
from src.api import create_app
from src.chain_inspector import ChainInspector
from src.discovery_hunter import (
    SUPPORTED_CHANNELS,
    ActiveContractHunter,
    _BENIGN_ERC20_BYTECODE,
    _HONEYPOT_UPGRADEABLE_BYTECODE,
)
from src.engine import ConditionAgentEngine
from src.schemas import (
    ChainId,
    ConditionRulePayload,
    DeterministicCondition,
    DeterministicResult,
    FinalAgentResponse,
    SemanticAuditResult,
    SemanticCondition,
)
from src.semantic_evaluator import MockSemanticEvaluator
from src.storage import AgentStorage
from src.x402_payment import MockX402Facilitator, X402Config


@pytest.fixture
def clean_chain_cache():
    ChainInspector._bytecode_cache.clear()
    yield
    ChainInspector._bytecode_cache.clear()


def _make_http_get_response(payload: Any, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = payload
    resp.raise_for_status = MagicMock()
    return resp


def _make_mock_w3_with_code(bytecode: bytes) -> MagicMock:
    w3 = MagicMock()
    w3.eth = MagicMock()
    w3.eth.get_code = AsyncMock(return_value=bytecode)
    return w3


async def _seed_storage_evaluation(
    storage: AgentStorage,
    rule_id: str,
    target_address: str,
    source: str,
    decision: str,
    risk_score: float,
    llm_invoked: bool = True,
    chain_id: ChainId = ChainId.BASE_MAINNET,
) -> None:
    checksum_addr = Web3.to_checksum_address(target_address)
    payload = ConditionRulePayload(
        rule_id=rule_id,
        chain_id=chain_id,
        deterministic=DeterministicCondition(
            target_address=checksum_addr,
            min_value_wei=0,
            check_native_balance=False,
        ),
        semantic=SemanticCondition(
            enabled=llm_invoked,
            policy_prompt="Audit contract bytecode and governance risk.",
            risk_threshold=7.0,
        ),
        context_metadata={"contract_address": checksum_addr},
    )
    sem_result = (
        SemanticAuditResult(
            conditions_met=risk_score >= 7.0,
            risk_score=risk_score,
            summary=f"Synthetic {decision} evaluation for {checksum_addr}",
            flagged_issues=["test_signal"] if risk_score >= 7.0 else [],
            recommended_action=decision,
            provider="mock",
            model="mock-v1",
        )
        if llm_invoked
        else None
    )
    response = FinalAgentResponse(
        rule_id=rule_id,
        chain_id=chain_id.value if hasattr(chain_id, "value") else int(chain_id),
        deterministic_check=DeterministicResult(
            passed=True,
            reason="Mock deterministic pass",
            observed_data={"target_is_contract": True, "bytecode_size_bytes": 128},
        ),
        llm_invoked=llm_invoked,
        semantic_Evaluation=sem_result,
    )
    await storage.record_evaluation(payload=payload, response=response, source=source)


# =========================================================================
# 1. ActiveContractHunter — All 5 Channels, Deduplication & Webhooks
# =========================================================================


class TestWave3ActiveContractHunter:
    """Validates ActiveContractHunter across all 5 discovery channels, dedup, and webhooks."""

    @pytest.mark.asyncio
    async def test_run_hunt_cycle_dry_run_all_5_channels_and_storage_persistence(
        self, tmp_path: Path, clean_chain_cache
    ):
        db_path = str(tmp_path / "hunter_wave3.db")
        storage = AgentStorage(db_path=db_path)
        await storage.initialize()

        hunter = ActiveContractHunter(
            storage=storage,
            require_high_risk_for_llm=True,
        )

        summary = await hunter.run_hunt_cycle(limit_per_channel=2, dry_run=True)

        assert set(summary["by_channel"].keys()) == set(SUPPORTED_CHANNELS)
        assert summary["total_discovered"] == len(summary["results"])
        assert summary["total_audited"] == summary["total_discovered"]
        assert summary["total_audited"] >= 5
        assert summary["high_risk_count"] >= 2

        for ch in SUPPORTED_CHANNELS:
            ch_info = summary["by_channel"][ch]
            assert ch_info["discovered"] >= 1
            assert ch_info["audited"] == ch_info["discovered"]

        # Verify require_high_risk_for_llm=True gates Stage-2 LLM on benign vs honeypot/upgradeable
        gt_results = summary["by_channel"]["geckoterminal_base"]["results"]
        assert len(gt_results) == 2
        gt_benign = [r for r in gt_results if "BASECLEAN" in r["label"]]
        gt_honeypot = [r for r in gt_results if "RUGPEPE" in r["label"]]
        assert len(gt_benign) == 1 and gt_benign[0]["llm_invoked"] is False
        assert len(gt_honeypot) == 1 and gt_honeypot[0]["llm_invoked"] is True
        assert gt_honeypot[0]["decision"] == "REJECT"
        assert gt_honeypot[0]["risk_score"] >= 8.0

        ds_results = summary["by_channel"]["dexscreener_base"]["results"]
        assert len(ds_results) == 2
        ds_benign = [r for r in ds_results if r["label"] == "SafeBaseToken"]
        ds_honeypot = [r for r in ds_results if r["label"] == "HoneypotProxyToken"]
        assert len(ds_benign) == 1 and ds_benign[0]["llm_invoked"] is False
        assert len(ds_honeypot) == 1 and ds_honeypot[0]["llm_invoked"] is True
        assert ds_honeypot[0]["decision"] == "REJECT"

        # Verify evaluations were persisted to temporary AgentStorage
        stored_rows = await storage.get_recent_feed_evaluations(limit=50)
        assert len(stored_rows) >= summary["total_audited"]
        stored_sources = {r["source"] for r in stored_rows}
        assert "hunter_geckoterminal" in stored_sources
        assert "hunter_dexscreener" in stored_sources
        assert "hunter_snapshot" in stored_sources

    @pytest.mark.asyncio
    async def test_hunt_geckoterminal_base_mocked_http_eip55_and_deduplication(
        self, tmp_path: Path, clean_chain_cache
    ):
        # Intentionally lowercase address in GeckoTerminal relationship id to assert EIP-55 conversion
        raw_lower_addr = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        expected_checksum = Web3.to_checksum_address(raw_lower_addr)

        gt_payload = {
            "data": [
                {
                    "id": "base_0x9999999999999999999999999999999999999999",
                    "attributes": {
                        "name": "TRAPTOKEN / WETH",
                        "address": "0x9999999999999999999999999999999999999999",
                    },
                    "relationships": {
                        "base_token": {
                            "data": {"id": f"base_{raw_lower_addr}"}
                        }
                    },
                }
            ]
        }

        mock_http = MagicMock()
        mock_http.get = AsyncMock(return_value=_make_http_get_response(gt_payload))

        storage = AgentStorage(db_path=str(tmp_path / "gt_dedup.db"))
        await storage.initialize()
        engine = ConditionAgentEngine(
            semantic_evaluator=MockSemanticEvaluator(),
            storage=storage,
        )
        hunter = ActiveContractHunter(
            engine=engine,
            storage=storage,
            http_client=mock_http,
            require_high_risk_for_llm=True,
        )

        mock_w3 = _make_mock_w3_with_code(_HONEYPOT_UPGRADEABLE_BYTECODE)
        with patch.object(ChainInspector, "_get_or_create_w3", return_value=mock_w3):
            first_results = await hunter.hunt_geckoterminal_base(limit=5, dry_run=False)
            second_results = await hunter.hunt_geckoterminal_base(limit=5, dry_run=False)

        assert len(first_results) == 1
        item = first_results[0]
        assert item["channel"] == "geckoterminal_base"
        assert item["target"] == expected_checksum
        assert item["target_address"] == expected_checksum
        assert item["llm_invoked"] is True
        assert item["decision"] == "REJECT"
        assert item["risk_score"] >= 9.0
        assert expected_checksum.lower() in hunter._seen_targets

        # Second call deduplicates via _seen_targets without re-auditing or fetching bytecode again
        assert second_results == []
        assert mock_http.get.await_count == 2
        mock_w3.eth.get_code.assert_awaited_once_with(expected_checksum)

    @pytest.mark.asyncio
    async def test_hunt_dexscreener_base_filters_solana_and_deduplicates(
        self, tmp_path: Path, clean_chain_cache
    ):
        base_token_lower = "0x1234567890abcdef1234567890abcdef12345678"
        base_token_checksum = Web3.to_checksum_address(base_token_lower)

        ds_payload = [
            {
                "chainId": "solana",
                "tokenAddress": "So11111111111111111111111111111111111111112",
                "header": "SolanaMemeToken",
            },
            {
                "chainId": "base",
                "tokenAddress": "not-an-evm-address",
                "header": "MalformedBaseItem",
            },
            {
                "chainId": "base",
                "tokenAddress": base_token_lower,
                "header": "LegitBaseToken",
                "url": "https://dexscreener.com/base/0x1234",
            },
        ]

        mock_http = MagicMock()
        mock_http.get = AsyncMock(return_value=_make_http_get_response(ds_payload))

        storage = AgentStorage(db_path=str(tmp_path / "ds_dedup.db"))
        await storage.initialize()
        engine = ConditionAgentEngine(
            semantic_evaluator=MockSemanticEvaluator(),
            storage=storage,
        )
        hunter = ActiveContractHunter(
            engine=engine,
            storage=storage,
            http_client=mock_http,
            require_high_risk_for_llm=True,
        )

        mock_w3 = _make_mock_w3_with_code(_BENIGN_ERC20_BYTECODE)
        with patch.object(ChainInspector, "_get_or_create_w3", return_value=mock_w3):
            first_results = await hunter.hunt_dexscreener_base(limit=5, dry_run=False)
            second_results = await hunter.hunt_dexscreener_base(limit=5, dry_run=False)

        assert len(first_results) == 1
        item = first_results[0]
        assert item["channel"] == "dexscreener_base"
        assert item["target_address"] == base_token_checksum
        assert item["llm_invoked"] is False
        assert item["decision"] == "APPROVE"
        assert base_token_checksum.lower() in hunter._seen_targets

        # Only the valid Base EVM address triggered RPC bytecode fetch
        mock_w3.eth.get_code.assert_awaited_once_with(base_token_checksum)
        assert second_results == []

    @pytest.mark.asyncio
    async def test_webhook_dispatch_on_high_risk_and_failure_isolation(
        self, tmp_path: Path, clean_chain_cache
    ):
        webhook_url = "https://hooks.example.test/alerts"
        mock_http = MagicMock()
        mock_http.post = AsyncMock(return_value=MagicMock(status_code=204))

        storage_ok = AgentStorage(db_path=str(tmp_path / "wh_ok.db"))
        await storage_ok.initialize()
        hunter_ok = ActiveContractHunter(
            storage=storage_ok,
            http_client=mock_http,
            webhook_url=webhook_url,
            public_api_url="https://agent.example.com",
        )

        summary_ok = await hunter_ok.run_hunt_cycle(
            channels=["geckoterminal_base"],
            limit_per_channel=2,
            dry_run=True,
        )
        assert summary_ok["high_risk_count"] >= 1
        assert mock_http.post.await_count == summary_ok["high_risk_count"]
        posted_url = mock_http.post.await_args_list[0].args[0]
        posted_json = mock_http.post.await_args_list[0].kwargs["json"]
        assert posted_url == webhook_url
        assert "embeds" in posted_json or "content" in posted_json

        # Failure isolation: webhook raises RuntimeError -> run_hunt_cycle does NOT raise
        failing_http = MagicMock()
        failing_http.post = AsyncMock(side_effect=RuntimeError("webhook downstream timeout"))
        storage_fail = AgentStorage(db_path=str(tmp_path / "wh_fail.db"))
        await storage_fail.initialize()
        hunter_fail = ActiveContractHunter(
            storage=storage_fail,
            http_client=failing_http,
            webhook_url=webhook_url,
        )

        summary_fail = await hunter_fail.run_hunt_cycle(
            channels=["geckoterminal_base"],
            limit_per_channel=2,
            dry_run=True,
        )
        assert summary_fail["total_audited"] == 2
        assert summary_fail["high_risk_count"] >= 1
        assert failing_http.post.await_count >= 1


# =========================================================================
# 2. CLI Scripts: active_contract_hunter.py & register_erc8004_agent.py
# =========================================================================


class TestWave3CLIScripts:
    """Validates Wave 3 CLI scripts offline via direct calls and subprocess."""

    @pytest.mark.asyncio
    async def test_active_contract_hunter_direct_run_hunter_dry_run_once(
        self, tmp_path: Path, capsys, clean_chain_cache
    ):
        db_file = str(tmp_path / "cli_direct.db")
        args = hunter_parse_args(["--dry-run", "--once", "--limit", "1", "--db-path", db_file])
        summary = await run_hunter(args)

        captured = capsys.readouterr()
        assert summary["total_audited"] >= 5
        assert "+" in captured.out and "|" in captured.out
        assert "Canal" in captured.out
        assert "Hunt Summary:" in captured.out

    def test_active_contract_hunter_subprocess_dry_run_once(self, tmp_path: Path):
        db_file = str(tmp_path / "cli_subproc.db")
        script_path = os.path.join(_SCRIPTS_DIR, "active_contract_hunter.py")
        proc = subprocess.run(
            [
                sys.executable,
                script_path,
                "--dry-run",
                "--once",
                "--limit",
                "1",
                "--db-path",
                db_file,
            ],
            cwd=_ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        assert "Web3 Systemic Agent: Active Multi-Channel Contract Hunter" in proc.stdout
        assert "Canal" in proc.stdout
        assert "llm_invoked" in proc.stdout
        assert "Hunt Summary:" in proc.stdout

    def test_erc8004_builders_validators_and_abi_encoding(self):
        manifest = build_erc8004_registration_json(
            public_url="https://agent.example.com/",
            pay_to_address="0x2b7f1fd931f7f28f89e0f688dd5bb7a620c24b63",
            version="1.0.2",
        )
        validate_erc8004_registration_json(manifest)

        assert manifest["type"] == ERC8004_TYPE_URI
        assert manifest["version"] == "1.0.2"
        assert manifest["x402Support"] is True
        assert manifest["paymentWallet"] == "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"
        assert manifest["image"] == "https://agent.example.com/icon.svg"

        agent_uri = encode_agent_uri_data(manifest)
        assert agent_uri.startswith("data:application/json;base64,")
        b64_part = agent_uri.split(",", 1)[1]
        decoded = json.loads(base64.b64decode(b64_part).decode("utf-8"))
        assert decoded == manifest

        calldata = encode_register_calldata(agent_uri)
        assert calldata.startswith(REGISTER_SELECTOR)
        assert calldata.startswith("0xf2c298be")
        raw_args = bytes.fromhex(calldata[len(REGISTER_SELECTOR):])
        offset = int.from_bytes(raw_args[0:32], "big")
        length = int.from_bytes(raw_args[32:64], "big")
        assert offset == 32
        assert length == len(agent_uri.encode("utf-8"))
        assert raw_args[64 : 64 + length].decode("utf-8") == agent_uri

        # Negative validation checks
        with pytest.raises(ValueError):
            build_erc8004_registration_json("ftp://invalid.local", manifest["paymentWallet"])
        with pytest.raises(ValueError):
            build_erc8004_registration_json("https://agent.example.com", "not-an-address")

        broken = dict(manifest)
        broken.pop("paymentWallet")
        with pytest.raises(ValueError):
            validate_erc8004_registration_json(broken)

    def test_register_erc8004_cli_dry_run_and_output_file(self, tmp_path: Path):
        script_path = os.path.join(_SCRIPTS_DIR, "register_erc8004_agent.py")
        out_file = tmp_path / "nested" / "erc8004-registration.json"

        proc = subprocess.run(
            [
                sys.executable,
                script_path,
                "--dry-run",
                "--public-url",
                "https://agent.example.com",
                "--pay-to",
                "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63",
                "--output",
                str(out_file),
            ],
            cwd=_ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr}"
        assert "ERC-8004 validation PASSED." in proc.stdout
        assert "0xf2c298be" in proc.stdout
        assert out_file.exists()

        written = json.loads(out_file.read_text(encoding="utf-8"))
        validate_erc8004_registration_json(written)
        assert written["paymentWallet"] == "0x2b7F1fd931f7f28f89e0f688Dd5Bb7a620c24b63"


# =========================================================================
# 3. Landing Page + Live Playground (GET / Content Negotiation)
# =========================================================================


class TestWave3LandingPageContentNegotiation:
    """Validates GET / JSON vs HTML negotiation and security headers."""

    @pytest.fixture
    def app_client(self, tmp_path: Path):
        storage = AgentStorage(db_path=str(tmp_path / "landing.db"))
        engine = ConditionAgentEngine(
            semantic_evaluator=MockSemanticEvaluator(),
            storage=storage,
        )
        app = create_app(
            engine=engine,
            storage=storage,
            x402_config=X402Config(enabled=True),
            facilitator=MockX402Facilitator(),
            public_evaluate_only=False,
            enable_background_scanner=False,
            rate_limit_per_minute=0,
        )
        with TestClient(app) as client:
            yield client

    def test_root_default_and_json_accept_return_service_discovery_json(self, app_client):
        for headers in ({"Accept": "*/*"}, {"Accept": "application/json"}):
            resp = app_client.get("/", headers=headers)
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("application/json")
            body = resp.json()
            assert body["version"] == "1.0.2"
            assert body["status"] == "online"
            assert body["endpoints"]["feed_recent"] == "/feed/recent"
            assert body["endpoints"]["report_template"] == "/report/{chain_id}/{address}"

        # Explicit ?format=json overrides text/html Accept header
        resp_override = app_client.get(
            "/?format=json",
            headers={"Accept": "text/html,application/xhtml+xml"},
        )
        assert resp_override.status_code == 200
        assert resp_override.headers["content-type"].startswith("application/json")
        assert resp_override.json()["version"] == "1.0.2"

    def test_root_html_negotiation_and_format_param_return_playground_and_headers(self, app_client):
        for url, headers in (
            ("/", {"Accept": "text/html,application/xhtml+xml"}),
            ("/?format=html", {"Accept": "*/*"}),
        ):
            resp = app_client.get(url, headers=headers)
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/html")
            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert resp.headers.get("x-frame-options") == "DENY"
            assert resp.headers.get("referrer-policy") == "no-referrer"

            html_body = resp.text
            assert "check_token_honeypot" in html_body
            assert "/feed/recent" in html_body
            assert "uvx" in html_body
            assert "Cursor" in html_body


# =========================================================================
# 4. Public Feed (/feed/recent) & Shareable Reports (/report/{chain_id}/{addr})
# =========================================================================


class TestWave3FeedAndShareableReports:
    """Validates public feed, lockdown allowlist, 422 checks, SVG card, and OpenGraph HTML."""

    USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    WETH_BASE = "0x4200000000000000000000000000000000000006"

    @pytest.fixture
    def public_app_and_storage(self, tmp_path: Path, monkeypatch, clean_chain_cache):
        monkeypatch.setenv("PUBLIC_API_URL", "https://agent.example.com")
        monkeypatch.setenv("ADMIN_API_KEY", "secret-admin-test-key")
        db_path = str(tmp_path / "public_feed.db")
        storage = AgentStorage(db_path=db_path)
        engine = ConditionAgentEngine(
            semantic_evaluator=MockSemanticEvaluator(),
            storage=storage,
        )
        app = create_app(
            engine=engine,
            storage=storage,
            x402_config=X402Config(enabled=True),
            facilitator=MockX402Facilitator(),
            public_evaluate_only=True,
            enable_background_scanner=False,
            rate_limit_per_minute=0,
        )
        with TestClient(app) as client:
            yield client, storage

    def test_public_evaluate_only_allows_feed_and_reports_without_admin_key(
        self, public_app_and_storage
    ):
        client, _ = public_app_and_storage

        # Admin-only route remains blocked (403) without admin key to prove lockdown is active
        assert client.get("/payments").status_code == 403

        # Wave 3 public endpoints return 200 (never 403)
        assert client.get("/feed/recent").status_code == 200
        assert client.head("/feed/recent").status_code == 200
        assert client.get(f"/report/8453/{self.USDC_BASE}").status_code == 200
        assert client.head(f"/report/8453/{self.USDC_BASE}").status_code == 200
        assert client.get(f"/report/8453/{self.USDC_BASE}/card.svg").status_code == 200
        assert client.head(f"/report/8453/{self.USDC_BASE}/card.svg").status_code == 200

    @pytest.mark.asyncio
    async def test_feed_recent_returns_populated_items_source_filter_and_limit_clamp(
        self, tmp_path: Path, monkeypatch
    ):
        monkeypatch.setenv("PUBLIC_API_URL", "https://agent.example.com")
        storage = AgentStorage(db_path=str(tmp_path / "populated_feed.db"))
        await storage.initialize()

        await _seed_storage_evaluation(
            storage,
            rule_id="feed-usdc",
            target_address=self.USDC_BASE,
            source="hunter_geckoterminal",
            decision="APPROVE",
            risk_score=1.5,
            llm_invoked=True,
        )
        await _seed_storage_evaluation(
            storage,
            rule_id="feed-weth",
            target_address=self.WETH_BASE,
            source="hunter_dexscreener",
            decision="REJECT",
            risk_score=9.2,
            llm_invoked=True,
        )

        engine = ConditionAgentEngine(
            semantic_evaluator=MockSemanticEvaluator(),
            storage=storage,
        )
        app = create_app(
            engine=engine,
            storage=storage,
            x402_config=X402Config(enabled=True),
            facilitator=MockX402Facilitator(),
            public_evaluate_only=True,
            enable_background_scanner=False,
            rate_limit_per_minute=0,
        )

        with TestClient(app) as client:
            resp = client.get("/feed/recent")
            assert resp.status_code == 200
            data = resp.json()
            assert data["service"] == "Web3 Systemic Agent"
            assert data["count"] == 2
            assert len(data["items"]) == 2

            first_item = data["items"][0]
            assert first_item["target_address"] == self.WETH_BASE
            assert first_item["report_url"] == f"https://agent.example.com/report/8453/{self.WETH_BASE}"
            assert (
                first_item["token_check_x402_url"]
                == f"https://agent.example.com/token/check?address={self.WETH_BASE}&chain_id=8453"
            )
            assert first_item["deep_audit_x402_url"] == "https://agent.example.com/audit/deep"

            # Source filter (case-insensitive)
            filtered = client.get("/feed/recent", params={"source": "HUNTER_GECKOTERMINAL"})
            assert filtered.status_code == 200
            f_data = filtered.json()
            assert f_data["count"] == 1
            assert f_data["items"][0]["target_address"] == self.USDC_BASE

            # Limit clamp: limit=0 clamps to 1
            clamped_low = client.get("/feed/recent", params={"limit": 0})
            assert clamped_low.status_code == 200
            assert clamped_low.json()["count"] == 1

            # Limit clamp: limit=999 clamps to 50 and executes cleanly
            clamped_high = client.get("/feed/recent", params={"limit": 999})
            assert clamped_high.status_code == 200
            assert clamped_high.json()["count"] == 2

    def test_report_and_card_svg_invalid_address_return_422(self, public_app_and_storage):
        client, _ = public_app_and_storage

        assert client.get("/report/8453/invalid-addr").status_code == 422
        assert client.head("/report/8453/invalid-addr").status_code == 422
        assert client.get("/report/8453/invalid-addr/card.svg").status_code == 422
        assert client.head("/report/8453/invalid-addr/card.svg").status_code == 422

    @pytest.mark.asyncio
    async def test_report_card_svg_and_json_vs_html_opengraph(
        self, tmp_path: Path, monkeypatch, clean_chain_cache
    ):
        monkeypatch.setenv("PUBLIC_API_URL", "https://agent.example.com")
        storage = AgentStorage(db_path=str(tmp_path / "report_og.db"))
        await storage.initialize()
        await _seed_storage_evaluation(
            storage,
            rule_id="report-usdc",
            target_address=self.USDC_BASE,
            source="hunter_geckoterminal",
            decision="REJECT",
            risk_score=9.5,
            llm_invoked=True,
        )
        ChainInspector._set_bytecode_cache(
            f"8453:{self.USDC_BASE}",
            _HONEYPOT_UPGRADEABLE_BYTECODE,
        )

        engine = ConditionAgentEngine(
            semantic_evaluator=MockSemanticEvaluator(),
            storage=storage,
        )
        app = create_app(
            engine=engine,
            storage=storage,
            x402_config=X402Config(enabled=True),
            facilitator=MockX402Facilitator(),
            public_evaluate_only=True,
            enable_background_scanner=False,
            rate_limit_per_minute=0,
        )

        with TestClient(app) as client:
            # 1. SVG OpenGraph card
            svg_resp = client.get(f"/report/8453/{self.USDC_BASE}/card.svg")
            assert svg_resp.status_code == 200
            assert svg_resp.headers["content-type"].startswith("image/svg+xml")
            assert svg_resp.headers.get("cache-control") == "public, max-age=300"
            assert "<svg" in svg_resp.text
            assert "1200" in svg_resp.text
            assert "630" in svg_resp.text
            assert self.USDC_BASE in svg_resp.text

            # 2. Report default JSON
            json_resp = client.get(
                f"/report/8453/{self.USDC_BASE}",
                headers={"Accept": "*/*"},
            )
            assert json_resp.status_code == 200
            assert json_resp.headers["content-type"].startswith("application/json")
            r_json = json_resp.json()
            assert r_json["address"] == self.USDC_BASE
            assert r_json["chain_id"] == 8453
            assert r_json["evaluated"] is True
            assert r_json["latest_decision"] == "REJECT"
            assert r_json["risk_score"] == 9.5
            assert r_json["bytecode_cached"] is True
            assert r_json["card_svg_url"] == f"https://agent.example.com/report/8453/{self.USDC_BASE}/card.svg"

            # 3. Report HTML with OpenGraph & Twitter cards
            html_resp = client.get(
                f"/report/8453/{self.USDC_BASE}",
                headers={"Accept": "text/html,application/xhtml+xml"},
            )
            assert html_resp.status_code == 200
            assert html_resp.headers["content-type"].startswith("text/html")
            expected_og_img = f"https://agent.example.com/report/8453/{self.USDC_BASE}/card.svg"
            assert 'property="og:image"' in html_resp.text
            assert expected_og_img in html_resp.text
            assert 'name="twitter:card"' in html_resp.text
            assert f"/report/8453/{self.USDC_BASE}/card.svg" in html_resp.text
