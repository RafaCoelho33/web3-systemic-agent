"""
Comprehensive Unit, Edge-Case & Repository Security Test Suite for Phase B5.
Covers every section of the Phase B5 Specification Contract:
1. Network Profiles & Facilitator Factory (ARBITRUM_ONE_USDC, NETWORK_PROFILES,
   get_network_profile, X402Config properties & use_live_facilitator, get_x402_facilitator).
2. DAO Governance Connector (GovernanceProposal, GovernanceAuditReport, GovernanceScanRequest,
   extract_onchain_hints, get_curated_dao_proposals, SnapshotGovernanceConnector fetch_proposals,
   proposal_to_rule_payload, and audit_proposals via ConditionAgentEngine).
3. FastAPI POST /governance/audit-proposals endpoint and api.py re-exports.
4. Git and Repository Security Audit (.gitignore rules, git ls-files clean of secrets,
   existence of README.md, scripts/governance_listener.py).
"""

import ast
import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
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
    import src.engine as engine_module
    import src.chain_inspector as chain_inspector_module
    import src.semantic_evaluator as semantic_evaluator_module

    sys.modules.setdefault("schemas", schemas_module)
    sys.modules.setdefault("storage", storage_module)
    sys.modules.setdefault("x402_payment", x402_module)
    sys.modules.setdefault("api", api_module)
    sys.modules.setdefault("engine", engine_module)
    sys.modules.setdefault("chain_inspector", chain_inspector_module)
    sys.modules.setdefault("semantic_evaluator", semantic_evaluator_module)
except ImportError:
    import schemas as schemas_module
    import storage as storage_module
    import x402_payment as x402_module
    import api as api_module
    import engine as engine_module
    import chain_inspector as chain_inspector_module
    import semantic_evaluator as semantic_evaluator_module

    sys.modules.setdefault("src.schemas", schemas_module)
    sys.modules.setdefault("src.storage", storage_module)
    sys.modules.setdefault("src.x402_payment", x402_module)
    sys.modules.setdefault("src.api", api_module)
    sys.modules.setdefault("src.engine", engine_module)
    sys.modules.setdefault("src.chain_inspector", chain_inspector_module)
    sys.modules.setdefault("src.semantic_evaluator", semantic_evaluator_module)

try:
    import src.governance_connector as gov_module
    sys.modules.setdefault("governance_connector", gov_module)
except ImportError:
    try:
        import governance_connector as gov_module
        sys.modules.setdefault("src.governance_connector", gov_module)
    except ImportError:
        gov_module = None

from schemas import (
    ChainId,
    ConditionRulePayload,
    DeterministicCondition,
    DeterministicResult,
    FinalAgentResponse,
    SemanticAuditResult,
    SemanticCondition,
)
from storage import AgentStorage
from x402_payment import (
    BASE_MAINNET_USDC,
    BASE_SEPOLIA_USDC,
    DEFAULT_FACILITATOR_URL,
    DEFAULT_PAY_TO_ADDRESS,
    DEFAULT_X402_NETWORK,
    HTTPX402Facilitator,
    MockX402Facilitator,
    X402Config,
)
from engine import ConditionAgentEngine
from chain_inspector import ChainInspector
from semantic_evaluator import MockSemanticEvaluator
from api import create_app

# Governance Connector imports (safe guarded)
if gov_module is not None:
    GovernanceAuditReport = getattr(gov_module, "GovernanceAuditReport", None)
    GovernanceProposal = getattr(gov_module, "GovernanceProposal", None)
    GovernanceScanRequest = getattr(gov_module, "GovernanceScanRequest", None)
    SnapshotGovernanceConnector = getattr(gov_module, "SnapshotGovernanceConnector", None)
    extract_onchain_hints = getattr(gov_module, "extract_onchain_hints", None)
    get_curated_dao_proposals = getattr(gov_module, "get_curated_dao_proposals", None)
    HAS_GOV = all([
        GovernanceAuditReport,
        GovernanceProposal,
        GovernanceScanRequest,
        SnapshotGovernanceConnector,
        extract_onchain_hints,
        get_curated_dao_proposals,
    ])
else:
    GovernanceAuditReport = None
    GovernanceProposal = None
    GovernanceScanRequest = None
    SnapshotGovernanceConnector = None
    extract_onchain_hints = None
    get_curated_dao_proposals = None
    HAS_GOV = False


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def clean_test_env(monkeypatch):
    """Guarantees clean x402 environment variables between tests."""
    vars_to_clean = [
        "X402_ENABLED",
        "X402_PRICE_EVALUATE",
        "X402_NETWORK",
        "PAY_TO_ADDRESS",
        "FACILITATOR_URL",
        "X402_ASSET",
        "X402_USE_LIVE_FACILITATOR",
    ]
    for var in vars_to_clean:
        monkeypatch.delenv(var, raising=False)
    yield
    for var in vars_to_clean:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def temp_storage(tmp_path: Path) -> AgentStorage:
    """Provides an isolated SQLite AgentStorage instance backed by tmp_path."""
    db_file = tmp_path / "test_phase_b5.db"
    return AgentStorage(db_path=str(db_file))


@pytest.fixture
def mock_engine(temp_storage: AgentStorage) -> ConditionAgentEngine:
    """Provides a ConditionAgentEngine with MockSemanticEvaluator and isolated storage."""
    evaluator = MockSemanticEvaluator()
    return ConditionAgentEngine(
        rpc_url="https://sepolia.base.org",
        semantic_evaluator=evaluator,
        storage=temp_storage,
    )


# =============================================================================
# SECTION 1: Dual-Network Profiles & Live Facilitator Factory
# =============================================================================

class TestSection1NetworkProfiles:
    """Verifies network profile dictionary, Arbitrum One constant, and lookup helper."""

    def test_arbitrum_one_usdc_constant(self):
        assert hasattr(x402_module, "ARBITRUM_ONE_USDC")
        arb_usdc = x402_module.ARBITRUM_ONE_USDC
        assert arb_usdc == "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
        assert Web3.is_checksum_address(arb_usdc)

    def test_network_profiles_structure_and_chain_ids(self):
        assert hasattr(x402_module, "NETWORK_PROFILES")
        profiles = x402_module.NETWORK_PROFILES
        assert isinstance(profiles, dict)

        expected_keys = {"eip155:84532", "eip155:8453", "eip155:42161"}
        assert expected_keys.issubset(set(profiles.keys()))

        # Base Sepolia
        base_sep = profiles["eip155:84532"]
        assert base_sep["chain_id"] == 84532
        assert base_sep["name"] == "Base Sepolia"
        assert base_sep["is_testnet"] is True
        assert base_sep["usdc_address"] == BASE_SEPOLIA_USDC
        assert "default_rpc" in base_sep

        # Base Mainnet
        base_main = profiles["eip155:8453"]
        assert base_main["chain_id"] == 8453
        assert base_main["name"] == "Base Mainnet"
        assert base_main["is_testnet"] is False
        assert base_main["usdc_address"] == BASE_MAINNET_USDC
        assert "default_rpc" in base_main

        # Arbitrum One
        arb_one = profiles["eip155:42161"]
        assert arb_one["chain_id"] == 42161
        assert arb_one["name"] == "Arbitrum One"
        assert arb_one["is_testnet"] is False
        assert arb_one["usdc_address"] == x402_module.ARBITRUM_ONE_USDC
        assert "default_rpc" in arb_one

    def test_get_network_profile_valid_lookups(self):
        get_profile = x402_module.get_network_profile
        p_sep = get_profile("eip155:84532")
        assert p_sep["chain_id"] == 84532
        assert p_sep["is_testnet"] is True

        p_base = get_profile("eip155:8453")
        assert p_base["chain_id"] == 8453
        assert p_base["is_testnet"] is False

        p_arb = get_profile("eip155:42161")
        assert p_arb["chain_id"] == 42161
        assert p_arb["usdc_address"] == x402_module.ARBITRUM_ONE_USDC

    def test_get_network_profile_whitespace_handling(self):
        get_profile = x402_module.get_network_profile
        p = get_profile("  eip155:84532  \n")
        assert p["chain_id"] == 84532

    def test_get_network_profile_returns_defensive_copy(self):
        get_profile = x402_module.get_network_profile
        copy1 = get_profile("eip155:84532")
        copy1["name"] = "MUTATED"
        copy2 = get_profile("eip155:84532")
        assert copy2["name"] == "Base Sepolia"

    def test_get_network_profile_unsupported_network_raises_value_error(self):
        get_profile = x402_module.get_network_profile
        with pytest.raises(ValueError) as exc_info:
            get_profile("eip155:999999")
        assert "Unsupported CAIP-2 network: eip155:999999" in str(exc_info.value)

    def test_get_network_profile_empty_string_raises_value_error(self):
        get_profile = x402_module.get_network_profile
        with pytest.raises(ValueError):
            get_profile("")


class TestSection1X402ConfigExtensions:
    """Verifies X402Config properties, use_live_facilitator resolution, and precedence."""

    def test_x402_config_properties_base_sepolia(self):
        cfg = X402Config(network="eip155:84532")
        assert cfg.chain_id == 84532
        assert cfg.usdc_contract_address == BASE_SEPOLIA_USDC
        assert cfg.is_testnet is True

    def test_x402_config_properties_base_mainnet(self):
        cfg = X402Config(network="eip155:8453")
        assert cfg.chain_id == 8453
        assert cfg.usdc_contract_address == BASE_MAINNET_USDC
        assert cfg.is_testnet is False

    def test_x402_config_properties_arbitrum_one(self):
        cfg = X402Config(network="eip155:42161")
        assert cfg.chain_id == 42161
        assert cfg.usdc_contract_address == x402_module.ARBITRUM_ONE_USDC
        assert cfg.is_testnet is False

    def test_x402_config_properties_unsupported_network_fallback(self):
        # When network is not in NETWORK_PROFILES, fallback parses integer after eip155: or defaults
        cfg = X402Config(network="eip155:12345")
        assert cfg.chain_id == 12345
        assert cfg.usdc_contract_address == BASE_SEPOLIA_USDC
        assert cfg.is_testnet is True

    def test_x402_config_use_live_facilitator_default_false(self):
        cfg = X402Config()
        assert cfg.use_live_facilitator is False

    def test_x402_config_use_live_facilitator_kwarg_true_and_false(self):
        cfg_true = X402Config(use_live_facilitator=True)
        assert cfg_true.use_live_facilitator is True

        cfg_false = X402Config(use_live_facilitator=False)
        assert cfg_false.use_live_facilitator is False

    @pytest.mark.parametrize("env_val", ["true", "1", "yes", "TRUE", "Yes"])
    def test_x402_config_use_live_facilitator_env_var_true_variants(self, monkeypatch, env_val):
        monkeypatch.setenv("X402_USE_LIVE_FACILITATOR", env_val)
        cfg = X402Config()
        assert cfg.use_live_facilitator is True

    @pytest.mark.parametrize("env_val", ["false", "0", "no", "anything_else", ""])
    def test_x402_config_use_live_facilitator_env_var_false_variants(self, monkeypatch, env_val):
        monkeypatch.setenv("X402_USE_LIVE_FACILITATOR", env_val)
        cfg = X402Config()
        assert cfg.use_live_facilitator is False

    def test_x402_config_use_live_facilitator_kwarg_precedence_over_env(self, monkeypatch):
        # Env says true, but kwarg says false
        monkeypatch.setenv("X402_USE_LIVE_FACILITATOR", "true")
        cfg = X402Config(use_live_facilitator=False)
        assert cfg.use_live_facilitator is False

        # Env says false, but kwarg says true
        monkeypatch.setenv("X402_USE_LIVE_FACILITATOR", "false")
        cfg2 = X402Config(use_live_facilitator=True)
        assert cfg2.use_live_facilitator is True


class TestSection1FacilitatorFactory:
    """Verifies get_x402_facilitator factory logic and create_app integration."""

    def test_get_x402_facilitator_default_returns_mock(self):
        get_fac = x402_module.get_x402_facilitator
        fac = get_fac()
        assert isinstance(fac, MockX402Facilitator)

    def test_get_x402_facilitator_when_live_flag_false_returns_mock(self):
        get_fac = x402_module.get_x402_facilitator
        cfg = X402Config(use_live_facilitator=False)
        fac = get_fac(cfg)
        assert isinstance(fac, MockX402Facilitator)

    def test_get_x402_facilitator_when_live_flag_true_returns_httpx_facilitator(self):
        get_fac = x402_module.get_x402_facilitator
        cfg = X402Config(
            use_live_facilitator=True,
            facilitator_url="https://live.facilitator.org",
        )
        fac = get_fac(cfg)
        assert isinstance(fac, HTTPX402Facilitator)

    def test_get_x402_facilitator_with_none_config_reads_env_live_flag(self, monkeypatch):
        get_fac = x402_module.get_x402_facilitator
        monkeypatch.setenv("X402_USE_LIVE_FACILITATOR", "true")
        fac = get_fac(None)
        assert isinstance(fac, HTTPX402Facilitator)

    def test_create_app_initializes_facilitator_via_factory_mock(self):
        cfg = X402Config(use_live_facilitator=False)
        app = create_app(x402_config=cfg)
        assert isinstance(app.state.facilitator, MockX402Facilitator)

    def test_create_app_initializes_facilitator_via_factory_live(self):
        cfg = X402Config(use_live_facilitator=True)
        app = create_app(x402_config=cfg)
        assert isinstance(app.state.facilitator, HTTPX402Facilitator)

    def test_create_app_preserves_explicit_facilitator_override(self):
        custom_fac = MockX402Facilitator()
        cfg = X402Config(use_live_facilitator=True)  # even if config says live
        app = create_app(facilitator=custom_fac, x402_config=cfg)
        assert app.state.facilitator is custom_fac


# =============================================================================
# SECTION 2: DAO Governance Connector
# =============================================================================

gov_required = pytest.mark.skipif(not HAS_GOV, reason="src/governance_connector.py not yet available")


@gov_required
class TestSection2GovernanceSchemas:
    """Verifies Pydantic schema validation for GovernanceProposal, Report, and Request."""

    def test_governance_proposal_model_defaults_and_valid_types(self):
        prop = GovernanceProposal(
            proposal_id="prop-001",
            space_id="arbitrumfoundation.eth",
            title="Fund Security Research",
            body="Proposal to allocate funds to protocol audit.",
        )
        assert prop.proposal_id == "prop-001"
        assert prop.space_id == "arbitrumfoundation.eth"
        assert prop.title == "Fund Security Research"
        assert prop.state == "active"
        assert prop.author == "0x0000000000000000000000000000000000000000"
        assert prop.target_address == "0x4200000000000000000000000000000000000006"
        assert prop.calldata == "0x"
        assert prop.tx_value_wei == 0
        assert prop.chain_id == ChainId.BASE_SEPOLIA

    def test_governance_proposal_address_checksumming(self):
        raw_addr = "0x4200000000000000000000000000000000000006".lower()
        prop = GovernanceProposal(
            proposal_id="p-checksum",
            space_id="ens.eth",
            title="T",
            body="B",
            target_address=raw_addr,
        )
        assert prop.target_address == Web3.to_checksum_address(raw_addr)
        assert Web3.is_checksum_address(prop.target_address)

    def test_governance_proposal_invalid_target_address_raises_validation_error(self):
        with pytest.raises(ValidationError):
            GovernanceProposal(
                proposal_id="p-inv",
                space_id="s",
                title="T",
                body="B",
                target_address="not-an-evm-address",
            )

    def test_governance_proposal_negative_tx_value_raises_validation_error(self):
        with pytest.raises(ValidationError):
            GovernanceProposal(
                proposal_id="p-neg",
                space_id="s",
                title="T",
                body="B",
                tx_value_wei=-100,
            )

    def test_governance_proposal_custom_chain_id(self):
        prop = GovernanceProposal(
            proposal_id="p-arb",
            space_id="arbitrumfoundation.eth",
            title="T",
            body="B",
            chain_id=ChainId.ARBITRUM_ONE,
        )
        assert prop.chain_id == ChainId.ARBITRUM_ONE

    def test_governance_audit_report_schema_valid(self):
        prop = GovernanceProposal(
            proposal_id="p-rep",
            space_id="ens.eth",
            title="T",
            body="B",
        )
        agent_resp = FinalAgentResponse(
            rule_id="gov-ens.eth-p-rep",
            chain_id=84532,
            deterministic_check=DeterministicResult(passed=True, reason="ok"),
            llm_invoked=False,
            semantic_Evaluation=None,
        )
        report = GovernanceAuditReport(
            proposal=prop,
            rule_id="gov-ens.eth-p-rep",
            agent_response=agent_resp,
            alert_level="INFO",
        )
        assert report.alert_level == "INFO"
        assert report.rule_id == "gov-ens.eth-p-rep"
        assert report.proposal.proposal_id == "p-rep"

    def test_governance_audit_report_invalid_alert_level_raises(self):
        prop = GovernanceProposal(
            proposal_id="p-rep2",
            space_id="ens.eth",
            title="T",
            body="B",
        )
        agent_resp = FinalAgentResponse(
            rule_id="gov-test",
            chain_id=84532,
            deterministic_check=DeterministicResult(passed=True, reason="ok"),
            llm_invoked=False,
            semantic_Evaluation=None,
        )
        with pytest.raises(ValidationError):
            GovernanceAuditReport(
                proposal=prop,
                rule_id="gov-test",
                agent_response=agent_resp,
                alert_level="HIGH",  # Only CRITICAL, WARNING, INFO are valid
            )

    def test_governance_scan_request_defaults(self):
        req = GovernanceScanRequest()
        assert req.spaces is None
        assert req.limit == 3
        assert req.chain_id == ChainId.BASE_SEPOLIA

    def test_governance_scan_request_custom_valid(self):
        req = GovernanceScanRequest(
            spaces=["arbitrumfoundation.eth"],
            limit=10,
            chain_id=ChainId.BASE_MAINNET,
        )
        assert req.spaces == ["arbitrumfoundation.eth"]
        assert req.limit == 10
        assert req.chain_id == ChainId.BASE_MAINNET

    @pytest.mark.parametrize("invalid_limit", [0, -1, 21, 100])
    def test_governance_scan_request_limit_out_of_bounds_raises(self, invalid_limit):
        with pytest.raises(ValidationError):
            GovernanceScanRequest(limit=invalid_limit)


@gov_required
class TestSection2ExtractOnchainHints:
    """Verifies regex and keyword heuristic extraction of EVM targets and calldata."""

    def test_extract_onchain_hints_explicit_42char_evm_address(self):
        text = "Please upgrade treasury proxy at 0x1111111111111111111111111111111111111111 immediately."
        hints = extract_onchain_hints(text)
        assert hints["target_address"] == Web3.to_checksum_address("0x1111111111111111111111111111111111111111")
        assert Web3.is_checksum_address(hints["target_address"])

    def test_extract_onchain_hints_default_fallback_address_when_none_found(self):
        text = "A proposal discussing community governance with no address anywhere."
        hints = extract_onchain_hints(text)
        assert hints["target_address"] == "0x4200000000000000000000000000000000000006"

    def test_extract_onchain_hints_keyword_transfer_ownership(self):
        text = "Execute transferOwnership to transfer control of the DAO governance token."
        hints = extract_onchain_hints(text)
        assert hints["calldata"].startswith("0xf2fde38b")

    def test_extract_onchain_hints_keyword_upgrade_to(self):
        text = "This proposal triggers upgradeTo to point implementation to audited v2."
        hints = extract_onchain_hints(text)
        assert hints["calldata"].startswith("0x3659cfe6")

    def test_extract_onchain_hints_keyword_transfer_and_treasury(self):
        text1 = "Routine treasury grant disbursement."
        hints1 = extract_onchain_hints(text1)
        assert hints1["calldata"].startswith("0xa9059cbb")

        text2 = "Call transfer(to, amount) from multisig."
        hints2 = extract_onchain_hints(text2)
        assert hints2["calldata"].startswith("0xa9059cbb")

    def test_extract_onchain_hints_explicit_calldata_hex(self):
        text = "Execute transaction with raw calldata 0x23b872dd000000000000000000000000deadbeefdeadbeef on target."
        hints = extract_onchain_hints(text)
        assert hints["calldata"].startswith("0x23b872dd")

    def test_extract_onchain_hints_empty_and_benign_text_defaults(self):
        hints = extract_onchain_hints("")
        assert hints["target_address"] == "0x4200000000000000000000000000000000000006"
        assert hints["calldata"] == "0x"


@gov_required
class TestSection2CuratedDAOProposals:
    """Verifies curated DAO proposal generation and realistic archetypes."""

    def test_get_curated_dao_proposals_returns_exact_requested_limit(self):
        props_1 = get_curated_dao_proposals(limit=1)
        assert len(props_1) == 1

        props_3 = get_curated_dao_proposals(limit=3)
        assert len(props_3) == 3

        props_5 = get_curated_dao_proposals(limit=5)
        # Up to 3 curated archetypes available, so len is at least 3
        assert len(props_5) >= 3

    def test_get_curated_dao_proposals_verifies_three_archetypes(self):
        props = get_curated_dao_proposals(limit=3)
        assert len(props) == 3

        # Archetype 1: Benign liquidity/parameter transfer (APPROVE candidate)
        benign = props[0]
        assert benign.calldata.startswith("0xa9059cbb")
        assert "treasury" in benign.title.lower() or "liquidity" in benign.title.lower() or "grant" in benign.title.lower()

        # Archetype 2: Malicious governance takeover (REJECT candidate, transferOwnership)
        malicious = props[1]
        assert malicious.calldata.startswith("0xf2fde38b")
        assert "without audit" in malicious.body.lower() or "routine" in malicious.body.lower()

        # Archetype 3: Audited UUPS proxy upgrade (MANUAL_REVIEW candidate, upgradeTo)
        audited = props[2]
        assert audited.calldata.startswith("0x3659cfe6")
        assert "audit" in audited.body.lower()

    def test_get_curated_dao_proposals_chain_id_propagation(self):
        props = get_curated_dao_proposals(default_chain_id=ChainId.ARBITRUM_ONE, limit=3)
        for p in props:
            assert p.chain_id == ChainId.ARBITRUM_ONE

    def test_get_curated_dao_proposals_checksummed_target_addresses(self):
        props = get_curated_dao_proposals(limit=3)
        for p in props:
            assert Web3.is_checksum_address(p.target_address)


@gov_required
class TestSection2SnapshotConnectorFetch:
    """Verifies Snapshot GraphQL querying, parsing, and resilient curated fallback."""

    def test_snapshot_connector_defaults_and_initialization(self):
        conn = SnapshotGovernanceConnector()
        assert conn.SNAPSHOT_GRAPHQL_URL == "https://hub.snapshot.org/graphql"
        assert "arbitrumfoundation.eth" in conn.DEFAULT_SPACES
        assert conn.default_chain_id == ChainId.BASE_SEPOLIA
        assert conn.timeout == 8.0

    @pytest.mark.asyncio
    async def test_snapshot_connector_fetch_proposals_graphql_success(self):
        conn = SnapshotGovernanceConnector()
        fake_graphql_data = {
            "data": {
                "proposals": [
                    {
                        "id": "prop-snap-001",
                        "title": "Protocol Parameter Adjustment",
                        "body": "Send treasury grant to 0x1111111111111111111111111111111111111111",
                        "author": "0x2222222222222222222222222222222222222222",
                        "state": "active",
                        "created": 1700000000,
                        "space": {"id": "arbitrumfoundation.eth"},
                    }
                ]
            }
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_graphql_data

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            proposals = await conn.fetch_proposals(spaces=["arbitrumfoundation.eth"], limit=1)

            assert len(proposals) == 1
            prop = proposals[0]
            assert prop.proposal_id == "prop-snap-001"
            assert prop.space_id == "arbitrumfoundation.eth"
            assert prop.target_address == Web3.to_checksum_address("0x1111111111111111111111111111111111111111")
            assert prop.calldata.startswith("0xa9059cbb")

    @pytest.mark.asyncio
    async def test_snapshot_connector_fetch_proposals_graphql_http_status_error_falls_back_to_curated(self):
        conn = SnapshotGovernanceConnector()
        mock_resp = MagicMock()
        mock_resp.status_code = 502
        mock_resp.text = "Bad Gateway"

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            proposals = await conn.fetch_proposals(limit=2, use_curated_fallback=True)

            assert len(proposals) == 2
            # Curated fallback was returned
            assert proposals[0].calldata.startswith("0xa9059cbb")

    @pytest.mark.asyncio
    async def test_snapshot_connector_fetch_proposals_graphql_timeout_falls_back_to_curated(self):
        conn = SnapshotGovernanceConnector()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("Snapshot connection timed out")
            proposals = await conn.fetch_proposals(limit=3, use_curated_fallback=True)

            assert len(proposals) == 3
            assert proposals[0].proposal_id.startswith("curated-") or "curated" in proposals[0].proposal_id

    @pytest.mark.asyncio
    async def test_snapshot_connector_fetch_proposals_graphql_empty_list_falls_back_to_curated(self):
        conn = SnapshotGovernanceConnector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"proposals": []}}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            proposals = await conn.fetch_proposals(limit=1, use_curated_fallback=True)
            assert len(proposals) == 1

    @pytest.mark.asyncio
    async def test_snapshot_connector_fetch_proposals_error_with_fallback_disabled(self):
        conn = SnapshotGovernanceConnector()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.ConnectError("Network down")
            with pytest.raises(httpx.RequestError):
                await conn.fetch_proposals(limit=2, use_curated_fallback=False)


@gov_required
class TestSection2ProposalToRulePayload:
    """Verifies translation of GovernanceProposal into ConditionRulePayload."""

    def test_proposal_to_rule_payload_structure_and_rule_id(self):
        conn = SnapshotGovernanceConnector()
        prop = GovernanceProposal(
            proposal_id="0xabcdef1234567890abcdef",
            space_id="aavedao.eth",
            title="Aave Liquidity Mining Update",
            body="Adjusting liquidity parameters for Base pool.",
            target_address="0x4200000000000000000000000000000000000006",
            calldata="0xa9059cbb000000000000000000000000",
            tx_value_wei=0,
            chain_id=ChainId.BASE_SEPOLIA,
        )

        payload = conn.proposal_to_rule_payload(prop)
        assert isinstance(payload, ConditionRulePayload)
        assert payload.rule_id == f"gov-{prop.space_id}-{prop.proposal_id[:12]}"
        assert payload.chain_id == ChainId.BASE_SEPOLIA

        # Deterministic condition assertions
        det = payload.deterministic
        assert det.target_address == prop.target_address
        assert det.min_value_wei == 0
        assert det.check_native_balance is False

        # Semantic condition assertions
        sem = payload.semantic
        assert sem.enabled is True
        assert sem.risk_threshold == 7.0
        assert "privilege escalation" in sem.policy_prompt.lower()

        # Context metadata assertions
        meta = payload.context_metadata
        assert meta["proposal_id"] == prop.proposal_id
        assert meta["space_id"] == prop.space_id
        assert meta["proposal_title"] == prop.title
        assert meta["calldata"] == prop.calldata
        assert meta["tx_value_wei"] == prop.tx_value_wei

    def test_proposal_to_rule_payload_custom_policy_prompt_and_threshold(self):
        conn = SnapshotGovernanceConnector()
        prop = GovernanceProposal(
            proposal_id="prop-custom-01",
            space_id="ens.eth",
            title="Custom Policy Check",
            body="Body text",
        )
        custom_prompt = "Custom policy: block any contract upgrade."
        payload = conn.proposal_to_rule_payload(
            prop,
            policy_prompt=custom_prompt,
            risk_threshold=5.5,
        )
        assert payload.semantic.policy_prompt == custom_prompt
        assert payload.semantic.risk_threshold == 5.5


@gov_required
class TestSection2AuditProposalsEngine:
    """Verifies end-to-end proposal auditing through ConditionAgentEngine."""

    @pytest.mark.asyncio
    async def test_audit_proposals_three_curated_scenarios_and_alert_levels(self, mock_engine):
        conn = SnapshotGovernanceConnector()
        proposals = get_curated_dao_proposals(limit=3)

        # Patch deterministic check so Stage 1 consistently passes and forwards calldata_analysis
        async def mock_eval_det(condition, context):
            calldata = context.get("calldata", "0x")
            selector_info = ChainInspector.inspect_calldata_selector(calldata)
            return DeterministicResult(
                passed=True,
                reason="Mock deterministic passed",
                observed_data={
                    "target_address": condition.target_address,
                    "calldata_analysis": selector_info,
                    "is_contract": True,
                },
            )

        with patch.object(ChainInspector, "evaluate_deterministic", side_effect=mock_eval_det):
            reports = await conn.audit_proposals(engine=mock_engine, proposals=proposals)

            assert len(reports) == 3

            # Proposal 1: Benign (APPROVE) -> alert_level == "INFO"
            rep_benign = reports[0]
            assert rep_benign.agent_response.semantic_Evaluation is not None
            assert rep_benign.agent_response.semantic_Evaluation.recommended_action == "APPROVE"
            assert rep_benign.alert_level == "INFO"

            # Proposal 2: Malicious takeover (REJECT) -> alert_level == "CRITICAL"
            rep_malicious = reports[1]
            assert rep_malicious.agent_response.semantic_Evaluation is not None
            assert rep_malicious.agent_response.semantic_Evaluation.recommended_action == "REJECT"
            assert rep_malicious.alert_level == "CRITICAL"

            # Proposal 3: Audited UUPS upgrade (MANUAL_REVIEW) -> alert_level == "WARNING"
            rep_upgrade = reports[2]
            assert rep_upgrade.agent_response.semantic_Evaluation is not None
            assert rep_upgrade.agent_response.semantic_Evaluation.recommended_action == "MANUAL_REVIEW"
            assert rep_upgrade.alert_level == "WARNING"

    @pytest.mark.asyncio
    async def test_audit_proposals_fetches_when_proposals_argument_is_none(self, mock_engine):
        conn = SnapshotGovernanceConnector()

        async def mock_eval_det(condition, context):
            return DeterministicResult(
                passed=True,
                reason="Mock passed",
                observed_data={"target_address": condition.target_address},
            )

        with patch.object(ChainInspector, "evaluate_deterministic", side_effect=mock_eval_det):
            with patch.object(conn, "fetch_proposals", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = get_curated_dao_proposals(limit=1)
                reports = await conn.audit_proposals(engine=mock_engine, proposals=None, limit=1)

                mock_fetch.assert_awaited_once()
                assert len(reports) == 1

    @pytest.mark.asyncio
    async def test_audit_proposals_persists_evaluations_to_storage_with_source_governance_listener(
        self, mock_engine, temp_storage
    ):
        conn = SnapshotGovernanceConnector()
        proposals = get_curated_dao_proposals(limit=1)

        async def mock_eval_det(condition, context):
            return DeterministicResult(
                passed=True,
                reason="Mock passed",
                observed_data={"target_address": condition.target_address},
            )

        with patch.object(ChainInspector, "evaluate_deterministic", side_effect=mock_eval_det):
            reports = await conn.audit_proposals(engine=mock_engine, proposals=proposals)
            assert len(reports) == 1

            # Verify persisted record in SQLite
            history = await temp_storage.get_evaluations(limit=5)
            assert len(history) >= 1
            latest = history[0]
            assert latest["source"] == "governance_listener"
            assert latest["rule_id"] == reports[0].rule_id

    @pytest.mark.asyncio
    async def test_audit_proposals_semantic_evaluation_none_yields_info_alert_level(self, mock_engine):
        conn = SnapshotGovernanceConnector()
        proposals = get_curated_dao_proposals(limit=1)

        # Force deterministic check to fail so semantic evaluation is None
        async def mock_eval_det_fail(condition, context):
            return DeterministicResult(
                passed=False,
                reason="Deterministic halt",
                observed_data={"target_address": condition.target_address},
            )

        with patch.object(ChainInspector, "evaluate_deterministic", side_effect=mock_eval_det_fail):
            reports = await conn.audit_proposals(engine=mock_engine, proposals=proposals)
            assert len(reports) == 1
            assert reports[0].agent_response.semantic_Evaluation is None
            assert reports[0].alert_level == "INFO"


# =============================================================================
# SECTION 3: FastAPI Governance Endpoint & Exports
# =============================================================================

@gov_required
class TestSection3FastAPIEndpointAndExports:
    """Verifies POST /governance/audit-proposals endpoint and api.py module re-exports."""

    def test_api_module_re_exports_phase_b5_symbols(self):
        # Root api module and src.api must expose Phase B5 components
        import api as root_api_module
        expected_exports = [
            "SnapshotGovernanceConnector",
            "GovernanceProposal",
            "GovernanceAuditReport",
            "NETWORK_PROFILES",
            "get_network_profile",
            "get_x402_facilitator",
        ]
        for sym in expected_exports:
            assert hasattr(api_module, sym), f"src.api missing {sym}"
            assert hasattr(root_api_module, sym), f"root api.py missing {sym}"

    def test_post_governance_audit_proposals_endpoint_curated_success(self, temp_storage):
        app = create_app(storage=temp_storage)
        client = TestClient(app)

        async def mock_eval_det(condition, context):
            calldata = context.get("calldata", "0x")
            selector_info = ChainInspector.inspect_calldata_selector(calldata)
            return DeterministicResult(
                passed=True,
                reason="ok",
                observed_data={
                    "target_address": condition.target_address,
                    "calldata_analysis": selector_info,
                },
            )

        with patch.object(ChainInspector, "evaluate_deterministic", side_effect=mock_eval_det):
            resp = client.post(
                "/governance/audit-proposals",
                json={"spaces": ["arbitrumfoundation.eth"], "limit": 2},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert isinstance(data, list)
            assert len(data) == 2
            report1 = data[0]
            assert "proposal" in report1
            assert "rule_id" in report1
            assert "agent_response" in report1
            assert "alert_level" in report1
            assert report1["alert_level"] in ("CRITICAL", "WARNING", "INFO")

    def test_post_governance_audit_proposals_endpoint_empty_request_uses_defaults(self, temp_storage):
        app = create_app(storage=temp_storage)
        client = TestClient(app)

        async def mock_eval_det(condition, context):
            return DeterministicResult(
                passed=True,
                reason="ok",
                observed_data={"target_address": condition.target_address},
            )

        with patch.object(ChainInspector, "evaluate_deterministic", side_effect=mock_eval_det):
            resp = client.post("/governance/audit-proposals", json={})
            assert resp.status_code == 200
            data = resp.json()
            assert isinstance(data, list)
            assert len(data) == 3  # default limit is 3

    def test_post_governance_audit_proposals_endpoint_invalid_limit_returns_422(self, temp_storage):
        app = create_app(storage=temp_storage)
        client = TestClient(app)

        resp = client.post("/governance/audit-proposals", json={"limit": 50})
        assert resp.status_code == 422

    def test_post_governance_audit_proposals_is_free_when_x402_enabled(self, temp_storage):
        # Even with X402 enabled, diagnostic /governance route is free without payment header
        cfg = X402Config(enabled=True)
        app = create_app(storage=temp_storage, x402_config=cfg)
        client = TestClient(app)

        async def mock_eval_det(condition, context):
            return DeterministicResult(
                passed=True,
                reason="ok",
                observed_data={"target_address": condition.target_address},
            )

        with patch.object(ChainInspector, "evaluate_deterministic", side_effect=mock_eval_det):
            resp = client.post("/governance/audit-proposals", json={"limit": 1})
            assert resp.status_code == 200
            assert resp.status_code != 402

    def test_root_service_discovery_endpoint(self, temp_storage):
        app = create_app(storage=temp_storage)
        client = TestClient(app)

        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "Web3 Condition-Action Trigger Agent"
        assert data["version"] == "1.0.0"
        assert data["status"] == "online"
        assert "x402_enabled" in data
        assert "x402_network" in data
        assert "price_per_eval_usdc" in data
        assert "pay_to_address" in data
        assert "endpoints" in data

        endpoints = data["endpoints"]
        assert endpoints["swagger_docs"] == "/docs"
        assert endpoints["health"] == "/health"
        assert endpoints["validate_rule"] == "/rules/validate"
        assert endpoints["evaluate"] == "/evaluate"
        assert endpoints["evaluate_batch"] == "/rules/evaluate-batch"
        assert endpoints["enqueue_job"] == "/rules/enqueue"
        assert endpoints["governance_audit"] == "/governance/audit-proposals"
        assert endpoints["metrics_summary"] == "/metrics/summary"
        assert endpoints["payments_ledger"] == "/payments"
        assert endpoints["error_logs"] == "/logs/errors"

        # Favicon returning 204
        fav_resp = client.get("/favicon.ico")
        assert fav_resp.status_code == 204


# =============================================================================
# SECTION 4: Repository & Git Security Gate
# =============================================================================

class TestSection4GitAndRepositorySecurity:
    """Verifies repository cleanliness, git ignore rules, and documentation presence."""

    def test_gitignore_blocks_sensitive_env_file(self):
        cmd = ["git", "check-ignore", "-q", ".env"]
        result = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True)
        assert result.returncode == 0, "Expected .env to be ignored by .gitignore"

    def test_gitignore_blocks_sensitive_buyer_wallet(self):
        cmd = ["git", "check-ignore", "-q", "scripts/.buyer_wallet.json"]
        result = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True)
        assert result.returncode == 0, "Expected scripts/.buyer_wallet.json to be ignored by .gitignore"

    def test_gitignore_blocks_sqlite_databases(self):
        cmd = ["git", "check-ignore", "-q", "data/agent.db"]
        result = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True)
        assert result.returncode == 0, "Expected data/agent.db to be ignored by .gitignore"

    def test_git_ls_files_contains_zero_sensitive_artifacts(self):
        cmd = ["git", "ls-files"]
        result = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True, check=True)
        tracked_files = result.stdout.splitlines()

        sensitive_substrings = [".env", ".buyer_wallet", ".key"]
        sensitive_extensions = [".db", ".sqlite", ".sqlite3"]

        violations = []
        for f in tracked_files:
            clean_f = f.strip().lower()
            if os.path.basename(clean_f) == ".env.example":
                continue
            if any(sub in clean_f for sub in sensitive_substrings):
                violations.append(f)
            elif any(clean_f.endswith(ext) for ext in sensitive_extensions):
                violations.append(f)

        assert len(violations) == 0, f"Sensitive files tracked in git: {violations}"

    def test_documentation_files_exist_and_non_empty(self):
        required_docs = ["README.md"]
        for doc in required_docs:
            p = Path(ROOT_DIR) / doc
            assert p.is_file(), f"Expected documentation file {doc} to exist"
            assert p.stat().st_size > 100, f"Expected documentation file {doc} to be non-empty (>100 bytes)"

    def test_governance_listener_script_exists_and_valid_syntax(self):
        script_path = Path(ROOT_DIR) / "scripts" / "governance_listener.py"
        assert script_path.is_file(), "scripts/governance_listener.py must exist"
        assert script_path.stat().st_size > 100, "scripts/governance_listener.py must not be empty"

        # AST syntax parsing verification
        source_code = script_path.read_text(encoding="utf-8")
        parsed = ast.parse(source_code, filename=str(script_path))
        assert isinstance(parsed, ast.Module)

    def test_governance_listener_cli_argument_support(self):
        script_path = Path(ROOT_DIR) / "scripts" / "governance_listener.py"
        source_code = script_path.read_text(encoding="utf-8")
        assert "--limit" in source_code or "-limit" in source_code
        assert "--curated" in source_code or "-curated" in source_code
