"""
Unit and mocked integration test suite for Engine 2: DAO Governance Daemon (scripts/governance_daemon.py).

Validates autonomous polling, multi-DAO monitoring (Uniswap, Arbitrum, ENS, Optimism, Aave, Aerodrome),
deduplication of audited proposals, deterministic and semantic risk evaluation pipeline via ConditionAgentEngine,
network failure resiliency, SQLite AgentStorage persistence, and dry-run CLI execution with zero real network dependency.
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import warnings

warnings.filterwarnings("ignore", category=ResourceWarning)
warnings.filterwarnings("ignore", category=pytest.PytestUnraisableExceptionWarning)

pytestmark = [
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]

# Ensure repo root, scripts, and src directories are accessible
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SCRIPTS_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scripts.governance_daemon import (
    DEFAULT_MONITORED_SPACES,
    audit_governance_proposals,
    get_mock_daemon_proposals,
    load_audited_proposal_ids,
    main,
    parse_args,
    parse_spaces,
    print_audit_table,
    run_governance_daemon,
)
from src.engine import ConditionAgentEngine
from src.governance_connector import (
    GovernanceAuditReport,
    GovernanceProposal,
    SnapshotGovernanceConnector,
)
from src.schemas import (
    ChainId,
    ConditionRulePayload,
    DeterministicResult,
    FinalAgentResponse,
    SemanticAuditResult,
)
from src.semantic_evaluator import MockSemanticEvaluator
from src.storage import AgentStorage


@pytest.fixture(autouse=True)
def mock_chain_inspector():
    """
    Autouse fixture that mocks ChainInspector deterministic evaluation in ConditionAgentEngine,
    ensuring zero external EVM RPC / aiohttp network calls and preventing unclosed client sessions.
    """
    with patch("src.engine.ChainInspector") as mock_ci_cls:
        mock_ci = MagicMock()
        mock_ci.evaluate_deterministic = AsyncMock(
            return_value=DeterministicResult(
                passed=True,
                reason="Mocked deterministic pass",
                observed_data={"code_length": 128},
            )
        )
        mock_ci_cls.return_value = mock_ci
        yield mock_ci_cls


# ============================================================================
# 1. Mandatory Core Tests
# ============================================================================


def test_daemon_initialization_defaults():
    """
    Mandatory Test 1:
    Validates default spaces (Uniswap, Arbitrum, ENS, Optimism, Aave, Aerodrome),
    default CLI options, and initial configurations.
    """
    expected_spaces = [
        "uniswap.eth",
        "arbitrumfoundation.eth",
        "ens.eth",
        "opcollective.eth",
        "aave.eth",
        "aerodrome.eth",
    ]
    assert DEFAULT_MONITORED_SPACES == expected_spaces
    assert len(DEFAULT_MONITORED_SPACES) == 6

    # Test parse_spaces fallback behavior on None, empty list, or empty string
    assert parse_spaces(None) == expected_spaces
    assert parse_spaces([]) == expected_spaces
    assert parse_spaces("") == expected_spaces

    # Test parse_args defaults
    args = parse_args([])
    assert args.poll_interval == 120.0
    assert args.once is False
    assert args.dry_run is False
    assert args.limit == 3
    assert args.spaces is None
    assert args.space_list is None
    assert args.min_alert_level == "WARNING"
    assert args.webhook_url is None
    assert args.db_path is None


@pytest.mark.asyncio
async def test_daemon_deduplication(tmp_path):
    """
    Mandatory Test 2:
    Validates that proposals audited in one round are remembered in the in-memory
    tracking set (and SQLite ledger) and are NOT re-audited in the subsequent round.
    """
    db_file = str(tmp_path / "test_dedup.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    mock_proposal = GovernanceProposal(
        proposal_id="prop-dedup-001",
        space_id="uniswap.eth",
        title="Test Proposal for Deduplication",
        body="Proposal body targeting 0x4200000000000000000000000000000000000006 with calldata 0xa9059cbb",
        author="0x1111111111111111111111111111111111111111",
        state="active",
        created=1710000000,
        target_address="0x4200000000000000000000000000000000000006",
        calldata="0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a7640000",
        tx_value_wei=0,
        chain_id=ChainId.BASE_SEPOLIA,
    )

    mock_connector = MagicMock(spec=SnapshotGovernanceConnector)
    # The connector returns the exact same proposal across both discovery iterations
    mock_connector.fetch_proposals = AsyncMock(return_value=[mock_proposal])
    real_connector = SnapshotGovernanceConnector()
    mock_connector.proposal_to_rule_payload = real_connector.proposal_to_rule_payload

    mock_engine = MagicMock(spec=ConditionAgentEngine)
    mock_engine.storage = storage

    mock_response = FinalAgentResponse(
        rule_id="gov-uniswap.eth-prop-dedup-0",
        chain_id=ChainId.BASE_SEPOLIA,
        deterministic_check=DeterministicResult(passed=True, reason="Conditions verified", observed_data={}),
        llm_invoked=True,
        semantic_Evaluation=SemanticAuditResult(
            conditions_met=True,
            risk_score=2.0,
            recommended_action="APPROVE",
            summary="Safe proposal",
            flagged_issues=[],
            input_tokens=100,
            output_tokens=50,
            estimated_cost_usd=0.0001,
        ),
    )
    mock_engine.process_rule = AsyncMock(return_value=mock_response)

    # Execute 2 iterations with poll_interval=0.01
    reports = await run_governance_daemon(
        poll_interval=0.01,
        once=False,
        dry_run=False,
        limit=1,
        spaces=["uniswap.eth"],
        engine=mock_engine,
        storage=storage,
        connector=mock_connector,
        max_iterations=2,
    )

    # The proposal was seen in iteration 1 and audited, but skipped in iteration 2
    assert mock_connector.fetch_proposals.call_count == 2
    assert mock_engine.process_rule.call_count == 1
    assert len(reports) == 1
    assert reports[0].proposal.proposal_id == "prop-dedup-001"


@pytest.mark.asyncio
async def test_daemon_run_once_dry_run(tmp_path):
    """
    Mandatory Test 3:
    Executes run_governance_daemon with dry_run=True and once=True with mocked
    engine and connector, verifying clean, successful completion and report generation.
    """
    db_file = str(tmp_path / "test_dry_run_once.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    mock_engine = MagicMock(spec=ConditionAgentEngine)
    mock_engine.storage = storage

    async def fake_process_rule(payload: ConditionRulePayload, source: str = "engine", job_id=None):
        resp = FinalAgentResponse(
            rule_id=payload.rule_id,
            chain_id=payload.chain_id,
            deterministic_check=DeterministicResult(passed=True, reason="Conditions verified", observed_data={}),
            llm_invoked=True,
            semantic_Evaluation=SemanticAuditResult(
                conditions_met=True,
                risk_score=1.5,
                recommended_action="APPROVE",
                summary="Simulated dry-run approval",
                flagged_issues=[],
                input_tokens=80,
                output_tokens=40,
                estimated_cost_usd=0.00008,
            ),
        )
        await storage.record_evaluation(payload, resp, source=source)
        return resp

    mock_engine.process_rule = AsyncMock(side_effect=fake_process_rule)

    reports = await run_governance_daemon(
        dry_run=True,
        once=True,
        limit=1,
        engine=mock_engine,
        storage=storage,
    )

    assert len(reports) == len(DEFAULT_MONITORED_SPACES)
    assert mock_engine.process_rule.call_count == len(DEFAULT_MONITORED_SPACES)
    for r in reports:
        assert isinstance(r, GovernanceAuditReport)
        assert r.alert_level == "INFO"
        assert r.agent_response.semantic_Evaluation.recommended_action == "APPROVE"


@pytest.mark.asyncio
async def test_daemon_custom_spaces(tmp_path):
    """
    Mandatory Test 4:
    Validates that --spaces custom.eth is parsed correctly and utilized
    by the daemon to inspect only the requested space.
    """
    # 1. Test CLI argument parsing
    args = parse_args(["--spaces", "custom.eth"])
    assert args.spaces == "custom.eth"
    assert parse_spaces(args.spaces) == ["custom.eth"]

    args_multi = parse_args(["--spaces", "custom1.eth,custom2.eth"])
    assert parse_spaces(args_multi.spaces) == ["custom1.eth", "custom2.eth"]

    # 2. Test runtime daemon behavior with custom space
    db_file = str(tmp_path / "test_custom_spaces.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    mock_connector = MagicMock(spec=SnapshotGovernanceConnector)
    mock_connector.fetch_proposals = AsyncMock(return_value=[])

    mock_engine = MagicMock(spec=ConditionAgentEngine)
    mock_engine.storage = storage

    await run_governance_daemon(
        spaces="custom.eth",
        once=True,
        connector=mock_connector,
        engine=mock_engine,
        storage=storage,
    )

    mock_connector.fetch_proposals.assert_called_once()
    call_kwargs = mock_connector.fetch_proposals.call_args.kwargs
    assert call_kwargs["spaces"] == ["custom.eth"]


@pytest.mark.asyncio
async def test_daemon_handles_network_exceptions_resiliently(tmp_path):
    """
    Mandatory Test 5:
    Simulates transient network and GraphQL API exceptions and validates
    that the daemon catches exceptions, logs warnings, does not crash,
    and continues gracefully across target spaces.
    """
    db_file = str(tmp_path / "test_resilience.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    mock_connector = MagicMock(spec=SnapshotGovernanceConnector)
    call_counter = 0

    async def transient_network_failure(*args, **kwargs):
        nonlocal call_counter
        call_counter += 1
        if call_counter == 1:
            raise httpx.ConnectError("Snapshot GraphQL endpoint unreachable")
        if call_counter == 2:
            raise httpx.ReadTimeout("Timeout querying Snapshot API")
        return []

    mock_connector.fetch_proposals = AsyncMock(side_effect=transient_network_failure)

    mock_engine = MagicMock(spec=ConditionAgentEngine)
    mock_engine.storage = storage

    # Daemon must handle exceptions without throwing
    reports = await run_governance_daemon(
        spaces=["uniswap.eth", "arbitrumfoundation.eth", "ens.eth"],
        once=True,
        connector=mock_connector,
        engine=mock_engine,
        storage=storage,
    )

    assert reports == []
    assert call_counter == 3


@pytest.mark.asyncio
async def test_daemon_persists_reports_to_storage(tmp_path):
    """
    Mandatory Test 6:
    Validates that audited proposal evaluation records are properly persisted
    to SQLite AgentStorage and can be retrieved via load_audited_proposal_ids.
    """
    db_file = str(tmp_path / "test_persistence.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    evaluator = MockSemanticEvaluator()
    engine = ConditionAgentEngine(
        semantic_evaluator=evaluator,
        storage=storage,
    )

    # Run dry-run scan over 2 spaces
    reports = await run_governance_daemon(
        dry_run=True,
        once=True,
        spaces=["uniswap.eth", "arbitrumfoundation.eth"],
        limit=1,
        engine=engine,
        storage=storage,
    )

    assert len(reports) == 2

    # Verify evaluations are stored in AgentStorage database
    evals = await storage.get_evaluations(limit=10)
    assert len(evals) >= 2

    persisted_rule_ids = {e["rule_id"] for e in evals}
    for r in reports:
        assert r.rule_id in persisted_rule_ids
        matching = [e for e in evals if e["rule_id"] == r.rule_id]
        assert matching[0]["source"] == "governance_daemon"

    # Verify load_audited_proposal_ids preloads them
    preloaded = await load_audited_proposal_ids(storage)
    for r in reports:
        assert (r.rule_id in preloaded) or (r.proposal.proposal_id in preloaded)


def test_cli_main_dry_run(monkeypatch, tmp_path):
    """
    Mandatory Test 7:
    Executes main() via CLI in dry-run single-pass mode, verifying that
    it terminates cleanly with zero unhandled exceptions.
    """
    db_file = str(tmp_path / "cli_main_dry_run.db")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "governance_daemon.py",
            "--dry-run",
            "--once",
            "--limit",
            "1",
            "--spaces",
            "uniswap.eth",
            "--db-path",
            db_file,
        ],
    )

    # main() must execute cleanly without raising SystemExit != 0 or uncaught exceptions
    main()

    assert os.path.exists(db_file)


# ============================================================================
# 2. Auxiliary Edge-Case and Resiliency Tests
# ============================================================================


def test_parse_spaces_edge_cases():
    """Validates parse_spaces handling of comma-separated strings, lists, and whitespace."""
    assert parse_spaces("uniswap.eth, aave.eth ") == ["uniswap.eth", "aave.eth"]
    assert parse_spaces(["uniswap.eth, arbitrumfoundation.eth", "ens.eth"]) == [
        "uniswap.eth",
        "arbitrumfoundation.eth",
        "ens.eth",
    ]
    # Deduplication of identical spaces when passed as list
    assert parse_spaces(["uniswap.eth", "uniswap.eth", "aave.eth"]) == ["uniswap.eth", "aave.eth"]


def test_get_mock_daemon_proposals():
    """Validates get_mock_daemon_proposals covers known DAOs and synthesizes custom spaces."""
    known_spaces = ["uniswap.eth", "arbitrumfoundation.eth", "ens.eth", "opcollective.eth", "aave.eth", "aerodrome.eth"]
    props = get_mock_daemon_proposals(known_spaces, limit=1)
    assert len(props) == 6
    space_ids = {p.space_id for p in props}
    assert space_ids == set(known_spaces)

    # Unknown space synthesis fallback
    custom_props = get_mock_daemon_proposals(["customdao.eth"], limit=1)
    assert len(custom_props) == 1
    assert custom_props[0].space_id == "customdao.eth"
    assert "Standard Treasury Allocation" in custom_props[0].title


@pytest.mark.asyncio
async def test_audit_governance_proposals_alert_severity_mapping(tmp_path):
    """Validates that audit_governance_proposals maps recommendations to appropriate alert levels."""
    db_file = str(tmp_path / "test_severity.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    connector = SnapshotGovernanceConnector()
    mock_engine = MagicMock(spec=ConditionAgentEngine)
    mock_engine.storage = storage

    proposal_critical = GovernanceProposal(
        proposal_id="prop-crit-001",
        space_id="uniswap.eth",
        title="Malicious Backdoor Proposal",
        body="Execute transferOwnership at 0x4200000000000000000000000000000000000006 calldata 0xf2fde38b",
        target_address="0x4200000000000000000000000000000000000006",
        calldata="0xf2fde38b000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        chain_id=ChainId.BASE_SEPOLIA,
    )
    proposal_warning = GovernanceProposal(
        proposal_id="prop-warn-002",
        space_id="uniswap.eth",
        title="Unverified Proxy Upgrade Proposal",
        body="Execute upgradeTo at 0x4200000000000000000000000000000000000006 calldata 0x3659cfe6",
        target_address="0x4200000000000000000000000000000000000006",
        calldata="0x3659cfe6000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        chain_id=ChainId.BASE_SEPOLIA,
    )

    async def mock_rule_eval(payload: ConditionRulePayload, source: str = "engine"):
        if "prop-crit" in payload.rule_id:
            action = "REJECT"
            score = 9.5
        else:
            action = "MANUAL_REVIEW"
            score = 6.0
        return FinalAgentResponse(
            rule_id=payload.rule_id,
            chain_id=payload.chain_id,
            deterministic_check=DeterministicResult(passed=True, reason="Conditions verified", observed_data={}),
            llm_invoked=True,
            semantic_Evaluation=SemanticAuditResult(
                conditions_met=True,
                risk_score=score,
                recommended_action=action,
                summary="Evaluation outcome",
                flagged_issues=["Flagged issue"],
                input_tokens=100,
                output_tokens=50,
                estimated_cost_usd=0.0001,
            ),
        )

    mock_engine.process_rule = AsyncMock(side_effect=mock_rule_eval)

    reports = await audit_governance_proposals(
        connector=connector,
        engine=mock_engine,
        proposals=[proposal_critical, proposal_warning],
    )

    assert len(reports) == 2
    assert reports[0].alert_level == "CRITICAL"
    assert reports[1].alert_level == "WARNING"


def test_print_audit_table(capsys):
    """Validates that print_audit_table outputs ASCII tables and handles empty inputs cleanly."""
    # 1. Empty reports
    print_audit_table([])
    captured_empty = capsys.readouterr().out
    assert "No new proposals audited." in captured_empty

    # 2. Populated reports
    proposal = GovernanceProposal(
        proposal_id="prop-test-table-001",
        space_id="uniswap.eth",
        title="Test Proposal",
        body="Body at 0x4200000000000000000000000000000000000006 calldata 0xa9059cbb",
        target_address="0x4200000000000000000000000000000000000006",
        calldata="0xa9059cbb",
        chain_id=ChainId.BASE_SEPOLIA,
    )
    report = GovernanceAuditReport(
        proposal=proposal,
        rule_id="gov-uniswap.eth-prop-test-ta",
        agent_response=FinalAgentResponse(
            rule_id="gov-uniswap.eth-prop-test-ta",
            chain_id=ChainId.BASE_SEPOLIA,
            deterministic_check=DeterministicResult(passed=True, reason="Conditions verified", observed_data={}),
            llm_invoked=True,
            semantic_Evaluation=SemanticAuditResult(
                conditions_met=True,
                risk_score=1.0,
                recommended_action="APPROVE",
                summary="Approved",
                flagged_issues=[],
                input_tokens=50,
                output_tokens=25,
                estimated_cost_usd=0.00005,
            ),
        ),
        alert_level="INFO",
    )
    print_audit_table([report])
    captured_pop = capsys.readouterr().out
    assert "Proposal ID" in captured_pop
    assert "Space" in captured_pop
    assert "Alert Level" in captured_pop
    assert "APPROVE" in captured_pop
    assert "uniswap.eth" in captured_pop


@pytest.mark.asyncio
async def test_daemon_webhook_alert_dispatch(tmp_path):
    """Validates that WebhookAlertDispatcher is triggered when webhook_url is configured."""
    db_file = str(tmp_path / "test_webhook.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    mock_engine = MagicMock(spec=ConditionAgentEngine)
    mock_engine.storage = storage

    async def fake_critical_rule(payload: ConditionRulePayload, source: str = "engine", job_id=None):
        return FinalAgentResponse(
            rule_id=payload.rule_id,
            chain_id=payload.chain_id,
            deterministic_check=DeterministicResult(passed=True, reason="Conditions verified", observed_data={}),
            llm_invoked=True,
            semantic_Evaluation=SemanticAuditResult(
                conditions_met=True,
                risk_score=9.5,
                recommended_action="REJECT",
                summary="Critical backdoor detected",
                flagged_issues=["Admin privilege escalation"],
                input_tokens=100,
                output_tokens=50,
                estimated_cost_usd=0.0001,
            ),
        )

    mock_engine.process_rule = AsyncMock(side_effect=fake_critical_rule)

    with patch("scripts.governance_daemon.WebhookAlertDispatcher") as mock_dispatcher_cls:
        mock_dispatcher_instance = MagicMock()
        mock_dispatcher_instance.dispatch_batch = AsyncMock(return_value=1)
        mock_dispatcher_cls.return_value = mock_dispatcher_instance

        reports = await run_governance_daemon(
            dry_run=True,
            once=True,
            spaces=["uniswap.eth"],
            limit=1,
            webhook_url="https://mock.webhook.url/alert",
            min_alert_level="WARNING",
            engine=mock_engine,
            storage=storage,
        )

        assert len(reports) == 1
        assert reports[0].alert_level == "CRITICAL"
        mock_dispatcher_cls.assert_called_once_with(
            webhook_url="https://mock.webhook.url/alert",
            public_api_url=None,
        )
        mock_dispatcher_instance.dispatch_batch.assert_called_once()


@pytest.mark.asyncio
async def test_load_audited_proposal_ids_resilience(tmp_path):
    """Validates that load_audited_proposal_ids handles empty databases and corrupted JSON rows gracefully."""
    db_file = str(tmp_path / "test_corrupt.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    # Preloading on clean DB returns empty set
    preloaded = await load_audited_proposal_ids(storage)
    assert preloaded == set()

    # Insert valid evaluation and invalid json row
    import aiosqlite
    async with aiosqlite.connect(db_file) as db:
        await db.execute(
            """
            INSERT INTO evaluations (
                created_at, rule_id, chain_id, job_id, source,
                stage1_passed, llm_invoked, decision, risk_score,
                provider, model, cached, input_tokens, output_tokens,
                est_cost_usd, latency_ms, status, request_json, response_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("2026-11-06T00:00:00Z", "gov-ens.eth-prop-1234", 84532, None, "governance_daemon", 1, 1, "APPROVE", 1.0, None, None, 0, 0, 0, 0.0, 0.0, "ok", '{"context_metadata": {"proposal_id": "prop-1234"}}', "{}"),
        )
        await db.execute(
            """
            INSERT INTO evaluations (
                created_at, rule_id, chain_id, job_id, source,
                stage1_passed, llm_invoked, decision, risk_score,
                provider, model, cached, input_tokens, output_tokens,
                est_cost_usd, latency_ms, status, request_json, response_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("2026-11-06T00:00:00Z", "gov-aave.eth-corrupt", 84532, None, "governance_daemon", 1, 1, "REJECT", 9.0, None, None, 0, 0, 0, 0.0, 0.0, "ok", "NOT_VALID_JSON", "{}"),
        )
        await db.commit()

    loaded = await load_audited_proposal_ids(storage)
    assert "gov-ens.eth-prop-1234" in loaded
    assert "prop-1234" in loaded
    assert "gov-aave.eth-corrupt" in loaded


@pytest.mark.asyncio
async def test_daemon_max_iterations_loop(tmp_path):
    """Validates that run_governance_daemon honors max_iterations and cleanly terminates the loop."""
    db_file = str(tmp_path / "test_max_iter.db")
    storage = AgentStorage(db_path=db_file)
    await storage.initialize()

    mock_connector = MagicMock(spec=SnapshotGovernanceConnector)
    mock_connector.fetch_proposals = AsyncMock(return_value=[])

    mock_engine = MagicMock(spec=ConditionAgentEngine)
    mock_engine.storage = storage

    reports = await run_governance_daemon(
        poll_interval=0.01,
        once=False,
        max_iterations=3,
        spaces=["uniswap.eth"],
        connector=mock_connector,
        engine=mock_engine,
        storage=storage,
    )

    assert reports == []
    assert mock_connector.fetch_proposals.call_count == 3

