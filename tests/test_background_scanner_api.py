"""
Unit and integration test suite for Background Scanner lifecycle in FastAPI API Layer (src/api.py).

Validates:
1. Scanner disabled by default in local environment (zero tasks created).
2. Scanner enabled via create_app(enable_background_scanner=True) flag with mocked Web3.
3. Scanner enabled via ENABLE_BACKGROUND_SCANNER=true environment variable.
4. Scanner enabled via RENDER=true environment variable fallback.
5. Explicit flag overrides environment variables (enable_background_scanner=False).
6. Graceful shutdown on application lifespan exit: scanner_task is cancelled,
   CancelledError is cleanly absorbed, and scanner_active becomes False without unhandled exceptions.
7. GET /metrics/summary reports accurate background_scanner_active status.
8. Background worker resilience to transient RPC exceptions.
9. Lifespan shutdown idempotence when scanner task is None.
"""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Ensure repo root, src, and scripts directories are accessible
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
for _p in (_ROOT_DIR, _SRC_DIR, _SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from scripts.block_contract_scanner import create_mock_w3
from src.api import create_app, _background_scanner_worker
from src.engine import ConditionAgentEngine
from src.semantic_evaluator import MockSemanticEvaluator
from src.storage import AgentStorage


@pytest.fixture
def temp_storage(tmp_path: Path) -> AgentStorage:
    """Provides an isolated SQLite AgentStorage instance backed by tmp_path."""
    db_file = tmp_path / "test_scanner_api.db"
    return AgentStorage(db_path=str(db_file))


@pytest.fixture
def mock_engine(temp_storage: AgentStorage) -> ConditionAgentEngine:
    """Provides a ConditionAgentEngine backed by MockSemanticEvaluator and isolated storage."""
    return ConditionAgentEngine(
        semantic_evaluator=MockSemanticEvaluator(),
        storage=temp_storage,
    )


@pytest.fixture(autouse=True)
def clean_env_and_w3(monkeypatch: pytest.MonkeyPatch):
    """
    Autouse fixture that sanitizes environment variables and guarantees that any
    instantiation of AsyncWeb3 inside src.api uses create_mock_w3() by default,
    preventing any external network or RPC calls.
    """
    monkeypatch.delenv("ENABLE_BACKGROUND_SCANNER", raising=False)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("PUBLIC_EVALUATE_ONLY", "false")
    monkeypatch.setenv("RPC_URL_8453", "http://mock-rpc-base.local")

    mock_w3_inst = create_mock_w3()
    with patch("src.api.AsyncWeb3", return_value=mock_w3_inst):
        yield mock_w3_inst


# ============================================================================
# Core Mandated Tests
# ============================================================================

def test_background_scanner_disabled_by_default_in_local_env(mock_engine, temp_storage):
    """
    Mandatory Test 1:
    Validates that create_app() without flags or environment variables starts with
    scanner_active = False and no background task is created.
    """
    app = create_app(engine=mock_engine, storage=temp_storage, public_evaluate_only=False)

    # Initial state upon instantiation
    assert getattr(app.state, "scanner_active", None) is False
    assert getattr(app.state, "scanner_task", None) is None

    # Inside application lifespan
    with TestClient(app) as client:
        assert app.state.scanner_active is False
        assert getattr(app.state, "scanner_task", None) is None

    # Post-shutdown state
    assert app.state.scanner_active is False
    assert getattr(app.state, "scanner_task", None) is None


def test_background_scanner_enabled_via_flag(mock_engine, temp_storage):
    """
    Mandatory Test 2:
    Validates that create_app(enable_background_scanner=True) initiates the background task
    with mocked Web3 during application lifespan.
    """
    app = create_app(
        engine=mock_engine,
        storage=temp_storage,
        enable_background_scanner=True,
        public_evaluate_only=False,
    )
    mock_w3 = create_mock_w3()
    app.state.scanner_w3 = mock_w3

    # Before lifespan
    assert app.state.scanner_active is False
    assert app.state.scanner_task is None

    with TestClient(app) as client:
        # Active inside lifespan
        assert app.state.scanner_active is True
        assert app.state.scanner_task is not None
        assert isinstance(app.state.scanner_task, asyncio.Task)
        assert not app.state.scanner_task.done()

    # Deactivated after lifespan shutdown
    assert app.state.scanner_active is False


def test_background_scanner_enabled_via_env(mock_engine, temp_storage, monkeypatch):
    """
    Mandatory Test 3:
    Validates that ENABLE_BACKGROUND_SCANNER=true initiates the background task
    during application lifespan when no explicit flag is supplied.
    """
    monkeypatch.setenv("ENABLE_BACKGROUND_SCANNER", "true")

    app = create_app(
        engine=mock_engine,
        storage=temp_storage,
        public_evaluate_only=False,
    )
    mock_w3 = create_mock_w3()
    app.state.scanner_w3 = mock_w3

    with TestClient(app) as client:
        assert app.state.scanner_active is True
        assert app.state.scanner_task is not None
        assert isinstance(app.state.scanner_task, asyncio.Task)
        assert not app.state.scanner_task.done()

    assert app.state.scanner_active is False


def test_background_scanner_graceful_shutdown(mock_engine, temp_storage):
    """
    Mandatory Test 4:
    Validates that upon exiting application lifespan, scanner_task is cancelled gracefully,
    CancelledError is caught, and scanner_active becomes False without raising unhandled exceptions.
    """
    app = create_app(
        engine=mock_engine,
        storage=temp_storage,
        enable_background_scanner=True,
        public_evaluate_only=False,
    )
    mock_w3 = create_mock_w3()
    app.state.scanner_w3 = mock_w3

    captured_task = None
    with TestClient(app) as client:
        assert app.state.scanner_active is True
        captured_task = app.state.scanner_task
        assert captured_task is not None
        assert not captured_task.done()

    # Lifespan has concluded
    assert app.state.scanner_active is False
    assert captured_task.done() or captured_task.cancelled()


def test_metrics_summary_reports_scanner_status(mock_engine, temp_storage):
    """
    Mandatory Test 5:
    Validates that GET /metrics/summary accurately reports background_scanner_active
    both when disabled and when enabled.
    """
    # 1. Scanner Disabled Case
    app_disabled = create_app(
        engine=mock_engine,
        storage=temp_storage,
        enable_background_scanner=False,
        public_evaluate_only=False,
    )
    with TestClient(app_disabled) as client:
        resp = client.get("/metrics/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "background_scanner_active" in data
        assert data["background_scanner_active"] is False

    # 2. Scanner Enabled Case
    app_enabled = create_app(
        engine=mock_engine,
        storage=temp_storage,
        enable_background_scanner=True,
        public_evaluate_only=False,
    )
    app_enabled.state.scanner_w3 = create_mock_w3()
    with TestClient(app_enabled) as client:
        resp = client.get("/metrics/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "background_scanner_active" in data
        assert data["background_scanner_active"] is True


# ============================================================================
# Additional Edge-Case & Robustness Tests
# ============================================================================

def test_background_scanner_enabled_via_render_env(mock_engine, temp_storage, monkeypatch):
    """
    Edge-Case Test:
    Validates that RENDER=true enables the background scanner automatically
    as a cloud deployment fallback when ENABLE_BACKGROUND_SCANNER is unset.
    """
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("ENABLE_BACKGROUND_SCANNER", raising=False)

    app = create_app(
        engine=mock_engine,
        storage=temp_storage,
        public_evaluate_only=False,
    )
    app.state.scanner_w3 = create_mock_w3()

    with TestClient(app) as client:
        assert app.state.scanner_active is True
        assert app.state.scanner_task is not None

    assert app.state.scanner_active is False


def test_background_scanner_flag_overrides_env(mock_engine, temp_storage, monkeypatch):
    """
    Edge-Case Test:
    Validates that explicit enable_background_scanner=False overrides
    ENABLE_BACKGROUND_SCANNER=true and RENDER=true.
    """
    monkeypatch.setenv("ENABLE_BACKGROUND_SCANNER", "true")
    monkeypatch.setenv("RENDER", "true")

    app = create_app(
        engine=mock_engine,
        storage=temp_storage,
        enable_background_scanner=False,
        public_evaluate_only=False,
    )

    with TestClient(app) as client:
        assert app.state.scanner_active is False
        assert getattr(app.state, "scanner_task", None) is None


@pytest.mark.asyncio
async def test_background_scanner_worker_transient_error_resilience(mock_engine, temp_storage):
    """
    Edge-Case Test:
    Validates that _background_scanner_worker catches transient exceptions
    (e.g., RPC timeouts) without failing or exiting prematurely.
    """
    app = create_app(
        engine=mock_engine,
        storage=temp_storage,
        enable_background_scanner=True,
        public_evaluate_only=False,
    )

    failing_w3 = MagicMock()
    # Mock eth.block_number to raise a transient exception on first call, then succeed
    call_count = 0

    async def flaky_block_number():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionResetError("Transient RPC connection reset")
        return 23419500

    failing_w3.eth.block_number = flaky_block_number
    failing_w3.provider = MagicMock()
    failing_w3.provider.disconnect = AsyncMock()
    app.state.scanner_w3 = failing_w3

    # Fast polling for test
    with patch("asyncio.sleep", AsyncMock(side_effect=[None, asyncio.CancelledError()])):
        with patch("scripts.block_contract_scanner.scan_recent_blocks", AsyncMock(return_value=[])):
            app.state.scanner_active = True
            await _background_scanner_worker(app)

    # Completed gracefully on CancelledError
    assert app.state.scanner_active is False
    assert call_count >= 1
    failing_w3.provider.disconnect.assert_awaited_once()


def test_background_scanner_shutdown_idempotent_when_task_none(mock_engine, temp_storage):
    """
    Edge-Case Test:
    Validates that lifespan shutdown runs cleanly without errors even if
    scanner_task is None or was already completed.
    """
    app = create_app(
        engine=mock_engine,
        storage=temp_storage,
        enable_background_scanner=False,
        public_evaluate_only=False,
    )
    app.state.scanner_task = None
    app.state.scanner_active = False

    with TestClient(app) as client:
        assert app.state.scanner_active is False

    assert app.state.scanner_active is False
