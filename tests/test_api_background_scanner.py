"""
Unit and integration tests for FastAPI background block scanner lifespan lifecycle.
Tests activation flags (ENABLE_BACKGROUND_SCANNER, RENDER, explicit parameter),
lifespan startup/shutdown, task cancellation, and GET /metrics/summary integration.
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Ensure repo root and src directories are accessible
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
_SCRIPTS_DIR = os.path.join(_ROOT_DIR, "scripts")
for _p in (_ROOT_DIR, _SRC_DIR, _SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from src.api import create_app, _background_scanner_worker
from src.engine import ConditionAgentEngine
from src.semantic_evaluator import MockSemanticEvaluator
from src.storage import AgentStorage


@pytest.fixture
def mock_storage():
    storage = AsyncMock(spec=AgentStorage)
    storage.get_summary_metrics = AsyncMock(return_value={
        "total_evaluations": 5,
        "total_errors": 0,
        "net_profit_usd": 0.05,
    })
    return storage


def test_health_endpoint_remains_unchanged(mock_storage):
    """Requirement: /health must continue responding {'status': 'ok'}."""
    app = create_app(storage=mock_storage, enable_background_scanner=False)
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_metrics_summary_includes_background_scanner_active(mock_storage):
    """Requirement: GET /metrics/summary must include background_scanner_active bool."""
    app = create_app(storage=mock_storage, enable_background_scanner=False)
    client = TestClient(app)
    resp = client.get("/metrics/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "background_scanner_active" in data
    assert data["background_scanner_active"] is False


def test_activation_flag_resolution_defaults():
    """Default resolution: without env vars, scanner is disabled."""
    with patch.dict(os.environ, {}, clear=True):
        app = create_app()
        assert getattr(app.state, "scanner_active", None) is False


def test_activation_flag_resolution_render_env():
    """When RENDER=true, scanner activates automatically by default."""
    with patch.dict(os.environ, {"RENDER": "true"}, clear=True):
        with patch("src.api.asyncio.create_task") as mock_create_task:
            app = create_app()
            # Lifespan context manager activation
            with TestClient(app):
                assert app.state.scanner_active is True
                assert mock_create_task.called


def test_activation_flag_resolution_enable_env():
    """When ENABLE_BACKGROUND_SCANNER=1, scanner activates."""
    with patch.dict(os.environ, {"ENABLE_BACKGROUND_SCANNER": "1"}, clear=True):
        with patch("src.api.asyncio.create_task") as mock_create_task:
            app = create_app()
            with TestClient(app):
                assert app.state.scanner_active is True
                assert mock_create_task.called


def test_activation_flag_explicit_override_overrules_render_env():
    """Explicit enable_background_scanner=False disables scanner even if RENDER=true."""
    with patch.dict(os.environ, {"RENDER": "true"}, clear=True):
        with patch("src.api.asyncio.create_task") as mock_create_task:
            app = create_app(enable_background_scanner=False)
            with TestClient(app):
                assert app.state.scanner_active is False
                assert not mock_create_task.called


@pytest.mark.asyncio
async def test_lifespan_lifecycle_startup_and_cancellation(mock_storage):
    """
    Tests full lifespan startup, active background task creation,
    and graceful cancellation upon shutdown.
    """
    mock_engine = ConditionAgentEngine(semantic_evaluator=MockSemanticEvaluator())
    app = create_app(
        engine=mock_engine,
        storage=mock_storage,
        enable_background_scanner=True,
    )

    # Provide a controlled dummy coroutine for worker to observe cancellation
    worker_started = asyncio.Event()
    worker_cancelled = asyncio.Event()

    async def fake_worker(app_inst):
        try:
            worker_started.set()
            while True:
                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            worker_cancelled.set()
            raise

    with patch("src.api._background_scanner_worker", side_effect=fake_worker):
        # Enter lifespan
        async with app.router.lifespan_context(app):
            assert app.state.scanner_active is True
            assert app.state.scanner_task is not None
            assert not app.state.scanner_task.done()

            # Wait for worker to run
            await asyncio.wait_for(worker_started.wait(), timeout=1.0)
            assert worker_started.is_set()

        # Lifespan exited (Shutdown)
        assert worker_cancelled.is_set()
        assert app.state.scanner_active is False
        assert app.state.scanner_task.done()


@pytest.mark.asyncio
async def test_background_scanner_worker_iteration(mock_storage):
    """
    Verifies that _background_scanner_worker scans blocks and audits contracts
    resiliently without crashing on transient exceptions.
    """
    mock_w3 = MagicMock()
    mock_w3.provider = MagicMock()
    mock_w3.provider.disconnect = AsyncMock()

    app = create_app(storage=mock_storage, enable_background_scanner=False)
    app.state.scanner_w3 = mock_w3

    # Mock block scanner functions
    fake_discovered = [{
        "block_number": 12345,
        "tx_hash": "0x123",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "deployer": "0xDeployer",
        "bytecode": b"\x60\x80",
    }]

    get_block_calls = 0

    async def mock_get_latest_block(_w3):
        nonlocal get_block_calls
        get_block_calls += 1
        if get_block_calls == 1:
            return 12345
        elif get_block_calls == 2:
            return 12346
        raise asyncio.CancelledError()

    with patch("src.api.get_latest_block_number", side_effect=mock_get_latest_block), \
         patch("src.api.scan_recent_blocks", AsyncMock(return_value=fake_discovered)) as mock_scan, \
         patch("src.api.audit_discovered_contracts", AsyncMock(return_value=[])) as mock_audit, \
         patch("src.api.asyncio.sleep", AsyncMock()):

        # Run worker directly
        await _background_scanner_worker(app)

        assert mock_scan.called
        assert mock_audit.called
        assert mock_w3.provider.disconnect.called
