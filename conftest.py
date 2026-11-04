"""
Root test configuration and fixtures for Web3 Condition-Action Trigger Agent.
"""

import pytest


@pytest.fixture(autouse=True)
def _clear_chain_inspector_cache():
    """Autouse fixture that clears ChainInspector caches before and after each test."""
    try:
        from src.chain_inspector import ChainInspector
    except ImportError:
        from chain_inspector import ChainInspector

    ChainInspector.clear_cache()
    yield
    ChainInspector.clear_cache()
