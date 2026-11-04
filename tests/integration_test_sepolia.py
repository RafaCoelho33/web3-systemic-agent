"""
Base Sepolia Integration Test Entry Point.
Conforms to CONTEXT.md Item 5.3 specification.

Imports all integration test suites from test_integration_sepolia.py.
Can be executed directly via:
    python tests/integration_test_sepolia.py
or via pytest:
    pytest tests/integration_test_sepolia.py
    pytest -m integration
"""
import sys
import os
import pytest

# Ensure parent directory is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tests.test_integration_sepolia import (
    BASE_SEPOLIA_CHAIN_ID,
    BASE_SEPOLIA_RPC,
    WETH9_ADDRESS,
    VITALIK_EOA_ADDRESS,
    ensure_sepolia_available,
    sepolia_engine,
    sepolia_weth_transfer_payload,
    TestSepoliaChainInspector,
    TestSepoliaConditionAgentEngine,
)

__all__ = [
    "BASE_SEPOLIA_CHAIN_ID",
    "BASE_SEPOLIA_RPC",
    "WETH9_ADDRESS",
    "VITALIK_EOA_ADDRESS",
    "ensure_sepolia_available",
    "sepolia_engine",
    "sepolia_weth_transfer_payload",
    "TestSepoliaChainInspector",
    "TestSepoliaConditionAgentEngine",
]

if __name__ == "__main__":
    sys.exit(pytest.main(["-v", "-m", "integration", __file__]))
