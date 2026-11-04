"""
Root entry point for the Web3 Condition-Action Trigger Agent HTTP API.
Re-exports the FastAPI app from src.api and provides CLI execution via uvicorn.
"""

import sys
import os

# Guarded dotenv loading: skipped during pytest execution or if python-dotenv not installed
if "pytest" not in sys.modules:
    try:
        import dotenv
        dotenv.load_dotenv(override=False)
    except ImportError:
        pass

# Ensure src is discoverable
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
for p in (ROOT_DIR, SRC_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from src.api import app, create_app, HealthCheckResponse, RuleValidationResponse
    from src.task_worker import AgentWorkerPool, JobStore, JobStatus, JobRecord
    from src.storage import AgentStorage
    from src.schemas import PaymentReceipt
    from src.x402_payment import X402Config, MockX402Facilitator
except ImportError:
    from api import app, create_app, HealthCheckResponse, RuleValidationResponse
    from task_worker import AgentWorkerPool, JobStore, JobStatus, JobRecord
    from storage import AgentStorage
    from schemas import PaymentReceipt
    from x402_payment import X402Config, MockX402Facilitator

__all__ = [
    "app",
    "create_app",
    "HealthCheckResponse",
    "RuleValidationResponse",
    "AgentWorkerPool",
    "JobStore",
    "JobStatus",
    "JobRecord",
    "AgentStorage",
    "PaymentReceipt",
    "X402Config",
    "MockX402Facilitator",
]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
