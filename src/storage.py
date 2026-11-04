"""
SQLite Storage and Ledger Persistence for Web3 Condition-Action Trigger Agent.
Provides asynchronous evaluation records, structured error logs, telemetry tracking,
and aggregation metrics using aiosqlite with sensitive credential redaction.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
import re
import sys
import tempfile
from typing import Dict, Any, Optional, List

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import aiosqlite
    import aiosqlite.core

    # Patch aiosqlite worker thread so closed asyncio event loops do not raise unhandled RuntimeError
    _orig_worker_thread = getattr(aiosqlite.core, "_connection_worker_thread", None)
    if _orig_worker_thread is not None and not getattr(_orig_worker_thread, "_is_patched", False):
        from aiosqlite.core import _STOP_RUNNING_SENTINEL, set_result, set_exception, LOG

        def _safe_connection_worker_thread(tx):
            while True:
                future, function = tx.get()
                result = None
                try:
                    if LOG:
                        LOG.debug("executing %s", function)
                    result = function()

                    if future:
                        try:
                            loop = future.get_loop()
                            if not loop.is_closed():
                                loop.call_soon_threadsafe(set_result, future, result)
                        except (RuntimeError, AssertionError):
                            pass
                    if LOG:
                        LOG.debug("operation %s completed", function)

                    if result is _STOP_RUNNING_SENTINEL:
                        break

                except BaseException as e:  # noqa B036
                    if LOG:
                        LOG.debug("returning exception %s", e)
                    if future:
                        try:
                            loop = future.get_loop()
                            if not loop.is_closed():
                                loop.call_soon_threadsafe(set_exception, future, e)
                        except (RuntimeError, AssertionError):
                            pass
                    if result is _STOP_RUNNING_SENTINEL:
                        break

        _safe_connection_worker_thread._is_patched = True
        aiosqlite.core._connection_worker_thread = _safe_connection_worker_thread
except ImportError:
    aiosqlite = None  # type: ignore

try:
    from src.schemas import ConditionRulePayload, FinalAgentResponse, PaymentReceipt
except ImportError:
    from schemas import ConditionRulePayload, FinalAgentResponse, PaymentReceipt

logger = logging.getLogger(__name__)

SENSITIVE_KEY_SUBSTRINGS = (
    "api_key",
    "apikey",
    "secret",
    "password",
    "token",
    "private_key",
    "authorization",
)

EXEMPT_KEYS = {
    "input_tokens",
    "output_tokens",
    "prompt_tokens",
    "completion_tokens",
    "candidates_token_count",
    "prompt_token_count",
}

API_KEY_REGEX = re.compile(r"(AIza[0-9A-Za-z_-]{20,}|sk-[0-9A-Za-z_-]{15,})")


def redact_secrets(obj: Any) -> Any:
    """
    Recursively redacts sensitive API keys, secrets, tokens, passwords, and private keys.
    Exempts token metric counts. Scrubs regex-matched API keys from string values.
    """
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if k_lower not in EXEMPT_KEYS and any(s in k_lower for s in SENSITIVE_KEY_SUBSTRINGS):
                redacted[k] = "***REDACTED***"
            else:
                redacted[k] = redact_secrets(v)
        return redacted
    elif isinstance(obj, list):
        return [redact_secrets(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(redact_secrets(item) for item in obj)
    elif isinstance(obj, str):
        return API_KEY_REGEX.sub("***REDACTED***", obj)
    elif hasattr(obj, "model_dump") and callable(obj.model_dump):
        return redact_secrets(obj.model_dump())
    return obj


def get_default_db_path() -> str:
    """
    Resolves the SQLite database file path.
    Uses LEDGER_DB_PATH if set; in pytest defaults to a per-process temp path;
    otherwise defaults to data/agent.db at project root.
    """
    env_path = os.getenv("LEDGER_DB_PATH")
    if env_path:
        return env_path
    if "pytest" in sys.modules:
        return os.path.join(tempfile.gettempdir(), f"agent_pytest_{os.getpid()}.db")
    return os.path.join(_ROOT_DIR, "data", "agent.db")


def is_valid_sqlite_path(path: Optional[str]) -> bool:
    """
    Validates whether a path is safe and accessible for SQLite connections.
    Rejects invalid drive letters on Windows, directories, or paths with non-existent parent roots.
    """
    if not path or not isinstance(path, str):
        return False
    if path == ":memory:":
        return True
    try:
        abs_path = os.path.abspath(path)
        if os.path.isdir(abs_path):
            return False
        drive, _ = os.path.splitdrive(abs_path)
        if drive:
            drive_root = drive + "\\" if not drive.endswith(("\\", "/")) else drive
            if not os.path.exists(drive_root):
                return False
        parent_dir = os.path.dirname(abs_path)
        if parent_dir:
            if os.path.exists(parent_dir):
                if not os.path.isdir(parent_dir):
                    return False
                if not os.access(parent_dir, os.W_OK):
                    return False
            else:
                ancestor = parent_dir
                while ancestor and not os.path.exists(ancestor):
                    prev = os.path.dirname(ancestor)
                    if prev == ancestor:
                        break
                    ancestor = prev
                if ancestor and os.path.exists(ancestor):
                    if not os.path.isdir(ancestor) or not os.access(ancestor, os.W_OK):
                        return False
                else:
                    return False
        return True
    except Exception:
        return False


class AgentStorage:
    """
    Asynchronous SQLite storage provider for evaluation telemetry and operational error logging.
    Guarantees non-blocking, exception-safe persistence that never crashes callers.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_default_db_path()
        self._initialized = False
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """
        Creates necessary parent directories and initializes SQLite tables and indices.
        """
        if self._initialized:
            return

        async with self._lock:
            if self._initialized:
                return

            if aiosqlite is None:
                logger.warning("aiosqlite is not available; AgentStorage will operate in no-op mode.")
                self._initialized = True
                return

            if not is_valid_sqlite_path(self.db_path):
                logger.warning(f"Invalid or unwritable SQLite path: {self.db_path}")
                self._initialized = True
                return

            try:
                if self.db_path != ":memory:":
                    parent_dir = os.path.dirname(os.path.abspath(self.db_path))
                    os.makedirs(parent_dir, exist_ok=True)

                async with aiosqlite.connect(self.db_path) as db:
                    await db.execute(
                        """
                        CREATE TABLE IF NOT EXISTS evaluations (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            created_at TEXT NOT NULL,
                            rule_id TEXT NOT NULL,
                            chain_id INTEGER NOT NULL,
                            job_id TEXT,
                            source TEXT NOT NULL,
                            stage1_passed INTEGER NOT NULL,
                            llm_invoked INTEGER NOT NULL,
                            decision TEXT,
                            risk_score REAL,
                            provider TEXT,
                            model TEXT,
                            cached INTEGER NOT NULL DEFAULT 0,
                            input_tokens INTEGER NOT NULL DEFAULT 0,
                            output_tokens INTEGER NOT NULL DEFAULT 0,
                            est_cost_usd REAL NOT NULL DEFAULT 0.0,
                            latency_ms REAL NOT NULL DEFAULT 0.0,
                            status TEXT NOT NULL,
                            request_json TEXT NOT NULL,
                            response_json TEXT NOT NULL
                        )
                        """
                    )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_evaluations_rule_id ON evaluations(rule_id)"
                    )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_evaluations_created_at ON evaluations(created_at)"
                    )

                    await db.execute(
                        """
                        CREATE TABLE IF NOT EXISTS error_log (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            created_at TEXT NOT NULL,
                            stage TEXT NOT NULL,
                            rule_id TEXT,
                            job_id TEXT,
                            error_type TEXT NOT NULL,
                            message TEXT NOT NULL,
                            traceback TEXT,
                            context_json TEXT
                        )
                        """
                    )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_error_log_stage ON error_log(stage)"
                    )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_error_log_created_at ON error_log(created_at)"
                    )

                    await db.execute(
                        """
                        CREATE TABLE IF NOT EXISTS payments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            payment_id TEXT NOT NULL UNIQUE,
                            created_at TEXT NOT NULL,
                            payer_address TEXT NOT NULL,
                            pay_to_address TEXT NOT NULL,
                            amount_usdc REAL NOT NULL,
                            amount_atomic INTEGER NOT NULL,
                            network TEXT NOT NULL,
                            asset TEXT NOT NULL,
                            tx_hash TEXT NOT NULL,
                            endpoint TEXT NOT NULL,
                            rule_id TEXT,
                            job_id TEXT,
                            status TEXT NOT NULL DEFAULT 'SETTLED'
                        )
                        """
                    )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_payments_payer ON payments(payer_address)"
                    )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at)"
                    )
                    await db.commit()

                self._initialized = True
            except Exception as exc:
                logger.warning(f"AgentStorage failed to initialize DB at {self.db_path}: {exc}")

    async def record_evaluation(
        self,
        payload: ConditionRulePayload,
        response: FinalAgentResponse,
        source: str = "engine",
        job_id: Optional[str] = None,
        latency_ms: Optional[float] = None,
    ) -> Optional[int]:
        """
        Records an evaluation lifecycle execution.
        Safely captures telemetry and redacts credentials without raising exceptions.
        """
        try:
            loop = asyncio.get_running_loop()
            if loop.is_closed() or not loop.is_running():
                return None
        except RuntimeError:
            return None

        try:
            if not is_valid_sqlite_path(self.db_path):
                return None

            if not self._initialized:
                await self.initialize()

            if aiosqlite is None:
                return None

            now = datetime.now(timezone.utc).isoformat()
            chain_id_val = (
                payload.chain_id.value
                if hasattr(payload.chain_id, "value")
                else int(payload.chain_id)
            )

            stage1_passed = 1 if response.deterministic_check.passed else 0
            llm_invoked = 1 if response.llm_invoked else 0
            sem = response.semantic_Evaluation

            decision = sem.recommended_action if sem is not None else None
            risk_score = float(sem.risk_score) if sem is not None else None
            provider = getattr(sem, "provider", None) if sem is not None else None
            model = getattr(sem, "model", None) if sem is not None else None
            cached = 1 if (sem is not None and getattr(sem, "cached", False)) else 0
            input_tokens = int(getattr(sem, "input_tokens", 0) or 0) if sem is not None else 0
            output_tokens = int(getattr(sem, "output_tokens", 0) or 0) if sem is not None else 0
            est_cost_usd = float(getattr(sem, "estimated_cost_usd", 0.0) or 0.0) if sem is not None else 0.0

            eval_latency = latency_ms
            if eval_latency is None and sem is not None:
                eval_latency = getattr(sem, "latency_ms", 0.0)
            eval_latency_ms = float(eval_latency or 0.0)

            status = "error" if response.deterministic_check.error is not None else "ok"

            req_dict = redact_secrets(payload.model_dump())
            resp_dict = redact_secrets(response.model_dump())
            request_json = json.dumps(req_dict, default=str)
            response_json = json.dumps(resp_dict, default=str)

            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    """
                    INSERT INTO evaluations (
                        created_at, rule_id, chain_id, job_id, source,
                        stage1_passed, llm_invoked, decision, risk_score,
                        provider, model, cached, input_tokens, output_tokens,
                        est_cost_usd, latency_ms, status, request_json, response_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        payload.rule_id,
                        chain_id_val,
                        job_id,
                        source,
                        stage1_passed,
                        llm_invoked,
                        decision,
                        risk_score,
                        provider,
                        model,
                        cached,
                        input_tokens,
                        output_tokens,
                        est_cost_usd,
                        eval_latency_ms,
                        status,
                        request_json,
                        response_json,
                    ),
                )
                await db.commit()
                return cursor.lastrowid
        except Exception as exc:
            logger.warning(f"AgentStorage failed to record evaluation in {self.db_path}: {exc}")
            return None

    async def log_error(
        self,
        stage: str,
        error_type: str,
        message: str,
        rule_id: Optional[str] = None,
        job_id: Optional[str] = None,
        traceback_str: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[int]:
        """
        Records an operational or execution error.
        Scrubs secrets from message, traceback, and context before saving.
        """
        try:
            loop = asyncio.get_running_loop()
            if loop.is_closed() or not loop.is_running():
                return None
        except RuntimeError:
            return None

        try:
            if not is_valid_sqlite_path(self.db_path):
                return None

            if not self._initialized:
                await self.initialize()

            if aiosqlite is None:
                return None

            now = datetime.now(timezone.utc).isoformat()
            redacted_message = str(redact_secrets(message)) if message is not None else ""
            redacted_traceback = (
                str(redact_secrets(traceback_str)) if traceback_str is not None else None
            )
            redacted_context = (
                json.dumps(redact_secrets(context), default=str) if context is not None else None
            )

            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    """
                    INSERT INTO error_log (
                        created_at, stage, rule_id, job_id, error_type, message, traceback, context_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        stage,
                        rule_id,
                        job_id,
                        error_type,
                        redacted_message,
                        redacted_traceback,
                        redacted_context,
                    ),
                )
                await db.commit()
                return cursor.lastrowid
        except Exception as exc:
            logger.warning(f"AgentStorage failed to log error in {self.db_path}: {exc}")
            return None

    async def get_evaluations(
        self, limit: int = 100, rule_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves recent evaluations with optional rule_id filtering.
        """
        try:
            if not is_valid_sqlite_path(self.db_path):
                return []

            if not self._initialized:
                await self.initialize()

            if aiosqlite is None:
                return []

            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                if rule_id:
                    cursor = await db.execute(
                        "SELECT * FROM evaluations WHERE rule_id = ? ORDER BY id DESC LIMIT ?",
                        (rule_id, limit),
                    )
                else:
                    cursor = await db.execute(
                        "SELECT * FROM evaluations ORDER BY id DESC LIMIT ?",
                        (limit,),
                    )
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:
            logger.warning(f"AgentStorage failed to get evaluations from {self.db_path}: {exc}")
            return []

    async def get_errors(
        self, limit: int = 100, stage: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves recent operational errors with optional stage filtering.
        """
        try:
            if not is_valid_sqlite_path(self.db_path):
                return []

            if not self._initialized:
                await self.initialize()

            if aiosqlite is None:
                return []

            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                if stage:
                    cursor = await db.execute(
                        "SELECT * FROM error_log WHERE stage = ? ORDER BY id DESC LIMIT ?",
                        (stage, limit),
                    )
                else:
                    cursor = await db.execute(
                        "SELECT * FROM error_log ORDER BY id DESC LIMIT ?",
                        (limit,),
                    )
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:
            logger.warning(f"AgentStorage failed to get errors from {self.db_path}: {exc}")
            return []

    async def record_payment(
        self,
        receipt: Any,
        rule_id: Optional[str] = None,
        job_id: Optional[str] = None,
        status: str = "SETTLED",
    ) -> Optional[int]:
        """
        Records an x402 payment settlement into the ledger.
        Returns cursor.lastrowid on success, or None on failure or duplicate payment_id.
        """
        try:
            loop = asyncio.get_running_loop()
            if loop.is_closed() or not loop.is_running():
                return None
        except RuntimeError:
            return None

        try:
            if not is_valid_sqlite_path(self.db_path):
                return None

            if not self._initialized:
                await self.initialize()

            if aiosqlite is None:
                return None

            payment_id = getattr(receipt, "payment_id", None) or (receipt.get("payment_id") if isinstance(receipt, dict) else None)
            if not payment_id:
                return None

            payer_address = getattr(receipt, "payer_address", None) or (receipt.get("payer_address") if isinstance(receipt, dict) else None)
            pay_to_address = getattr(receipt, "pay_to_address", None) or (receipt.get("pay_to_address") if isinstance(receipt, dict) else None)
            amount_usdc = float(getattr(receipt, "amount_usdc", 0.0) if not isinstance(receipt, dict) else receipt.get("amount_usdc", 0.0))
            amount_atomic = int(getattr(receipt, "amount_atomic", 0) if not isinstance(receipt, dict) else receipt.get("amount_atomic", 0))
            network = getattr(receipt, "network", "eip155:84532") if not isinstance(receipt, dict) else receipt.get("network", "eip155:84532")
            asset = getattr(receipt, "asset", "USDC") if not isinstance(receipt, dict) else receipt.get("asset", "USDC")
            tx_hash = getattr(receipt, "tx_hash", "") if not isinstance(receipt, dict) else receipt.get("tx_hash", "")
            endpoint = getattr(receipt, "endpoint", "") if not isinstance(receipt, dict) else receipt.get("endpoint", "")
            created_at = (
                getattr(receipt, "settled_at", None)
                or (receipt.get("settled_at") if isinstance(receipt, dict) else None)
                or datetime.now(timezone.utc).isoformat()
            )

            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    """
                    INSERT INTO payments (
                        payment_id, created_at, payer_address, pay_to_address,
                        amount_usdc, amount_atomic, network, asset, tx_hash,
                        endpoint, rule_id, job_id, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(payment_id),
                        str(created_at),
                        str(payer_address),
                        str(pay_to_address),
                        amount_usdc,
                        amount_atomic,
                        str(network),
                        str(asset),
                        str(tx_hash),
                        str(endpoint),
                        rule_id,
                        job_id,
                        status,
                    ),
                )
                await db.commit()
                return cursor.lastrowid
        except Exception as exc:
            logger.warning(f"AgentStorage failed to record payment in {self.db_path}: {exc}")
            return None

    async def is_payment_settled(self, payment_id: str) -> bool:
        """
        Checks whether a payment with the specified payment_id already exists in the ledger.
        Used to prevent payment replay attacks.
        """
        try:
            if not is_valid_sqlite_path(self.db_path):
                return False

            if not self._initialized:
                await self.initialize()

            if aiosqlite is None:
                return False

            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT 1 FROM payments WHERE payment_id = ? LIMIT 1",
                    (str(payment_id),),
                ) as cursor:
                    row = await cursor.fetchone()
                    return row is not None
        except Exception as exc:
            logger.warning(f"AgentStorage failed to check settled payment in {self.db_path}: {exc}")
            return False

    async def get_payments(
        self, limit: int = 100, payer_address: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves recent payments ordered by id DESC with optional payer_address filter.
        """
        try:
            if not is_valid_sqlite_path(self.db_path):
                return []

            if not self._initialized:
                await self.initialize()

            if aiosqlite is None:
                return []

            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                if payer_address:
                    cursor = await db.execute(
                        "SELECT * FROM payments WHERE payer_address = ? ORDER BY id DESC LIMIT ?",
                        (payer_address, limit),
                    )
                else:
                    cursor = await db.execute(
                        "SELECT * FROM payments ORDER BY id DESC LIMIT ?",
                        (limit,),
                    )
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:
            logger.warning(f"AgentStorage failed to get payments from {self.db_path}: {exc}")
            return []

    async def get_summary_metrics(self, target_price_usd: float = 0.01) -> Dict[str, Any]:
        """
        Aggregates operational metrics across all historical evaluations, error logs, and payments.
        """
        try:
            if not is_valid_sqlite_path(self.db_path):
                return {
                    "total_evaluations": 0,
                    "stage1_filter_rate_pct": 0.0,
                    "total_cost_usd": 0.0,
                    "avg_cost_per_eval_usd": 0.0,
                    "avg_cost_per_llm_call_usd": 0.0,
                    "max_cost_usd": 0.0,
                    "p95_cost_usd": 0.0,
                    "pct_under_target": 0.0,
                    "total_errors": 0,
                    "errors_by_stage": {},
                    "total_input_tokens": 0,
                    "total_output_tokens": 0,
                    "total_payments_settled": 0,
                    "total_revenue_usdc": 0.0,
                    "net_profit_usd": 0.0,
                }

            if not self._initialized:
                await self.initialize()

            if aiosqlite is None:
                raise RuntimeError("aiosqlite is not available")

            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("SELECT * FROM evaluations ORDER BY id ASC") as cursor:
                    eval_rows = await cursor.fetchall()
                async with db.execute(
                    "SELECT stage, COUNT(*) as count FROM error_log GROUP BY stage"
                ) as cursor:
                    error_stage_rows = await cursor.fetchall()
                async with db.execute("SELECT COUNT(*) as total FROM error_log") as cursor:
                    total_error_row = await cursor.fetchone()
                async with db.execute(
                    "SELECT COUNT(*) as count, COALESCE(SUM(amount_usdc), 0.0) as revenue FROM payments WHERE status = 'SETTLED'"
                ) as cursor:
                    pmt_row = await cursor.fetchone()

            total_evaluations = len(eval_rows)
            stage1_halted_count = sum(1 for r in eval_rows if r["llm_invoked"] == 0)
            llm_invoked_count = sum(1 for r in eval_rows if r["llm_invoked"] == 1)
            stage1_filter_rate_pct = (
                round((stage1_halted_count / total_evaluations) * 100.0, 2)
                if total_evaluations > 0
                else 0.0
            )

            total_input_tokens = sum(int(r["input_tokens"] or 0) for r in eval_rows)
            total_output_tokens = sum(int(r["output_tokens"] or 0) for r in eval_rows)
            costs = [float(r["est_cost_usd"] or 0.0) for r in eval_rows]
            total_cost_usd = round(sum(costs), 8)
            avg_cost_per_eval_usd = (
                round(total_cost_usd / total_evaluations, 8) if total_evaluations > 0 else 0.0
            )

            llm_costs = [
                float(r["est_cost_usd"] or 0.0)
                for r in eval_rows
                if r["llm_invoked"] == 1
            ]
            avg_cost_per_llm_call_usd = (
                round(sum(llm_costs) / len(llm_costs), 8) if llm_costs else 0.0
            )

            if costs:
                sorted_costs = sorted(costs)
                max_cost_usd = round(sorted_costs[-1], 8)
                p95_index = int(0.95 * len(sorted_costs))
                if p95_index >= len(sorted_costs):
                    p95_index = len(sorted_costs) - 1
                p95_cost_usd = round(sorted_costs[p95_index], 8)
            else:
                max_cost_usd = 0.0
                p95_cost_usd = 0.0

            price_covers_max_cost = (
                bool(target_price_usd > max_cost_usd) if total_evaluations > 0 else True
            )

            errors_by_stage = {r["stage"]: int(r["count"]) for r in error_stage_rows}
            total_errors = int(total_error_row["total"] or 0) if total_error_row else 0

            total_payments_settled = int(pmt_row["count"] or 0) if pmt_row else 0
            total_revenue_usdc = round(float(pmt_row["revenue"] or 0.0), 6) if pmt_row else 0.0
            net_profit_usd = round(total_revenue_usdc - total_cost_usd, 6)

            return {
                "total_evaluations": total_evaluations,
                "stage1_halted_count": stage1_halted_count,
                "stage1_filter_rate_pct": stage1_filter_rate_pct,
                "stage1_Filter_rate_pct": stage1_filter_rate_pct,
                "llm_invoked_count": llm_invoked_count,
                "total_input_tokens": total_input_tokens,
                "total_output_tokens": total_output_tokens,
                "total_cost_usd": total_cost_usd,
                "avg_cost_per_eval_usd": avg_cost_per_eval_usd,
                "avg_cost_per_llm_call_usd": avg_cost_per_llm_call_usd,
                "max_cost_usd": max_cost_usd,
                "p95_cost_usd": p95_cost_usd,
                "target_price_usd": float(target_price_usd),
                "price_covers_max_cost": price_covers_max_cost,
                "errors_by_stage": errors_by_stage,
                "total_errors": total_errors,
                "total_payments_settled": total_payments_settled,
                "total_revenue_usdc": total_revenue_usdc,
                "net_profit_usd": net_profit_usd,
            }
        except Exception as exc:
            logger.warning(f"Error querying summary metrics from {self.db_path}: {exc}")
            return {
                "total_evaluations": 0,
                "stage1_halted_count": 0,
                "stage1_filter_rate_pct": 0.0,
                "stage1_Filter_rate_pct": 0.0,
                "llm_invoked_count": 0,
                "total_input_tokens": 0,
                "total_output_tokens": 0,
                "total_cost_usd": 0.0,
                "avg_cost_per_eval_usd": 0.0,
                "avg_cost_per_llm_call_usd": 0.0,
                "max_cost_usd": 0.0,
                "p95_cost_usd": 0.0,
                "target_price_usd": float(target_price_usd),
                "price_covers_max_cost": True,
                "errors_by_stage": {},
                "total_errors": 0,
                "total_payments_settled": 0,
                "total_revenue_usdc": 0.0,
                "net_profit_usd": 0.0,
            }
