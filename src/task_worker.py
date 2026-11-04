"""
Asynchronous Worker Pool and Job Store for Web3 Condition-Action Trigger Agent.
Manages background job queues, decoupled execution workers, and state transitions.
"""

import asyncio
from datetime import datetime, timezone
from enum import Enum
import logging
import os
import sys
import time
import traceback
from typing import Dict, Any, Optional, List
import uuid
from pydantic import BaseModel, Field

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from src.schemas import ConditionRulePayload, FinalAgentResponse
    from src.engine import ConditionAgentEngine
    from src.storage import AgentStorage
except ImportError:
    from schemas import ConditionRulePayload, FinalAgentResponse
    from engine import ConditionAgentEngine
    from storage import AgentStorage

logger = logging.getLogger(__name__)

DEFAULT_JOB_TTL_SECONDS = 3600
DEFAULT_MAX_JOBS = 10000


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class JobRecord(BaseModel):
    job_id: str
    status: JobStatus = JobStatus.QUEUED
    payload: ConditionRulePayload
    result: Optional[FinalAgentResponse] = None
    error: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class JobStore:
    """
    In-memory storage and lifecycle management for asynchronous evaluation jobs.
    Implements TTL expiration cleanup and bounded capacity eviction.
    """

    def __init__(
        self,
        ttl_seconds: Optional[float] = None,
        max_jobs: Optional[int] = None,
    ):
        self.ttl_seconds = float(
            ttl_seconds
            if ttl_seconds is not None
            else os.getenv("JOB_TTL_SECONDS", DEFAULT_JOB_TTL_SECONDS)
        )
        self.max_jobs = int(
            max_jobs
            if max_jobs is not None
            else os.getenv("JOB_MAX_COUNT", DEFAULT_MAX_JOBS)
        )
        self._jobs: Dict[str, JobRecord] = {}
        self._job_created_at: Dict[str, float] = {}
        self._job_updated_at: Dict[str, float] = {}

    def cleanup_expired(self, now: Optional[float] = None) -> int:
        """
        Removes terminal jobs (COMPLETED, FAILED, CANCELLED) older than ttl_seconds.
        """
        current_time = now if now is not None else time.time()
        terminal_states = {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}
        expired_ids = []

        for jid, job in list(self._jobs.items()):
            if job.status in terminal_states:
                last_time = self._job_updated_at.get(jid, self._job_created_at.get(jid, current_time))
                if (current_time - last_time) > self.ttl_seconds:
                    expired_ids.append(jid)

        for jid in expired_ids:
            self._jobs.pop(jid, None)
            self._job_created_at.pop(jid, None)
            self._job_updated_at.pop(jid, None)

        return len(expired_ids)

    def create_job(
        self, payload: ConditionRulePayload, job_id: Optional[str] = None
    ) -> JobRecord:
        self.cleanup_expired()

        # Enforce bounded capacity
        while len(self._jobs) >= self.max_jobs:
            terminal_states = {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}
            terminal_jids = [
                jid for jid, j in self._jobs.items() if j.status in terminal_states
            ]
            if terminal_jids:
                # Evict oldest terminal job
                oldest_term_jid = min(
                    terminal_jids, key=lambda j: self._job_created_at.get(j, 0.0)
                )
                self._jobs.pop(oldest_term_jid, None)
                self._job_created_at.pop(oldest_term_jid, None)
                self._job_updated_at.pop(oldest_term_jid, None)
            else:
                # Evict oldest job overall (FIFO)
                oldest_jid = min(
                    self._jobs.keys(), key=lambda j: self._job_created_at.get(j, 0.0)
                )
                self._jobs.pop(oldest_jid, None)
                self._job_created_at.pop(oldest_jid, None)
                self._job_updated_at.pop(oldest_jid, None)

        jid = job_id or str(uuid.uuid4())
        now_dt = datetime.now(timezone.utc).isoformat()
        now_ts = time.time()

        job = JobRecord(
            job_id=jid,
            status=JobStatus.QUEUED,
            payload=payload,
            result=None,
            error=None,
            created_at=now_dt,
            updated_at=now_dt,
        )
        self._jobs[jid] = job
        self._job_created_at[jid] = now_ts
        self._job_updated_at[jid] = now_ts
        return job

    def get_job(self, job_id: str) -> Optional[JobRecord]:
        self.cleanup_expired()
        return self._jobs.get(job_id)

    def update_job(
        self,
        job_id: str,
        status: Optional[JobStatus] = None,
        result: Optional[FinalAgentResponse] = None,
        error: Optional[str] = None,
    ) -> Optional[JobRecord]:
        job = self._jobs.get(job_id)
        if not job:
            return None
        now_dt = datetime.now(timezone.utc).isoformat()
        now_ts = time.time()
        if status is not None:
            job.status = status
        if result is not None:
            job.result = result
        if error is not None:
            job.error = error
        job.updated_at = now_dt
        self._job_updated_at[job_id] = now_ts
        return job

    def cancel_job(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job:
            return False
        job.status = JobStatus.CANCELLED
        now_dt = datetime.now(timezone.utc).isoformat()
        now_ts = time.time()
        job.updated_at = now_dt
        self._job_updated_at[job_id] = now_ts
        return True


class AgentWorkerPool:
    """
    Asynchronous queue worker pool executing ConditionAgentEngine jobs concurrently.
    """

    def __init__(
        self,
        engine: Optional[ConditionAgentEngine] = None,
        num_workers: int = 2,
        job_store: Optional[JobStore] = None,
        storage: Optional[Any] = None,
        ttl_seconds: Optional[float] = None,
        max_jobs: Optional[int] = None,
    ):
        self.engine = engine if engine is not None else ConditionAgentEngine()
        self.num_workers = num_workers
        self.storage = storage
        self.job_store = (
            job_store
            if job_store is not None
            else JobStore(ttl_seconds=ttl_seconds, max_jobs=max_jobs)
        )
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._worker_tasks: List[asyncio.Task] = []
        self._started = False
        self._running = False

    def start(self) -> None:
        """
        Starts the background worker tasks if not already running.
        """
        if self._started:
            return
        self._started = True
        self._running = True
        for _ in range(self.num_workers):
            task = asyncio.create_task(self._worker_loop())
            self._worker_tasks.append(task)

    def enqueue(self, payload: ConditionRulePayload) -> str:
        """
        Enqueues a new rule payload for asynchronous evaluation and returns its job_id.
        Automatically starts the background workers if they are not yet running.
        """
        if not self._started:
            self.start()
        job = self.job_store.create_job(payload=payload)
        self.queue.put_nowait(job.job_id)
        return job.job_id

    def get_job(self, job_id: str) -> Optional[JobRecord]:
        """
        Retrieves the current job record by job_id.
        """
        return self.job_store.get_job(job_id)

    def cancel_job(self, job_id: str) -> bool:
        """
        Marks an enqueued or active job as CANCELLED.
        """
        return self.job_store.cancel_job(job_id)

    async def shutdown(self) -> None:
        """
        Asynchronously stops workers and cleanly drains worker coroutines.
        """
        self._running = False
        for task in self._worker_tasks:
            task.cancel()
        if self._worker_tasks:
            await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        self._worker_tasks.clear()
        self._started = False

    def stop(self) -> None:
        """
        Synchronously cancels background worker tasks.
        """
        self._running = False
        for task in self._worker_tasks:
            task.cancel()
        self._worker_tasks.clear()
        self._started = False

    async def _worker_loop(self) -> None:
        while self._running:
            try:
                job_id = await self.queue.get()
            except asyncio.CancelledError:
                break
            except Exception:
                continue

            try:
                job = self.job_store.get_job(job_id)
                if not job:
                    continue

                # If job was cancelled before execution started, skip processing
                if job.status == JobStatus.CANCELLED:
                    continue

                # Transition to PROCESSING
                self.job_store.update_job(job_id, status=JobStatus.PROCESSING)

                try:
                    result = await self.engine.process_rule(
                        job.payload, source="worker", job_id=job_id
                    )
                    # Check if cancelled while processing was running
                    current_job = self.job_store.get_job(job_id)
                    if current_job and current_job.status == JobStatus.CANCELLED:
                        pass
                    else:
                        self.job_store.update_job(
                            job_id, status=JobStatus.COMPLETED, result=result
                        )
                except Exception as exc:
                    logger.exception(f"Exception during worker execution for job '{job_id}': {exc}")
                    self.job_store.update_job(
                        job_id, status=JobStatus.FAILED, error=str(exc)
                    )
                    active_storage = self.storage or getattr(self.engine, "storage", None)
                    if active_storage:
                        try:
                            await active_storage.log_error(
                                stage="worker",
                                error_type=type(exc).__name__,
                                message=str(exc),
                                rule_id=job.payload.rule_id,
                                job_id=job_id,
                                traceback_str=traceback.format_exc(),
                            )
                        except Exception:
                            pass
            finally:
                self.queue.task_done()
