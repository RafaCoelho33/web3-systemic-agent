"""
Semantic Evaluation Layer for Web3 Condition-Action Trigger Agent.
Supports MockSemanticEvaluator for local testing/cost-free simulation,
OpenAISemanticEvaluator using OpenAI Structured Outputs, and
GeminiSemanticEvaluator using Google GenAI SDK (google-genai) with structured schema enforcement.
"""

import hashlib
import json
import logging
import os
import sys
import time
from typing import Dict, Any, Optional, Protocol, Union
from pydantic import BaseModel

# Ensure module search paths support running directly or as a package
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, "..")) if os.path.basename(_CURRENT_DIR) == "src" else _CURRENT_DIR
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Guarded dotenv loading: skipped during pytest execution or if python-dotenv not installed
if "pytest" not in sys.modules:
    try:
        import dotenv
        _env_file = os.path.join(_ROOT_DIR, ".env")
        if os.path.exists(_env_file):
            dotenv.load_dotenv(_env_file, override=False)
        dotenv.load_dotenv(override=False)
    except ImportError:
        pass

try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    AsyncOpenAI = None  # type: ignore
    OPENAI_AVAILABLE = False

try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    genai = None  # type: ignore
    types = None  # type: ignore
    GEMINI_AVAILABLE = False

try:
    from src.schemas import SemanticCondition, SemanticAuditResult, LLMAuditOutput
except ImportError:
    from schemas import SemanticCondition, SemanticAuditResult, LLMAuditOutput

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an autonomous Web3 Security and Governance Auditor.
Your role is to evaluate smart contract transactions, calldata, and DAO proposals against specified governance policies.
You will receive:
1. The security/governance policy prompt.
2. The risk score threshold (0.0 to 10.0) above which an alert or intervention is warranted.
3. Observed on-chain data (contract bytecode presence, native balance, function selector, signature).
4. Context metadata (calldata, transaction value in wei, proposal description).

Carefully cross-reference the natural language proposal text with the actual on-chain bytecode, function signature, and value.
Specifically watch for:
- Discrepancies where the proposal claims harmless actions but executes high-privilege functions (e.g. transferOwnership, upgradeTo, mint, arbitrary approvals).
- Lack of security audit mentions for high-risk operations.
- Treasury drainage or unexpected value transfers.

You must output a structured audit response matching the SemanticAuditResult schema:
- conditions_met: boolean, True if calculated risk_score >= risk_threshold, False otherwise.
- risk_score: float between 0.0 and 10.0 representing risk severity.
- flagged_issues: list of strings detailing specific concerns found.
- summary: concise technical rationale.
- recommended_action:
    * 'REJECT' if risk_score >= 8.0
    * 'MANUAL_REVIEW' if risk_score >= risk_threshold and risk_score < 8.0
    * 'APPROVE' if risk_score < risk_threshold
"""

SEVERITY_ORDER = {
    "APPROVE": 1,
    "MANUAL_REVIEW": 2,
    "REJECT": 3,
}


def enforce_decision_policy(
    result: SemanticAuditResult, risk_threshold: float
) -> SemanticAuditResult:
    """
    Enforces deterministic decision policy on a semantic audit result:
    - Severity order: APPROVE < MANUAL_REVIEW < REJECT
    - Policy action: score >= 8.0 -> REJECT; score >= risk_threshold -> MANUAL_REVIEW; else APPROVE
    - Final action: the more severe of policy_action and result.recommended_action (never downgrade)
    - conditions_met = (risk_score >= risk_threshold)
    - Appends escalation notices to flagged_issues if action was modified
    - Returns a new copy; never mutates the input
    """
    score = result.risk_score
    if score >= 8.0:
        policy_action = "REJECT"
    elif score >= risk_threshold:
        policy_action = "MANUAL_REVIEW"
    else:
        policy_action = "APPROVE"

    raw_action = str(result.recommended_action).strip().upper()
    policy_severity = SEVERITY_ORDER.get(policy_action, 1)
    llm_severity = SEVERITY_ORDER.get(raw_action, 1)

    if policy_severity >= llm_severity:
        final_action = policy_action
    else:
        final_action = raw_action

    conditions_met = bool(score >= risk_threshold)
    new_flagged = list(result.flagged_issues)

    if final_action != result.recommended_action:
        new_flagged.append(
            f"Decision escalated by deterministic policy: LLM suggested {result.recommended_action} -> {final_action}"
        )

    return result.model_copy(
        update={
            "conditions_met": conditions_met,
            "recommended_action": final_action,
            "flagged_issues": new_flagged,
        }
    )


class SemanticEvaluatorProtocol(Protocol):
    """Protocol defining the interface for semantic evaluators."""

    async def evaluate(
        self,
        condition: SemanticCondition,
        observed_onchain: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> SemanticAuditResult:
        ...


class LLMClientProtocol(Protocol):
    """Legacy alias preserved for backward compatibility."""

    async def evaluate(self, system_prompt: str, user_prompt: str) -> SemanticAuditResult:
        ...


def _make_semantic_cache_key(
    condition: SemanticCondition,
    observed_onchain: Dict[str, Any],
    metadata: Dict[str, Any],
) -> str:
    key_dict = {
        "policy_prompt": condition.policy_prompt,
        "risk_threshold": float(condition.risk_threshold),
        "observed_onchain": observed_onchain,
        "metadata": metadata,
    }
    raw = json.dumps(key_dict, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


DEFAULT_LLM_MAX_INPUT_CHARS = 32000


def get_llm_max_input_chars(override: Optional[int] = None) -> int:
    """
    Returns max input characters allowed for LLM prompts.
    Prioritizes explicit override, then LLM_MAX_INPUT_CHARS environment variable,
    defaulting to DEFAULT_LLM_MAX_INPUT_CHARS (32,000).
    """
    if override is not None:
        return int(override)
    val = os.getenv("LLM_MAX_INPUT_CHARS")
    if val is not None:
        try:
            return int(val)
        except (ValueError, TypeError):
            pass
    return DEFAULT_LLM_MAX_INPUT_CHARS


MODEL_PRICING_PER_1M: Dict[str, tuple[float, float]] = {
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-1.5-flash": (0.075, 0.30),
    "gemini-3.5-flash-lite": (0.075, 0.30),
    "gemini-3.1-flash-lite": (0.075, 0.30),
    "gemini-3.8-flash": (0.10, 0.40),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "mock": (0.0, 0.0),
}
DEFAULT_PRICING_PER_1M: tuple[float, float] = (0.30, 1.20)


def estimate_llm_cost_usd(
    model: Optional[str], input_tokens: int, output_tokens: int
) -> float:
    """
    Estimates evaluation cost in USD based on model pricing per 1M tokens.
    Supports exact model matching and prefix matching.
    """
    if not model or model.lower() == "mock" or (input_tokens <= 0 and output_tokens <= 0):
        return 0.0

    m_lower = model.lower()
    pricing = None
    if m_lower in MODEL_PRICING_PER_1M:
        pricing = MODEL_PRICING_PER_1M[m_lower]
    else:
        for k in sorted(MODEL_PRICING_PER_1M.keys(), key=len, reverse=True):
            if m_lower.startswith(k):
                pricing = MODEL_PRICING_PER_1M[k]
                break

    if pricing is None:
        pricing = DEFAULT_PRICING_PER_1M

    in_rate, out_rate = pricing
    cost = (max(0, input_tokens) * in_rate + max(0, output_tokens) * out_rate) / 1_000_000.0
    return round(cost, 8)


def prepare_bounded_context(
    metadata: Dict[str, Any], max_chars: Optional[int] = None
) -> tuple[Dict[str, Any], bool]:
    """
    Inspects context metadata serialized JSON length.
    If exceeding max_chars limit, returns a shallow-copied dictionary with truncated large fields
    and marked with '...[TRUNCATED]'. Never mutates the caller's input metadata.
    """
    limit = get_llm_max_input_chars(max_chars)
    serialized = json.dumps(metadata, sort_keys=True, default=str)
    if len(serialized) <= limit:
        return (dict(metadata), False)

    truncated = dict(metadata)
    marker = "...[TRUNCATED]"

    # First attempt: truncate string values
    str_keys = [k for k, v in truncated.items() if isinstance(v, str)]
    if str_keys:
        str_keys.sort(key=lambda k: len(truncated[k]), reverse=True)
        for k in str_keys:
            curr_len = len(json.dumps(truncated, sort_keys=True, default=str))
            if curr_len <= limit:
                break
            excess = curr_len - limit
            val = truncated[k]
            keep_len = max(0, len(val) - excess - len(marker) - 10)
            truncated[k] = val[:keep_len] + marker

    # Fallback if still exceeding (e.g. non-string fields or many fields)
    curr_len = len(json.dumps(truncated, sort_keys=True, default=str))
    if curr_len > limit:
        for k in sorted(truncated.keys(), key=lambda x: len(str(truncated[x])), reverse=True):
            curr_len = len(json.dumps(truncated, sort_keys=True, default=str))
            if curr_len <= limit:
                break
            val_str = str(truncated[k])
            excess = curr_len - limit
            keep_len = max(0, len(val_str) - excess - len(marker) - 10)
            truncated[k] = val_str[:keep_len] + marker

    return (truncated, True)


class MockSemanticEvaluator:
    """
    Local development evaluator that simulates structured LLM output without spending API credits.
    Preserved intact for zero-cost development, deterministic unit tests, and CI/CD pipelines.
    """

    def __init__(self, max_input_chars: Optional[int] = None, **kwargs: Any):
        self._cache: Dict[str, SemanticAuditResult] = {}
        self.cache_hits: int = 0
        self.max_input_chars = max_input_chars

    @property
    def cache(self) -> Dict[str, SemanticAuditResult]:
        return self._cache

    @property
    def semantic_cache(self) -> Dict[str, SemanticAuditResult]:
        return self._cache

    def clear_cache(self) -> None:
        self._cache.clear()
        self.cache_hits = 0

    async def evaluate(
        self,
        condition: SemanticCondition,
        observed_onchain: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SemanticAuditResult:
        start_time = time.perf_counter()
        ctx = metadata if metadata is not None else (context or {})
        bounded_ctx, was_truncated = prepare_bounded_context(ctx, self.max_input_chars)
        cache_key = _make_semantic_cache_key(condition, observed_onchain, bounded_ctx)

        if cache_key in self._cache:
            self.cache_hits += 1
            return self._cache[cache_key].model_copy(
                update={
                    "cached": True,
                    "estimated_cost_usd": 0.0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
                }
            )

        calldata_info = observed_onchain.get("calldata_analysis", {})
        signature = calldata_info.get("signature", "")
        proposal_text = str(bounded_ctx.get("proposal_description", "")).lower()

        flagged = []
        score = 2.0

        # Heuristic simulation of LLM reasoning over discrepancies between text and bytecode/calldata
        if "transferOwnership" in signature or "upgradeTo" in signature:
            score += 5.5
            flagged.append(f"Critical privilege function detected: {signature}")

        has_positive_audit = ("audit" in proposal_text) and not any(
            neg in proposal_text for neg in ("without audit", "without any audit", "no audit", "lacking audit")
        )

        if not has_positive_audit and score > 5.0:
            score += 2.0
            flagged.append("High-privilege execution without explicit audit reference in proposal description.")

        if was_truncated:
            flagged.append("Context metadata truncated due to LLM_MAX_INPUT_CHARS limit")

        score = min(score, 10.0)
        conditions_met = score >= condition.risk_threshold

        action = "REJECT" if score >= 8.0 else ("MANUAL_REVIEW" if conditions_met else "APPROVE")
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        result = SemanticAuditResult(
            conditions_met=conditions_met,
            risk_score=score,
            flagged_issues=flagged,
            summary=(
                f"Evaluated policy '{condition.policy_prompt}'. "
                f"Detected function '{signature}' on contract {observed_onchain.get('target_address')}."
            ),
            recommended_action=action,
            cached=False,
            provider="mock",
            model="mock",
            input_tokens=0,
            output_tokens=0,
            estimated_cost_usd=0.0,
            latency_ms=latency_ms,
        )
        self._cache[cache_key] = result
        return result


class OpenAISemanticEvaluator:
    """
    Concrete production LLM evaluator leveraging OpenAI's Structured Outputs
    via client.beta.chat.completions.parse, enforcing the LLMAuditOutput Pydantic schema.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.0,
        fallback_to_mock: bool = False,
        client: Optional[Any] = None,
        max_input_chars: Optional[int] = None,
        **kwargs: Any,
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key and client is None:
            raise ValueError(
                "OpenAI API key must be provided or configured in the OPENAI_API_KEY environment variable."
            )
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL")
        self.temperature = temperature
        self.fallback_to_mock = fallback_to_mock
        self.max_input_chars = max_input_chars
        self._cache: Dict[str, SemanticAuditResult] = {}
        self.cache_hits: int = 0

        if client is not None:
            self.client = client
        else:
            if not OPENAI_AVAILABLE:
                raise ImportError("The 'openai' package is not installed. Install it via 'pip install openai'.")
            client_kwargs: Dict[str, Any] = {"api_key": self.api_key}
            if self.base_url:
                client_kwargs["base_url"] = self.base_url
            self.client = AsyncOpenAI(**client_kwargs)

    @property
    def cache(self) -> Dict[str, SemanticAuditResult]:
        return self._cache

    @property
    def semantic_cache(self) -> Dict[str, SemanticAuditResult]:
        return self._cache

    def clear_cache(self) -> None:
        self._cache.clear()
        self.cache_hits = 0

    async def evaluate(
        self,
        condition: SemanticCondition,
        observed_onchain: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SemanticAuditResult:
        start_time = time.perf_counter()
        ctx = metadata if metadata is not None else (context or {})
        bounded_ctx, was_truncated = prepare_bounded_context(ctx, self.max_input_chars)
        cache_key = _make_semantic_cache_key(condition, observed_onchain, bounded_ctx)

        if cache_key in self._cache:
            self.cache_hits += 1
            return self._cache[cache_key].model_copy(
                update={
                    "cached": True,
                    "estimated_cost_usd": 0.0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
                }
            )

        user_prompt_data = {
            "policy_prompt": condition.policy_prompt,
            "risk_threshold": condition.risk_threshold,
            "observed_onchain": observed_onchain,
            "context_metadata": bounded_ctx,
        }
        user_prompt = (
            f"Please audit the following Web3 transaction/proposal against the policy:\n\n"
            f"{json.dumps(user_prompt_data, indent=2, default=str)}"
        )

        try:
            completion = await self.client.beta.chat.completions.parse(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format=LLMAuditOutput,
                temperature=self.temperature,
            )

            usage = getattr(completion, "usage", None)
            val_in = getattr(usage, "prompt_tokens", 0) if usage is not None else 0
            input_tokens = val_in if isinstance(val_in, int) else 0
            val_out = getattr(usage, "completion_tokens", 0) if usage is not None else 0
            output_tokens = val_out if isinstance(val_out, int) else 0

            cost_usd = estimate_llm_cost_usd(self.model, input_tokens, output_tokens)
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

            parsed_result = completion.choices[0].message.parsed
            if parsed_result is not None:
                if isinstance(parsed_result, SemanticAuditResult):
                    final_res = parsed_result.model_copy()
                elif isinstance(parsed_result, (LLMAuditOutput, BaseModel)):
                    final_res = SemanticAuditResult(**parsed_result.model_dump())
                elif isinstance(parsed_result, dict):
                    final_res = SemanticAuditResult.model_validate(parsed_result)
                else:
                    final_res = SemanticAuditResult.model_validate(parsed_result)
            else:
                # Fallback for structured content string validation
                raw_content = completion.choices[0].message.content or "{}"
                try:
                    llm_out = LLMAuditOutput.model_validate_json(raw_content)
                    final_res = SemanticAuditResult(**llm_out.model_dump())
                except Exception:
                    final_res = SemanticAuditResult.model_validate_json(raw_content)

            flagged_list = list(final_res.flagged_issues)
            if was_truncated and not any(
                "Context metadata truncated due to LLM_MAX_INPUT_CHARS limit" in str(x)
                for x in flagged_list
            ):
                flagged_list.append("Context metadata truncated due to LLM_MAX_INPUT_CHARS limit")

            final_res = final_res.model_copy(
                update={
                    "cached": False,
                    "provider": "openai",
                    "model": self.model,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "estimated_cost_usd": cost_usd,
                    "latency_ms": latency_ms,
                    "flagged_issues": flagged_list,
                }
            )
            self._cache[cache_key] = final_res
            return final_res

        except Exception as exc:
            logger.error(
                f"OpenAISemanticEvaluator failed during execution: {exc}",
                exc_info=not self.fallback_to_mock,
            )
            if self.fallback_to_mock:
                logger.warning("Failing over to MockSemanticEvaluator due to OpenAI API exception.")
                mock_evaluator = MockSemanticEvaluator(max_input_chars=self.max_input_chars)
                mock_result = await mock_evaluator.evaluate(condition, observed_onchain, bounded_ctx)
                new_flagged = list(mock_result.flagged_issues)
                new_flagged.append(f"LLM provider failure (OpenAI): {exc}")
                if was_truncated and not any(
                    "Context metadata truncated due to LLM_MAX_INPUT_CHARS limit" in str(x)
                    for x in new_flagged
                ):
                    new_flagged.append("Context metadata truncated due to LLM_MAX_INPUT_CHARS limit")
                new_action = mock_result.recommended_action
                if str(new_action).strip().upper() == "APPROVE":
                    new_action = "MANUAL_REVIEW"
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                return mock_result.model_copy(
                    update={
                        "flagged_issues": new_flagged,
                        "recommended_action": new_action,
                        "cached": False,
                        "provider": "openai",
                        "model": self.model,
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "estimated_cost_usd": 0.0,
                        "latency_ms": latency_ms,
                    }
                )
            raise


class GeminiSemanticEvaluator:
    """
    Concrete production LLM evaluator leveraging Google Gemini's native API via google-genai SDK,
    enforcing structured JSON outputs matching the LLMAuditOutput Pydantic schema.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        fallback_to_mock: bool = True,
        temperature: float = 0.1,
        client: Optional[Any] = None,
        max_input_chars: Optional[int] = None,
        **kwargs: Any,
    ):
        resolved_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not resolved_key and client is None:
            raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY not configured")

        self.api_key = resolved_key
        # Priority: kwarg model > model_name > env GEMINI_MODEL > "gemini-2.0-flash"
        self.model_name = (
            kwargs.get("model")
            or model_name
            or os.getenv("GEMINI_MODEL")
            or "gemini-2.0-flash"
        )
        self.fallback_to_mock = fallback_to_mock
        self.temperature = temperature
        self.max_input_chars = max_input_chars
        self._cache: Dict[str, SemanticAuditResult] = {}
        self.cache_hits: int = 0

        if client is not None:
            self.client = client
        else:
            if not GEMINI_AVAILABLE:
                raise ImportError(
                    "The 'google-genai' package is not installed. Install it via 'pip install google-genai'."
                )
            self.client = genai.Client(api_key=self.api_key)

    @property
    def cache(self) -> Dict[str, SemanticAuditResult]:
        return self._cache

    @property
    def semantic_cache(self) -> Dict[str, SemanticAuditResult]:
        return self._cache

    def clear_cache(self) -> None:
        self._cache.clear()
        self.cache_hits = 0

    @property
    def model(self) -> str:
        """Alias property for backward compatibility with evaluators exposing .model"""
        return self.model_name

    async def evaluate(
        self,
        condition: SemanticCondition,
        observed_onchain: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SemanticAuditResult:
        start_time = time.perf_counter()
        ctx = metadata if metadata is not None else (context or {})
        bounded_ctx, was_truncated = prepare_bounded_context(ctx, self.max_input_chars)
        cache_key = _make_semantic_cache_key(condition, observed_onchain, bounded_ctx)

        if cache_key in self._cache:
            self.cache_hits += 1
            return self._cache[cache_key].model_copy(
                update={
                    "cached": True,
                    "estimated_cost_usd": 0.0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "latency_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
                }
            )

        user_prompt_data = {
            "policy_prompt": condition.policy_prompt,
            "risk_threshold": condition.risk_threshold,
            "observed_onchain": observed_onchain,
            "context_metadata": bounded_ctx,
        }
        prompt = (
            f"Please audit the following Web3 transaction/proposal against the policy:\n\n"
            f"{json.dumps(user_prompt_data, indent=2, default=str)}"
        )

        try:
            config_kwargs: Dict[str, Any] = {
                "response_mime_type": "application/json",
                "system_instruction": SYSTEM_PROMPT,
                "temperature": self.temperature,
            }
            if types is not None:
                config_kwargs["response_schema"] = LLMAuditOutput
                config = types.GenerateContentConfig(**config_kwargs)
            else:
                config = config_kwargs

            used_model = self.model_name
            try:
                response = await self.client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=config,
                )
            except Exception as initial_exc:
                exc_str = str(initial_exc)
                is_mock = hasattr(self.client, "_mock_name") or hasattr(
                    getattr(self.client, "aio", None), "_mock_name"
                )
                if not is_mock and any(
                    err_code in exc_str for err_code in ("503", "UNAVAILABLE", "404", "NOT_FOUND")
                ):
                    alt_model = (
                        "gemini-3.5-flash-lite"
                        if self.model_name != "gemini-3.5-flash-lite"
                        else "gemini-3.1-flash-lite"
                    )
                    logger.warning(
                        f"Gemini model '{self.model_name}' encountered error ({initial_exc}). Retrying once with failover model '{alt_model}'."
                    )
                    used_model = alt_model
                    response = await self.client.aio.models.generate_content(
                        model=alt_model,
                        contents=prompt,
                        config=config,
                    )
                else:
                    raise

            usage = getattr(response, "usage_metadata", None)
            val_in = getattr(usage, "prompt_token_count", 0) if usage is not None else 0
            input_tokens = val_in if isinstance(val_in, int) else 0
            val_out = getattr(usage, "candidates_token_count", 0) if usage is not None else 0
            output_tokens = val_out if isinstance(val_out, int) else 0

            cost_usd = estimate_llm_cost_usd(used_model, input_tokens, output_tokens)
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

            # Check if response was returned directly as SemanticAuditResult or LLMAuditOutput (e.g. mock returns instance)
            if isinstance(response, SemanticAuditResult):
                final_res = response.model_copy()
            elif isinstance(response, LLMAuditOutput):
                final_res = SemanticAuditResult(**response.model_dump())
            elif hasattr(response, "parsed") and response.parsed is not None:
                if isinstance(response.parsed, SemanticAuditResult):
                    final_res = response.parsed.model_copy()
                elif isinstance(response.parsed, LLMAuditOutput):
                    final_res = SemanticAuditResult(**response.parsed.model_dump())
                elif isinstance(response.parsed, dict):
                    final_res = SemanticAuditResult.model_validate(response.parsed)
                else:
                    final_res = SemanticAuditResult.model_validate(response.parsed)
            else:
                raw_text = getattr(response, "text", "") or ""
                cleaned_text = raw_text.strip()
                if cleaned_text.startswith("```json"):
                    cleaned_text = cleaned_text[7:]
                elif cleaned_text.startswith("```"):
                    cleaned_text = cleaned_text[3:]
                if cleaned_text.endswith("```"):
                    cleaned_text = cleaned_text[:-3]
                cleaned_text = cleaned_text.strip()

                if cleaned_text:
                    try:
                        llm_out = LLMAuditOutput.model_validate_json(cleaned_text)
                        final_res = SemanticAuditResult(**llm_out.model_dump())
                    except Exception:
                        final_res = SemanticAuditResult.model_validate_json(cleaned_text)
                else:
                    raise ValueError("Empty or invalid response received from Gemini API")

            flagged_list = list(final_res.flagged_issues)
            if was_truncated and not any(
                "Context metadata truncated due to LLM_MAX_INPUT_CHARS limit" in str(x)
                for x in flagged_list
            ):
                flagged_list.append("Context metadata truncated due to LLM_MAX_INPUT_CHARS limit")

            final_res = final_res.model_copy(
                update={
                    "cached": False,
                    "provider": "gemini",
                    "model": used_model,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "estimated_cost_usd": cost_usd,
                    "latency_ms": latency_ms,
                    "flagged_issues": flagged_list,
                }
            )
            self._cache[cache_key] = final_res
            return final_res

        except Exception as exc:
            logger.error(
                f"GeminiSemanticEvaluator failed during execution: {exc}",
                exc_info=not self.fallback_to_mock,
            )
            if self.fallback_to_mock:
                logger.warning("Failing over to MockSemanticEvaluator due to Gemini API exception.")
                mock_evaluator = MockSemanticEvaluator(max_input_chars=self.max_input_chars)
                mock_result = await mock_evaluator.evaluate(condition, observed_onchain, bounded_ctx)
                new_flagged = list(mock_result.flagged_issues)
                new_flagged.append(f"LLM provider failure (Gemini): {exc}")
                if was_truncated and not any(
                    "Context metadata truncated due to LLM_MAX_INPUT_CHARS limit" in str(x)
                    for x in new_flagged
                ):
                    new_flagged.append("Context metadata truncated due to LLM_MAX_INPUT_CHARS limit")
                new_action = mock_result.recommended_action
                if str(new_action).strip().upper() == "APPROVE":
                    new_action = "MANUAL_REVIEW"
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                return mock_result.model_copy(
                    update={
                        "flagged_issues": new_flagged,
                        "recommended_action": new_action,
                        "cached": False,
                        "provider": "gemini",
                        "model": self.model_name,
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "estimated_cost_usd": 0.0,
                        "latency_ms": latency_ms,
                    }
                )
            raise


def get_semantic_evaluator(
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    force_mock: bool = False,
    provider: Optional[str] = None,
    fallback_to_mock: bool = True,
    max_input_chars: Optional[int] = None,
    **kwargs: Any,
) -> Union[GeminiSemanticEvaluator, OpenAISemanticEvaluator, MockSemanticEvaluator]:
    """
    Factory function for resilient evaluator instantiation:
    1. If force_mock is True -> MockSemanticEvaluator()
    2. If provider == "gemini" or (no explicit provider and GEMINI_API_KEY / GOOGLE_API_KEY is present):
       instantiates GeminiSemanticEvaluator.
    3. If provider == "openai" or (no explicit provider and OPENAI_API_KEY is present):
       instantiates OpenAISemanticEvaluator.
    4. Otherwise defaults to MockSemanticEvaluator().
    Any initialization failures gracefully fall back to MockSemanticEvaluator.
    """
    if force_mock:
        logger.info("force_mock is enabled; returning MockSemanticEvaluator.")
        return MockSemanticEvaluator(max_input_chars=max_input_chars, **kwargs)

    norm_provider = provider.lower().strip() if provider else None
    if norm_provider == "mock":
        return MockSemanticEvaluator(max_input_chars=max_input_chars, **kwargs)

    # Priority 2: Gemini
    has_gemini_env = bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
    if norm_provider == "gemini" or (
        norm_provider is None and (
            has_gemini_env or (api_key and not os.getenv("OPENAI_API_KEY") and not str(api_key).startswith("sk-"))
        )
    ):
        try:
            gemini_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
            evaluator = GeminiSemanticEvaluator(
                api_key=gemini_key,
                model_name=model or kwargs.pop("model_name", None),
                fallback_to_mock=fallback_to_mock,
                max_input_chars=max_input_chars,
                **kwargs,
            )
            logger.info(f"Initialized GeminiSemanticEvaluator using model '{evaluator.model_name}'.")
            return evaluator
        except Exception as exc:
            logger.warning(
                f"Failed to initialize GeminiSemanticEvaluator ({exc}). Falling back gracefully to MockSemanticEvaluator."
            )
            return MockSemanticEvaluator(max_input_chars=max_input_chars, **kwargs)

    # Priority 3: OpenAI
    has_openai_env = bool(os.getenv("OPENAI_API_KEY"))
    if norm_provider == "openai" or (norm_provider is None and (has_openai_env or api_key)):
        try:
            openai_key = api_key or os.getenv("OPENAI_API_KEY")
            evaluator = OpenAISemanticEvaluator(
                api_key=openai_key,
                model=model,
                fallback_to_mock=fallback_to_mock,
                max_input_chars=max_input_chars,
                **kwargs,
            )
            logger.info(f"Initialized OpenAISemanticEvaluator using model '{evaluator.model}'.")
            return evaluator
        except Exception as exc:
            logger.warning(
                f"Failed to initialize OpenAISemanticEvaluator ({exc}). Falling back gracefully to MockSemanticEvaluator."
            )
            return MockSemanticEvaluator(max_input_chars=max_input_chars, **kwargs)

    logger.info("No LLM API keys configured; defaulting to MockSemanticEvaluator.")
    return MockSemanticEvaluator(max_input_chars=max_input_chars, **kwargs)
